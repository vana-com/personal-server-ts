/**
 * Retire local legacy files once the stream data holds them.
 *
 * Deleting a file cannot be undone, so every gate below is a code check, and
 * the delete itself is off unless the host turns it on (`deleteEnabled`).
 * Import and readback run whenever the account is switched; they delete
 * nothing.
 *
 * A local version is deleted only when ALL of these hold:
 *   1. the delete is enabled and this is not a dry run;
 *   2. this device's own import finished for every connector of the scope;
 *   3. a readback of exactly this version passed (see `readback.ts`), and a
 *      FRESH readback taken in the same pass, immediately before the delete,
 *      passes too: the published view can change after an earlier pass was
 *      stored, so a stored pass never deletes on its own;
 *   4. when the readback relied on the delete fence, this device STAGED rows
 *      for every connector of the scope (`importStaged`: an empty import
 *      source sets `importDone` for all, but stages nothing, so it proves no
 *      row of the file was ever delivered), and every target stream of the
 *      scope that has seen a delete has since been re-collected by a full run
 *      on this device (a record the fence dropped must not be retired before
 *      the device could collect it again). After a whole-source delete the
 *      readback passes (the file predates the delete) but the file stays
 *      until the source is reconnected and a full run commits;
 *   5. the file still hashes to what the fresh readback read, right before
 *      the delete.
 *
 * The registry must be an authority for the scope (`deleteBasis`): covered by
 * live complete heads, or deleted whole, and not ambiguous. Otherwise the
 * scope is skipped: neither fenced nor passed.
 *
 * Retire writes nothing to the gateway: no tombstone of the legacy name and
 * no remote blob delete. It erases only this device's checked local versions,
 * each fenced by its local id and path, so a version that landed since the
 * readback survives.
 */

import type { DataStoragePort } from "../../ports/index.js";
import { contentHash } from "../../storage/legacy-entity-key-sets.js";
import type { IndexEntry } from "../../storage/index/types.js";
import { isPhysicalScope } from "../../stream-sync/scope-routing.js";
import { isGatewayReservedScope } from "../delete-data-port.js";
import {
  readbackVersion,
  type DeleteBasis,
  type ReadbackView,
} from "./readback.js";
import {
  versionKey,
  type ReadbackRecord,
  type RetireLedger,
} from "./ledger.js";

const PAGE_SIZE = 200;
const VERSION_PAGE_SIZE = 500;

export type RetireDecision =
  | "no_import"
  | "no_readback"
  | "readback_failed"
  | "fence_not_imported"
  | "fence_not_recollected"
  | "file_changed"
  | "ready";

export interface RetireFileReport {
  readonly scope: string;
  readonly version: string;
  readonly importDone: boolean;
  /** `none` = no stored readback for this exact version. */
  readonly readback: "pass" | "fail" | "none";
  readonly readbackReason: string | null;
  readonly decision: RetireDecision;
  readonly wouldDelete: boolean;
}

export interface RetireReport {
  readonly mode: "delete" | "dry-run" | "readback-only";
  readonly files: readonly RetireFileReport[];
  readonly deleted: number;
}

/** What the stream side tells a retire pass. */
export interface RetireHost extends ReadbackView {
  /** Whether this device finished importing for the connector. */
  importDone(connector: string): Promise<boolean>;
  /** Whether this device staged rows for the connector (not a vacuous pass). */
  importStaged(connector: string): Promise<boolean>;
  /** A full run of the connector committed the stream after this delete version. */
  fullRunSince(
    connector: string,
    stream: string,
    deleteVersion: number,
  ): Promise<boolean>;
}

export interface RetireDeps {
  storage: Pick<
    DataStoragePort,
    "listScopes" | "listVersions" | "readEnvelope" | "deleteVersion"
  >;
  host: RetireHost;
  ledger: RetireLedger;
  /**
   * The delete step's own switch. False: readbacks run and are recorded, and
   * nothing is deleted. Default off in every host.
   */
  deleteEnabled: boolean;
  /** Report only: nothing is deleted whatever `deleteEnabled` says. */
  dryRun?: boolean;
  now?: () => Date;
}

function localRows(
  storage: Pick<DataStoragePort, "listVersions">,
  scope: string,
): IndexEntry[] {
  const rows: IndexEntry[] = [];
  for (let offset = 0; ; offset += VERSION_PAGE_SIZE) {
    const page = storage.listVersions(scope, {
      limit: VERSION_PAGE_SIZE,
      offset,
    });
    rows.push(...page);
    if (page.length < VERSION_PAGE_SIZE) return rows;
  }
}

function legacyScopes(storage: RetireDeps["storage"]): string[] {
  const scopes: string[] = [];
  for (let offset = 0; ; offset += PAGE_SIZE) {
    const page = storage.listScopes({ limit: PAGE_SIZE, offset });
    for (const { scope } of page.scopes) {
      if (isPhysicalScope(scope) || isGatewayReservedScope(scope)) continue;
      scopes.push(scope);
    }
    if (page.scopes.length < PAGE_SIZE) return scopes;
  }
}

/** The local file still hashes to what the readback read. */
async function holds(
  deps: RetireDeps,
  scope: string,
  row: IndexEntry,
  readback: ReadbackRecord,
): Promise<boolean> {
  if (readback.fileHash === undefined) return false;
  try {
    const envelope = await deps.storage.readEnvelope(scope, row.collectedAt);
    return contentHash(envelope.data) === readback.fileHash;
  } catch {
    return false;
  }
}

async function decide(
  deps: RetireDeps,
  scope: string,
  row: IndexEntry,
  basis: DeleteBasis,
  stored: ReadbackRecord | null,
): Promise<RetireFileReport> {
  const version = versionKey(row);
  const { streams } = basis;
  let importDone = streams.length > 0;
  for (const connector of new Set(streams.map((s) => s.connector))) {
    if (!(await deps.host.importDone(connector))) importDone = false;
  }
  const readback = stored === null ? "none" : stored.pass ? "pass" : "fail";
  const report = (decision: RetireDecision): RetireFileReport => ({
    scope,
    version,
    importDone,
    readback,
    readbackReason: stored?.reason ?? null,
    decision,
    wouldDelete: decision === "ready",
  });
  if (!importDone) return report("no_import");
  if (stored === null) return report("no_readback");
  if (!stored.pass) return report("readback_failed");
  if (stored.fenced > 0) {
    for (const connector of new Set(streams.map((s) => s.connector))) {
      if (!(await deps.host.importStaged(connector))) {
        return report("fence_not_imported");
      }
    }
    for (const s of streams) {
      if (s.deleteVersion === 0) continue;
      if (
        !(await deps.host.fullRunSince(s.connector, s.stream, s.deleteVersion))
      ) {
        return report("fence_not_recollected");
      }
    }
  }
  return report("ready");
}

/**
 * One pass over the local legacy scopes: read back every version that has no
 * passing readback, then, when enabled, delete the versions that are ready.
 * A delete always follows a readback taken in this pass (see the header).
 * A dry run reads every version back and marks what it stores as dry.
 */
export async function retireLegacyFiles(
  deps: RetireDeps,
): Promise<RetireReport> {
  const mayDelete = deps.deleteEnabled && deps.dryRun !== true;
  const dry = deps.dryRun === true;
  const mode = deps.dryRun
    ? "dry-run"
    : deps.deleteEnabled
      ? "delete"
      : "readback-only";
  const files: RetireFileReport[] = [];
  let deleted = 0;
  const readbackDeps = {
    storage: deps.storage,
    view: deps.host,
    ledger: deps.ledger,
    dry,
    ...(deps.now ? { now: deps.now } : {}),
  };
  for (const scope of legacyScopes(deps.storage)) {
    const basis = deps.host.deleteBasis(scope);
    if (basis === null) continue; // no authority, no read target or listing not whole
    const rows = localRows(deps.storage, scope);
    for (const row of rows) {
      let record = await deps.ledger.readback(scope, versionKey(row));
      // Read back only once import is done: a readback before it would fail
      // for a reason the import is about to fix.
      let importReady = basis.streams.length > 0;
      for (const connector of new Set(basis.streams.map((s) => s.connector))) {
        if (!(await deps.host.importDone(connector))) importReady = false;
      }
      if (importReady && (dry || record === null || !record.pass)) {
        record = await readbackVersion(readbackDeps, scope, row);
      }
      let report = await decide(deps, scope, row, basis, record);
      if (report.wouldDelete && mayDelete) {
        // The stored pass may be stale: take the readback again now, and
        // decide on that one. The basis is read again with it.
        const fresh = await readbackVersion(readbackDeps, scope, row);
        const freshBasis = deps.host.deleteBasis(scope);
        report =
          freshBasis === null
            ? { ...report, decision: "no_readback", wouldDelete: false }
            : await decide(deps, scope, row, freshBasis, fresh);
        // The file read back is the file deleted: hash it once more.
        if (report.wouldDelete && !(await holds(deps, scope, row, fresh))) {
          report = { ...report, decision: "file_changed", wouldDelete: false };
        }
      }
      files.push(report);
      if (!report.wouldDelete || !mayDelete) continue;
      const removed = await deps.storage.deleteVersion(scope, row.collectedAt, {
        id: row.id,
        path: row.path,
      });
      if (removed) deleted += 1;
    }
  }
  return { mode, files, deleted };
}
