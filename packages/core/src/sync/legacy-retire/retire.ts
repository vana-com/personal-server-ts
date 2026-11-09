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
 *   3. a stored readback of exactly this version passed (see `readback.ts`);
 *   4. when the readback relied on the delete fence, every target stream of
 *      the scope that has seen a delete has since been re-collected by a full
 *      run on this device (a record the fence dropped must not be retired
 *      before the device could collect it again).
 *
 * Retire writes nothing to the gateway: no tombstone of the legacy name and
 * no remote blob delete. It erases only this device's checked local versions,
 * each fenced by its local id and path, so a version that landed since the
 * readback survives.
 */

import type { DataStoragePort } from "../../ports/index.js";
import type { IndexEntry } from "../../storage/index/types.js";
import { isPhysicalScope } from "../../stream-sync/scope-routing.js";
import { isGatewayReservedScope } from "../delete-data-port.js";
import { readbackVersion, type ReadbackView } from "./readback.js";
import { versionKey, type RetireLedger } from "./ledger.js";

const PAGE_SIZE = 200;
const VERSION_PAGE_SIZE = 500;

export type RetireDecision =
  | "no_import"
  | "no_readback"
  | "readback_failed"
  | "fence_not_recollected"
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

async function decide(
  deps: RetireDeps,
  scope: string,
  row: IndexEntry,
  streams: readonly {
    connector: string;
    stream: string;
    deleteVersion: number;
  }[],
): Promise<RetireFileReport> {
  const version = versionKey(row);
  let importDone = streams.length > 0;
  for (const connector of new Set(streams.map((s) => s.connector))) {
    if (!(await deps.host.importDone(connector))) importDone = false;
  }
  const stored = await deps.ledger.readback(scope, version);
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
 * stored readback (or a failed one, since the stream may have caught up),
 * then, when enabled, delete the versions that are ready.
 */
export async function retireLegacyFiles(
  deps: RetireDeps,
): Promise<RetireReport> {
  const mayDelete = deps.deleteEnabled && deps.dryRun !== true;
  const mode = deps.dryRun
    ? "dry-run"
    : deps.deleteEnabled
      ? "delete"
      : "readback-only";
  const files: RetireFileReport[] = [];
  let deleted = 0;
  for (const scope of legacyScopes(deps.storage)) {
    const streams = deps.host.streamDeletes(scope);
    if (streams === null) continue; // no read target / listing not whole
    const rows = localRows(deps.storage, scope);
    for (const row of rows) {
      const stored = await deps.ledger.readback(scope, versionKey(row));
      // Read back only once import is done: a readback before it would fail
      // for a reason the import is about to fix.
      let importReady = streams.length > 0;
      for (const connector of new Set(streams.map((s) => s.connector))) {
        if (!(await deps.host.importDone(connector))) importReady = false;
      }
      if (importReady && (stored === null || !stored.pass)) {
        await readbackVersion(
          {
            storage: deps.storage,
            view: deps.host,
            ledger: deps.ledger,
            ...(deps.now ? { now: deps.now } : {}),
          },
          scope,
          row,
        );
      }
      const report = await decide(deps, scope, row, streams);
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
