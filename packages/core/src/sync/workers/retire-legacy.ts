import type { Logger } from "../../logger/index.js";
import type { DataStoragePort } from "../../ports/index.js";
import type { IndexEntry } from "../../storage/index/types.js";
import { isPhysicalScope } from "../../stream-sync/scope-routing.js";
import {
  entityKeySets,
  keysHeld,
  type EntityKeySets,
} from "../../storage/legacy-entity-key-sets.js";
import { isGatewayReservedScope } from "../delete-data-port.js";
import type { DeleteScopeResult } from "./delete.js";

/** Scopes deleted per cycle: each costs a tombstone and a storage batch. */
export const RETIRE_LEGACY_SCOPES_PER_CYCLE = 10;

const PAGE_SIZE = 200;
const VERSION_PAGE_SIZE = 500;

/** The reader's answer for one legacy scope (`StreamSyncReadService.viewCoverage`). */
export type RetireCoverage =
  | { readonly kind: "covered"; readonly throughMs: number }
  | { readonly kind: "skip"; readonly reason: "incomplete" | "ambiguous" };

/**
 * What a cycle needs to retire legacy scopes, read fresh each cycle by
 * `SyncManagerOptions.retireLegacy`.
 */
export interface RetireLegacyOption {
  /** Do the stream views cover this legacy scope, and up to when. */
  coverage(scope: string): RetireCoverage;
  /**
   * The entity keys the served view holds for the scope, or null when the
   * view cannot be read or is not keyed. A complete head lets the view
   * replace a file for reads; it does not prove the view holds every record
   * of the file, so deleting needs the keys.
   */
  viewKeys(scope: string): Promise<EntityKeySets | null>;
  /**
   * Like `viewKeys`, but as the owner reads: this device's unpublished local
   * runs count. For the upload gate only, never for a delete: a key held only
   * by an unpublished run is not yet on any other device.
   */
  ownerViewKeys?(scope: string): Promise<EntityKeySets | null>;
  /** Changes whenever an imported view of the scope changes; keys a memo. */
  viewRevision?(scope: string): string;
  /** ISO time the Account switch was last turned on; absent retires nothing. */
  switchedAt: string | undefined;
}

/**
 * The one place the switch is defined, for every host: on while the host's
 * CURRENT config has `streamSync.write` on and both the stream-sync writer and
 * reader exist. The config object is read at each call, so turning the switch
 * off stops the next cycle without a rebuild.
 */
export function liveRetireLegacy(input: {
  config: { streamSync: { write: boolean; switchedAt?: string | undefined } };
  writer: unknown;
  reader:
    | {
        viewCoverage(scope: string): RetireCoverage;
        viewKeys(scope: string): Promise<EntityKeySets | null>;
        ownerViewKeys?(scope: string): Promise<EntityKeySets | null>;
        viewRevision?(scope: string): string;
      }
    | null
    | undefined;
}): () => RetireLegacyOption | null {
  return () => {
    const { reader } = input;
    if (!input.config.streamSync.write || !input.writer || !reader) {
      return null;
    }
    return {
      coverage: (scope) => reader.viewCoverage(scope),
      viewKeys: (scope) => reader.viewKeys(scope),
      ...(reader.ownerViewKeys
        ? { ownerViewKeys: (scope: string) => reader.ownerViewKeys!(scope) }
        : {}),
      ...(reader.viewRevision
        ? { viewRevision: (scope: string) => reader.viewRevision!(scope) }
        : {}),
      switchedAt: input.config.streamSync.switchedAt,
    };
  };
}

export interface RetireLegacyDeps {
  storage: Pick<
    DataStoragePort,
    "listScopes" | "listVersions" | "readEnvelope"
  >;
  /**
   * ISO time the Account switch was last turned on. Absent or unparsable:
   * nothing is retired and no old-app write is counted.
   */
  switchedAt: string | undefined;
  /** Do the stream views cover this legacy scope, and up to when. */
  coverage(scope: string): RetireCoverage;
  /** The keys the served view holds for the scope; see `RetireLegacyOption`. */
  viewKeys(scope: string): Promise<EntityKeySets | null>;
  /** Changes whenever an imported view of the scope changes. Absent: no memo. */
  viewRevision?(scope: string): string;
  /**
   * Scopes found not held, keyed to the view revision and local versions that
   * produced the answer. The caller keeps it across cycles so a scope that
   * never retires is not re-read until its view or its files change.
   */
  notHeldMemo?: Map<string, string>;
  /**
   * Whether the switch is still on. Read before each scope's delete, so
   * turning it off mid-pass stops further deletes. Absent: always on.
   */
  stillOn?: () => boolean;
  /**
   * When the gateway registered the scope's current head (the registry row's
   * `addedAt`), or null when it has no row (no remote legacy file). Each older
   * version was registered earlier, so this is the latest registration time of
   * the scope's legacy files, from any device.
   */
  registeredAt(scope: string): Promise<string | null>;
  /** Durable scope deletion: gateway tombstone, storage blobs, local copy. */
  deleteScope(scope: string): Promise<DeleteScopeResult>;
  logger: Pick<Logger, "info" | "warn">;
}

export interface RetireLegacyResult {
  /** Legacy scopes held locally. */
  considered: number;
  /** Scopes whose delete finished at the gateway. */
  deleted: number;
  /** Scopes kept, by reason. */
  skipped: {
    /** A view is missing, incomplete, or the listing is not whole. */
    incomplete: number;
    /** More than one connection could have produced the legacy data. */
    ambiguous: number;
    /** A local row is newer than the head, or has no usable time. */
    uncovered: number;
    /**
     * The newest local file holds a key the served view lacks, or membership
     * cannot be proven (no reviewed key, a body that is not keyed, a view
     * that cannot be read).
     */
    notInView: number;
    /** A legacy file was registered at or after the switch, or its time is unknown. */
    afterSwitch: number;
    /** The delete did not reach the gateway; retried next cycle. */
    failed: number;
  };
  /**
   * Scopes whose legacy files reached the gateway registry at or after the
   * switch (another device's old app), counted over the scopes this pass got
   * as far as checking. This device's own local rows never count: its
   * current app stops uploading legacy files at the switch. A number only.
   */
  legacyWritesAfterSwitch: number;
}

function emptyResult(): RetireLegacyResult {
  return {
    considered: 0,
    deleted: 0,
    skipped: {
      incomplete: 0,
      ambiguous: 0,
      uncovered: 0,
      notInView: 0,
      afterSwitch: 0,
      failed: 0,
    },
    legacyWritesAfterSwitch: 0,
  };
}

export function localRows(
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

/**
 * Delete the legacy files of every scope the stream views fully replace.
 * The caller runs it only while the account is switched to stream sync, after
 * a download pass that did not fail.
 *
 * A scope is retired only when deleting it cannot lose data that no surface
 * can read. All of these hold, else the scope is skipped and counted:
 *   - every target of the scope has a complete live view, from one connection;
 *   - no local row was collected after the oldest head used (a cheap
 *     pre-filter: a newer row may hold data the head lacks);
 *   - the gateway registered no legacy file of the scope at or after the
 *     switch (`addedAt`): such a file comes from another device's old app and
 *     is in no stream. Local rows are not judged by time: this device's own
 *     current app writes none after the switch, and membership protects them;
 *   - membership: every entity key of the newest local file is in the served
 *     view. A complete head does not mean the view holds every record of a
 *     file (a connector that exposes a window, a row from another device).
 *
 * Idempotent and safe between devices: a scope with no local files is not
 * listed again; a device racing another gets `already-deleted` and `missing`
 * blobs, which `deleteScope` treats as success. Stream-sync names and
 * gateway-reserved scopes are never touched. Logs counts only.
 */
export async function retireLegacyScopes(
  deps: RetireLegacyDeps,
): Promise<RetireLegacyResult> {
  const result = emptyResult();
  const switchedAtMs = deps.switchedAt ? Date.parse(deps.switchedAt) : NaN;
  if (!Number.isFinite(switchedAtMs)) return result;

  // Snapshot the listing first: deleting while paging would shift offsets.
  const scopes: string[] = [];
  for (let offset = 0; ; offset += PAGE_SIZE) {
    const page = deps.storage.listScopes({ limit: PAGE_SIZE, offset });
    for (const { scope } of page.scopes) {
      if (isPhysicalScope(scope) || isGatewayReservedScope(scope)) continue;
      scopes.push(scope);
    }
    if (page.scopes.length < PAGE_SIZE) break;
  }
  result.considered = scopes.length;

  let budget = RETIRE_LEGACY_SCOPES_PER_CYCLE;
  for (const scope of scopes) {
    const rows = localRows(deps.storage, scope);
    const times = rows.map((row) => Date.parse(row.collectedAt));

    const coverage = deps.coverage(scope);
    if (coverage.kind === "skip") {
      result.skipped[coverage.reason] += 1;
      continue;
    }
    if (times.some((t) => !Number.isFinite(t) || t > coverage.throughMs)) {
      result.skipped.uncovered += 1;
      continue;
    }
    // null: the gateway never saw the scope, so no remote legacy file exists.
    let registered: number | null;
    try {
      const at = await deps.registeredAt(scope);
      registered = at === null ? null : Date.parse(at);
    } catch {
      registered = NaN;
    }
    if (registered !== null && !(registered < switchedAtMs)) {
      // A registration made elsewhere, or a time we cannot read: keep it.
      if (Number.isFinite(registered)) result.legacyWritesAfterSwitch += 1;
      result.skipped.afterSwitch += 1;
      continue;
    }
    if (budget === 0) continue; // next cycle
    if (!(await versionsAreHeld(deps, scope, rows))) {
      result.skipped.notInView += 1;
      continue;
    }
    // The switch may have been turned off while this pass ran.
    if (deps.stillOn && !deps.stillOn()) break;
    // Files can land while the checks above awaited. The delete erases every
    // version it lists, so list again right here (no await before the delete
    // lists them itself): a changed set was not all checked; next cycle.
    if (fingerprint(localRows(deps.storage, scope)) !== fingerprint(rows)) {
      result.skipped.notInView += 1;
      continue;
    }
    budget -= 1;
    try {
      const outcome = await deps.deleteScope(scope);
      if (outcome.durable) result.deleted += 1;
      else result.skipped.failed += 1;
    } catch {
      result.skipped.failed += 1;
    }
  }
  if (result.considered > 0) {
    deps.logger.info({ ...result }, "Retire pass over legacy scopes");
  }
  return result;
}

/** Identity of a set of local versions: a new or replaced file changes it. */
function fingerprint(rows: readonly IndexEntry[]): string {
  return rows
    .map((row) => `${row.id}|${row.collectedAt}`)
    .sort()
    .join(",");
}

/**
 * Every entity key of every local version of the scope is in `view`. The
 * delete removes all versions, so each one must be held, not only the newest
 * (a connector that exposes a window drops old keys from later versions).
 * Unknown (no key table, an unreadable file) is not held.
 */
export async function localKeysHeld(
  storage: Pick<DataStoragePort, "readEnvelope">,
  scope: string,
  rows: readonly IndexEntry[],
  view: EntityKeySets,
): Promise<boolean> {
  for (const row of rows) {
    let local: EntityKeySets | null;
    try {
      const envelope = await storage.readEnvelope(scope, row.collectedAt);
      local = entityKeySets(scope, envelope.data);
    } catch {
      return false;
    }
    if (!local || !keysHeld(local, view)) return false;
  }
  return true;
}

async function versionsAreHeld(
  deps: Pick<
    RetireLegacyDeps,
    "storage" | "viewKeys" | "viewRevision" | "notHeldMemo"
  >,
  scope: string,
  rows: readonly IndexEntry[],
): Promise<boolean> {
  if (rows.length === 0) return true; // nothing local to lose
  const revision = deps.viewRevision?.(scope);
  const token =
    revision === undefined ? null : `${revision}#${fingerprint(rows)}`;
  if (token !== null && deps.notHeldMemo?.get(scope) === token) return false;
  let view: EntityKeySets | null;
  try {
    view = await deps.viewKeys(scope);
  } catch {
    return false; // transient: not remembered
  }
  if (view === null) return false;
  const held = await localKeysHeld(deps.storage, scope, rows, view);
  if (token !== null && deps.notHeldMemo) {
    if (held) deps.notHeldMemo.delete(scope);
    else deps.notHeldMemo.set(scope, token);
  }
  return held;
}

const STATUS_VALUES = new Set(["ok", "skipped", "failed", "deferred"]);
/** Payload fields that carry a count or a status, and nothing else. */
const LOGGABLE_FIELDS = new Set([
  "durable",
  "gateway",
  "storage",
  "local",
  "blobsDeleted",
  "blobsMissing",
  "blobsPending",
  "deleted",
  "missing",
  "failed",
  "pending",
  "markers",
  "released",
  "rolledBack",
  "converged",
  "considered",
  "skipped",
  "legacyWritesAfterSwitch",
]);

function countsOnlyValue(value: unknown): unknown {
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (typeof value === "string" && STATUS_VALUES.has(value)) return value;
  if (typeof value === "object" && value !== null && !Array.isArray(value)) {
    const inner = Object.fromEntries(
      Object.entries(value)
        .filter(([, v]) => typeof v === "number")
        .map(([k, v]) => [k, v]),
    );
    return Object.keys(inner).length > 0 ? inner : undefined;
  }
  return undefined;
}

/**
 * A logger for the whole legacy-delete path. Payloads keep only the fields in
 * an allowlist, and only when the value is a number, a boolean, a status word
 * or a flat object of numbers. No scope name, id, version, key or error text
 * passes. The message string is fixed text and stays.
 */
export function countsOnlyLogger(logger: Logger): Logger {
  const strip = (payloadOrMessage?: unknown): unknown => {
    if (typeof payloadOrMessage === "string") return payloadOrMessage;
    if (typeof payloadOrMessage !== "object" || payloadOrMessage === null) {
      return undefined;
    }
    const out: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(payloadOrMessage)) {
      if (!LOGGABLE_FIELDS.has(key)) continue;
      const kept = countsOnlyValue(value);
      if (kept !== undefined) out[key] = kept;
    }
    return out;
  };
  return {
    debug: (p, m) => logger.debug(strip(p), m),
    info: (p, m) => logger.info(strip(p), m),
    warn: (p, m) => logger.warn(strip(p), m),
    error: (p, m) => logger.error(strip(p), m),
  };
}

/** The class of an error, for logs that must not carry its message. */
export function errorClass(err: unknown): string {
  return err instanceof Error ? err.name : "NonError";
}
