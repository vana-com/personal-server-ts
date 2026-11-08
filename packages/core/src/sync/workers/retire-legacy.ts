import type { Logger } from "../../logger/index.js";
import type { DataStoragePort } from "../../ports/index.js";
import type { IndexEntry } from "../../storage/index/types.js";
import { isPhysicalScope } from "../../stream-sync/scope-routing.js";
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
  reader: { viewCoverage(scope: string): RetireCoverage } | null | undefined;
}): () => RetireLegacyOption | null {
  return () => {
    const { reader } = input;
    if (!input.config.streamSync.write || !input.writer || !reader) {
      return null;
    }
    return {
      coverage: (scope) => reader.viewCoverage(scope),
      switchedAt: input.config.streamSync.switchedAt,
    };
  };
}

export interface RetireLegacyDeps {
  storage: Pick<DataStoragePort, "listScopes" | "listVersions">;
  /**
   * ISO time the Account switch was last turned on. Absent or unparsable:
   * nothing is retired and no old-app write is counted.
   */
  switchedAt: string | undefined;
  /** Do the stream views cover this legacy scope, and up to when. */
  coverage(scope: string): RetireCoverage;
  /**
   * When the gateway registered the scope's current head (the registry row's
   * `addedAt`), or null when it has no row (no remote legacy file). Each older version was registered
   * earlier, so this is the latest write time of the scope's legacy files.
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
    /** A legacy file was written at or after the switch, or its time is unknown. */
    afterSwitch: number;
    /** The delete did not reach the gateway; retried next cycle. */
    failed: number;
  };
  /**
   * Legacy files written at or after the switch (old-app writes), counted
   * over the scopes this pass looked at. A number only.
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
      afterSwitch: 0,
      failed: 0,
    },
    legacyWritesAfterSwitch: 0,
  };
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

/**
 * Delete the legacy files of every scope the stream views fully replace.
 * The caller runs it only while the account is switched to stream sync, after
 * a download pass that did not fail.
 *
 * A scope is retired only when deleting it cannot lose data that no surface
 * can read. All of these hold, else the scope is skipped and counted:
 *   - every target of the scope has a complete live view, from one connection;
 *   - no local row was collected after the oldest head used (the heads cover
 *     the rows). A row not uploaded is fine when a complete head covers it:
 *     after the switch legacy is read-only history and uploads never finish;
 *   - every legacy file was written before the switch: the local rows by
 *     `collectedAt`, the scope's latest registration by the gateway's
 *     `addedAt`. A file written at or after the switch comes from an old app
 *     and is in no stream.
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
    const writtenAfter = times.filter(
      (t) => !Number.isFinite(t) || t >= switchedAtMs,
    ).length;
    result.legacyWritesAfterSwitch += writtenAfter;

    const coverage = deps.coverage(scope);
    if (coverage.kind === "skip") {
      result.skipped[coverage.reason] += 1;
      continue;
    }
    if (times.some((t) => !Number.isFinite(t) || t > coverage.throughMs)) {
      result.skipped.uncovered += 1;
      continue;
    }
    if (writtenAfter > 0) {
      result.skipped.afterSwitch += 1;
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
      // A write made elsewhere, or a time we cannot read: keep the scope.
      if (Number.isFinite(registered)) result.legacyWritesAfterSwitch += 1;
      result.skipped.afterSwitch += 1;
      continue;
    }
    if (budget === 0) continue; // next cycle
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
