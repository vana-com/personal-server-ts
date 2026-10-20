import type { DataPointFeedPort, DataPointFeedRecord } from "../ports/index.js";
import type { IndexEntry } from "../storage/index/types.js";
import { isTombstoneRecord } from "./tombstone.js";

/**
 * Where a deletion verdict came from. `assumed-live` is the only source that
 * is never verified: the tracker had no fact and could not reach the gateway.
 */
export type ScopeDeletionSource =
  "feed" | "gateway" | "local-delete" | "assumed-live";

export type ScopeDeletionVerdict =
  | {
      deleted: true;
      deletedAt: string;
      /**
       * The tombstone's registry version, or null when the gateway did not
       * say (a 410 without a body). Null covers every local entry.
       */
      version: string | null;
      source: Exclude<ScopeDeletionSource, "assumed-live">;
      /**
       * False when the tombstone is older than `maxStalenessMs`, the
       * re-check could not reach the gateway, and the last known state is
       * being served (fail-safe: refuse rather than resurrect).
       */
      verified: boolean;
    }
  | {
      deleted: false;
      source: ScopeDeletionSource;
      /** False when the verdict is a fallback because the gateway was unreachable. */
      verified: boolean;
    };

export interface ScopeDeletionResolveOptions {
  /**
   * `if-stale` (default): trust a fresh feed pass or a recent per-scope
   * verdict, and only ask the gateway when neither exists.
   * `always`: ask the gateway unless a recent per-scope verdict exists. Used
   * for local misses, where "never had it" and "deleted long ago" look the
   * same to the local index and a fresh feed pass cannot tell them apart.
   */
  consultGateway?: "if-stale" | "always";
  /** Maximum wait for gateway state. Zero uses cached state only. */
  gatewayTimeoutMs?: number;
}

/**
 * Per-process memory of which scopes the gateway has tombstoned, kept current
 * by every component that talks to the registry, so reads can refuse deleted
 * data without a gateway round-trip per request.
 *
 * Facts flow in from:
 *   - the download worker (every listed row, deleted or live, plus a
 *     "feed pass complete" marker when the listing had no further pages),
 *   - the upload worker (a successful registration means the scope is live),
 *   - the delete worker (a landed tombstone means the scope is deleted),
 *   - direct gateway lookups made by `resolve` itself.
 *
 * Every remembered verdict, live or deleted, ages out after `maxStalenessMs`
 * and is then re-established from the feed or a gateway lookup. Consistency
 * window, stated explicitly:
 *   - a tombstone landed by THIS replica is visible to its reads immediately;
 *   - a tombstone landed by ANOTHER replica is visible here once the download
 *     feed lists it (one sync poll interval while sync is healthy), or after
 *     at most `maxStalenessMs` plus one gateway lookup when the feed is not
 *     fresh (sync off, blocked, or a multi-page backlog);
 *   - a re-add on another replica after a tombstone becomes visible here on
 *     the same schedule: the feed lists the live row, or the tombstone ages
 *     out and the next read re-checks the gateway;
 *   - while the gateway is unreachable the tracker serves its last known
 *     state (`verified: false`) rather than failing every read; it re-checks
 *     after `gatewayRetryMs`. A partitioned replica therefore keeps serving
 *     its local copy (or keeps refusing a tombstoned scope) until
 *     connectivity returns, and never longer than `maxStalenessMs` after it
 *     does.
 */
export interface ScopeDeletionTracker {
  /** Durable or pending observations, independent of the registry's current file state. */
  readonly deletionHistory?: ScopeDeletionHistory;
  /**
   * Record a gateway tombstone for `scope`. `source` names who learned it
   * (default "feed"; the delete worker passes "local-delete").
   */
  markDeleted(
    scope: string,
    tombstone: ScopeTombstone,
    source?: Exclude<ScopeDeletionSource, "assumed-live">,
  ): void;
  /** Record that the registry holds a live (non-tombstoned) row for `scope`. */
  markLive(scope: string): void;
  /**
   * Record that a deletion-aware feed listing completed with no further
   * pages: every tombstone up to `at` has been fed through `markDeleted`.
   * `full` means the listing started from no cursor and therefore covered
   * the whole registry, so a scope re-added since its tombstone would have
   * been listed live (and marked live); only then are the remembered
   * tombstones re-validated as of `at`. An incremental pass (`since` the
   * cursor) proves nothing about tombstones it did not list, so those keep
   * ageing and are re-checked at the gateway after `maxStalenessMs`.
   * Retries pending history writes before recording completion. A storage
   * error propagates and leaves the unsuccessful observations pending.
   */
  noteFeedSynced(at?: Date, options?: { full?: boolean }): void;
  /** Synchronous view: a known tombstone, or null when none is known. */
  knownDeletion(scope: string): ScopeTombstone | null;
  /** Milliseconds since the last complete feed pass, or null if none yet. */
  feedAgeMs(): number | null;
  /** Async verdict, consulting the gateway only as described above. */
  resolve(
    scope: string,
    options?: ScopeDeletionResolveOptions,
  ): Promise<ScopeDeletionVerdict>;
  readonly maxStalenessMs: number;
}

export interface ScopeTombstone {
  deletedAt: string;
  /** Registry version of the tombstone; null when unknown (covers everything). */
  version: string | null;
}

/** Owner-partitioned metadata supplied by the runtime, never projected data. */
export interface ScopeDeletionHistory {
  remember(scope: string, tombstone: ScopeTombstone): void;
  get(scope: string): ScopeTombstone | null;
}

export interface ScopeDeletionTrackerOptions {
  deletionHistory?: ScopeDeletionHistory;
  /** Deletion-aware registry lookup for on-demand checks. Optional: without it the tracker only knows what it is told. */
  feed?: DataPointFeedPort;
  /** Data owner used for on-demand lookups. Optional for the same reason. */
  serverOwner?: string;
  /**
   * How old a complete feed pass or a per-scope verdict (live or deleted)
   * may be before `resolve` asks the gateway again. Default 120_000 (two
   * default sync poll intervals, so one missed cycle does not turn every
   * read into a lookup).
   */
  maxStalenessMs?: number;
  /** Back-off after a failed gateway lookup before trying again. Default 15_000. */
  gatewayRetryMs?: number;
  /** Upper bound on remembered live verdicts (probing unknown scopes must not grow memory without bound). Default 10_000. */
  maxLiveEntries?: number;
  now?: () => Date;
  logger?: {
    warn?(payload: Record<string, unknown>, message: string): void;
  };
}

export const DEFAULT_SCOPE_DELETION_MAX_STALENESS_MS = 120_000;
export const DEFAULT_SCOPE_DELETION_GATEWAY_RETRY_MS = 15_000;
const DEFAULT_MAX_LIVE_ENTRIES = 10_000;

interface KnownTombstone extends ScopeTombstone {
  source: Exclude<ScopeDeletionSource, "assumed-live">;
  /** When the registry last confirmed the tombstone (ms). */
  verifiedAtMs: number;
}

class DeletionLookupTimeout extends Error {}

/** A timed-out response is never applied to the tracker cache. */
async function beforeDeadline<T>(
  request: Promise<T>,
  timeoutMs?: number,
  onTimeout?: () => void,
): Promise<T> {
  if (timeoutMs === undefined) return request;
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      request,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          reject(
            new DeletionLookupTimeout("Deletion lookup deadline exceeded"),
          );
          onTimeout?.();
        }, timeoutMs);
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

export function createScopeDeletionTracker(
  options: ScopeDeletionTrackerOptions = {},
): ScopeDeletionTracker {
  const maxStalenessMs =
    options.maxStalenessMs ?? DEFAULT_SCOPE_DELETION_MAX_STALENESS_MS;
  const gatewayRetryMs =
    options.gatewayRetryMs ?? DEFAULT_SCOPE_DELETION_GATEWAY_RETRY_MS;
  const maxLiveEntries = options.maxLiveEntries ?? DEFAULT_MAX_LIVE_ENTRIES;
  const now = options.now ?? (() => new Date());
  const nowMs = () => now().getTime();

  // scope -> tombstone. Kept until the registry shows the scope live, but
  // re-validated once older than maxStalenessMs (a re-add elsewhere must not
  // leave this replica answering 410 forever).
  const deleted = new Map<string, KnownTombstone>();
  // scope -> when a gateway lookup last confirmed the scope live (ms).
  const live = new Map<string, number>();
  let lastFeedSyncMs: number | null = null;
  let lastGatewayFailureMs: number | null = null;
  // Coalesce concurrent lookups of the same scope into one request.
  const inflight = new Map<string, Promise<ScopeDeletionVerdict | null>>();
  // A live file may clear `deleted`, but cannot clear an observed canonical
  // refusal whose history write failed. Remove it only after persistence.
  const pendingHistory = new Map<string, ScopeTombstone>();
  const history = options.deletionHistory;

  function persistPendingHistory(scope: string): void {
    const tombstone = pendingHistory.get(scope);
    if (!history || !tombstone) return;
    history.remember(scope, tombstone);
    pendingHistory.delete(scope);
  }

  const deletionHistory: ScopeDeletionHistory | undefined = history
    ? {
        remember(scope, tombstone) {
          pendingHistory.set(scope, tombstone);
          persistPendingHistory(scope);
        },
        get(scope) {
          // Preserve durable-read errors and the existing durable fact when
          // an update failed. Either fact is sufficient to refuse canonical.
          return history.get(scope) ?? pendingHistory.get(scope) ?? null;
        },
      }
    : undefined;

  function rememberLive(scope: string, at: number): void {
    deleted.delete(scope);
    live.delete(scope);
    live.set(scope, at);
    // Map preserves insertion order; the first key is the oldest verdict.
    while (live.size > maxLiveEntries) {
      const oldest = live.keys().next().value;
      if (oldest === undefined) break;
      live.delete(oldest);
    }
  }

  function rememberDeleted(
    scope: string,
    tombstone: ScopeTombstone,
    source: KnownTombstone["source"],
  ): void {
    const normalized = {
      deletedAt: tombstone.deletedAt,
      version: normalizeVersion(tombstone.version),
    };
    deleted.set(scope, {
      ...normalized,
      source,
      verifiedAtMs: nowMs(),
    });
    live.delete(scope);
    deletionHistory?.remember(scope, normalized);
  }

  function isFresh(at: number | null): boolean {
    return at !== null && nowMs() - at <= maxStalenessMs;
  }

  function verdictFromRecord(
    scope: string,
    record: DataPointFeedRecord | null,
  ): ScopeDeletionVerdict {
    const deletedAt = deletionTimestamp(record);
    if (deletedAt !== null) {
      const version = tombstoneVersion(record);
      rememberDeleted(scope, { deletedAt, version }, "gateway");
      return {
        deleted: true,
        deletedAt,
        version,
        source: "gateway",
        verified: true,
      };
    }
    rememberLive(scope, nowMs());
    return { deleted: false, source: "gateway", verified: true };
  }

  /**
   * Ask the registry. Null when it cannot be asked right now (no feed or
   * owner wired, inside the failure back-off, or the request failed): the
   * caller falls back to its last known state.
   */
  async function lookup(
    scope: string,
    timeoutMs?: number,
  ): Promise<ScopeDeletionVerdict | null> {
    const feed = options.feed;
    const owner = options.serverOwner;
    if (!feed || !owner || (timeoutMs !== undefined && timeoutMs <= 0))
      return null;
    if (
      lastGatewayFailureMs !== null &&
      nowMs() - lastGatewayFailureMs < gatewayRetryMs
    ) {
      return null;
    }
    const pending = inflight.get(scope);
    if (pending) {
      // A read may already own an unbounded lookup. Inventory still has its
      // own deadline and must not wait for that request.
      return beforeDeadline(pending, timeoutMs).catch((error) => {
        if (error instanceof DeletionLookupTimeout) return null;
        throw error;
      });
    }
    const request = (async () => {
      let record: DataPointFeedRecord | null;
      const controller =
        timeoutMs === undefined ? undefined : new AbortController();
      try {
        record = await beforeDeadline(
          feed.getDataPoint({
            ownerAddress: owner,
            scope,
            ...(controller ? { signal: controller.signal } : {}),
          }),
          timeoutMs,
          () => controller?.abort(),
        );
        lastGatewayFailureMs = null;
      } catch (err) {
        lastGatewayFailureMs = nowMs();
        options.logger?.warn?.(
          {
            scope,
            error: err instanceof Error ? err.message : String(err),
            retryAfterMs: gatewayRetryMs,
          },
          "Could not check gateway deletion state; serving last known state",
        );
        return null;
      }
      // Persistence failures must propagate. Treating them as a network
      // outage could answer assumed-live before the deletion is recorded.
      return verdictFromRecord(scope, record);
    })().finally(() => inflight.delete(scope));
    inflight.set(scope, request);
    return request;
  }

  function lastKnownVerdict(scope: string): ScopeDeletionVerdict {
    // Sync or a local delete can teach us a tombstone during the lookup.
    const known = deleted.get(scope);
    return known
      ? {
          deleted: true,
          deletedAt: known.deletedAt,
          version: known.version,
          source: known.source,
          verified: false,
        }
      : { deleted: false, source: "assumed-live", verified: false };
  }

  return {
    maxStalenessMs,
    deletionHistory,

    markDeleted(scope, tombstone, source = "feed") {
      rememberDeleted(scope, tombstone, source);
    },

    markLive(scope) {
      rememberLive(scope, nowMs());
    },

    noteFeedSynced(at, options) {
      // One attempt per pending scope per completed feed pass, including
      // live/empty passes after the gateway has stopped listing a deletion.
      for (const scope of pendingHistory.keys()) persistPendingHistory(scope);
      lastFeedSyncMs = (at ?? now()).getTime();
      if (!options?.full) return;
      // A full listing would have shown any re-add as a live row (and marked
      // it live above), so every tombstone still here is confirmed. Tombstones
      // an incremental pass happened to list were refreshed by markDeleted.
      for (const tombstone of deleted.values()) {
        tombstone.verifiedAtMs = Math.max(
          tombstone.verifiedAtMs,
          lastFeedSyncMs,
        );
      }
    },

    knownDeletion(scope) {
      const known = deleted.get(scope);
      return known === undefined
        ? null
        : { deletedAt: known.deletedAt, version: known.version };
    },

    feedAgeMs() {
      return lastFeedSyncMs === null ? null : nowMs() - lastFeedSyncMs;
    },

    async resolve(scope, resolveOptions) {
      const known = deleted.get(scope);
      if (known !== undefined) {
        if (isFresh(known.verifiedAtMs)) {
          return {
            deleted: true,
            deletedAt: known.deletedAt,
            version: known.version,
            source: known.source,
            verified: true,
          };
        }
        // Stale tombstone: the scope may have been re-added elsewhere. Ask;
        // if the registry cannot be reached, keep refusing (never resurrect
        // on a guess) and say the verdict is unverified.
        const rechecked = await lookup(scope, resolveOptions?.gatewayTimeoutMs);
        if (rechecked !== null) return rechecked;
        return lastKnownVerdict(scope);
      }
      if (isFresh(live.get(scope) ?? null)) {
        return { deleted: false, source: "gateway", verified: true };
      }
      const consult = resolveOptions?.consultGateway ?? "if-stale";
      if (consult === "if-stale" && isFresh(lastFeedSyncMs)) {
        return { deleted: false, source: "feed", verified: true };
      }
      return (
        (await lookup(scope, resolveOptions?.gatewayTimeoutMs)) ??
        lastKnownVerdict(scope)
      );
    },
  };
}

/**
 * A tombstone is visible either as `deletedAt` (a feed that models deletion)
 * or, from a gateway that lists tombstones as plain rows, as the tombstone
 * commitments themselves; `addedAt` is then the deletion time.
 */
export function deletionTimestamp(
  record:
    | (Pick<DataPointFeedRecord, "dataHash" | "metadataHash" | "addedAt"> & {
        deletedAt?: string | null;
      })
    | null,
): string | null {
  if (!record) return null;
  if (record.deletedAt) return record.deletedAt;
  return isTombstoneRecord(record) ? record.addedAt : null;
}

/**
 * The tombstone's registry version as the gateway reported it, normalised to
 * a positive decimal string, or null when it did not say (the 410 fallback
 * synthesises "0").
 */
export function tombstoneVersion(
  record: Pick<DataPointFeedRecord, "expectedVersion"> | null,
): string | null {
  return normalizeVersion(record?.expectedVersion ?? null);
}

function normalizeVersion(value: string | null | undefined): string | null {
  if (typeof value !== "string" || !/^\d+$/.test(value)) return null;
  return BigInt(value) > 0n ? BigInt(value).toString() : null;
}

/**
 * True when a local index entry is part of what a gateway tombstone deleted,
 * decided causally rather than by comparing clocks across machines:
 *   - a synced entry is covered when its registry version is at or below
 *     the tombstone's (the tombstone superseded it);
 *   - an unsynced entry is covered unless it was ingested with knowledge of
 *     this tombstone or a later one (`afterTombstoneVersion` >= tombstone
 *     version), which makes it a deliberate re-add;
 *   - a tombstone of unknown version covers everything.
 * Data ingested concurrently with a deletion elsewhere (before this replica
 * learned of it) is therefore covered too: refusing to resurrect is the
 * failure this guards against, and the window is one sync poll interval.
 */
export function isEntryCoveredByTombstone(
  entry: Pick<IndexEntry, "version" | "dataPointId" | "afterTombstoneVersion">,
  tombstone: Pick<ScopeTombstone, "version">,
): boolean {
  const version = normalizeVersion(tombstone.version);
  if (version === null) return true;
  const tombstoned = BigInt(version);
  if (entry.dataPointId !== null) return BigInt(entry.version) <= tombstoned;
  const marker = entry.afterTombstoneVersion;
  if (
    marker === null ||
    marker === undefined ||
    !Number.isSafeInteger(marker)
  ) {
    return true;
  }
  return BigInt(marker) < tombstoned;
}
