import type { DataPointFeedPort, DataPointFeedRecord } from "../ports/index.js";
import { isTombstoneRecord } from "./tombstone.js";

/**
 * Where a deletion verdict came from. `assumed-live` is the only unverified
 * source: it means the tracker had no fact and could not reach the gateway.
 */
export type ScopeDeletionSource =
  "feed" | "gateway" | "local-delete" | "assumed-live";

export type ScopeDeletionVerdict =
  | {
      deleted: true;
      deletedAt: string;
      source: Exclude<ScopeDeletionSource, "assumed-live">;
      verified: true;
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
 * Consistency window, stated explicitly:
 *   - a tombstone landed by THIS replica is visible to its reads immediately;
 *   - a tombstone landed by ANOTHER replica is visible here once the download
 *     feed lists it (one sync poll interval while sync is healthy), or after
 *     at most `maxStalenessMs` plus one gateway lookup when the feed is not
 *     fresh (sync off, blocked, or a multi-page backlog);
 *   - while the gateway is unreachable the tracker serves its last known
 *     state (`verified: false`) rather than failing every read; it re-checks
 *     after `gatewayRetryMs`. A partitioned replica therefore keeps serving
 *     its local copy until connectivity returns, and never longer than
 *     `maxStalenessMs` after it does.
 * A deleted verdict is sticky until the registry shows the scope live again
 * (a re-add), which the feed, the upload worker or a direct lookup reports.
 */
export interface ScopeDeletionTracker {
  /**
   * Record a gateway tombstone for `scope`. `source` names who learned it
   * (default "feed"; the delete worker passes "local-delete").
   */
  markDeleted(
    scope: string,
    deletedAt: string,
    source?: Exclude<ScopeDeletionSource, "assumed-live">,
  ): void;
  /** Record that the registry holds a live (non-tombstoned) row for `scope`. */
  markLive(scope: string): void;
  /**
   * Record that a deletion-aware feed listing completed with no further
   * pages: every tombstone up to `at` has been fed through `markDeleted`.
   */
  noteFeedSynced(at?: Date): void;
  /** Synchronous view: a known tombstone, or null when none is known. */
  knownDeletion(scope: string): { deletedAt: string } | null;
  /** Milliseconds since the last complete feed pass, or null if none yet. */
  feedAgeMs(): number | null;
  /** Async verdict, consulting the gateway only as described above. */
  resolve(
    scope: string,
    options?: ScopeDeletionResolveOptions,
  ): Promise<ScopeDeletionVerdict>;
  readonly maxStalenessMs: number;
}

export interface ScopeDeletionTrackerOptions {
  /** Deletion-aware registry lookup for on-demand checks. Optional: without it the tracker only knows what it is told. */
  feed?: DataPointFeedPort;
  /** Data owner used for on-demand lookups. Optional for the same reason. */
  serverOwner?: string;
  /**
   * How old a complete feed pass or a per-scope gateway verdict may be before
   * `resolve` asks the gateway again. Default 120_000 (two default sync poll
   * intervals, so one missed cycle does not turn every read into a lookup).
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

  // scope -> tombstone. Sticky until the registry shows the scope live.
  const deleted = new Map<
    string,
    { deletedAt: string; source: Exclude<ScopeDeletionSource, "assumed-live"> }
  >();
  // scope -> when a gateway lookup last confirmed the scope live (ms).
  const live = new Map<string, number>();
  let lastFeedSyncMs: number | null = null;
  let lastGatewayFailureMs: number | null = null;
  // Coalesce concurrent lookups of the same scope into one request.
  const inflight = new Map<string, Promise<ScopeDeletionVerdict>>();

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

  function isFresh(at: number | null): boolean {
    return at !== null && nowMs() - at <= maxStalenessMs;
  }

  function verdictFromRecord(
    scope: string,
    record: DataPointFeedRecord | null,
  ): ScopeDeletionVerdict {
    const deletedAt = deletionTimestamp(record);
    if (deletedAt !== null) {
      deleted.set(scope, { deletedAt, source: "gateway" });
      live.delete(scope);
      return { deleted: true, deletedAt, source: "gateway", verified: true };
    }
    rememberLive(scope, nowMs());
    return { deleted: false, source: "gateway", verified: true };
  }

  async function lookup(scope: string): Promise<ScopeDeletionVerdict> {
    const feed = options.feed;
    const owner = options.serverOwner;
    if (!feed || !owner) {
      return { deleted: false, source: "assumed-live", verified: false };
    }
    if (
      lastGatewayFailureMs !== null &&
      nowMs() - lastGatewayFailureMs < gatewayRetryMs
    ) {
      return { deleted: false, source: "assumed-live", verified: false };
    }
    const pending = inflight.get(scope);
    if (pending) return pending;
    const request = (async () => {
      try {
        const record = await feed.getDataPoint({
          ownerAddress: owner,
          scope,
        });
        lastGatewayFailureMs = null;
        return verdictFromRecord(scope, record);
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
        return {
          deleted: false,
          source: "assumed-live",
          verified: false,
        } satisfies ScopeDeletionVerdict;
      } finally {
        inflight.delete(scope);
      }
    })();
    inflight.set(scope, request);
    return request;
  }

  return {
    maxStalenessMs,

    markDeleted(scope, deletedAt, source = "feed") {
      deleted.set(scope, { deletedAt, source });
      live.delete(scope);
    },

    markLive(scope) {
      rememberLive(scope, nowMs());
    },

    noteFeedSynced(at) {
      lastFeedSyncMs = (at ?? now()).getTime();
    },

    knownDeletion(scope) {
      const known = deleted.get(scope);
      return known === undefined ? null : { deletedAt: known.deletedAt };
    },

    feedAgeMs() {
      return lastFeedSyncMs === null ? null : nowMs() - lastFeedSyncMs;
    },

    async resolve(scope, resolveOptions) {
      const known = deleted.get(scope);
      if (known !== undefined) {
        return {
          deleted: true,
          deletedAt: known.deletedAt,
          source: known.source,
          verified: true,
        };
      }
      if (isFresh(live.get(scope) ?? null)) {
        return { deleted: false, source: "gateway", verified: true };
      }
      const consult = resolveOptions?.consultGateway ?? "if-stale";
      if (consult === "if-stale" && isFresh(lastFeedSyncMs)) {
        return { deleted: false, source: "feed", verified: true };
      }
      return lookup(scope);
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
 * True when a local index entry was ingested at or before the gateway
 * deletion, i.e. it is part of what the owner deleted rather than a fresh
 * re-add. Unparseable timestamps count as covered: resurrecting deleted data
 * is the failure this guards against.
 */
export function isEntryCoveredByDeletion(
  entry: { createdAt: string },
  deletedAt: string,
): boolean {
  const created = Date.parse(entry.createdAt);
  const deleted = Date.parse(deletedAt);
  if (Number.isNaN(created) || Number.isNaN(deleted)) return true;
  return created <= deleted;
}
