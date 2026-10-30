import type { VersionInventoryClient } from "../additions/version-inventory.js";
import type {
  TombstoneFinalityPort,
  TombstoneFinalityState,
} from "../ports/index.js";
import { isTombstoneRecord } from "./tombstone.js";

const PAGE_LIMIT = 1000;
const MAX_PAGES = 20;

export interface InventoryTombstoneFinalityOptions {
  /** Clock seam for tests; defaults to `Date.now`. */
  now?: () => number;
  /** First wait after a scope reports nothing settling (default 1 min). */
  minRecheckMs?: number;
  /** Longest wait between reads for one scope (default 15 min). */
  maxRecheckMs?: number;
}

const SETTLED = new Set(["finalized", "failed"]);

/**
 * Tombstone finality read from the gateway's version inventory
 * (`GET /v1/data/:id/versions`, owner or registered-server signed).
 *
 * Only `finalized` counts. The gateway moves a data version
 * pending → submitting → confirmed → finalized, and can still push a
 * `confirmed` version back to `pending` on a reorg
 * (data-gateway `reconcileConfirmedDataPoints`); until a tombstone is
 * finalized its settlement can fail, the gateway rolls the head back, and
 * a writer may recover the failed slot.
 *
 * While a tombstone at or above the asked version is settling, every call
 * reads the inventory, so a sync cycle sees finality on its next pass. The
 * route has no rate limit; a call costs one signed read of at most
 * `MAX_PAGES` pages.
 *
 * When nothing is settling and nothing is finalized (a scope that was never
 * registered, a rolled-back tombstone, a newer write above it), the scope is
 * not read again until its recheck time, which doubles from `minRecheckMs`
 * up to `maxRecheckMs`. Such keys may never become free, so they cost a few
 * reads an hour, not one per sync cycle. `recheckNow` drops the wait when a
 * new tombstone is queued. The backoff only delays a deletion, never brings
 * one forward.
 */
export function createInventoryTombstoneFinality(
  inventory: Pick<VersionInventoryClient, "page">,
  options: InventoryTombstoneFinalityOptions = {},
): TombstoneFinalityPort {
  const now = options.now ?? Date.now;
  const minRecheck = options.minRecheckMs ?? 60_000;
  const maxRecheck = options.maxRecheckMs ?? 15 * 60_000;
  const recheck = new Map<string, { at: number; interval: number }>();
  const idle: TombstoneFinalityState = {
    finalized: null,
    settling: false,
    rolledBack: null,
  };

  async function read(
    scope: string,
    from: bigint,
  ): Promise<TombstoneFinalityState> {
    let after = (from > 0n ? from - 1n : 0n).toString();
    let finalized: bigint | null = null;
    let settling = false;
    // The highest listed row at or above `from`, and the head as of the last
    // page (each page is its own snapshot; the last one is the newest).
    let top: { version: bigint; failedTombstone: boolean } | null = null;
    let head: {
      expectedVersion: string;
      deletedAt: string | null;
      dataHash: string;
      metadataHash: string;
    } | null = null;
    let complete = false;
    for (let count = 0; count < MAX_PAGES; count++) {
      const result = await inventory.page(scope, { after, limit: PAGE_LIMIT });
      head = result.data.head ?? null;
      for (const version of result.data.versions) {
        const value = BigInt(version.expectedVersion);
        if (value < from) continue;
        if (top === null || value > top.version) {
          top = {
            version: value,
            failedTombstone: version.isTombstone && version.status === "failed",
          };
        }
        if (!version.isTombstone) continue;
        if (version.status === "finalized") {
          if (finalized === null || value > finalized) finalized = value;
        } else if (!SETTLED.has(version.status)) {
          settling = true;
        }
      }
      if (!result.pagination.hasMore) {
        complete = true;
        break;
      }
      const next = result.pagination.nextAfter;
      if (next === null) break;
      after = next;
    }
    // An unfinished traversal can only under-report: keys wait longer, and
    // it never reports a rollback it did not see to the end.
    let rolledBack: string | null = null;
    if (complete && !settling && top?.failedTombstone) {
      const live =
        head !== null &&
        head.deletedAt === null &&
        !isTombstoneRecord(head) &&
        BigInt(head.expectedVersion) < top.version;
      if (live) rolledBack = top.version.toString();
    }
    return {
      finalized: finalized === null ? null : finalized.toString(),
      settling,
      rolledBack,
    };
  }

  return {
    async tombstoneState(scope, atOrAbove) {
      const waiting = recheck.get(scope);
      if (waiting && now() < waiting.at) return idle;
      const state = await read(scope, BigInt(atOrAbove));
      if (state.finalized !== null || state.settling) {
        recheck.delete(scope);
        return state;
      }
      const interval = waiting
        ? Math.min(waiting.interval * 2, maxRecheck)
        : minRecheck;
      recheck.set(scope, { at: now() + interval, interval });
      return state;
    },
    recheckNow(scope) {
      recheck.delete(scope);
    },
  };
}
