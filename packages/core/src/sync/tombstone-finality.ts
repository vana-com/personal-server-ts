import type { VersionInventoryClient } from "../additions/version-inventory.js";
import type { TombstoneFinalityPort } from "../ports/index.js";

const PAGE_LIMIT = 1000;
const MAX_PAGES = 20;

export interface InventoryTombstoneFinalityOptions {
  /** Clock seam for tests; defaults to `Date.now`. */
  now?: () => number;
  /** First wait after a scope reports no finalized tombstone (default 1 min). */
  minRecheckMs?: number;
  /** Longest wait between reads for one scope (default 15 min). */
  maxRecheckMs?: number;
}

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
 * A scope that reports no finalized tombstone is not read again until its
 * recheck time, which doubles from `minRecheckMs` up to `maxRecheckMs`. A
 * held key whose deletion may never become final (a failed tombstone, or a
 * scope that was never registered) then costs a few reads an hour, not one
 * per sync cycle. The backoff only delays a deletion, never brings one
 * forward.
 */
export function createInventoryTombstoneFinality(
  inventory: Pick<VersionInventoryClient, "page">,
  options: InventoryTombstoneFinalityOptions = {},
): TombstoneFinalityPort {
  const now = options.now ?? Date.now;
  const minRecheck = options.minRecheckMs ?? 60_000;
  const maxRecheck = options.maxRecheckMs ?? 15 * 60_000;
  const recheck = new Map<string, { at: number; interval: number }>();

  async function read(scope: string, from: bigint): Promise<bigint | null> {
    let after = (from > 0n ? from - 1n : 0n).toString();
    let highest: bigint | null = null;
    for (let count = 0; count < MAX_PAGES; count++) {
      const result = await inventory.page(scope, { after, limit: PAGE_LIMIT });
      for (const version of result.data.versions) {
        if (!version.isTombstone || version.status !== "finalized") continue;
        const value = BigInt(version.expectedVersion);
        if (value >= from && (highest === null || value > highest)) {
          highest = value;
        }
      }
      if (!result.pagination.hasMore) return highest;
      const next = result.pagination.nextAfter;
      if (next === null) break;
      after = next;
    }
    // An unfinished traversal can only under-report: keys wait longer.
    return highest;
  }

  return {
    async finalizedTombstoneAtOrAbove(scope, atOrAbove) {
      const waiting = recheck.get(scope);
      if (waiting && now() < waiting.at) return null;
      const highest = await read(scope, BigInt(atOrAbove));
      if (highest !== null) {
        recheck.delete(scope);
        return highest.toString();
      }
      const interval = waiting
        ? Math.min(waiting.interval * 2, maxRecheck)
        : minRecheck;
      recheck.set(scope, { at: now() + interval, interval });
      return null;
    },
  };
}
