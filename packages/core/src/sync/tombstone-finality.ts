import type { VersionInventoryClient } from "../additions/version-inventory.js";
import type { TombstoneFinalityPort } from "../ports/index.js";

const PAGE_LIMIT = 1000;
const MAX_PAGES = 20;

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
 */
export function createInventoryTombstoneFinality(
  inventory: Pick<VersionInventoryClient, "page">,
): TombstoneFinalityPort {
  return {
    async finalizedTombstoneAtOrAbove(scope, atOrAbove) {
      const from = BigInt(atOrAbove);
      let after = (from > 0n ? from - 1n : 0n).toString();
      let highest: bigint | null = null;
      for (let count = 0; count < MAX_PAGES; count++) {
        const result = await inventory.page(scope, {
          after,
          limit: PAGE_LIMIT,
        });
        for (const version of result.data.versions) {
          if (!version.isTombstone || version.status !== "finalized") continue;
          const value = BigInt(version.expectedVersion);
          if (value >= from && (highest === null || value > highest)) {
            highest = value;
          }
        }
        if (!result.pagination.hasMore) return highest?.toString() ?? null;
        const next = result.pagination.nextAfter;
        if (next === null) break;
        after = next;
      }
      // An unfinished traversal can only under-report: keys wait longer.
      return highest?.toString() ?? null;
    },
  };
}
