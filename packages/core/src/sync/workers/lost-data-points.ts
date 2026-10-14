/**
 * Re-queue scopes whose registration the gateway no longer has.
 *
 * The upload worker marks an entry synced (stamps its dataPointId) as soon as
 * the gateway accepts the registration, before it settles on chain. If the
 * settle later fails terminally, the gateway rolls the head back to an older
 * version or deletes it outright. The entry still reads as synced, so the
 * worker never re-posts it and the scope is missing from the gateway for good:
 * no replica can download it, and every paid read fails because the gateway
 * cannot find the data point the access record names.
 *
 * Once per boot, check each scope's latest synced entry against the gateway
 * and clear its dataPointId when the gateway has no data point at all, or only
 * an older version. The next upload cycle registers it again (rebasing onto
 * the registry's live version when needed).
 */

import type { DataStoragePort } from "../../ports/index.js";
import type { Logger } from "../../logger/index.js";
import type { GatewayClient } from "@opendatalabs/vana-sdk/browser";

export interface LostDataPointDeps {
  storage: Pick<
    DataStoragePort,
    "listScopes" | "findEntry" | "updateDataPointId"
  >;
  gateway: Pick<GatewayClient, "getDataPoint">;
  logger: Logger;
}

const SCOPE_PAGE = 200;
const CONCURRENCY = 8;

/** Returns the scopes re-queued for upload. */
export async function requeueLostDataPoints(
  deps: LostDataPointDeps,
): Promise<string[]> {
  const latest = [];
  for (let offset = 0; ; offset += SCOPE_PAGE) {
    const page = deps.storage.listScopes({ limit: SCOPE_PAGE, offset });
    for (const summary of page.scopes) {
      const entry = deps.storage.findEntry({ scope: summary.scope });
      if (entry?.dataPointId) latest.push(entry);
    }
    if (page.scopes.length < SCOPE_PAGE) break;
  }

  const requeued: string[] = [];
  for (let i = 0; i < latest.length; i += CONCURRENCY) {
    await Promise.all(
      latest.slice(i, i + CONCURRENCY).map(async (entry) => {
        let record;
        try {
          record = await deps.gateway.getDataPoint(entry.dataPointId!);
        } catch {
          // Deleted by the owner (tombstone) or the gateway is unreachable:
          // neither is evidence that the registration was lost.
          return;
        }
        const registered = record ? Number(record.expectedVersion) : 0;
        if (registered >= entry.version) return;
        await deps.storage.updateDataPointId(entry.path, null);
        requeued.push(entry.scope);
        deps.logger.warn(
          {
            scope: entry.scope,
            version: entry.version,
            registeredVersion: record ? registered : null,
          },
          "Gateway lost this scope's registration; re-queued for upload",
        );
      }),
    );
  }
  return requeued;
}
