/**
 * Re-queue scopes whose registration the gateway no longer has.
 *
 * The upload worker marks an entry synced (stamps its dataPointId) as soon as
 * the gateway accepts the registration, before it settles on chain. If the
 * settle later fails terminally and no version survives, the gateway deletes
 * the data point. The entry still reads as synced, so the worker never
 * re-posts it and the scope is missing from the gateway for good: no replica
 * can download it, and every paid read fails because the gateway cannot find
 * the data point the access record names.
 *
 * Check each scope's latest synced entry against the gateway and clear its
 * dataPointId when the gateway has no data point at all; the next upload cycle
 * registers it again. Only the "gone entirely" case is re-queued: when the
 * head merely rolled back to an older version, the download worker would
 * re-stamp the row from that older version before a failed re-upload could be
 * retried, so that case is left to a dedicated fix.
 */

import {
  DataPointDeletedError,
  type GatewayClient,
} from "@opendatalabs/vana-sdk/browser";
import type { DataStoragePort } from "../../ports/index.js";
import type { Logger } from "../../logger/index.js";

export interface LostDataPointDeps {
  storage: Pick<
    DataStoragePort,
    "listScopes" | "findEntry" | "updateDataPointId"
  >;
  gateway: Pick<GatewayClient, "getDataPoint">;
  logger: Logger;
}

export interface LostDataPointResult {
  /** Scopes re-queued for upload. */
  requeued: string[];
  /** A gateway lookup failed; run the check again on a later cycle. */
  complete: boolean;
}

const SCOPE_PAGE = 200;
const CONCURRENCY = 8;

export async function requeueLostDataPoints(
  deps: LostDataPointDeps,
): Promise<LostDataPointResult> {
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
  let complete = true;
  for (let i = 0; i < latest.length; i += CONCURRENCY) {
    await Promise.all(
      latest.slice(i, i + CONCURRENCY).map(async (entry) => {
        let record;
        try {
          record = await deps.gateway.getDataPoint(entry.dataPointId!);
        } catch (err) {
          // A tombstone is the owner's deletion, not a lost registration.
          // Anything else is a failed lookup: no evidence either way, so the
          // caller retries the check later instead of trusting this pass.
          if (!(err instanceof DataPointDeletedError)) complete = false;
          return;
        }
        if (record) return;
        await deps.storage.updateDataPointId(entry.path, null);
        requeued.push(entry.scope);
        deps.logger.warn(
          { scope: entry.scope, version: entry.version },
          "Gateway has no data point for this synced scope; re-queued for upload",
        );
      }),
    );
  }
  return { requeued, complete };
}
