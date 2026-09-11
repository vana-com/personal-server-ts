import type { DstackClient } from "../dstack/client.js";
import { cachedDstackInfo } from "../dstack/info-cache.js";
import type { FleetConfigValidity } from "../fleet/security-config.js";
import type { HealthResponse } from "./types.js";

/** Reported in place of the dstack fields when nothing has ever been read. */
const DSTACK_UNREACHABLE = "unreachable";

export async function readHealth(
  client: DstackClient,
  nodeId: string | null,
  activeSandboxes = 0,
  draining = false,
  config?: FleetConfigValidity,
): Promise<HealthResponse> {
  // Callers poll this route with short budgets (the fleet poller used 8 s), so
  // the guest agent is never on the critical path: the boot-time read answers.
  const info = await cachedDstackInfo(client);

  return {
    ...info,
    // Answering without appId/composeHash/instanceId beats hanging: a caller
    // that needs them retries, one that only needs draining is served.
    ...(info ? {} : { dstack: DSTACK_UNREACHABLE }),
    nodeId,
    activeSandboxes,
    draining,
    configIssuedAt: config?.issuedAt ?? null,
    // A signed non-expiring bundle and an unsigned agent both report null here;
    // configIssuedAt distinguishes them.
    configExpiresAt: config?.expiresAt ?? null,
  };
}
