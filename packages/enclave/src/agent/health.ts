import type { DstackClient } from "../dstack/client.js";
import type { FleetConfigValidity } from "../fleet/security-config.js";
import type { HealthResponse } from "./types.js";

export async function readHealth(
  client: DstackClient,
  nodeId: string | null,
  activeSandboxes = 0,
  draining = false,
  config?: FleetConfigValidity,
): Promise<HealthResponse> {
  return {
    ...(await client.info()),
    nodeId,
    activeSandboxes,
    draining,
    configIssuedAt: config?.issuedAt ?? null,
    // A signed non-expiring bundle and an unsigned agent both report null here;
    // configIssuedAt distinguishes them.
    configExpiresAt: config?.expiresAt ?? null,
  };
}
