import type { DstackClient } from "../dstack/client.js";
import type { HealthResponse } from "./types.js";

export async function readHealth(
  client: DstackClient,
  nodeId: string | null,
  activeSandboxes = 0,
  draining = false,
): Promise<HealthResponse> {
  return { ...(await client.info()), nodeId, activeSandboxes, draining };
}
