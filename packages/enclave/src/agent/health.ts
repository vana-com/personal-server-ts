import type { DstackClient } from "../dstack/client.js";
import type { HealthResponse } from "./types.js";

export async function readHealth(
  client: DstackClient,
): Promise<HealthResponse> {
  return client.info();
}
