import { expect, it } from "vitest";
import type { PrewarmDeps } from "../jobs/run.js";
import { MAINNET_CHAIN_ID, MOKSHA_CHAIN_ID } from "../chain-id.js";
import { startFleetWorker } from "./worker-runtime.js";

// The chain guard is the first check after FLEET_ENABLED, and the peer-policy
// check is the next one: reaching that message proves the chain was admitted.
const PAST_THE_CHAIN_GUARD = /Admitted controller peer policy required/;
const UNSUPPORTED_CHAIN_ID = 1337;

function start(chainId: number) {
  return startFleetWorker({
    env: { FLEET_ENABLED: "true" },
    sandbox: { chainId } as PrewarmDeps,
    nodeId: "worker-1",
    nodeSecret: "n".repeat(32),
    capacity: 1,
  });
}

it("admits both supported chains and rejects any other", async () => {
  await expect(start(MOKSHA_CHAIN_ID)).rejects.toThrow(PAST_THE_CHAIN_GUARD);
  await expect(start(MAINNET_CHAIN_ID)).rejects.toThrow(PAST_THE_CHAIN_GUARD);
  await expect(start(UNSUPPORTED_CHAIN_ID)).rejects.toThrow(
    "CHAIN_ID must be 1480 or 14800",
  );
});
