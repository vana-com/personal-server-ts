import type { DeltaApplyResult } from "../../stream-sync/ports.js";

/** A local sync's `applyDelta` that hands every delta to the cycle. */
export async function deltaToCycle(): Promise<DeltaApplyResult> {
  return { outcome: "cycle", reason: "this test runs every wake as a cycle" };
}
