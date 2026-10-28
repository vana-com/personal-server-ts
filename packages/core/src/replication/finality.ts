import type { Hex } from "viem";

/** Scheduling hints only. Every wake still requires independent finalized evidence. */
export interface ReplicaFinalityHints {
  head(): Promise<bigint>;
}

export function createReplicaFinalityHints(deps: {
  rpc: {
    getBlock(input: {
      blockTag: "finalized";
    }): Promise<{ number: bigint | null; hash?: Hex | null }>;
  };
}): ReplicaFinalityHints {
  return {
    async head() {
      const block = await deps.rpc.getBlock({ blockTag: "finalized" });
      if (block.number === null || block.number < 0n)
        throw new Error("missing finalized scheduling head");
      return block.number;
    },
  };
}
