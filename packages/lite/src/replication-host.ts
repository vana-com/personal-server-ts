import {
  AdditionsBudget,
  AdditionsBudgetExceeded,
} from "@opendatalabs/personal-server-ts-core/additions";
import { ReplicaFragmentSizeError } from "@opendatalabs/personal-server-ts-core/replication/delivery";
import { createDpv2ReplicaTransport } from "@opendatalabs/personal-server-ts-core/replication/dpv2";
import {
  createReplicaEvidenceAdapter,
  type ReplicaEvidenceRpc,
} from "@opendatalabs/personal-server-ts-core/replication/evidence";
import type { createLiteReplicaWorker } from "./replication.js";

export interface LiteReplicaHostPorts extends Omit<
  Parameters<typeof createDpv2ReplicaTransport>[0],
  "evidence"
> {
  chainId: number;
  registry: `0x${string}`;
}

/** Host supplies its existing HTTP/RPC bridge and the same signing/storage
 * authority as legacy Lite sync. This factory invents no authority fallback.
 */
export function createLiteReplicaHostTransport(
  input: LiteReplicaHostPorts & {
    rpc: ReplicaEvidenceRpc;
    fetch: typeof globalThis.fetch;
    gatewayUrl: string;
    maxIncomingBytes?: number;
  },
) {
  const cap = input.maxIncomingBytes ?? 8 * 1024 * 1024;
  if (!Number.isSafeInteger(cap) || cap < 1 || cap > 8 * 1024 * 1024)
    throw new RangeError("invalid Lite replica download bound");
  if (!input.storage.downloadBounded)
    throw new Error("bounded replica storage download required");
  const bounded = input.storage.downloadBounded.bind(input.storage);
  const evidence = createReplicaEvidenceAdapter(input);
  return createDpv2ReplicaTransport({
    ...input,
    evidence,
    storage: {
      ...input.storage,
      download: async (url) => {
        // readBoundedResponse accounts for both chunks and contiguous copy.
        const budget = new AdditionsBudget(cap * 2, 25000);
        let bytes: Uint8Array;
        try {
          bytes = await bounded(url, budget);
        } catch (error) {
          if (
            error instanceof AdditionsBudgetExceeded &&
            (budget.remainingMilliseconds ?? 0) > 0
          )
            throw new ReplicaFragmentSizeError(
              "replica ciphertext exceeds host bound",
            );
          throw error;
        }
        if (bytes.length > cap)
          throw new ReplicaFragmentSizeError(
            "replica ciphertext exceeds host bound",
          );
        return bytes;
      },
    },
  });
}

export type LiteReplicaWorker = ReturnType<typeof createLiteReplicaWorker>;
