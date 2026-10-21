/** Read-only dev prerequisite check. Creates an ephemeral owner; reads no account/config files. */
import { createPublicClient, http } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { createReplicaEvidenceAdapter } from "../packages/core/src/replication/evidence.js";
import { replicaRegistrationState } from "../packages/core/src/replication/dpv2.js";
import { replicaScope } from "../packages/core/src/replication/transport.js";

const gatewayUrl = "https://dp-rpc-dev.vana.org";
const storageUrl = "https://storage-dev.vana.org";
const rpcUrl = "https://rpc.moksha.vana.org";
const registry = "0x8f1eFCdff3d0d5BB535e32620721c7EBed151867";

async function main() {
  const owner = privateKeyToAccount(generatePrivateKey()).address;
  const scope = replicaScope(
    crypto.randomUUID().replaceAll("-", ""),
    crypto.randomUUID().replaceAll("-", ""),
    0,
  );
  for (const origin of [gatewayUrl, storageUrl]) {
    const response = await fetch(`${origin}/health`, {
      signal: AbortSignal.timeout(25_000),
    });
    await response.body?.cancel();
    if (!response.ok) throw new Error(`Dev health failed (${response.status})`);
  }
  const rpc = createPublicClient({
    transport: http(rpcUrl, { timeout: 25_000, retryCount: 0 }),
  });
  const evidence = await createReplicaEvidenceAdapter({
    owner,
    registry,
    chainId: 14800,
    gatewayUrl,
    rpc,
    fetch: (input, init) =>
      fetch(input, { ...init, signal: AbortSignal.timeout(25_000) }),
  })(scope);
  const state = replicaRegistrationState(evidence, { owner, scope });
  if (state !== "absent") throw new Error(`Fresh owner slot is ${state}`);
  console.log(
    JSON.stringify({
      gatewayUrl,
      storageUrl,
      rpcUrl,
      chainId: 14800,
      registry,
      state,
      finalizedBlock: evidence.chain?.blockNumber.toString(),
      finalizedHash: evidence.chain?.blockHash,
      historyApiRequired: false,
    }),
  );
}

main().catch((error: unknown) => {
  console.error(
    error instanceof Error ? error.message : "Dev preflight failed",
  );
  process.exitCode = 1;
});
