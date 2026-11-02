/**
 * What every replication host builds the same way before its first step:
 * the partition it joins, the declarations it binds and the network ports
 * it talks to (host contract §4.1, §4.2). Node and PS-Lite both assemble
 * replication here and differ only in their storage adapter and persistence.
 */
import { createPublicClient, http, type Hex } from "viem";
import {
  getChainConfig,
  type GatewayClient,
} from "@opendatalabs/vana-sdk/browser";
import type { DeclarationSnapshot } from "../pdpp/types.js";
import type { DataPointFeedPort } from "../ports/index.js";
import type { ServerConfig } from "../schemas/server-config.js";
import type { ServerSigner } from "../signing/index.js";
import type { BoundedStorageAdapter } from "../storage/adapters/interface.js";
import {
  createDpv2ReplicaTransport,
  type ReplicaTransportPort,
} from "./dpv2.js";
import { createReplicaEvidenceAdapter } from "./evidence.js";
import { createReplicaFinalityHints } from "./finality.js";
import {
  replicaDeclarationContext,
  replicaEnvironmentForChain,
  replicaPartitionOwner,
} from "./host-config.js";
import {
  createGatewayReplicaRoster,
  type ReplicaRosterPort,
} from "./roster.js";
import type { ReplicaEnvironment } from "./writer-identity.js";

/** The network side of replication: carrier and roster. */
export interface ReplicationNetworkPorts {
  transport: ReplicaTransportPort;
  roster: ReplicaRosterPort;
}

/** DPv2 on Vana storage and the gateway, with finalized RPC evidence. */
export function createReplicationNetworkPorts(input: {
  config: Pick<ServerConfig, "gateway">;
  owner: `0x${string}`;
  masterKey: Uint8Array;
  storage: BoundedStorageAdapter;
  gateway: Pick<GatewayClient, "registerDataPoint">;
  feed: DataPointFeedPort;
  signer: Pick<ServerSigner, "signAddData">;
}): ReplicationNetworkPorts {
  const { gateway } = input.config;
  const chain = getChainConfig(gateway.chainId);
  if (!chain) throw new Error(`no RPC for chain ${gateway.chainId}`);
  const rpc = createPublicClient({ chain, transport: http() });
  return {
    transport: createDpv2ReplicaTransport({
      owner: input.owner,
      masterKey: input.masterKey,
      storage: input.storage,
      gateway: input.gateway,
      feed: input.feed,
      signer: input.signer,
      finality: createReplicaFinalityHints({ rpc }),
      evidence: createReplicaEvidenceAdapter({
        owner: input.owner,
        registry: gateway.contracts.dataRegistry as Hex,
        chainId: gateway.chainId,
        rpc: rpc as Parameters<typeof createReplicaEvidenceAdapter>[0]["rpc"],
        gatewayUrl: gateway.url,
      }),
    }),
    roster: createGatewayReplicaRoster({ gatewayUrl: gateway.url }),
  };
}

/** A host's replication partition, or why replication cannot run this boot. */
export type ReplicationHostPlan =
  | {
      state: "ready";
      /** The owner as the partition compares it (lowercase). */
      owner: `0x${string}`;
      environment: ReplicaEnvironment;
      context: ReturnType<typeof replicaDeclarationContext>;
    }
  | { state: "blocked"; reason: string };

/**
 * The partition and declaration bindings for one owner. A chain without a
 * signed environment, no retained declarations or a stream that cannot be
 * bound blocks replication: the first baseline freezes the binding set, so
 * an empty or guessed one would never match a peer.
 */
export function planReplicationHost(input: {
  owner: string;
  chainId: number;
  declarations: readonly DeclarationSnapshot[];
}): ReplicationHostPlan {
  const environment = replicaEnvironmentForChain(input.chainId);
  if (!environment)
    return { state: "blocked", reason: `unsupported_chain:${input.chainId}` };
  if (input.declarations.length === 0)
    return { state: "blocked", reason: "no_retained_declarations" };
  try {
    const owner = replicaPartitionOwner(input.owner) as `0x${string}`;
    return {
      state: "ready",
      owner,
      environment,
      context: replicaDeclarationContext(owner, input.declarations),
    };
  } catch (error) {
    return {
      state: "blocked",
      reason: error instanceof Error ? error.message : String(error),
    };
  }
}
