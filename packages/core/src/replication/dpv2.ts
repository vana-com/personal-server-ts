import type { ReplicaFinalityHints } from "./finality.js";
export { createReplicaFinalityHints } from "./finality.js";
import {
  decryptWithPassword,
  deriveScopeKey,
  encryptWithPassword,
  type GatewayClient,
} from "@opendatalabs/vana-sdk/browser";
import {
  bytesToHex,
  encodeAbiParameters,
  keccak256,
  stringToHex,
  type Hex,
} from "viem";
import type { StorageAdapter } from "../storage/adapters/interface.js";
import type { DataPointFeedPort } from "../ports/index.js";
import type { ServerSigner } from "../signing/signer.js";
import type { PreparedFragment } from "./transport.js";

const tombstoneDataHash = keccak256(
  stringToHex("vana.data-point.tombstone.v1"),
);
const tombstoneMetadataHash = keccak256(
  stringToHex("vana.data-point.tombstone.metadata.v1"),
);

export interface ReplicaCommitment {
  owner: string;
  scope: string;
  version: string;
  dataHash: string;
  metadataHash: string;
  deleted: boolean;
}
/** DataRegistryV2 stores the hash-pair commitment, never its preimages. */
export interface ReplicaFinalizedChainEvidence {
  owner: string;
  scope: string;
  version: "1";
  currentVersion: string;
  status: "None" | "Active" | "Inactive" | "Unavailable";
  commitment: Hex;
  chainId: number;
  registry: Hex;
  blockNumber: bigint;
  blockHash: Hex;
  blockTimestamp: bigint;
}
export interface ReplicaRegistrationEvidence {
  head: ReplicaCommitment | null;
  /** null means unavailable, never authoritative absence. currentVersion=0 proves absence. */
  chain: ReplicaFinalizedChainEvidence | null;
  pending: boolean;
}
export function replicaChainCommitment(dataHash: Hex, metadataHash: Hex): Hex {
  return keccak256(
    encodeAbiParameters(
      [{ type: "bytes32" }, { type: "bytes32" }],
      [dataHash, metadataHash],
    ),
  );
}
export interface ReplicaTransportPort {
  finality?: ReplicaFinalityHints;
  encrypt(scope: string, plaintext: Uint8Array): Promise<Uint8Array>;
  decrypt(scope: string, encrypted: Uint8Array): Promise<Uint8Array>;
  evidence(scope: string): Promise<ReplicaRegistrationEvidence>;
  put(fragment: PreparedFragment): Promise<void>;
  register(fragment: PreparedFragment): Promise<void>;
  get(scope: string): Promise<Uint8Array>;
  list(
    cursor: string | null,
  ): Promise<{ scopes: string[]; cursor: string | null }>;
}

/** Uses existing DPv2 crypto, storage keying, AddData signing and owner feed. No file-head rebase. */
export function createDpv2ReplicaTransport(deps: {
  finality?: ReplicaFinalityHints;
  owner: `0x${string}`;
  masterKey: Uint8Array;
  storage: StorageAdapter;
  gateway: Pick<GatewayClient, "registerDataPoint">;
  feed: DataPointFeedPort;
  signer: Pick<ServerSigner, "signAddData">;
  /** Host verifies the current head against a pinned finalized DataRegistryV2 commitment.
   * SDK head-only lookup cannot implement this port. No production fallback is allowed. */
  evidence: (scope: string) => Promise<ReplicaRegistrationEvidence>;
}): ReplicaTransportPort {
  const password = (scope: string) =>
    bytesToHex(deriveScopeKey(deps.masterKey, scope)).slice(2);
  return {
    finality: deps.finality,
    encrypt: (scope, bytes) => encryptWithPassword(bytes, password(scope)),
    decrypt: (scope, bytes) => decryptWithPassword(bytes, password(scope)),
    evidence: deps.evidence,
    async put(fragment) {
      await deps.storage.upload(`${fragment.scope}/1`, fragment.encrypted);
    },
    async register(fragment) {
      const msg = {
        ownerAddress: deps.owner,
        scope: fragment.scope,
        dataHash: fragment.dataHash,
        metadataHash: fragment.metadataHash,
        expectedVersion: 1n,
      };
      await deps.gateway.registerDataPoint({
        ...msg,
        expectedVersion: "1",
        signature: await deps.signer.signAddData(msg),
      });
    },
    get: (scope) => deps.storage.download(deps.storage.urlForKey(`${scope}/1`)),
    async list(cursor) {
      const page = await deps.feed.listDataPointsByOwner(deps.owner, cursor, {
        includeDeleted: true,
      });
      // The subsequent evidence lookup verifies owner, version, settlement and deletion.
      return {
        scopes: page.dataPoints.map((p) => p.scope),
        cursor: page.cursor,
      };
    },
  };
}

export function replicaRegistrationState(
  evidence: ReplicaRegistrationEvidence,
  expected: {
    owner: string;
    scope: string;
    dataHash?: string;
    metadataHash?: string;
  },
): "absent" | "pending" | "confirmed" | "conflict" {
  const { head, chain } = evidence;
  // Only facts from the requested finalized slot can permanently quarantine.
  // A Gateway optimistic head can roll back; status can reactivate.
  if (
    !chain ||
    chain.owner.toLowerCase() !== expected.owner.toLowerCase() ||
    chain.scope !== expected.scope ||
    chain.version !== "1" ||
    !/^(0|[1-9][0-9]*)$/.test(chain.currentVersion)
  )
    return "pending";
  if (BigInt(chain.currentVersion) > 1n) return "conflict";
  if (
    chain.currentVersion === "1" &&
    expected.dataHash !== undefined &&
    expected.metadataHash !== undefined &&
    replicaChainCommitment(
      expected.dataHash as Hex,
      expected.metadataHash as Hex,
    ).toLowerCase() !== chain.commitment.toLowerCase()
  )
    return "conflict";
  if (evidence.pending) return "pending";
  if (chain.currentVersion === "0") {
    return !head &&
      chain.status === "None" &&
      /^0x0{64}$/i.test(chain.commitment)
      ? "absent"
      : "pending";
  }
  if (chain.status !== "Active" || !head) return "pending";
  if (
    head.owner.toLowerCase() !== expected.owner.toLowerCase() ||
    head.scope !== expected.scope ||
    head.version !== "1" ||
    head.deleted ||
    (head.dataHash.toLowerCase() === tombstoneDataHash &&
      head.metadataHash.toLowerCase() === tombstoneMetadataHash) ||
    !/^0x[0-9a-fA-F]{64}$/.test(head.dataHash) ||
    !/^0x[0-9a-fA-F]{64}$/.test(head.metadataHash) ||
    (expected.dataHash !== undefined &&
      head.dataHash.toLowerCase() !== expected.dataHash.toLowerCase()) ||
    (expected.metadataHash !== undefined &&
      head.metadataHash.toLowerCase() !== expected.metadataHash.toLowerCase())
  )
    return "pending";
  return replicaChainCommitment(
    head.dataHash as Hex,
    head.metadataHash as Hex,
  ).toLowerCase() === chain.commitment.toLowerCase()
    ? "confirmed"
    : "pending";
}

/** Expected optimistic version-one registration, distinct from disagreements/errors. */
export function replicaAwaitingFinality(
  evidence: ReplicaRegistrationEvidence,
  expected: {
    owner: string;
    scope: string;
    dataHash?: string;
    metadataHash?: string;
  },
): boolean {
  const { head, chain } = evidence;
  return (
    replicaRegistrationState(evidence, expected) === "pending" &&
    chain !== null &&
    chain.owner.toLowerCase() === expected.owner.toLowerCase() &&
    chain.scope === expected.scope &&
    chain.version === "1" &&
    chain.currentVersion === "0" &&
    chain.status === "None" &&
    /^0x0{64}$/i.test(chain.commitment) &&
    head !== null &&
    head.owner.toLowerCase() === expected.owner.toLowerCase() &&
    head.scope === expected.scope &&
    head.version === "1" &&
    !head.deleted &&
    !(
      head.dataHash.toLowerCase() === tombstoneDataHash &&
      head.metadataHash.toLowerCase() === tombstoneMetadataHash
    ) &&
    /^0x[0-9a-f]{64}$/i.test(head.dataHash) &&
    /^0x[0-9a-f]{64}$/i.test(head.metadataHash) &&
    (expected.dataHash === undefined ||
      head.dataHash.toLowerCase() === expected.dataHash.toLowerCase()) &&
    (expected.metadataHash === undefined ||
      head.metadataHash.toLowerCase() === expected.metadataHash.toLowerCase())
  );
}
