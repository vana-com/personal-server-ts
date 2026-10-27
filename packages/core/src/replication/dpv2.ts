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
import {
  replicaFragmentKey,
  replicaManifestKey,
  type PreparedFragment,
  type PreparedManifest,
} from "./transport.js";

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
/**
 * DataRegistryV2 stores the hash-pair commitment, never its preimages.
 * `version` is the requested slot; `commitment` is that slot's commitment,
 * zero while `currentVersion` is below it.
 */
export interface ReplicaFinalizedChainEvidence {
  owner: string;
  scope: string;
  version: string;
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
  /** The Gateway's current head of the scope: its latest version only. */
  head: ReplicaCommitment | null;
  /** null means unavailable, never authoritative absence. */
  chain: ReplicaFinalizedChainEvidence | null;
  pending: boolean;
}
/** One registered slot: a writer scope at one version. */
export interface ReplicaSlot {
  owner: string;
  scope: string;
  version: number;
  dataHash?: string;
  metadataHash?: string;
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
  /** The owner whose keys and signer this port uses. A worker refuses any other binding. */
  owner?: string;
  finality?: ReplicaFinalityHints;
  encrypt(scope: string, plaintext: Uint8Array): Promise<Uint8Array>;
  decrypt(scope: string, encrypted: Uint8Array): Promise<Uint8Array>;
  /** Finalized evidence of one slot, plus the Gateway head of its scope. */
  evidence(
    scope: string,
    version: number,
  ): Promise<ReplicaRegistrationEvidence>;
  /** Store an unregistered fragment at its content address. */
  putFragment(
    fragment: Pick<PreparedFragment, "scope" | "digest" | "encrypted">,
  ): Promise<void>;
  getFragment(scope: string, digest: string): Promise<Uint8Array>;
  /** False only when storage definitively has no object at the address. */
  hasFragment(scope: string, digest: string): Promise<boolean>;
  put(manifest: PreparedManifest): Promise<void>;
  /** The batch's single AddData registration, at version `manifest.version`. */
  register(manifest: PreparedManifest): Promise<void>;
  get(scope: string, version: number): Promise<Uint8Array>;
  /** Owner feed page: every scope with the Gateway's latest version of it. */
  list(cursor: string | null): Promise<{
    points: { scope: string; version: string }[];
    cursor: string | null;
  }>;
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
  /** Host verifies a slot against a pinned finalized DataRegistryV2 commitment.
   * SDK head-only lookup cannot implement this port. No production fallback is allowed. */
  evidence: (
    scope: string,
    version: number,
  ) => Promise<ReplicaRegistrationEvidence>;
}): ReplicaTransportPort {
  const password = (scope: string) =>
    bytesToHex(deriveScopeKey(deps.masterKey, scope)).slice(2);
  const fragmentUrl = (scope: string, digest: string) =>
    deps.storage.urlForKey(replicaFragmentKey(scope, digest));
  return {
    owner: deps.owner,
    finality: deps.finality,
    encrypt: (scope, bytes) => encryptWithPassword(bytes, password(scope)),
    decrypt: (scope, bytes) => decryptWithPassword(bytes, password(scope)),
    evidence: deps.evidence,
    async putFragment(fragment) {
      await deps.storage.upload(
        replicaFragmentKey(fragment.scope, fragment.digest),
        fragment.encrypted,
      );
    },
    getFragment: (scope, digest) =>
      deps.storage.download(fragmentUrl(scope, digest)),
    hasFragment: (scope, digest) =>
      deps.storage.exists(fragmentUrl(scope, digest)),
    async put(manifest) {
      await deps.storage.upload(
        replicaManifestKey(manifest.scope, manifest.version),
        manifest.encrypted,
      );
    },
    async register(manifest) {
      const msg = {
        ownerAddress: deps.owner,
        scope: manifest.scope,
        dataHash: manifest.dataHash,
        metadataHash: manifest.metadataHash,
        expectedVersion: BigInt(manifest.version),
      };
      await deps.gateway.registerDataPoint({
        ...msg,
        expectedVersion: String(manifest.version),
        signature: await deps.signer.signAddData(msg),
      });
    },
    get: (scope, version) =>
      deps.storage.download(
        deps.storage.urlForKey(replicaManifestKey(scope, version)),
      ),
    async list(cursor) {
      const page = await deps.feed.listDataPointsByOwner(deps.owner, cursor, {
        includeDeleted: true,
      });
      // The Gateway version only says where to look. Each slot is verified
      // against finalized evidence before anything is fetched or trusted.
      return {
        points: page.dataPoints.map((p) => ({
          scope: p.scope,
          version: p.expectedVersion,
        })),
        cursor: page.cursor,
      };
    },
  };
}

const isTombstone = (head: ReplicaCommitment) =>
  head.dataHash.toLowerCase() === tombstoneDataHash &&
  head.metadataHash.toLowerCase() === tombstoneMetadataHash;
const uintPattern = /^(0|[1-9][0-9]*)$/;
const hashPattern = /^0x[0-9a-fA-F]{64}$/;
const expectedCommitment = (slot: ReplicaSlot) =>
  slot.dataHash !== undefined && slot.metadataHash !== undefined
    ? replicaChainCommitment(
        slot.dataHash as Hex,
        slot.metadataHash as Hex,
      ).toLowerCase()
    : undefined;
/** The chain object is for exactly this owner, scope and slot. */
function chainFor(
  evidence: ReplicaRegistrationEvidence,
  slot: ReplicaSlot,
): ReplicaFinalizedChainEvidence | undefined {
  const { chain } = evidence;
  return chain &&
    Number.isSafeInteger(slot.version) &&
    slot.version >= 1 &&
    chain.owner.toLowerCase() === slot.owner.toLowerCase() &&
    chain.scope === slot.scope &&
    chain.version === String(slot.version) &&
    uintPattern.test(chain.currentVersion)
    ? chain
    : undefined;
}
/** The Gateway head is live and agrees with the slot where it can. */
function headAgrees(
  head: ReplicaCommitment | null,
  slot: ReplicaSlot,
  commitment: string,
): boolean {
  if (
    !head ||
    head.owner.toLowerCase() !== slot.owner.toLowerCase() ||
    head.scope !== slot.scope ||
    !uintPattern.test(head.version) ||
    head.deleted ||
    isTombstone(head) ||
    !hashPattern.test(head.dataHash) ||
    !hashPattern.test(head.metadataHash)
  )
    return false;
  const version = BigInt(head.version);
  if (version < BigInt(slot.version)) return false;
  // Only the latest version has a head. A later head says nothing about
  // this slot's preimages; the finalized chain commitment binds them.
  if (version > BigInt(slot.version)) return true;
  return (
    (slot.dataHash === undefined ||
      head.dataHash.toLowerCase() === slot.dataHash.toLowerCase()) &&
    (slot.metadataHash === undefined ||
      head.metadataHash.toLowerCase() === slot.metadataHash.toLowerCase()) &&
    replicaChainCommitment(
      head.dataHash as Hex,
      head.metadataHash as Hex,
    ).toLowerCase() === commitment
  );
}

/**
 * The registration state of one slot. Versions append, so a later version
 * is normal. A finalized slot commitment never changes, so only a finalized
 * commitment that differs from the known expected hash pair quarantines.
 * A Gateway head can roll back and status can reactivate: both stay pending.
 */
export function replicaRegistrationState(
  evidence: ReplicaRegistrationEvidence,
  slot: ReplicaSlot,
): "absent" | "pending" | "confirmed" | "conflict" {
  const chain = chainFor(evidence, slot);
  if (!chain) return "pending";
  const current = BigInt(chain.currentVersion);
  const version = BigInt(slot.version);
  const expected = expectedCommitment(slot);
  const committed = chain.commitment.toLowerCase();
  if (current >= version && expected !== undefined && expected !== committed)
    return "conflict";
  if (evidence.pending) return "pending";
  if (current < version) {
    // No finalized commitment at this slot. Absent only if the Gateway has
    // no head at or above it either (an optimistic registration).
    const { head } = evidence;
    const headBelow =
      !head ||
      (uintPattern.test(head.version) && BigInt(head.version) < version);
    return headBelow &&
      /^0x0{64}$/i.test(chain.commitment) &&
      (current > 0n || chain.status === "None")
      ? "absent"
      : "pending";
  }
  if (chain.status !== "Active") return "pending";
  return headAgrees(evidence.head, slot, committed) ? "confirmed" : "pending";
}

/**
 * A finalized registration of exactly the expected commitment whose status
 * is not Active (for example temporarily Unavailable). Status can
 * reactivate, so this is a Wait on the chain, never a conflict or an error.
 * A receiver that has not fetched the slot yet has no expected commitment:
 * any finalized commitment then counts, because nothing is fetched or
 * trusted until the status is Active again.
 */
export function replicaRegistrationInactive(
  evidence: ReplicaRegistrationEvidence,
  slot: ReplicaSlot,
): boolean {
  const chain = chainFor(evidence, slot);
  const expected = expectedCommitment(slot);
  return (
    replicaRegistrationState(evidence, slot) === "pending" &&
    !evidence.pending &&
    chain !== undefined &&
    BigInt(chain.currentVersion) >= BigInt(slot.version) &&
    chain.status !== "Active" &&
    (expected === undefined
      ? !/^0x0{64}$/i.test(chain.commitment)
      : expected === chain.commitment.toLowerCase())
  );
}

/**
 * Expected optimistic registration of this slot, distinct from disagreements
 * and errors: the Gateway head is at or above the slot and finality has not
 * reached it. Only a head at exactly the slot can be checked against hashes.
 */
export function replicaAwaitingFinality(
  evidence: ReplicaRegistrationEvidence,
  slot: ReplicaSlot,
): boolean {
  const chain = chainFor(evidence, slot);
  const { head } = evidence;
  return (
    replicaRegistrationState(evidence, slot) === "pending" &&
    chain !== undefined &&
    BigInt(chain.currentVersion) < BigInt(slot.version) &&
    (BigInt(chain.currentVersion) > 0n || chain.status === "None") &&
    /^0x0{64}$/i.test(chain.commitment) &&
    head !== null &&
    head.owner.toLowerCase() === slot.owner.toLowerCase() &&
    head.scope === slot.scope &&
    uintPattern.test(head.version) &&
    BigInt(head.version) >= BigInt(slot.version) &&
    !head.deleted &&
    !isTombstone(head) &&
    hashPattern.test(head.dataHash) &&
    hashPattern.test(head.metadataHash) &&
    (head.version !== String(slot.version) ||
      ((slot.dataHash === undefined ||
        head.dataHash.toLowerCase() === slot.dataHash.toLowerCase()) &&
        (slot.metadataHash === undefined ||
          head.metadataHash.toLowerCase() === slot.metadataHash.toLowerCase())))
  );
}
