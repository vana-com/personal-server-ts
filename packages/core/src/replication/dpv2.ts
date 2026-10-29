import type { ReplicaFinalityHints } from "./finality.js";
export { createReplicaFinalityHints } from "./finality.js";
import {
  deriveScopeKey,
  encryptWithPassword,
  type GatewayClient,
} from "@opendatalabs/vana-sdk/browser";
import {
  CompressedDataPacket,
  decrypt,
  enums,
  readMessage,
  SymEncryptedIntegrityProtectedDataPacket,
  SymEncryptedSessionKeyPacket,
} from "openpgp";
import {
  bytesToHex,
  encodeAbiParameters,
  keccak256,
  stringToHex,
  type Hex,
} from "viem";
import type { BoundedStorageAdapter } from "../storage/adapters/interface.js";
import { isDefinitiveNotFound } from "../storage/adapters/sdk.js";
import { abortable } from "./coordinator.js";
import {
  AdditionsBudget,
  AdditionsBudgetExceeded,
} from "../additions/budget.js";
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
/** Every peer read has a finite default, including existence probes. */
export const REPLICA_RECEIVE_TIMEOUT_MS = 30_000;
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
/**
 * The carrier will not read an object: it is larger than the caller's bound,
 * it is a compressed OpenPGP message, whose plaintext size the ciphertext
 * does not bound, or its packets are outside the profile every writer emits,
 * which bounds the password KDF. Writers never make any of these.
 */
export class ReplicaObjectRefused extends Error {
  constructor(readonly cause_: "oversize" | "compressed" | "profile") {
    super(`replica object refused: ${cause_}`);
    this.name = "ReplicaObjectRefused";
  }
}
/** One bounded read: stop reading and throw ReplicaObjectRefused past `maxBytes`. */
export interface ReplicaRead {
  maxBytes: number;
  signal?: AbortSignal;
}
export interface ReplicaTransportPort {
  /** The owner whose keys and signer this port uses. A worker refuses any other binding. */
  owner?: string;
  finality?: ReplicaFinalityHints;
  encrypt(scope: string, plaintext: Uint8Array): Promise<Uint8Array>;
  /** Exact size for this uncompressed codec, independent of content and randomness.
   * Without this capability, aggregate attribution stays Retry rather than
   * guessing which operations are permanently unsupported. */
  encryptedByteLength?: (plaintextBytes: number) => number;
  /**
   * Refuses a message outside the writers' OpenPGP profile before its KDF
   * runs, and a compressed message, so the plaintext is never larger than
   * `encrypted`.
   */
  decrypt(scope: string, encrypted: Uint8Array): Promise<Uint8Array>;
  /** Finalized evidence of one slot, plus the Gateway head of its scope. */
  evidence(
    scope: string,
    version: number,
  ): Promise<ReplicaRegistrationEvidence>;
  /** Store an unregistered fragment at its content address. */
  putFragment(
    fragment: Pick<PreparedFragment, "scope" | "digest" | "encrypted">,
    signal?: AbortSignal,
  ): Promise<void>;
  getFragment(
    scope: string,
    digest: string,
    read: ReplicaRead,
  ): Promise<Uint8Array>;
  /** False only when storage definitively has no object at the address. */
  hasFragment(
    scope: string,
    digest: string,
    signal?: AbortSignal,
  ): Promise<boolean>;
  put(manifest: PreparedManifest, signal?: AbortSignal): Promise<void>;
  /** The batch's single AddData registration, at version `manifest.version`. */
  register(manifest: PreparedManifest): Promise<void>;
  get(scope: string, version: number, read: ReplicaRead): Promise<Uint8Array>;
  /** Owner feed page: every scope with the Gateway's latest version of it. */
  list(cursor: string | null): Promise<{
    points: { scope: string; version: string }[];
    cursor: string | null;
  }>;
}

/** SDK binary literal + AES-256 SKESKv4 / SEIPDv1, without compression or AEAD. */
export function replicaOpenPgpCiphertextByteLength(
  plaintextBytes: number,
): number {
  if (
    !Number.isSafeInteger(plaintextBytes) ||
    plaintextBytes < 0 ||
    plaintextBytes > 0xffffffff - 128
  )
    throw new RangeError("invalid replica plaintext length");
  // New-format packet: tag, one/two/five length octets, then body.
  const packet = (body: number) =>
    1 + (body < 192 ? 1 : body < 8384 ? 2 : 5) + body;
  // 48-byte encrypted session-key packet; binary literal has a six-byte
  // header; SEIPDv1 has version(1), CFB prefix(18), MDC header/hash(22).
  return 48 + packet(41 + packet(6 + plaintextBytes));
}

/** Uses existing DPv2 crypto, storage keying, AddData signing and owner feed. No file-head rebase. */
export function createDpv2ReplicaTransport(deps: {
  finality?: ReplicaFinalityHints;
  owner: `0x${string}`;
  masterKey: Uint8Array;
  /** Every read is bounded, so an adapter without bounded reads is refused. */
  storage: BoundedStorageAdapter;
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
  if (typeof deps.storage.downloadBounded !== "function")
    throw new TypeError(
      "replication needs a storage adapter with bounded reads",
    );
  const password = (scope: string) =>
    bytesToHex(deriveScopeKey(deps.masterKey, scope)).slice(2);
  const fragmentUrl = (scope: string, digest: string) =>
    deps.storage.urlForKey(replicaFragmentKey(scope, digest));
  async function download(url: string, read: ReplicaRead) {
    const timeout = AbortSignal.timeout(REPLICA_RECEIVE_TIMEOUT_MS);
    const signal = read.signal
      ? AbortSignal.any([read.signal, timeout])
      : timeout;
    let bytes: Uint8Array;
    // The bounded reader charges the chunks and their contiguous copy.
    try {
      bytes = await abortable(signal, () =>
        deps.storage.downloadBounded(
          url,
          new AdditionsBudget(2 * read.maxBytes, undefined, signal),
        ),
      );
    } catch (error) {
      signal.throwIfAborted();
      if (error instanceof AdditionsBudgetExceeded)
        throw new ReplicaObjectRefused("oversize");
      throw error;
    }
    if (bytes.length > read.maxBytes)
      throw new ReplicaObjectRefused("oversize");
    return bytes;
  }
  return {
    owner: deps.owner,
    finality: deps.finality,
    encrypt: (scope, bytes) => encryptWithPassword(bytes, password(scope)),
    encryptedByteLength: replicaOpenPgpCiphertextByteLength,
    decrypt: (scope, bytes) => decryptUncompressed(bytes, password(scope)),
    evidence: deps.evidence,
    async putFragment(fragment, signal) {
      await deps.storage.upload(
        replicaFragmentKey(fragment.scope, fragment.digest),
        fragment.encrypted,
        signal,
      );
    },
    getFragment: (scope, digest, read) =>
      download(fragmentUrl(scope, digest), read),
    async hasFragment(scope, digest, signal) {
      try {
        // A zero-byte bounded probe proves presence as soon as bytes arrive.
        // StorageAdapter.exists may hide a full SDK download; never call it.
        await download(fragmentUrl(scope, digest), { maxBytes: 0, signal });
        return true;
      } catch (error) {
        if (error instanceof ReplicaObjectRefused) return true;
        if (isDefinitiveNotFound(error)) return false;
        throw error;
      }
    },
    async put(manifest, signal) {
      await deps.storage.upload(
        replicaManifestKey(manifest.scope, manifest.version),
        manifest.encrypted,
        signal,
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
    get: (scope, version, read) =>
      download(
        deps.storage.urlForKey(replicaManifestKey(scope, version)),
        read,
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

/**
 * The iterated S2K count byte of OpenPGP.js's default, which the SDK's
 * `encryptWithPassword` uses: 16 MiB hashed per password attempt.
 */
const REPLICA_S2K_MAX_COUNT_BYTE = 224;

/**
 * Refuse packets outside the profile the SDK's `encryptWithPassword` emits on
 * OpenPGP.js defaults, before decrypt runs the password KDF: exactly one v4
 * password packet whose S2K is iterated and salted SHA-256 at no more than
 * the default count, then one v1 integrity-protected data packet. So the KDF
 * runs once, takes no memory parameter (Argon2 is refused) and hashes at most
 * 16 MiB. Reading the packets runs no KDF.
 */
function checkReplicaProfile(packets: readonly unknown[]) {
  const [session, data, ...rest] = packets;
  const s2k = (session as { s2k?: { type?: unknown } } | undefined)?.s2k as
    { type?: unknown; algorithm?: unknown; c?: unknown } | undefined;
  if (
    rest.length !== 0 ||
    !(session instanceof SymEncryptedSessionKeyPacket) ||
    (session as unknown as { version: unknown }).version !== 4 ||
    s2k?.type !== "iterated" ||
    s2k.algorithm !== enums.hash.sha256 ||
    typeof s2k.c !== "number" ||
    s2k.c > REPLICA_S2K_MAX_COUNT_BYTE ||
    !(data instanceof SymEncryptedIntegrityProtectedDataPacket) ||
    (data as unknown as { version: unknown }).version !== 1
  )
    throw new ReplicaObjectRefused("profile");
}

/**
 * The SDK's password decryption inside the writers' profile, refusing
 * compression before it inflates anything. OpenPGP 6.3 constructs the allowed
 * class for tag 8 before it reads the packet, and wraps what `read` throws,
 * so the refusal is a flag.
 */
async function decryptUncompressed(encrypted: Uint8Array, password: string) {
  let compressed = false;
  class RefusedCompressedPacket extends CompressedDataPacket {
    override async read(): Promise<void> {
      compressed = true;
      throw new Error("compressed OpenPGP packet");
    }
  }
  const config = {
    additionalAllowedPackets: [RefusedCompressedPacket],
    maxDecompressedMessageSize: 0,
    ignoreUnsupportedPackets: false,
    ignoreMalformedPackets: false,
  };
  try {
    const message = await readMessage({ binaryMessage: encrypted, config });
    checkReplicaProfile(message.packets);
    const { data } = await decrypt({
      message,
      passwords: [password],
      format: "binary",
      config,
    });
    if (!(data instanceof Uint8Array))
      throw new Error("unexpected OpenPGP stream");
    return data;
  } catch (error) {
    if (compressed) throw new ReplicaObjectRefused("compressed");
    throw error;
  }
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
