import { keccak256, type Hex } from "viem";
import { ReplicaObjectRefused, REPLICA_RECEIVE_TIMEOUT_MS } from "./dpv2.js";
export { REPLICA_RECEIVE_TIMEOUT_MS } from "./dpv2.js";
import { abortable } from "./coordinator.js";
import {
  decodeParsedReplicaFragment,
  decodeParsedReplicaManifest,
  fragmentMatchesManifest,
  parseReplicaJson,
  ReplicaJsonRefused,
  ReplicaManifestRefused,
  replicaMetadataHash,
  replicaDigest,
  type ParsedReplicaJson,
  type ReplicaManifest,
  type ReplicaFragment,
} from "./transport.js";

interface ReplicaObjectInput {
  maxBytes: number;
  signal?: AbortSignal;
  read(signal: AbortSignal): Promise<Uint8Array>;
  decrypt(encrypted: Uint8Array): Promise<Uint8Array>;
}

/**
 * The shared boundary for every peer object. Fragments have a ciphertext
 * commitment, which can be checked before decryption. Once it matches, any
 * decrypt/parse failure is terminal. Manifest commitments need parsed JSON.
 */
async function receiveReplicaJson(
  input: ReplicaObjectInput,
  ciphertextCommitted?: (encrypted: Uint8Array) => boolean,
): Promise<
  | {
      tag: "parsed";
      encrypted: Uint8Array;
      plaintext: Uint8Array;
      parsed: ParsedReplicaJson;
    }
  | { tag: "refused" }
  | { tag: "mismatch" }
> {
  const timeout = AbortSignal.timeout(REPLICA_RECEIVE_TIMEOUT_MS);
  const signal = input.signal
    ? AbortSignal.any([input.signal, timeout])
    : timeout;
  let plaintext: Uint8Array | undefined;
  let committed = false;
  try {
    const encrypted = await abortable(signal, () => input.read(signal));
    if (encrypted.length > input.maxBytes)
      throw new ReplicaObjectRefused("oversize");
    if (ciphertextCommitted) {
      if (!ciphertextCommitted(encrypted)) return { tag: "mismatch" };
      committed = true;
    }
    plaintext = await abortable(signal, () => input.decrypt(encrypted));
    if (plaintext.length > input.maxBytes)
      throw new ReplicaObjectRefused("oversize");
    return {
      tag: "parsed",
      encrypted,
      plaintext,
      parsed: parseReplicaJson(plaintext),
    };
  } catch (error) {
    signal.throwIfAborted();
    if (
      committed ||
      error instanceof ReplicaObjectRefused ||
      error instanceof ReplicaJsonRefused
    )
      return { tag: "refused" };
    if (plaintext !== undefined) return { tag: "mismatch" };
    throw error;
  }
}

export type ReplicaManifestReceipt =
  | {
      tag: "manifest";
      manifest: ReplicaManifest;
      dataHash: Hex;
      metadataHash: Hex;
    }
  /** Terminal for the slot: the bytes can never be a valid manifest there. */
  | { tag: "refused"; reason: ReplicaManifestRefused["reason"] }
  /** The bytes are not the slot's finalized commitment; storage may repair them. */
  | { tag: "mismatch" };

/**
 * The one decode boundary for a manifest a peer supplied, in this order: a
 * read bounded by `maxBytes`, the transport's packet check and decryption, a
 * bounded JSON parse, the finalized commitment, then decoding.
 *
 * Before the commitment, bytes that no writer makes (over the bound,
 * compressed, outside the OpenPGP profile, JSON over its bounds) are refused
 * as `manifest_invalid`: their cost is the attack, and the data hash is over
 * plaintext they would have to produce. Other bytes that fail before it are
 * a mismatch, or a thrown read or decrypt error, which the caller retries.
 * After the commitment the bytes are authentic and do not change on retry,
 * so every failure is a refusal.
 */
export async function receiveReplicaManifest(
  input: ReplicaObjectInput & {
    scope: string;
    owner: string;
    /** Whether this hash pair is the slot's finalized commitment. */
    committed(dataHash: Hex, metadataHash: Hex): boolean;
  },
): Promise<ReplicaManifestReceipt> {
  const received = await receiveReplicaJson(input);
  if (received.tag === "refused")
    return { tag: "refused", reason: "manifest_invalid" };
  if (received.tag === "mismatch") return received;
  const { encrypted, plaintext, parsed } = received;
  const { value } = parsed;
  const collectedAt =
    typeof value === "object" && value !== null
      ? (value as { collectedAt?: unknown }).collectedAt
      : undefined;
  if (typeof collectedAt !== "string") return { tag: "mismatch" };
  const dataHash = keccak256(plaintext);
  const metadataHash = replicaMetadataHash(
    input.scope,
    collectedAt,
    encrypted.length,
  );
  if (!input.committed(dataHash, metadataHash)) return { tag: "mismatch" };
  try {
    return {
      tag: "manifest",
      manifest: decodeParsedReplicaManifest(parsed, input.scope, input.owner),
      dataHash,
      metadataHash,
    };
  } catch (error) {
    return {
      tag: "refused",
      reason:
        error instanceof ReplicaManifestRefused
          ? error.reason
          : "manifest_invalid",
    };
  }
}

/** Same receive boundary, authenticated by the signed manifest's ciphertext entry. */
export async function receiveReplicaFragment(
  input: ReplicaObjectInput & {
    scope: string;
    owner: string;
    manifest: ReplicaManifest;
    index: number;
  },
): Promise<
  | { tag: "fragment"; fragment: ReplicaFragment }
  | { tag: "refused"; reason: "fragment_mismatch" }
> {
  const entry = input.manifest.fragments[input.index];
  if (!entry) return { tag: "refused", reason: "fragment_mismatch" };
  const received = await receiveReplicaJson(
    input,
    (encrypted) =>
      encrypted.length === entry.bytes &&
      replicaDigest(encrypted) === entry.digest,
  );
  if (received.tag !== "parsed")
    return { tag: "refused", reason: "fragment_mismatch" };
  try {
    const fragment = decodeParsedReplicaFragment(
      received.parsed,
      input.scope,
      input.owner,
    );
    if (!fragmentMatchesManifest(fragment, input.manifest, input.index))
      return { tag: "refused", reason: "fragment_mismatch" };
    return { tag: "fragment", fragment };
  } catch {
    return { tag: "refused", reason: "fragment_mismatch" };
  }
}
