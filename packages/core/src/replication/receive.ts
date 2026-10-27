import { keccak256, type Hex } from "viem";
import { ReplicaObjectRefused } from "./dpv2.js";
import {
  decodeParsedReplicaManifest,
  parseReplicaJson,
  ReplicaJsonRefused,
  ReplicaManifestRefused,
  replicaMetadataHash,
  type ParsedReplicaJson,
  type ReplicaManifest,
} from "./transport.js";

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
export async function receiveReplicaManifest(input: {
  scope: string;
  owner: string;
  maxBytes: number;
  /** The stored manifest, read within `maxBytes`. */
  read(): Promise<Uint8Array>;
  decrypt(encrypted: Uint8Array): Promise<Uint8Array>;
  /** Whether this hash pair is the slot's finalized commitment. */
  committed(dataHash: Hex, metadataHash: Hex): boolean;
}): Promise<ReplicaManifestReceipt> {
  let encrypted: Uint8Array;
  let plaintext: Uint8Array | undefined;
  let parsed: ParsedReplicaJson;
  try {
    encrypted = await input.read();
    if (encrypted.length > input.maxBytes)
      throw new ReplicaObjectRefused("oversize");
    plaintext = await input.decrypt(encrypted);
    if (plaintext.length > input.maxBytes)
      throw new ReplicaObjectRefused("oversize");
    parsed = parseReplicaJson(plaintext);
  } catch (error) {
    if (
      error instanceof ReplicaObjectRefused ||
      error instanceof ReplicaJsonRefused
    )
      return { tag: "refused", reason: "manifest_invalid" };
    // Plaintext that is not JSON has no `collectedAt`, so no metadata hash
    // to check against the commitment.
    if (plaintext !== undefined) return { tag: "mismatch" };
    throw error;
  }
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
