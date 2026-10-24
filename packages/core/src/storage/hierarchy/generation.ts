import { sha256, stringToBytes } from "viem";
import { canonicalJson } from "./canonical-json.js";

/** SHA-256 (lowercase hex) of a JSON value with object keys sorted. */
export function canonicalDigest(value: unknown): string {
  return sha256(stringToBytes(canonicalJson(value))).slice(2);
}

/**
 * The immutable generation of a published version: the digest of its
 * envelope with object keys sorted, so the same envelope in any key order has
 * one generation. Storage computes it from the bytes it published and records
 * it on the index row; a caller's value is never used. A block manifest
 * records the generation it was built from (`envelopeDigest`), which binds
 * the sidecar to exactly one version.
 */
export function envelopeGeneration(envelope: unknown): string {
  return canonicalDigest(envelope);
}
