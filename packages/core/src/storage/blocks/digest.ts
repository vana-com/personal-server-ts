import { PDPP_CLASSIFIER_VERSION } from "../../sync/pdpp-import.js";
import { canonicalDigest } from "../hierarchy/generation.js";
import { DataBlockStorageError } from "./errors.js";
import type {
  DataBlockManifest,
  DataBlockRef,
  DataScopeBlock,
  ReadScopeBlocksResponse,
} from "./types.js";

/** `canonicalDigest` of a full block payload, as a manifest records it. */
export function blockDigest(block: DataScopeBlock): string {
  return canonicalDigest(block);
}

/**
 * Check a stored block payload against its manifest entry before any of it
 * is paged or served. A payload of another version at the same ordinal id
 * (a version deleted and published again after the manifest was read) fails
 * here, whatever its provenance. An old manifest entry without a digest is
 * not checked; such a sidecar is not bound (see `boundEnvelopeDigest`).
 */
export function verifyStoredBlock(
  ref: Pick<DataBlockRef, "id" | "digest">,
  block: DataScopeBlock,
): DataScopeBlock {
  if (ref.digest !== undefined && ref.digest !== blockDigest(block)) {
    throw new DataBlockStorageError(
      "block_digest_mismatch",
      `Block payload ${ref.id} does not match its manifest`,
    );
  }
  return block;
}

/**
 * The manifest's `envelopeDigest` when the sidecar is fully bound to one
 * version: the digest is present and every block has a digest. Otherwise
 * undefined, and a non-owner read must not trust the sidecar.
 */
export function boundEnvelopeDigest(
  manifest: DataBlockManifest,
): string | undefined {
  if (manifest.envelopeDigest === undefined) return undefined;
  return manifest.blocks.every((ref) => ref.digest !== undefined)
    ? manifest.envelopeDigest
    : undefined;
}

/**
 * The manifest's `pdppOrigin` if, and only if, the current classifier
 * produced it. A manifest from an older classifier says nothing a non-owner
 * may rely on: it is reported as absent, so the disclosure policy decides on
 * the bytes instead. A matching generation proves byte identity, not that the
 * recorded classification still holds under today's rules.
 */
export function trustedPdppOrigin(
  manifest: Pick<DataBlockManifest, "pdppOrigin" | "pdppClassifier">,
): boolean | undefined {
  return manifest.pdppClassifier === PDPP_CLASSIFIER_VERSION
    ? manifest.pdppOrigin
    : undefined;
}

/**
 * The provenance and version binding a block read reports, for the
 * disclosure policy. A storage reports it only for blocks it checked with
 * `verifyStoredBlock` against this same manifest, in the same read.
 */
export function manifestBinding(
  manifest: DataBlockManifest,
): Pick<
  ReadScopeBlocksResponse,
  "pdppOrigin" | "envelopeDigest" | "redaction"
> {
  const envelopeDigest = boundEnvelopeDigest(manifest);
  const pdppOrigin = trustedPdppOrigin(manifest);
  return {
    ...(manifest.redaction ? { redaction: manifest.redaction } : {}),
    ...(pdppOrigin === undefined ? {} : { pdppOrigin }),
    ...(envelopeDigest === undefined ? {} : { envelopeDigest }),
  };
}
