import { keccak256, stringToHex } from "viem";

/**
 * Durable-deletion tombstone commitments.
 *
 * A deletion is an owner-signed DPv2 AddData for version `current + 1` whose
 * dataHash / metadataHash are these well-known constants. The gateway, the
 * SDK and every personal server derive the SAME bytes from the same UTF-8
 * labels, so a tombstone is recognisable on-chain and in every feed without
 * any out-of-band flag. Do not change the labels: they are the cross-repo
 * contract.
 *
 * TODO(vana-sdk > 3.14.0): the SDK now exports TOMBSTONE_DATA_HASH,
 * TOMBSTONE_METADATA_HASH, isTombstoneHashes(), isDataPointTombstone() and
 * deriveDataPointId() with these exact values. Switch to those exports and
 * drop the local copies once the PS pins a release that ships them.
 */
export const TOMBSTONE_DATA_HASH_LABEL = "vana.data-point.tombstone.v1";
export const TOMBSTONE_METADATA_HASH_LABEL =
  "vana.data-point.tombstone.metadata.v1";

/** keccak256(utf8("vana.data-point.tombstone.v1")) */
export const TOMBSTONE_DATA_HASH: `0x${string}` = keccak256(
  stringToHex(TOMBSTONE_DATA_HASH_LABEL),
);

/** keccak256(utf8("vana.data-point.tombstone.metadata.v1")) */
export const TOMBSTONE_METADATA_HASH: `0x${string}` = keccak256(
  stringToHex(TOMBSTONE_METADATA_HASH_LABEL),
);

/** True when a data-point record's commitments are the tombstone constants. */
export function isTombstoneRecord(record: {
  dataHash: string;
  metadataHash: string;
}): boolean {
  return (
    record.dataHash.toLowerCase() === TOMBSTONE_DATA_HASH &&
    record.metadataHash.toLowerCase() === TOMBSTONE_METADATA_HASH
  );
}
