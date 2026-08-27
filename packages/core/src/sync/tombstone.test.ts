import { describe, expect, it } from "vitest";

import {
  TOMBSTONE_DATA_HASH,
  TOMBSTONE_METADATA_HASH,
  isTombstoneRecord,
} from "./tombstone.js";

// These literals are the cross-repo contract (gateway + SDK + PS). If this
// test fails, the constants drifted and tombstones would stop being
// recognised on one side of the protocol.
describe("tombstone constants", () => {
  it("TOMBSTONE_DATA_HASH = keccak256(utf8('vana.data-point.tombstone.v1'))", () => {
    expect(TOMBSTONE_DATA_HASH).toBe(
      "0x30c45ee72fe56d1927701316925ab7ceacd3b6f9267061735d59396f075c6222",
    );
  });

  it("TOMBSTONE_METADATA_HASH = keccak256(utf8('vana.data-point.tombstone.metadata.v1'))", () => {
    expect(TOMBSTONE_METADATA_HASH).toBe(
      "0xc5255a141acd6a2ae55971b62c0a85977c2511989dc114ad2abc2b7644f57d90",
    );
  });

  it("isTombstoneRecord matches case-insensitively on both commitments", () => {
    expect(
      isTombstoneRecord({
        dataHash: TOMBSTONE_DATA_HASH.toUpperCase(),
        metadataHash: TOMBSTONE_METADATA_HASH,
      }),
    ).toBe(true);
    expect(
      isTombstoneRecord({
        dataHash: TOMBSTONE_DATA_HASH,
        metadataHash: "0x" + "00".repeat(32),
      }),
    ).toBe(false);
  });
});
