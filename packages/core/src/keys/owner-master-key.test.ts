/**
 * Pins the two owner keys against fixed signatures.
 *
 * One wallet signature over the master-key message has several valid
 * encodings: v can be 0/1 or 27/28, and s can be low or high. Each encoding
 * verifies. The legacy master key keeps the raw 65 bytes, so each encoding
 * gives a different legacy key. The stream master key uses one normal form, so
 * every encoding gives the same key. These tests keep the two apart.
 *
 * Vectors come from `packages/stream-sync/vectors/v1.json` (`streamMasterKey`).
 * The `v = 0x01` low-s vector is the same r and s with v changed.
 */

import { deriveMasterKey } from "@opendatalabs/vana-sdk/browser";
import { bytesToHex, hexToBytes, type Hex } from "viem";
import { describe, expect, it } from "vitest";
import { legacyMasterKey, streamMasterKey } from "./owner-master-key.js";

/** Canonical: v = 0x1b (27), low s. Legacy and stream keys are equal. */
const CANONICAL_V1B =
  "0x1f5c9b3bafc291e8ea7aa4e0c5700a109e68aa2431fdbea08b49f9bf91b5c7db2aaa192de5cdf866e5f9f5f39502a66bd696a1399a537eac8ffb826c00e4e1d51b";

/** Non-canonical: v = 0x00, low s. */
const NON_CANONICAL_V00 =
  "0x1f5c9b3bafc291e8ea7aa4e0c5700a109e68aa2431fdbea08b49f9bf91b5c7db2aaa192de5cdf866e5f9f5f39502a66bd696a1399a537eac8ffb826c00e4e1d500";

/** Non-canonical: v = 0x01, low s. */
const NON_CANONICAL_V01 =
  "0x1f5c9b3bafc291e8ea7aa4e0c5700a109e68aa2431fdbea08b49f9bf91b5c7db2aaa192de5cdf866e5f9f5f39502a66bd696a1399a537eac8ffb826c00e4e1d501";

/** Non-canonical: v = 0x1c (28), high s (n - s). */
const NON_CANONICAL_HIGH_S =
  "0x1f5c9b3bafc291e8ea7aa4e0c5700a109e68aa2431fdbea08b49f9bf91b5c7dbd555e6d21a3207991a060a0c6afd5992e4183bad14f5218f2fd6dc20cf515f6c1c";

/**
 * Golden stream master key for the high-s vector: the same signature in normal
 * form (low s, v = 0x1b). Checked in so a change to the normalization fails
 * here, not only in a relation to another call.
 */
const GOLDEN_STREAM_KEY_HIGH_S =
  "0x1f5c9b3bafc291e8ea7aa4e0c5700a109e68aa2431fdbea08b49f9bf91b5c7db2aaa192de5cdf866e5f9f5f39502a66bd696a1399a537eac8ffb826c00e4e1d51b";

const CANONICAL_AND_NON_CANONICAL: Array<{ name: string; sig: Hex }> = [
  { name: "v=0x00 low s", sig: NON_CANONICAL_V00 as Hex },
  { name: "v=0x01 low s", sig: NON_CANONICAL_V01 as Hex },
  { name: "v=0x1c high s", sig: NON_CANONICAL_HIGH_S as Hex },
];

describe("legacyMasterKey", () => {
  it.each([
    { name: "canonical v=0x1b", sig: CANONICAL_V1B as Hex },
    ...CANONICAL_AND_NON_CANONICAL,
  ])("is the raw 65 signature bytes for $name", ({ sig }) => {
    const raw = hexToBytes(sig);
    expect(raw.length).toBe(65);
    expect(bytesToHex(legacyMasterKey(sig))).toBe(bytesToHex(raw));
  });

  it.each([
    { name: "canonical v=0x1b", sig: CANONICAL_V1B as Hex },
    ...CANONICAL_AND_NON_CANONICAL,
  ])("equals the SDK deriveMasterKey for $name", ({ sig }) => {
    expect(bytesToHex(legacyMasterKey(sig))).toBe(
      bytesToHex(deriveMasterKey(sig)),
    );
  });
});

describe("streamMasterKey", () => {
  it.each(CANONICAL_AND_NON_CANONICAL)(
    "differs from the legacy key for $name",
    ({ sig }) => {
      expect(bytesToHex(streamMasterKey(sig))).not.toBe(
        bytesToHex(legacyMasterKey(sig)),
      );
    },
  );

  it("equals the legacy key for the canonical form", () => {
    expect(bytesToHex(streamMasterKey(CANONICAL_V1B as Hex))).toBe(
      bytesToHex(legacyMasterKey(CANONICAL_V1B as Hex)),
    );
  });

  it("matches the checked-in golden for the high-s vector", () => {
    expect(bytesToHex(streamMasterKey(NON_CANONICAL_HIGH_S as Hex))).toBe(
      GOLDEN_STREAM_KEY_HIGH_S,
    );
  });
});
