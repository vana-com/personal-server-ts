import { describe, expect, it } from "vitest";
import { toHex } from "./bytes.js";
import { InvalidArgumentError } from "./errors.js";
import { streamMasterKeyFromSignature } from "./master-key.js";

// Anvil account #0 over "vana-master-key-v1": low s, v = 27.
const SIGNATURE =
  "0x1f5c9b3bafc291e8ea7aa4e0c5700a109e68aa2431fdbea08b49f9bf91b5c7db2aaa192de5cdf866e5f9f5f39502a66bd696a1399a537eac8ffb826c00e4e1d51b";
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const r = SIGNATURE.slice(2, 66);
const s = BigInt("0x" + SIGNATURE.slice(66, 130));
const highS = (N - s).toString(16).padStart(64, "0");
const lowS = s.toString(16).padStart(64, "0");

function bytes(hex: string): Uint8Array {
  return Uint8Array.from(Buffer.from(hex.slice(2), "hex"));
}

describe("streamMasterKeyFromSignature", () => {
  it("returns the normal form unchanged", () => {
    expect(toHex(streamMasterKeyFromSignature(SIGNATURE))).toBe(
      SIGNATURE.slice(2),
    );
  });

  it.each([
    ["v 0/1", `0x${r}${lowS}00`],
    ["high s", `0x${r}${highS}1c`],
    ["v 0/1 and high s", `0x${r}${highS}01`],
    ["upper-case hex", SIGNATURE.toUpperCase().replace("0X", "0x")],
  ])("maps the %s encoding to the same key", (_, encoding) => {
    expect(toHex(streamMasterKeyFromSignature(encoding))).toBe(
      SIGNATURE.slice(2),
    );
  });

  it("accepts bytes and does not change them", () => {
    const input = bytes(`0x${r}${highS}1c`);
    const before = toHex(input);
    expect(toHex(streamMasterKeyFromSignature(input))).toBe(SIGNATURE.slice(2));
    expect(toHex(input)).toBe(before);
  });

  it.each([
    ["64 bytes", new Uint8Array(64)],
    ["66 bytes", new Uint8Array(66)],
    ["short hex", SIGNATURE.slice(0, -2)],
    ["no 0x prefix", SIGNATURE.slice(2)],
    ["non-hex", `0x${"zz".repeat(65)}`],
    ["v = 29", `0x${r}${lowS}1d`],
    ["s = 0", `0x${r}${"0".repeat(64)}1b`],
    ["s = n", `0x${r}${N.toString(16)}1b`],
    ["r = 0", `0x${"0".repeat(64)}${lowS}1b`],
  ])("rejects %s", (_, input) => {
    expect(() => streamMasterKeyFromSignature(input)).toThrow(
      InvalidArgumentError,
    );
  });
});
