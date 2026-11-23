import { describe, expect, it } from "vitest";
import { InvalidArgumentError } from "./errors.js";
import {
  canonicalBytes32,
  keccakHex,
  sha256Hex,
  toHex,
  utf8,
  utf8Length,
} from "./bytes.js";

const digits = "0123456789abcdefABCDEF".repeat(3).slice(0, 64);
const lower = `0x${digits.toLowerCase()}`;

describe("canonicalBytes32", () => {
  it.each([
    lower,
    `0x${digits.toUpperCase()}`,
    `0X${digits}`,
    `0X${digits.toUpperCase()}`,
    digits,
    digits.toUpperCase(),
  ])("returns lowercase 0x for %s", (input) => {
    expect(canonicalBytes32(input)).toBe(lower);
  });
  it.each([
    "",
    "0x",
    "wrong",
    `0x${digits.slice(1)}`,
    `0x${digits}0`,
    `0x${"g".repeat(64)}`,
    ` ${lower}`,
    `${lower}\n`,
    `0x0x${digits}`,
  ])("rejects %j", (input) => {
    expect(() => canonicalBytes32(input)).toThrow(InvalidArgumentError);
  });
});

describe("utf8Length", () => {
  it("counts the bytes the encoder would write", () => {
    const samples = [
      "",
      "plain ascii",
      "café ünïcödé",
      "emoji 🐟 and 𝄞 surrogate pairs",
      "lone \uD800 surrogate",
      "x".repeat(70_000),
    ];
    for (const text of samples) {
      expect(utf8Length(text)).toBe(utf8(text).length);
    }
  });
});

describe("toHex", () => {
  it("writes lowercase two-digit pairs for every byte", () => {
    const bytes = Uint8Array.from({ length: 256 }, (_, i) => i);
    expect(toHex(bytes)).toBe(Buffer.from(bytes).toString("hex"));
    expect(toHex(new Uint8Array())).toBe("");
  });
});

describe("hash port output formatting", () => {
  it("forwards a sliced byte view to SHA-256 and emits lowercase text without a prefix", async () => {
    const bytes = Uint8Array.of(99, 1, 2, 88).subarray(1, 3);
    const result = await sha256Hex(async (seen) => {
      expect(seen).toEqual(Uint8Array.of(1, 2));
      return Uint8Array.from({ length: 32 }, () => 0xab);
    }, bytes);

    expect(result).toBe("ab".repeat(32));
  });

  it("formats the Keccak port result as a prefixed registry hash", async () => {
    const result = await keccakHex(async (seen) => {
      expect(seen).toEqual(new Uint8Array());
      return Uint8Array.from({ length: 32 }, (_, index) =>
        index === 0 ? 0 : 0xcd,
      );
    }, new Uint8Array());

    expect(result).toBe("0x00" + "cd".repeat(31));
  });
});
