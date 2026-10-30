import { describe, expect, it } from "vitest";

import { keccak256 } from "viem";

import { keccak256Cooperatively } from "./keccak.js";

const chunkBytes = 256 * 1024;

const payloads = [
  { name: "empty", bytes: new Uint8Array() },
  {
    name: "small",
    bytes: new TextEncoder().encode("small publication payload"),
  },
  {
    name: "multibyte UTF-8",
    bytes: new TextEncoder().encode("multibyte: 日本語🌊é"),
  },
  { name: "Keccak rate minus one", bytes: new Uint8Array(135).fill(0x13) },
  { name: "Keccak rate", bytes: new Uint8Array(136).fill(0x24) },
  { name: "Keccak rate plus one", bytes: new Uint8Array(137).fill(0x35) },
  { name: "chunk minus one", bytes: new Uint8Array(chunkBytes - 1).fill(0x46) },
  { name: "one chunk", bytes: new Uint8Array(chunkBytes).fill(0x57) },
  { name: "chunk plus one", bytes: new Uint8Array(chunkBytes + 1).fill(0x68) },
  {
    name: "multiple chunks",
    bytes: new Uint8Array(2 * chunkBytes + 79).fill(0x79),
  },
];

describe("cooperative publication Keccak", () => {
  it.each(payloads)("matches viem for $name bytes", async ({ bytes }) => {
    await expect(keccak256Cooperatively(bytes)).resolves.toBe(keccak256(bytes));
  });
});
