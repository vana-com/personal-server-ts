/**
 * Byte identity for the allocation cuts (82d13f6b): the current canonical JSON,
 * utf8Length and toHex must produce exactly the bytes of the pre-cut code. The
 * reference functions below are copies of the pre-cut implementations.
 *
 * Mutants this test must fail: dropping the key sort (ordering) or writing keys
 * without JSON escaping (escaping).
 */
import { describe, expect, it } from "vitest";
import { canonicalJson } from "./json.js";
import { toHex, utf8, utf8Length } from "./bytes.js";

// ---- pre-cut reference (HEAD 8229f180b-era json.ts writeArray/writeObject, join-based)
function legacyCanonical(value: unknown): string {
  return legacyWrite(value, 0);
}
function legacyWrite(value: unknown, depth: number): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "string":
      return JSON.stringify(value);
    case "number":
      return JSON.stringify(value);
    case "object":
      return Array.isArray(value)
        ? legacyArray(value, depth)
        : legacyObject(value as Record<string, unknown>, depth);
    default:
      throw new Error("unsupported");
  }
}
function legacyArray(value: readonly unknown[], depth: number): string {
  const parts: string[] = [];
  for (let i = 0; i < value.length; i += 1)
    parts.push(legacyWrite(value[i], depth + 1));
  return `[${parts.join(",")}]`;
}
function legacyObject(value: Record<string, unknown>, depth: number): string {
  const parts: string[] = [];
  for (const key of Object.keys(value).sort()) {
    parts.push(`${JSON.stringify(key)}:${legacyWrite(value[key], depth + 1)}`);
  }
  return `{${parts.join(",")}}`;
}
function legacyUtf8Length(text: string): number {
  return new TextEncoder().encode(text).length;
}
function legacyToHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 1) {
    out += bytes[i]!.toString(16).padStart(2, "0");
  }
  return out;
}

// ---- seeded generator (mulberry32), so failures reproduce
function prng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const CHARS = [
  "a",
  "Z",
  "0",
  " ",
  '"',
  "\\",
  "/",
  "\n",
  "\t",
  "\u0001",
  "\u001f",
  "é",
  "ü",
  "中",
  "🐟",
  "𝄞",
  " ",
  "￿",
  "\uD800",
  "\uDC00",
];
const KEY_CHARS = ["a", "B", "_", "-", "é", "中", '"', "\\", "🐟", "~"];

function randomString(
  rand: () => number,
  alphabet: string[],
  max: number,
): string {
  const n = Math.floor(rand() * (max + 1));
  let out = "";
  for (let i = 0; i < n; i += 1)
    out += alphabet[Math.floor(rand() * alphabet.length)];
  return out;
}

function randomValue(rand: () => number, depth: number): unknown {
  const pick = rand();
  if (depth > 3 || pick < 0.5) {
    const leaf = Math.floor(rand() * 6);
    if (leaf === 0) return null;
    if (leaf === 1) return rand() < 0.5;
    if (leaf === 2)
      return Math.floor((rand() - 0.5) * 1e9) / (rand() < 0.5 ? 1 : 1000);
    if (leaf === 3)
      return [1e21, -0, 1e-7, 123456789.125][Math.floor(rand() * 4)];
    return randomString(rand, CHARS, 12);
  }
  if (pick < 0.65) {
    const n = Math.floor(rand() * 4);
    return Array.from({ length: n }, () => randomValue(rand, depth + 1));
  }
  const obj: Record<string, unknown> = {};
  const n = Math.floor(rand() * 5);
  for (let i = 0; i < n; i += 1)
    obj[randomString(rand, KEY_CHARS, 6)] = randomValue(rand, depth + 1);
  return obj;
}

const RECORDS = 3000;

describe("pre-cut byte identity", () => {
  it("canonical JSON matches the pre-cut writer over generated records", () => {
    const rand = prng(0x5eed);
    for (let i = 0; i < RECORDS; i += 1) {
      const value = randomValue(rand, 0);
      expect(canonicalJson(value), `record ${i}`).toBe(legacyCanonical(value));
    }
  });

  it("covers empty containers, nesting, non-ASCII and surrogates in the sample", () => {
    const rand = prng(0x5eed);
    const seen = {
      emptyArray: false,
      emptyObject: false,
      lone: false,
      pair: false,
      nested: false,
    };
    for (let i = 0; i < RECORDS; i += 1) {
      const text = canonicalJson(randomValue(rand, 0));
      if (text.includes("[]")) seen.emptyArray = true;
      if (text.includes("{}")) seen.emptyObject = true;
      if (text.includes("\\ud800") || text.includes("\\udc00"))
        seen.lone = true;
      if (/[\u{10000}-\u{10FFFF}]/u.test(text)) seen.pair = true;
      if (
        text.includes("[{") ||
        text.includes("{[") ||
        text.includes("[[") ||
        text.includes("{{")
      )
        seen.nested = true;
    }
    expect(Object.values(seen).every(Boolean)).toBe(true);
  });

  it("utf8Length and toHex match the pre-cut code on generated text and bytes", () => {
    const rand = prng(0xbeef);
    for (let i = 0; i < RECORDS; i += 1) {
      const text = randomString(rand, [...CHARS, "x".repeat(40)], 60);
      expect(utf8Length(text), `text ${i}`).toBe(legacyUtf8Length(text));
      const bytes = utf8(text);
      expect(toHex(bytes), `hex ${i}`).toBe(legacyToHex(bytes));
    }
    const all = Uint8Array.from({ length: 256 }, (_, b) => b);
    expect(toHex(all)).toBe(legacyToHex(all));
  });
});
