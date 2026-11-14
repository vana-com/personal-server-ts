import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  prefixBits,
  selectChangedBuckets,
} from "../../../core/src/localdb/part-layout.js";

const key = (i: number) => createHash("sha256").update(`k${i}`).digest("hex");
const bits = (hex: string, n: number) =>
  BigInt(`0x${hex.slice(0, 4)}`)
    .toString(2)
    .padStart(16, "0")
    .slice(0, n);
const parts = (...prefixes: string[]) => prefixes.map((prefix) => ({ prefix }));
const prefixFree = (prefixes: readonly string[]) =>
  prefixes.every((a, i) =>
    prefixes.every((b, j) => i === j || !b.startsWith(a)),
  );

describe("selectChangedBuckets", () => {
  it("encodes only the bucket that holds a changed key", () => {
    const k = key(1);
    const own = bits(k, 2);
    const buckets = ["00", "01", "10", "11"];
    expect(
      selectChangedBuckets(buckets, [k], parts("00", "01", "10", "11"), false),
    ).toEqual([own]);
  });

  it("merges every base part under a coarser bucket", () => {
    // One bucket "0" holds the two base parts "00" and "01".
    const k = key(2);
    const bucket = bits(k, 1);
    const base =
      bucket === "0" ? parts("00", "01", "1") : parts("0", "10", "11");
    const out = selectChangedBuckets(["0", "1"], [k], base, false);
    expect(out).toEqual([bucket]);
  });

  it("encodes every bucket of a base part that a changed bucket splits", () => {
    // The base part "" is cut into buckets "0" and "1": a change in "0" drops
    // "", so "1" must be encoded as well.
    const k = [1, 2, 3, 4, 5, 6].map(key).find((x) => bits(x, 1) === "0")!;
    expect(selectChangedBuckets(["0", "1"], [k], parts(""), false)).toEqual([
      "0",
      "1",
    ]);
  });

  it("leaves a base part that no changed bucket overlaps", () => {
    const k = [1, 2, 3, 4, 5, 6].map(key).find((x) => bits(x, 1) === "0")!;
    expect(
      selectChangedBuckets(["0", "1"], [k], parts("0", "1"), false),
    ).toEqual(["0"]);
  });

  it("encodes every bucket when the whole head is rewritten", () => {
    expect(
      selectChangedBuckets(["0", "10", "11"], [], parts("0", "1"), true),
    ).toEqual(["0", "10", "11"]);
  });

  it("ignores a changed key with no bucket (a delete with no rows)", () => {
    expect(selectChangedBuckets([], [key(1)], [], false)).toEqual([]);
  });

  it("returns a prefix-free set", () => {
    const buckets = ["000", "001", "01", "10", "11"];
    const out = selectChangedBuckets(
      buckets,
      Array.from({ length: 40 }, (_, i) => key(i)),
      parts("00", "01", "1"),
      false,
    );
    expect(prefixFree(out)).toBe(true);
  });
});

/** The pre-table implementation, kept as the oracle: one `find` per key. */
function legacySelectChangedBuckets(
  buckets: readonly string[],
  changedKeys: readonly string[],
  baseParts: readonly { readonly prefix: string }[],
  rewriteAll: boolean,
): string[] {
  const changed = new Set<string>();
  for (const key of changedKeys) {
    const bucket = buckets.find(
      (prefix) => prefixBits(key, prefix.length) === prefix,
    );
    if (bucket !== undefined) changed.add(bucket);
  }
  const dropped = new Set<string>(
    rewriteAll ? baseParts.map((p) => p.prefix) : [],
  );
  for (;;) {
    const before = changed.size + dropped.size;
    for (const part of baseParts) {
      if ([...changed].some((bucket) => overlaps(bucket, part.prefix))) {
        dropped.add(part.prefix);
      }
    }
    for (const bucket of buckets) {
      if ([...dropped].some((prefix) => overlaps(bucket, prefix))) {
        changed.add(bucket);
      }
    }
    if (changed.size + dropped.size === before) break;
  }
  return [...changed].sort();
}

const overlaps = (a: string, b: string) => a.startsWith(b) || b.startsWith(a);

/** A seeded generator, so a failing case can be replayed. */
function random(seed: number) {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

describe("selectChangedBuckets matches the per-key implementation", () => {
  it("agrees on random partitions, overlapping bucket lists, base parts and rewriteAll", () => {
    const next = random(20261113);
    const pick = (n: number) => Math.floor(next() * n);
    const bitString = (length: number) =>
      Array.from({ length }, () => (next() < 0.5 ? "0" : "1")).join("");
    // Recursively split the bit space: a partition with mixed depths.
    const split = (prefix: string, depth: number): string[] =>
      depth === 0 || (prefix.length >= 3 && next() < 0.3)
        ? [prefix]
        : [
            ...split(`${prefix}0`, depth - 1),
            ...split(`${prefix}1`, depth - 1),
          ];

    let checked = 0;
    for (let trial = 0; trial < 300; trial += 1) {
      const shape = trial % 3;
      // shape 0: a partition; 1: arbitrary prefixes that may overlap or repeat;
      // 2: a partition with some buckets longer than the 16-bit table.
      const buckets =
        shape === 1
          ? Array.from({ length: 1 + pick(12) }, () => bitString(pick(17)))
          : split("", 1 + pick(8)).sort();
      if (shape === 2) buckets.push(bitString(17 + pick(4)));
      const keys = Array.from({ length: pick(300) }, () =>
        key(pick(1_000_000)),
      );
      const baseParts =
        next() < 0.5
          ? []
          : Array.from({ length: pick(6) }, () => ({
              prefix: bitString(pick(10)),
            }));
      const rewriteAll = next() < 0.3;
      expect(
        selectChangedBuckets(buckets, keys, baseParts, rewriteAll),
        `trial ${trial}`,
      ).toEqual(
        legacySelectChangedBuckets(buckets, keys, baseParts, rewriteAll),
      );
      checked += 1;
    }
    expect(checked).toBe(300);
  });

  it("agrees when keys repeat their first 16 bits and when no bucket matches", () => {
    const k = key(7);
    const sibling = k.slice(0, 4) + k.slice(4).split("").reverse().join("");
    const buckets = ["0000", "0001", "0010", "1", "1111"];
    for (const keys of [[k, sibling], [k], []]) {
      expect(selectChangedBuckets(buckets, keys, [], false)).toEqual(
        legacySelectChangedBuckets(buckets, keys, [], false),
      );
    }
    expect(selectChangedBuckets(["0000"], [k], [], false)).toEqual(
      legacySelectChangedBuckets(["0000"], [k], [], false),
    );
  });
});
