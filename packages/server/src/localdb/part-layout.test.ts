import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { selectChangedBuckets } from "../../../core/src/localdb/part-layout.js";

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
