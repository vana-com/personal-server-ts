import { describe, expect, it } from "vitest";
import type {
  LogOmitted,
  LogOperation,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { heldKeys, removalsOf } from "./log-progressive.js";

const stamp = { o: 1, r: "a" };
const upsert = (stream: string, pkHash: string): LogOperation => ({
  kind: "upsert",
  stream,
  pkHash,
  stamp,
  firstSeen: 1,
  value: { id: pkHash },
});
const remove = (stream: string, pkHash: string): LogOperation => ({
  kind: "delete",
  stream,
  pkHash,
  key: [pkHash],
  stamp,
});
const omit = (stream: string, pkHash: string): LogOmitted => ({
  kind: "omitted",
  stream,
  pkHash,
  key: [pkHash],
  stamp,
});
const complete = (stream: string, pkHashes: string[]): LogOperation => ({
  kind: "complete",
  stream,
  cutoff: stamp,
  omitted: pkHashes.map((pkHash) => ({ pkHash, key: [pkHash] })),
});

describe("removalsOf", () => {
  it("records the last batch that deletes or omits a key, per stream", () => {
    const removed = removalsOf([
      { index: 1, operations: [remove("a", "k1"), omit("a", "k2")] },
      { index: 3, operations: [remove("a", "k1"), remove("b", "k1")] },
    ]);
    expect(removed.get("a")!.get("k1")).toBe(3);
    expect(removed.get("a")!.get("k2")).toBe(1);
    expect(removed.get("b")!.get("k1")).toBe(3);
  });

  it("takes the keys a completion omits, and nothing from one that omits none", () => {
    const removed = removalsOf([
      { index: 2, operations: [complete("a", ["k1", "k2"])] },
      { index: 4, operations: [complete("b", [])] },
    ]);
    expect([...removed.get("a")!.keys()].sort()).toEqual(["k1", "k2"]);
    expect(removed.has("b")).toBe(false);
  });

  it("does not look at upserts", () => {
    expect(
      removalsOf([{ index: 0, operations: [upsert("a", "k1")] }]).size,
    ).toBe(0);
  });
});

describe("heldKeys", () => {
  const removed = removalsOf([
    { index: 3, operations: [remove("a", "k1"), omit("a", "k2")] },
  ]);

  it("holds a key of the batch that a later batch removes", () => {
    expect(
      heldKeys(removed, "a", 1, [upsert("a", "k1"), upsert("a", "k3")]),
    ).toEqual(["k1"]);
  });

  it("holds nothing once the batch is the one that removes, or after it", () => {
    expect(heldKeys(removed, "a", 3, [upsert("a", "k1")])).toEqual([]);
    expect(heldKeys(removed, "a", 5, [upsert("a", "k1")])).toEqual([]);
  });

  it("holds a key of its own stream only", () => {
    expect(heldKeys(removed, "b", 1, [upsert("b", "k1")])).toEqual([]);
  });
});
