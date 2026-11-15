import { describe, expect, it } from "vitest";
import { canonicalJson } from "./json.js";
import { sha256Hex, utf8 } from "./bytes.js";
import { deletionKeyMatchesHash, pkHash, primaryKeyValues } from "./records.js";
import { nodePorts } from "./test-support/ports.js";

const sha256 = nodePorts.sha256;
const hashOf = (values: unknown[]) =>
  sha256Hex(sha256, utf8(canonicalJson(values)));

// A deletion names its key by a hash (the log's identity) and by the typed
// primary-key values the hash was computed from. The check is one hash.
describe("a deletion's key and the hash that names it", () => {
  it("accepts the values the hash covers, with their types", async () => {
    expect(
      await deletionKeyMatchesHash(sha256, ["id"], [1], await hashOf([1])),
    ).toBe(true);
    expect(
      await deletionKeyMatchesHash(sha256, ["id"], ["1"], await hashOf(["1"])),
    ).toBe(true);
    expect(
      await deletionKeyMatchesHash(
        sha256,
        ["id"],
        [true],
        await hashOf([true]),
      ),
    ).toBe(true);
  });

  it("does not take 1 for '1': the same record key, two different records", async () => {
    expect(
      await deletionKeyMatchesHash(sha256, ["id"], [1], await hashOf(["1"])),
    ).toBe(false);
    expect(
      await deletionKeyMatchesHash(sha256, ["id"], ["1"], await hashOf([1])),
    ).toBe(false);
    expect(
      await deletionKeyMatchesHash(sha256, ["id"], ["B"], await hashOf(["A"])),
    ).toBe(false);
  });

  it("accepts a composite key in order, and no other order or type", async () => {
    const pk = ["a", "b"];
    expect(
      await deletionKeyMatchesHash(
        sha256,
        pk,
        ["x", 2],
        await hashOf(["x", 2]),
      ),
    ).toBe(true);
    expect(
      await deletionKeyMatchesHash(
        sha256,
        pk,
        ["x", "2"],
        await hashOf(["x", 2]),
      ),
    ).toBe(false);
    expect(
      await deletionKeyMatchesHash(
        sha256,
        pk,
        [2, "x"],
        await hashOf(["x", 2]),
      ),
    ).toBe(false);
  });

  it("refuses a key of the wrong arity, even when it hashes to the hash", async () => {
    expect(
      await deletionKeyMatchesHash(
        sha256,
        ["a", "b"],
        ["x"],
        await hashOf(["x"]),
      ),
    ).toBe(false);
    expect(
      await deletionKeyMatchesHash(sha256, ["id"], [], await hashOf([])),
    ).toBe(false);
  });

  it("refuses a value that is not a string, a finite number or a boolean", async () => {
    // Whatever the hash, such a value is not a key (it cannot give a record key).
    const hash = await hashOf([1]);
    for (const bad of [null, { a: 1 }, ["x"], Number.NaN, Infinity])
      expect(await deletionKeyMatchesHash(sha256, ["id"], [bad], hash)).toBe(
        false,
      );
  });

  it("refuses a hash that is not 64 lowercase hex", async () => {
    expect(await deletionKeyMatchesHash(sha256, ["id"], [1], "abc")).toBe(
      false,
    );
  });

  it("has no limit on the number of key fields", async () => {
    const primaryKey = Array.from({ length: 40 }, (_, i) => `f${i}`);
    const key = primaryKey.map((_, i) => i);
    expect(
      await deletionKeyMatchesHash(sha256, primaryKey, key, await hashOf(key)),
    ).toBe(true);
  });

  it("is the input pkHash hashes", async () => {
    for (const [record, primaryKey] of [
      [{ id: 7 }, ["id"]],
      [{ id: "7" }, ["id"]],
      [{ a: "x", b: 2, c: true }, ["a", "b", "c"]],
    ] as const) {
      expect(
        await deletionKeyMatchesHash(
          sha256,
          primaryKey,
          primaryKeyValues(record, primaryKey) as never,
          await pkHash(sha256, record, primaryKey),
        ),
      ).toBe(true);
    }
  });
});
