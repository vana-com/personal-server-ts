import { describe, expect, it } from "vitest";
import { canonicalJson } from "./json.js";
import { sha256Hex, utf8 } from "./bytes.js";
import {
  deletionKeyMatchesHash,
  keyFromRecordKey,
  pkHash,
  primaryKeyValues,
} from "./records.js";
import { nodePorts } from "./test-support/ports.js";
import {
  decodeSegment,
  encodeSegment,
  LOG_FORMAT,
  type LogKey,
  type Segment,
} from "./log.js";

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

// Key values that a hash could treat as one thing and a reader as another.
// Each one either names the same hash at the writer and the reader, or the
// segment that carries it is refused by the reader.
describe("adversarial key values, at the writer and at the reader", () => {
  const segmentWith = async (key: LogKey): Promise<Segment> => ({
    format: LOG_FORMAT,
    connector: "c",
    ns: "fedcba9876543210",
    generation: 1,
    keyCheck: "0123456789abcdef",
    position: 1,
    observedAt: 10,
    base: 0,
    snapshot: null,
    refs: [],
    streams: [
      {
        stream: "a",
        primaryKey: ["id"],
        profile: { key: null, version: "1.0.0" },
        complete: true,
      },
    ],
    operations: [
      {
        kind: "delete",
        stream: "a",
        pkHash: await hashOf(key as unknown[]),
        key,
        stamp: { o: 5, r: "run-1" },
      },
    ],
  });
  const textOf = async (key: LogKey) =>
    new TextDecoder().decode(encodeSegment(await segmentWith(key)));

  /** What a reader derives from the bytes, and whether its check passes. */
  const readerSees = async (bytes: Uint8Array) => {
    const decoded = decodeSegment(bytes);
    if (decoded.kind !== "ok") return decoded.kind;
    const op = decoded.segment.operations[0] as {
      pkHash: string;
      key: LogKey;
    };
    return {
      key: op.key,
      matches: await deletionKeyMatchesHash(sha256, ["id"], op.key, op.pkHash),
    };
  };

  it("-0 is written as 0, hashes as 0, and the reader accepts it as 0", async () => {
    const text = await textOf([-0]);
    expect(text).toContain('"rk":[0]');
    expect(await hashOf([-0])).toBe(await hashOf([0]));
    expect(await readerSees(utf8(text))).toEqual({ key: [0], matches: true });
    // A writer's literal `-0` on the wire is not what the writer would have
    // written: refused.
    expect(await readerSees(utf8(text.replace('"rk":[0]', '"rk":[-0]')))).toBe(
      "malformed",
    );
  });

  it("1, 1.0 and 1e0 are one number, written as 1: the other spellings are refused", async () => {
    const text = await textOf([1]);
    expect(text).toContain('"rk":[1]');
    expect(await hashOf([1])).toBe(await hashOf([JSON.parse("1.0")]));
    expect(await hashOf([1])).toBe(await hashOf([JSON.parse("1e0")]));
    expect(await readerSees(utf8(text))).toEqual({ key: [1], matches: true });
    for (const spelling of ["1.0", "1e0", "1E0", "10e-1", "+1"])
      expect(
        await readerSees(utf8(text.replace('"rk":[1]', `"rk":[${spelling}]`))),
      ).toBe("malformed");
    // The number and its text are two different keys.
    expect(await hashOf([1])).not.toBe(await hashOf(["1"]));
  });

  it("an integer above 2^53 is the double it parses to, at both ends; the exact digits are refused", async () => {
    const above = JSON.parse("9007199254740993"); // 2^53 + 1, parsed as 2^53
    expect(above).toBe(9007199254740992);
    const text = await textOf([above]);
    expect(text).toContain('"rk":[9007199254740992]');
    expect(await readerSees(utf8(text))).toEqual({
      key: [9007199254740992],
      matches: true,
    });
    // The digits the double cannot hold are not what the writer would write.
    expect(
      await readerSees(
        utf8(text.replace("9007199254740992]", "9007199254740993]")),
      ),
    ).toBe("malformed");
  });

  it("a string with a precomposed accent and the same with a decomposed one are two keys, and neither is folded", async () => {
    const precomposed = "\u00e9";
    const decomposed = "e\u0301";
    expect(precomposed).not.toBe(decomposed);
    expect(precomposed.normalize("NFD")).toBe(decomposed);
    expect(await hashOf([precomposed])).not.toBe(await hashOf([decomposed]));
    for (const value of [precomposed, decomposed])
      expect(await readerSees(utf8(await textOf([value])))).toEqual({
        key: [value],
        matches: true,
      });
    // A hash for one does not accept the other's key.
    expect(
      await deletionKeyMatchesHash(
        sha256,
        ["id"],
        [decomposed],
        await hashOf([precomposed]),
      ),
    ).toBe(false);
  });
});

// A delete made before typed keys were kept has only the record key. The
// stream's declared key types give the tuple back, and only where the string is
// exactly what the type prints; the hash then settles whether it is right.
describe("a typed key rebuilt from the record key and the declared key types", () => {
  const rebuilt = async (
    record: Record<string, unknown>,
    primaryKey: string[],
    types: ("string" | "number" | "integer" | "boolean" | null)[] | null,
  ) => {
    const key = keyFromRecordKey(
      primaryKey,
      types,
      primaryKey.length === 1
        ? String(record[primaryKey[0]!])
        : JSON.stringify(primaryKey.map((f) => String(record[f]))),
    );
    const hash = await pkHash(sha256, record, primaryKey);
    return {
      key,
      hashes:
        key !== null &&
        (await deletionKeyMatchesHash(sha256, primaryKey, key, hash)),
    };
  };

  it("rebuilds a number, a string, a boolean and a compound key, each hashing to the record's hash", async () => {
    expect(await rebuilt({ id: 7 }, ["id"], ["integer"])).toEqual({
      key: [7],
      hashes: true,
    });
    expect(await rebuilt({ id: "7" }, ["id"], ["string"])).toEqual({
      key: ["7"],
      hashes: true,
    });
    expect(await rebuilt({ id: true }, ["id"], ["boolean"])).toEqual({
      key: [true],
      hashes: true,
    });
    expect(
      await rebuilt(
        { a: "x", b: 2.5, c: false },
        ["a", "b", "c"],
        ["string", "number", "boolean"],
      ),
    ).toEqual({ key: ["x", 2.5, false], hashes: true });
  });

  it("is not determined when the schema declares no type, or one that the string cannot be", async () => {
    expect(keyFromRecordKey(["id"], null, "7")).toBeNull();
    expect(keyFromRecordKey(["id"], [null], "7")).toBeNull();
    expect(keyFromRecordKey(["a", "b"], ["string"], '["x","y"]')).toBeNull();
    expect(keyFromRecordKey(["id"], ["integer"], "7.0")).toBeNull();
    expect(keyFromRecordKey(["id"], ["integer"], "07")).toBeNull();
    expect(keyFromRecordKey(["id"], ["number"], "abc")).toBeNull();
    expect(keyFromRecordKey(["id"], ["boolean"], "yes")).toBeNull();
    expect(keyFromRecordKey(["a", "b"], ["string", "string"], "x")).toBeNull();
  });

  it("a rebuilt key whose type is not the data's type does not hash to the record's hash", async () => {
    // The schema says string; the connector sent the number 7.
    expect(await rebuilt({ id: 7 }, ["id"], ["string"])).toEqual({
      key: ["7"],
      hashes: false,
    });
  });
});
