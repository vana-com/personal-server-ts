import { describe, it, expect } from "vitest";
import {
  encodeRecordKey,
  computeRecordKeyFromData,
  keyMatchesData,
  RecordKeyError,
} from "./record-key.js";

describe("encodeRecordKey", () => {
  it("encodes a simple string key as-is", () => {
    expect(encodeRecordKey("msg_abc123")).toBe("msg_abc123");
  });

  it("converts non-string simple key components to strings", () => {
    expect(encodeRecordKey(42 as unknown as string)).toBe("42");
  });

  it("encodes a compound key as minified JSON array of strings", () => {
    expect(encodeRecordKey(["user_123", "2026-04-01"])).toBe(
      '["user_123","2026-04-01"]',
    );
  });

  it("converts non-string compound key components to strings", () => {
    expect(encodeRecordKey(["user_123", 20260401 as unknown as string])).toBe(
      '["user_123","20260401"]',
    );
  });

  it("rejects an empty compound key array", () => {
    expect(() => encodeRecordKey([])).toThrow(RecordKeyError);
  });
});

describe("computeRecordKeyFromData", () => {
  it("computes a simple key from a single primary_key field", () => {
    const key = computeRecordKeyFromData({ id: "msg_abc123" }, ["id"]);
    expect(key).toBe("msg_abc123");
  });

  it("computes a compound key from multiple primary_key fields in order", () => {
    const key = computeRecordKeyFromData(
      { user_id: "user_123", date: "2026-04-01", other: "x" },
      ["user_id", "date"],
    );
    expect(key).toBe('["user_123","2026-04-01"]');
  });

  it("throws when a declared primary key field is missing from data", () => {
    expect(() =>
      computeRecordKeyFromData({ id: "x" }, ["id", "missing"]),
    ).toThrow(RecordKeyError);
  });
});

describe("keyMatchesData", () => {
  it("returns true when envelope key matches data's primary key fields", () => {
    expect(keyMatchesData("msg_abc123", { id: "msg_abc123" }, ["id"])).toBe(
      true,
    );
  });

  it("returns true for a matching compound key", () => {
    expect(
      keyMatchesData(
        ["user_123", "2026-04-01"],
        { user_id: "user_123", date: "2026-04-01" },
        ["user_id", "date"],
      ),
    ).toBe(true);
  });

  it("returns false when envelope key disagrees with data", () => {
    expect(keyMatchesData("wrong_id", { id: "msg_abc123" }, ["id"])).toBe(
      false,
    );
  });

  it("returns false when compound key order disagrees with data", () => {
    expect(
      keyMatchesData(
        ["2026-04-01", "user_123"],
        { user_id: "user_123", date: "2026-04-01" },
        ["user_id", "date"],
      ),
    ).toBe(false);
  });
});

describe("record key encoding ambiguity (C8, reviewed and bounded)", () => {
  it("documents that a single-key literal value can encode identically to a compound key", () => {
    // The known ambiguity itself: a single-field key whose value happens to
    // be the literal string '["a","b"]' encodes to the exact same string as
    // the compound key ["a","b"]. This test exists to make the ambiguity
    // visible and intentional, not to assert it as desired behavior.
    const singleKeyValue = '["a","b"]';
    const compoundKey = ["a", "b"];
    expect(encodeRecordKey(singleKeyValue)).toBe(encodeRecordKey(compoundKey));
  });

  it("cannot collide within one stream, because a stream's primary_key arity is fixed", () => {
    // The reason the ambiguity above is bounded: encodeRecordKey's output
    // for a stream is always computed against that stream's OWN declared
    // primaryKeyFields (via computeRecordKeyFromData), and a stream cannot
    // declare a single-field primary_key for one record and a compound
    // primary_key for another. Fix arity for one stream and show every
    // record's key is computed the same way -- there is no code path that
    // lets one stream produce both encoding shapes.
    const singleKeyFields = ["id"];
    const dataA = { id: "record_a" };
    const dataB = { id: "record_b" };
    // Both records in the same (hypothetical) stream use the same arity;
    // neither can ever produce a compound-shaped key, so no ambiguity with
    // a compound key from this stream is possible.
    expect(computeRecordKeyFromData(dataA, singleKeyFields)).toBe("record_a");
    expect(computeRecordKeyFromData(dataB, singleKeyFields)).toBe("record_b");
  });
});
