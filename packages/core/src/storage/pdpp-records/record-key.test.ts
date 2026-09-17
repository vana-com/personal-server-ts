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
