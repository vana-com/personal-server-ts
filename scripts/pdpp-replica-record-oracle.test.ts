import { describe, expect, it } from "vitest";
import {
  assertCanonicalRecordsEqual,
  CANONICAL_RECORD_COLUMNS,
  canonicalRecordsEqual,
  projectCanonicalRecords,
  type CanonicalRecord,
} from "./pdpp-replica-record-oracle.js";

const record: CanonicalRecord = {
  instance: "conn",
  stream: "messages",
  record_key: "one",
  data: JSON.stringify({ id: "one", blob_ref: { blob_id: "blob-a" } }),
  emitted_at: "2026-10-20T10:00:00.000Z",
  deleted: 0,
  blob_id: "blob-a",
};

describe("canonical replica record equality", () => {
  it("accepts the same rows in a different input order", () => {
    assertCanonicalRecordsEqual(
      [
        record,
        { ...record, instance: "other" },
        { ...record, stream: "other" },
      ],
      [
        { ...record, stream: "other" },
        { ...record, instance: "other" },
        record,
      ],
    );
  });

  it("compares JSON data by value, independent of object key order", () => {
    const reorderedData = JSON.stringify({
      nested: { z: 3, a: 1 },
      items: ["first", "second"],
      id: "one",
    });
    const orderedData = JSON.stringify({
      id: "one",
      items: ["first", "second"],
      nested: { a: 1, z: 3 },
    });
    expect(
      canonicalRecordsEqual(
        [{ ...record, data: orderedData }],
        [{ ...record, data: reorderedData }],
      ),
    ).toBe(true);
    expect(
      canonicalRecordsEqual(
        [{ ...record, data: orderedData }],
        [
          {
            ...record,
            data: JSON.stringify({
              id: "one",
              items: ["second", "first"],
              nested: { a: 1, z: 3 },
            }),
          },
        ],
      ),
    ).toBe(false);
    expect(
      canonicalRecordsEqual(
        [record],
        [{ ...record, data: JSON.stringify({ id: "one", text: "changed" }) }],
      ),
    ).toBe(false);
  });

  it("projects every canonical column and rejects a missing column", () => {
    expect(projectCanonicalRecords([{ ...record, version: 9 }])).toEqual([
      record,
    ]);
    expect(CANONICAL_RECORD_COLUMNS).toEqual([
      "instance",
      "stream",
      "record_key",
      "data",
      "emitted_at",
      "deleted",
      "blob_id",
    ]);
    for (const field of CANONICAL_RECORD_COLUMNS) {
      const incomplete: Record<string, unknown> = { ...record };
      delete incomplete[field];
      expect(() => projectCanonicalRecords([incomplete])).toThrow(
        `Canonical record is missing field ${field}`,
      );
    }
  });

  it.each([
    { ...record, deleted: "0" },
    { ...record, data: {} },
  ])("rejects invalid field values", (invalid) => {
    expect(() => projectCanonicalRecords([invalid])).toThrow(
      "Canonical record has an invalid field value",
    );
  });

  it.each(["emitted_at", "instance", "stream", "deleted", "blob_id"] as const)(
    "rejects a %s mismatch",
    (field) => {
      const changed = {
        ...record,
        [field]:
          field === "deleted"
            ? 1
            : field === "emitted_at"
              ? "2026-10-20T10:00:01.000Z"
              : `${record[field] as string}-changed`,
      };
      expect(canonicalRecordsEqual([record], [changed])).toBe(false);
    },
  );
});
