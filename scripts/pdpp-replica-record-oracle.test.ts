import { describe, expect, it } from "vitest";
import {
  assertCanonicalRecordsEqual,
  assertBlobBytesAvailable,
  assertReplicaSnapshotsEqual,
  CANONICAL_RECORD_COLUMNS,
  blobMapsEqual,
  blobMatches,
  blobsVerified,
  canonicalRecordsEqual,
  projectCanonicalRecords,
  type CanonicalRecord,
  type ReplicaBlobMap,
} from "./pdpp-replica-record-oracle.js";

const record: CanonicalRecord = {
  instance: "conn",
  stream: "messages",
  record_key: "one",
  data: JSON.stringify({ id: "one", blob_ref: { blob_id: "blob-a" } }),
  emitted_at: "2026-10-20T10:00:00.000Z",
  deleted: 0,
  deleted_at: null,
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

  it("compares JSON numbers without losing integer precision", () => {
    expect(
      canonicalRecordsEqual(
        [{ ...record, data: '{"n":9007199254740993}' }],
        [{ ...record, data: '{"n":9007199254740992}' }],
      ),
    ).toBe(false);
    expect(
      canonicalRecordsEqual(
        [{ ...record, data: '{"n":1.0}' }],
        [{ ...record, data: '{"n":1e0}' }],
      ),
    ).toBe(true);
  });

  it("rejects duplicate JSON object keys", () => {
    expect(() =>
      canonicalRecordsEqual(
        [{ ...record, data: '{"n":1,"n":2}' }],
        [{ ...record, data: '{"n":2}' }],
      ),
    ).toThrow("Duplicate JSON object key");
  });

  it("projects every canonical column and rejects a missing column", () => {
    expect(
      projectCanonicalRecords([{ ...record, deleted_at: null, version: 9 }]),
    ).toEqual([{ ...record, deleted_at: null }]);
    expect(CANONICAL_RECORD_COLUMNS).toEqual([
      "instance",
      "stream",
      "record_key",
      "data",
      "emitted_at",
      "deleted",
      "deleted_at",
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

  it("rejects a deleted_at mismatch", () => {
    const live = { ...record, deleted_at: null };
    expect(
      canonicalRecordsEqual(
        [live],
        [{ ...live, deleted_at: "2026-10-20T10:00:00.000Z" }],
      ),
    ).toBe(false);
  });

  it.each([
    { ...record, deleted: "0" },
    { ...record, deleted_at: 42 },
    { ...record, data: {} },
  ])("rejects invalid field values", (invalid) => {
    expect(() => projectCanonicalRecords([invalid])).toThrow(
      "Canonical record has an invalid field value",
    );
  });

  it.each([
    "emitted_at",
    "instance",
    "stream",
    "deleted",
    "deleted_at",
    "blob_id",
  ] as const)("rejects a %s mismatch", (field) => {
    const changed = {
      ...record,
      [field]:
        field === "deleted"
          ? 1
          : field === "emitted_at"
            ? "2026-10-20T10:00:01.000Z"
            : field === "deleted_at"
              ? "2026-10-20T10:00:00.000Z"
              : `${record[field] as string}-changed`,
    };
    expect(canonicalRecordsEqual([record], [changed])).toBe(false);
  });
});

describe("replica blob byte equality", () => {
  const blob = { sha256: "abc123", bytes: 4 };

  it("rejects a hash or size mismatch", () => {
    const expected = { canonicalRecords: [record], blobs: { blob } };
    expect(
      blobMapsEqual({ blob }, { blob: { ...blob, sha256: "other" } }),
    ).toBe(false);
    expect(blobMapsEqual({ blob }, { blob: { ...blob, bytes: 5 } })).toBe(
      false,
    );
    expect(() =>
      assertReplicaSnapshotsEqual(expected, {
        ...expected,
        blobs: { blob: { ...blob, sha256: "other" } },
      }),
    ).toThrow("Replica blob mismatch");
    expect(() =>
      assertReplicaSnapshotsEqual(expected, {
        ...expected,
        blobs: { blob: { ...blob, bytes: 5 } },
      }),
    ).toThrow("Replica blob mismatch");
  });

  it("rejects a blob missing from one replica", () => {
    expect(blobMapsEqual({ blob: blob }, {})).toBe(false);
    expect(() =>
      assertReplicaSnapshotsEqual(
        { canonicalRecords: [record], blobs: { blob } },
        { canonicalRecords: [record], blobs: {} },
      ),
    ).toThrow("Replica blob mismatch");
  });

  it.each(["left", "right"] as const)(
    "rejects unavailable bytes on the %s replica",
    (side) => {
      const left: ReplicaBlobMap =
        side === "left" ? { blob: { unavailable: true } } : { blob };
      const right: ReplicaBlobMap =
        side === "right" ? { blob: { unavailable: true } } : { blob };
      expect(blobsVerified(left)).toBe(side !== "left");
      expect(blobsVerified(right)).toBe(side !== "right");
      expect(() =>
        assertBlobBytesAvailable(side === "left" ? left : right),
      ).toThrow("Referenced blob bytes failed verification");
      expect(() =>
        assertReplicaSnapshotsEqual(
          { canonicalRecords: [record], blobs: left },
          { canonicalRecords: [record], blobs: right },
        ),
      ).toThrow("Referenced blob bytes failed verification");
    },
  );

  it("rejects a verified blob with the wrong expected hash", () => {
    expect(blobMatches({ blob }, "blob", "abc123")).toBe(true);
    expect(blobMatches({ blob }, "blob", "wrong-hash")).toBe(false);
    expect(blobMatches({}, "blob", "abc123")).toBe(false);
  });
});
