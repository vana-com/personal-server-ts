import { createHash } from "node:crypto";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { PdppRecordEnvelopeInput } from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";

const SOURCE = "https://registry.pdpp.dev/sources/claude";
const METHOD = "anthropic";
const INSTANCE = "conn_a";
const T1 = "2026-09-10T06:30:00.000Z";

const sha = (preimage: string) =>
  createHash("sha256").update(preimage, "utf8").digest("hex");

type Row = { id: string; [field: string]: unknown };

describe("P7 completion_policy preserve_if_unchanged over real SQLite", () => {
  let db: InstanceType<typeof Database>;
  let store: ReturnType<typeof createSqliteRecordStore>;

  beforeEach(() => {
    db = new Database(":memory:");
    store = createSqliteRecordStore(db);
    store.registerConnection({
      instance: INSTANCE,
      sourceId: SOURCE,
      method: METHOD,
      label: "a",
    });
    store.registerConnection({
      instance: "conn_b",
      sourceId: SOURCE,
      method: METHOD,
      label: "b",
    });
  });
  afterEach(() => store.close());

  const envelope = (row: Row, op?: "delete"): PdppRecordEnvelopeInput => ({
    instance: INSTANCE,
    stream: "profiles",
    key: row.id,
    data: row,
    emitted_at: "2026-09-01T00:00:00.000Z",
    ...(op ? { op } : {}),
  });
  const replace = (
    rows: Row[],
    extra: {
      sourceCollectedAt?: string;
      completionPolicy?: unknown;
      method?: string;
      generation?: number;
      instance?: string;
      envelopes?: PdppRecordEnvelopeInput[];
    } = {},
  ) =>
    store.replaceStream({
      instance: extra.instance ?? INSTANCE,
      stream: "profiles",
      method: extra.method ?? METHOD,
      generation: extra.generation ?? 1,
      emittedAt: "2026-09-02T00:00:00.000Z",
      envelopes: extra.envelopes ?? rows.map((row) => envelope(row)),
      primaryKey: ["id"],
      ...(extra.sourceCollectedAt
        ? { sourceCollectedAt: extra.sourceCollectedAt }
        : {}),
      ...(extra.completionPolicy === undefined
        ? {}
        : {
            completionPolicy: extra.completionPolicy as "preserve_if_unchanged",
          }),
    });
  const preserve = (rows: Row[], extra = {}) =>
    replace(rows, { ...extra, completionPolicy: "preserve_if_unchanged" });

  const dump = (table: string, order: string) =>
    db.prepare(`SELECT * FROM ${table} ORDER BY ${order}`).all();
  const receipts = () => dump("pdpp_stream_completion", "instance, stream");
  const everything = () => ({
    receipts: receipts(),
    records: dump("pdpp_records", "instance, stream, record_key"),
    changes: dump("pdpp_record_changes", "id"),
    arrival: dump("pdpp_record_arrival", "instance, stream, record_key"),
    clock: dump("pdpp_write_clock", "id"),
  });
  /** Moves the global write clock with a write to another connection. */
  const unrelatedWrite = () =>
    store.replaceStream({
      instance: "conn_b",
      stream: "profiles",
      method: METHOD,
      generation: 1,
      emittedAt: "2026-09-02T00:00:00.000Z",
      primaryKey: ["id"],
      envelopes: [
        {
          instance: "conn_b",
          stream: "profiles",
          key: "z",
          data: { id: "z", n: Math.random() },
          emitted_at: "2026-09-01T00:00:00.000Z",
        },
      ],
    });
  const nativeReceipt = (rows: string, count = 2) =>
    store.completeStreams(
      {
        instance: INSTANCE,
        sourceId: SOURCE,
        method: METHOD,
        generation: 1,
        sourceCollectedAt: T1,
        collectionTimeBasis: "host_run_finished",
        streams: [
          {
            stream: "profiles",
            coverage: "full_stream",
            liveCount: count,
            snapshotSha256: sha(
              `["${SOURCE}","${INSTANCE}","${METHOD}",1,"profiles",[${rows}]]`,
            ),
          },
        ],
      },
      () => ["id"],
    );

  const A = { id: "a", v: 1 };
  const B = { id: "b", v: 1 };
  const PAIRS_AB = `["a",{"id":"a","v":1}],["b",{"id":"b","v":1}]`;

  describe("without the policy", () => {
    it("clears a receipt on an unchanged replay, as P7 always has", () => {
      replace([A, B], { sourceCollectedAt: T1 });
      expect(receipts()).toHaveLength(1);
      replace([A, B]);
      expect(receipts()).toEqual([]);
    });

    it("writes a new receipt from an explicit time on an unchanged replay", () => {
      replace([A, B], { sourceCollectedAt: "2026-09-10T06:30:00.000Z" });
      replace([A, B], { sourceCollectedAt: "2026-09-12T06:30:00.000Z" });
      expect(
        (receipts() as { source_collected_at: string }[]).map(
          (r) => r.source_collected_at,
        ),
      ).toEqual(["2026-09-12T06:30:00.000Z"]);
    });
  });

  describe("with the policy and an identical live set", () => {
    it("keeps a legacy receipt byte for byte after unrelated clock movement", () => {
      replace([A, B], { sourceCollectedAt: "2026-09-10T08:30:00+02:00" });
      const stored = receipts();
      unrelatedWrite();
      const before = everything();

      const result = preserve([A, B]);

      expect(result).toMatchObject({
        applied: true,
        accepted: 0,
        unchanged: 2,
        deleted: 0,
      });
      expect(receipts()).toEqual(stored);
      expect(everything().records).toEqual(before.records);
      expect(everything().changes).toEqual(before.changes);
      expect(everything().clock).toEqual(before.clock);
    });

    it("keeps a native receipt byte for byte", () => {
      replace([A, B]);
      nativeReceipt(PAIRS_AB);
      const stored = receipts();
      expect(stored).toHaveLength(1);
      unrelatedWrite();

      preserve([B, A]);

      expect(receipts()).toEqual(stored);
    });

    it("creates no receipt when there was none", () => {
      replace([A, B]);
      preserve([A, B]);
      expect(receipts()).toEqual([]);
    });

    it("never turns a P7 replace into new completion evidence", () => {
      replace([A, B]);
      preserve([A, B]);
      preserve([A, B]);
      expect(receipts()).toEqual([]);
    });
  });

  describe("with the policy and a changed live set", () => {
    beforeEach(() => {
      replace([A, B]);
      nativeReceipt(PAIRS_AB);
    });
    it.each([
      ["an added key", [A, B, { id: "c", v: 1 }]],
      ["a deleted key (a retained extra key in the store)", [A]],
      ["an updated value with the same count", [A, { id: "b", v: 2 }]],
      ["an updated unknown property", [A, { id: "b", v: 1, extra: true }]],
      ["an empty snapshot", []],
    ])("drops the receipt for %s", (_name, rows) => {
      expect(receipts()).toHaveLength(1);
      preserve(rows as Row[]);
      expect(receipts()).toEqual([]);
    });

    it("drops the receipt for an explicit delete of a live key", () => {
      store.replaceStream({
        instance: INSTANCE,
        stream: "profiles",
        method: METHOD,
        generation: 1,
        emittedAt: "2026-09-02T00:00:00.000Z",
        primaryKey: ["id"],
        completionPolicy: "preserve_if_unchanged",
        envelopes: [envelope(A), envelope(B, "delete")],
      });
      expect(receipts()).toEqual([]);
    });

    it("drops the receipt when a tombstoned key is revived", () => {
      preserve([A]);
      replace([A, B]);
      nativeReceipt(PAIRS_AB);
      preserve([A, B]);
      expect(receipts()).toHaveLength(1);
      preserve([A]);
      preserve([A, B]);
      expect(receipts()).toEqual([]);
    });
  });

  describe("an invalid prior receipt is never kept or blessed", () => {
    it.each([
      ["another live count", "live_count = 9"],
      ["a non-numeric write_seq", "write_seq = 'garbage'"],
      ["a fractional write_seq", "write_seq = 0.5"],
      ["a write_seq from the future", "write_seq = 999999"],
      ["an unparseable time", "source_collected_at = 'garbage'"],
      ["another method", "method = 'other'"],
      ["another generation", "generation = 4"],
    ])("drops a receipt with %s", (_name, set) => {
      replace([A, B], { sourceCollectedAt: T1 });
      db.exec(`UPDATE pdpp_stream_completion SET ${set}`);
      preserve([A, B]);
      expect(receipts()).toEqual([]);
    });

    it.each([
      ["another digest", `snapshot_sha256 = '${"0".repeat(64)}'`],
      ["a non-canonical time", "source_collected_at = '2026-09-10T06:30:00Z'"],
      ["a basis of another kind", "collection_time_basis = 'other'"],
      ["no basis", "collection_time_basis = NULL"],
    ])("drops a native receipt with %s", (_name, set) => {
      replace([A, B]);
      nativeReceipt(PAIRS_AB);
      db.exec(`UPDATE pdpp_stream_completion SET ${set}`);
      preserve([A, B]);
      expect(receipts()).toEqual([]);
    });
  });

  describe("refusals change nothing", () => {
    beforeEach(() => {
      replace([A, B]);
      nativeReceipt(PAIRS_AB);
    });
    it.each([
      ["a stale generation", { generation: 2 }, "binding_generation_mismatch"],
      ["another method", { method: "other" }, "instance_bound_to_other_method"],
    ])("rolls back on %s", (_name, extra, reason) => {
      const before = everything();
      expect(() => preserve([A, B], extra)).toThrow(
        expect.objectContaining({ reason }),
      );
      expect(everything()).toEqual(before);
    });

    it("keeps rows and receipt when a record is rejected", () => {
      const before = everything();
      const result = preserve([], {
        envelopes: [
          envelope(A),
          { ...envelope(B), key: ["x"] as never, data: null as never },
        ],
      });
      expect(result.applied).toBe(false);
      expect(everything()).toEqual(before);
    });

    it.each([
      [
        "a policy with an explicit time",
        { completionPolicy: "preserve_if_unchanged", sourceCollectedAt: T1 },
      ],
      ["an unknown policy", { completionPolicy: "keep" }],
      ["a non-string policy", { completionPolicy: 1 }],
      ["a null policy", { completionPolicy: null }],
    ])("refuses %s before any write", (_name, extra) => {
      const before = everything();
      expect(() =>
        store.replaceStream({
          instance: INSTANCE,
          stream: "profiles",
          method: METHOD,
          generation: 1,
          emittedAt: "x",
          envelopes: [],
          primaryKey: ["id"],
          ...(extra as object),
        }),
      ).toThrow(TypeError);
      expect(everything()).toEqual(before);
    });
  });

  describe("faults roll everything back", () => {
    beforeEach(() => {
      replace([A, B]);
      nativeReceipt(PAIRS_AB);
    });
    it("restores rows and receipt when the second row write fails", () => {
      db.exec(`
        CREATE TRIGGER fail_second BEFORE INSERT ON pdpp_record_changes
        WHEN NEW.record_key = 'c'
        BEGIN SELECT RAISE(ABORT, 'second row fault'); END;
      `);
      const before = everything();
      expect(() =>
        preserve([
          { id: "b", v: 9 },
          { id: "c", v: 1 },
        ]),
      ).toThrow("second row fault");
      expect(everything()).toEqual(before);
    });

    it("restores rows and receipt when the receipt delete fails", () => {
      db.exec(`
        CREATE TRIGGER fail_delete BEFORE DELETE ON pdpp_stream_completion
        BEGIN SELECT RAISE(ABORT, 'receipt delete fault'); END;
      `);
      const before = everything();
      expect(() => preserve([A, { id: "b", v: 2 }])).toThrow(
        "receipt delete fault",
      );
      expect(everything()).toEqual(before);
    });

    it("never touches the receipt of an unchanged replay, even if deleting it would fail", () => {
      db.exec(`
        CREATE TRIGGER fail_delete BEFORE DELETE ON pdpp_stream_completion
        BEGIN SELECT RAISE(ABORT, 'receipt delete fault'); END;
      `);
      const stored = receipts();
      preserve([A, B]);
      expect(receipts()).toEqual(stored);
    });
  });
});
