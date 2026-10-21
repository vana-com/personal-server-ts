import { describe, it, expect, beforeEach, afterEach } from "vitest";
import Database from "better-sqlite3";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
import { createPdppSyncSessionService } from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { createTestBoundRecordStore } from "../__fixtures__/bound-record-store.js";
import {
  CursorExpiredError,
  encodeCursor,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import type { PdppRecordEnvelopeInput } from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";

function messagesSemantics() {
  return "append_only" as const;
}
function messagesPk() {
  return ["id"];
}
function playlistsSemantics() {
  return "mutable_state" as const;
}
function playlistsPk() {
  return ["id"];
}

describe("sqlite record store", () => {
  let db: InstanceType<typeof Database>;
  let store: ReturnType<typeof createSqliteRecordStore>;

  beforeEach(() => {
    db = new Database(":memory:");
    store = createTestBoundRecordStore(db);
  });

  afterEach(() => {
    store.close();
  });

  it("ingests and reads back a record", () => {
    const envelope: PdppRecordEnvelopeInput = {
      instance: "inst_1",
      stream: "messages",
      key: "msg_1",
      data: { id: "msg_1", content: "hi" },
      emitted_at: "2026-04-01T00:00:00.000Z",
    };
    const result = store.ingestBatch([envelope], messagesSemantics, messagesPk);
    expect(result.accepted).toBe(1);
    const record = store.getRecord("inst_1", "messages", "msg_1");
    expect(record?.data).toEqual({ id: "msg_1", content: "hi" });
  });

  it("serves the first historical list page without scanning each record's whole instance history", () => {
    for (let version = 1; version <= 2; version++) {
      const envelopes = Array.from({ length: 5000 }, (_, i) => ({
        instance: "inst_1",
        stream: "playlists",
        key: `r${i}`,
        data: { id: `r${i}`, value: version },
        emitted_at: `2026-04-0${version}T00:00:00.${String(i).padStart(6, "0")}Z`,
      }));
      expect(
        store.ingestBatch(envelopes, playlistsSemantics, playlistsPk).accepted,
      ).toBe(5000);
    }
    const started = performance.now();
    const page = store.listRecords("playlists", {
      instanceIds: ["inst_1"],
      limit: 100,
      order: "asc",
    });
    expect(page.data).toHaveLength(100);
    // A large margin above an indexed seek; the faulty correlated scan takes
    // seconds even for this small history, before a client can get page one.
    expect(performance.now() - started).toBeLessThan(1000);
  }, 30_000);

  it("uses a covering index for per-instance stream summaries", () => {
    // Plan the exact SELECT `listStreams` prepares, not a copy of it.
    const prepared: string[] = [];
    const prepare = db.prepare.bind(db);
    db.prepare = ((sql: string) => {
      prepared.push(sql);
      return prepare(sql);
    }) as typeof db.prepare;
    try {
      store.listStreams(["inst_1"]);
    } finally {
      db.prepare = prepare as typeof db.prepare;
    }
    const summary = prepared.find((sql) => /GROUP BY stream/.test(sql));
    expect(summary).toBeDefined();
    const plan = db
      .prepare(`EXPLAIN QUERY PLAN ${summary}`)
      .all("inst_1") as Array<{ detail: string }>;

    expect(plan.map((row) => row.detail).join("\n")).toMatch(
      /USING COVERING INDEX idx_pdpp_records_live_instance_stream_emitted_key/,
    );
  });

  it("test fixture forwards validateData with and without an explicit binding", () => {
    const rejectBad = (
      _stream: string,
      _instance: string,
      data: Record<string, unknown>,
    ) => (data.content === "bad" ? "content is bad" : null);
    const envelope = (instance: string, key: string, content: string) => ({
      instance,
      stream: "messages",
      key,
      data: { id: key, content },
      emitted_at: "2026-04-01T00:00:00.000Z",
    });
    const unbound = store.ingestBatch(
      [envelope("inst_1", "ok", "hi"), envelope("inst_1", "no", "bad")],
      messagesSemantics,
      messagesPk,
      undefined,
      rejectBad,
    );
    expect(unbound.results.map((r) => r.outcome)).toEqual([
      "accepted",
      "rejected",
    ]);
    const bound = store.ingestBatch(
      [envelope("inst_2", "no", "bad")],
      messagesSemantics,
      messagesPk,
      { method: "m", generation: 1 },
      rejectBad,
    );
    expect(bound.results.map((r) => r.outcome)).toEqual(["rejected"]);
    expect(store.getRecord("inst_1", "messages", "no")).toBeUndefined();
    expect(store.getRecord("inst_2", "messages", "no")).toBeUndefined();
  });

  describe("method-less ingest (the sync importer path)", () => {
    const base: PdppRecordEnvelopeInput = {
      instance: "inst_1",
      stream: "media",
      key: "media_1",
      data: { id: "media_1", blob_ref: { blob_id: "blob_missing" } },
      emitted_at: "2026-04-01T00:00:00.000Z",
    };
    const counts = () =>
      db
        .prepare(
          `SELECT (SELECT COUNT(*) FROM pdpp_records) AS records,
                  (SELECT COUNT(*) FROM pdpp_record_changes) AS changes,
                  (SELECT COUNT(*) FROM pdpp_instance_binding) AS bindings,
                  (SELECT value FROM pdpp_write_clock) AS clock`,
        )
        .get();

    it("is refused on an instance with no binding row, even with a nonexistent blob_ref", () => {
      const raw = createSqliteRecordStore(db);
      const before = counts();
      const result = raw.ingestBatch(
        [base],
        () => "append_only",
        () => ["id"],
      );
      expect(result.results).toEqual([
        { index: 0, outcome: "rejected", reason: "method_required" },
      ]);
      expect(counts()).toEqual(before);
      expect(raw.getRecord("inst_1", "media", "media_1")).toBeUndefined();
    });

    it("is refused on a bound instance and leaves its rows intact", () => {
      const raw = createSqliteRecordStore(db);
      raw.registerConnection({
        instance: "inst_1",
        sourceId: "https://test.invalid/method-a",
        method: "method_a",
        label: "Method A",
      });
      const own = { ...base, stream: "messages", key: "msg_1" };
      own.data = { id: "msg_1", content: "from method A" };
      expect(
        raw.ingestBatch([own], messagesSemantics, messagesPk, {
          method: "method_a",
          generation: 1,
        }).accepted,
      ).toBe(1);

      const rejected = raw.ingestBatch(
        [{ ...own, data: { id: "msg_1", content: "method-blind overwrite" } }],
        messagesSemantics,
        messagesPk,
      );
      expect(rejected.results).toEqual([
        { index: 0, outcome: "rejected", reason: "method_required" },
      ]);
      expect(raw.getRecord("inst_1", "messages", "msg_1")?.data).toEqual({
        id: "msg_1",
        content: "from method A",
      });
    });
  });

  it("refuses a replace without a method and writes nothing", () => {
    const raw = createSqliteRecordStore(db);
    const count = () =>
      db
        .prepare(
          `SELECT (SELECT COUNT(*) FROM pdpp_records) AS records,
                  (SELECT COUNT(*) FROM pdpp_instance_binding) AS bindings,
                  (SELECT value FROM pdpp_write_clock) AS clock`,
        )
        .get();
    const before = count();
    for (const method of ["", null as unknown as string]) {
      expect(() =>
        raw.replaceStream({
          instance: "inst_1",
          stream: "playlists",
          method,
          generation: 1,
          emittedAt: "2026-04-01T00:00:00.000Z",
          primaryKey: playlistsPk(),
          envelopes: [
            {
              instance: "inst_1",
              stream: "playlists",
              key: "p1",
              data: { id: "p1" },
              emitted_at: "2026-04-01T00:00:00.000Z",
            },
          ],
        }),
      ).toThrow("method_required");
    }
    expect(count()).toEqual(before);
    expect(raw.getInstanceBinding("inst_1").method).toBeNull();
  });

  it("reads a binding without creating a row", () => {
    const before = db
      .prepare("SELECT COUNT(*) AS n FROM pdpp_instance_binding")
      .get();
    expect(store.getInstanceBinding("inst_unseen")).toEqual({
      instance: "inst_unseen",
      sourceId: null,
      label: "",
      deletedAt: null,
      method: null,
      generation: 1,
      resetClock: 0,
      empty: true,
    });
    expect(
      db.prepare("SELECT COUNT(*) AS n FROM pdpp_instance_binding").get(),
    ).toEqual(before);
    expect(before).toEqual({ n: 0 });
  });

  it("allocates monotonic versions for mutable_state upserts", () => {
    const base: PdppRecordEnvelopeInput = {
      instance: "inst_1",
      stream: "playlists",
      key: "pl_1",
      data: { id: "pl_1", name: "v1" },
      emitted_at: "2026-04-01T00:00:00.000Z",
    };
    store.ingestBatch([base], playlistsSemantics, playlistsPk);
    store.ingestBatch(
      [
        {
          ...base,
          data: { id: "pl_1", name: "v2" },
          emitted_at: "2026-04-02T00:00:00.000Z",
        },
      ],
      playlistsSemantics,
      playlistsPk,
    );
    const record = store.getRecord("inst_1", "playlists", "pl_1");
    expect(record?.version).toBe(2);
  });

  it("is a no-op for a duplicate key on an append_only stream", () => {
    const envelope: PdppRecordEnvelopeInput = {
      instance: "inst_1",
      stream: "messages",
      key: "msg_1",
      data: { id: "msg_1", content: "hi" },
      emitted_at: "2026-04-01T00:00:00.000Z",
    };
    store.ingestBatch([envelope], messagesSemantics, messagesPk);
    const second = store.ingestBatch(
      [{ ...envelope, data: { id: "msg_1", content: "changed" } }],
      messagesSemantics,
      messagesPk,
    );
    expect(second.accepted).toBe(0);
    expect(store.getRecord("inst_1", "messages", "msg_1")?.data.content).toBe(
      "hi",
    );
  });

  it("does not leave partial version/record_changes state when one envelope in a batch is invalid", () => {
    const good: PdppRecordEnvelopeInput = {
      instance: "inst_1",
      stream: "messages",
      key: "msg_1",
      data: { id: "msg_1", content: "hi" },
      emitted_at: "2026-04-01T00:00:00.000Z",
    };
    const bad: PdppRecordEnvelopeInput = {
      instance: "inst_1",
      stream: "messages",
      key: "msg_2",
      data: { id: "different", content: "bad" },
      emitted_at: "2026-04-01T00:00:00.000Z",
    };
    const result = store.ingestBatch(
      [good, bad],
      messagesSemantics,
      messagesPk,
    );
    expect(result.accepted).toBe(1);
    expect(result.rejected).toHaveLength(1);
    expect(store.getRecord("inst_1", "messages", "msg_1")).toBeDefined();
    expect(store.getRecord("inst_1", "messages", "msg_2")).toBeUndefined();

    const changesCount = db
      .prepare("SELECT COUNT(*) as n FROM pdpp_record_changes")
      .get() as { n: number };
    expect(changesCount.n).toBe(1);
  });

  it("rolls back current rows and history when a history insert fails", () => {
    db.exec(`
      CREATE TRIGGER fail_second_history BEFORE INSERT ON pdpp_record_changes
      WHEN NEW.record_key = 'msg_2'
      BEGIN SELECT RAISE(ABORT, 'injected history failure'); END;
    `);
    const envelopes: PdppRecordEnvelopeInput[] = ["msg_1", "msg_2"].map(
      (id) => ({
        instance: "inst_1",
        stream: "messages",
        key: id,
        data: { id },
        emitted_at: "2026-04-01T00:00:00.000Z",
      }),
    );

    expect(() =>
      store.ingestBatch(envelopes, messagesSemantics, messagesPk),
    ).toThrow("injected history failure");
    expect(store.getRecord("inst_1", "messages", "msg_1")).toBeUndefined();
    expect(store.getRecord("inst_1", "messages", "msg_2")).toBeUndefined();
    expect(
      (
        db.prepare("SELECT COUNT(*) AS n FROM pdpp_record_changes").get() as {
          n: number;
        }
      ).n,
    ).toBe(0);
  });

  it("produces a spec-shaped tombstone on owner delete", () => {
    store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "playlists",
          key: "pl_1",
          data: { id: "pl_1", name: "v1" },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
      ],
      playlistsSemantics,
      playlistsPk,
    );
    const deleted = store.deleteRecord(
      "inst_1",
      "playlists",
      "pl_1",
      "2026-04-02T00:00:00.000Z",
      "mutable_state",
    );
    expect(deleted).toBe(true);
    expect(store.getRecord("inst_1", "playlists", "pl_1")).toBeUndefined();
  });

  it("rejects delete on an append_only stream", () => {
    store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "messages",
          key: "msg_1",
          data: { id: "msg_1" },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
      ],
      messagesSemantics,
      messagesPk,
    );
    expect(
      store.deleteRecord(
        "inst_1",
        "messages",
        "msg_1",
        "2026-04-02T00:00:00.000Z",
        "append_only",
      ),
    ).toBe(false);
  });

  it("paginates list records with a stable cursor and clamps by limit", () => {
    const envelopes: PdppRecordEnvelopeInput[] = Array.from(
      { length: 3 },
      (_, i) => ({
        instance: "inst_1",
        stream: "messages",
        key: `msg_${i}`,
        data: { id: `msg_${i}`, n: i },
        emitted_at: `2026-04-0${i + 1}T00:00:00.000Z`,
      }),
    );
    store.ingestBatch(envelopes, messagesSemantics, messagesPk);

    const page1 = store.listRecords("messages", {
      instanceIds: ["inst_1"],
      limit: 2,
      order: "asc",
    });
    expect(page1.data).toHaveLength(2);
    expect(page1.hasMore).toBe(true);

    const page2 = store.listRecords("messages", {
      instanceIds: ["inst_1"],
      limit: 2,
      order: "asc",
      cursor: page1.nextCursor,
    });
    expect(page2.data).toHaveLength(1);
    expect(page2.hasMore).toBe(false);
  });

  it("rejects a cursor reused against a different order", () => {
    store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "messages",
          key: "msg_1",
          data: { id: "msg_1" },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
        {
          instance: "inst_1",
          stream: "messages",
          key: "msg_2",
          data: { id: "msg_2" },
          emitted_at: "2026-04-02T00:00:00.000Z",
        },
      ],
      messagesSemantics,
      messagesPk,
    );
    const page1 = store.listRecords("messages", {
      instanceIds: ["inst_1"],
      limit: 1,
      order: "asc",
    });
    expect(() =>
      store.listRecords("messages", {
        instanceIds: ["inst_1"],
        limit: 1,
        order: "desc",
        cursor: page1.nextCursor,
      }),
    ).toThrow();
  });

  it("never exposes an unprojected field through fields projection", () => {
    store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "messages",
          key: "msg_1",
          data: { id: "msg_1", a: "visible", c: "secret" },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
      ],
      messagesSemantics,
      messagesPk,
    );
    const page = store.listRecords("messages", {
      instanceIds: ["inst_1"],
      limit: 10,
      order: "asc",
      fields: ["id", "a"],
    });
    expect(page.data[0].data).not.toHaveProperty("c");
  });

  it("does not leak writes made after page 1 into later pages of the same changes_since session", () => {
    store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "playlists",
          key: "pl_1",
          data: { id: "pl_1", name: "v1" },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
        {
          instance: "inst_1",
          stream: "playlists",
          key: "pl_2",
          data: { id: "pl_2", name: "v1" },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
      ],
      playlistsSemantics,
      playlistsPk,
    );

    const page1 = createPdppSyncSessionService(store).read({
      stream: "playlists",
      instanceIds: ["inst_1"],
      limit: 1,
    });
    expect(page1.hasMore).toBe(true);

    store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "playlists",
          key: "pl_3",
          data: { id: "pl_3", name: "brand new" },
          emitted_at: "2026-04-03T00:00:00.000Z",
        },
      ],
      playlistsSemantics,
      playlistsPk,
    );

    const page2 = createPdppSyncSessionService(store).read({
      stream: "playlists",
      instanceIds: ["inst_1"],
      limit: 10,
      cursor: page1.nextCursor,
    });
    expect(page2.data.map((r) => r.recordKey)).not.toContain("pl_3");
  });

  it("surfaces a tombstone for a deletion to a cursor predating it", () => {
    store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "playlists",
          key: "pl_1",
          data: { id: "pl_1", name: "v1" },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
      ],
      playlistsSemantics,
      playlistsPk,
    );
    const session1 = createPdppSyncSessionService(store).read({
      stream: "playlists",
      instanceIds: ["inst_1"],
      limit: 10,
    });
    store.deleteRecord(
      "inst_1",
      "playlists",
      "pl_1",
      "2026-04-02T00:00:00.000Z",
      "mutable_state",
    );
    const session2 = createPdppSyncSessionService(store).read({
      stream: "playlists",
      instanceIds: ["inst_1"],
      limit: 10,
      changesSince: session1.nextChangesSince,
    });
    expect(session2.data).toHaveLength(1);
    expect(session2.data[0].deleted).toBe(true);
  });

  it("does not surface a record whose only change is outside the field projection", () => {
    store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "playlists",
          key: "pl_1",
          data: { id: "pl_1", a: "1", c: "secret1" },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
      ],
      playlistsSemantics,
      playlistsPk,
    );
    const session1 = createPdppSyncSessionService(store).read({
      stream: "playlists",
      instanceIds: ["inst_1"],
      limit: 10,
      eligibilityFields: ["id", "a"],
    });
    store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "playlists",
          key: "pl_1",
          data: { id: "pl_1", a: "1", c: "secret2" },
          emitted_at: "2026-04-02T00:00:00.000Z",
        },
      ],
      playlistsSemantics,
      playlistsPk,
    );
    const session2 = createPdppSyncSessionService(store).read({
      stream: "playlists",
      instanceIds: ["inst_1"],
      limit: 10,
      eligibilityFields: ["id", "a"],
      changesSince: session1.nextChangesSince,
    });
    expect(session2.data).toHaveLength(0);
  });

  it("stores and retrieves blob metadata", () => {
    store.putBlobMeta({
      blobId: "blob_1",
      mimeType: "image/jpeg",
      sizeBytes: 1024,
      sha256: "abc",
    });
    const meta = store.getBlobMeta("blob_1");
    expect(meta).toEqual({
      blobId: "blob_1",
      mimeType: "image/jpeg",
      sizeBytes: 1024,
      sha256: "abc",
    });
  });

  it("lists streams with record counts", () => {
    store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "messages",
          key: "msg_1",
          data: { id: "msg_1" },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
        {
          instance: "inst_1",
          stream: "messages",
          key: "msg_2",
          data: { id: "msg_2" },
          emitted_at: "2026-04-02T00:00:00.000Z",
        },
      ],
      messagesSemantics,
      messagesPk,
    );
    const streams = store.listStreams(["inst_1"]);
    expect(streams).toEqual([
      {
        stream: "messages",
        recordCount: 2,
        lastUpdated: "2026-04-02T00:00:00.000Z",
      },
    ]);
  });

  describe("findBlobReferences", () => {
    it("finds the record that references a blob_id via data.blob_ref.blob_id", () => {
      store.putBlobMeta({
        blobId: "blob_x",
        mimeType: "image/png",
        sizeBytes: 1,
        sha256: "00",
      });
      store.ingestBatch(
        [
          {
            instance: "inst_1",
            stream: "media",
            key: "media_1",
            data: { id: "media_1", blob_ref: { blob_id: "blob_x" } },
            emitted_at: "2026-04-01T00:00:00.000Z",
          },
        ],
        () => "append_only",
        () => ["id"],
      );
      expect(store.findBlobReferences("blob_x")).toEqual([
        {
          instance: "inst_1",
          stream: "media",
          recordKey: "media_1",
        },
      ]);
    });

    it("returns an empty array when no record references the blob_id", () => {
      expect(store.findBlobReferences("blob_nonexistent")).toEqual([]);
    });

    it("does not find a reference from a deleted record", () => {
      store.putBlobMeta({
        blobId: "blob_x",
        mimeType: "image/png",
        sizeBytes: 1,
        sha256: "00",
      });
      store.ingestBatch(
        [
          {
            instance: "inst_1",
            stream: "media",
            key: "media_1",
            data: { id: "media_1", blob_ref: { blob_id: "blob_x" } },
            emitted_at: "2026-04-01T00:00:00.000Z",
          },
        ],
        () => "mutable_state",
        () => ["id"],
      );
      store.deleteRecord(
        "inst_1",
        "media",
        "media_1",
        "2026-04-02T00:00:00.000Z",
        "mutable_state",
      );
      expect(store.findBlobReferences("blob_x")).toEqual([]);
    });

    it("finds every non-deleted record that references the same blob_id", () => {
      store.putBlobMeta({
        blobId: "blob_shared",
        mimeType: "image/png",
        sizeBytes: 1,
        sha256: "00",
      });
      store.ingestBatch(
        [
          {
            instance: "inst_1",
            stream: "media",
            key: "media_1",
            data: { id: "media_1", blob_ref: { blob_id: "blob_shared" } },
            emitted_at: "2026-04-01T00:00:00.000Z",
          },
          {
            instance: "inst_2",
            stream: "media",
            key: "media_2",
            data: { id: "media_2", blob_ref: { blob_id: "blob_shared" } },
            emitted_at: "2026-04-01T00:00:01.000Z",
          },
        ],
        () => "append_only",
        () => ["id"],
      );
      const references = store.findBlobReferences("blob_shared");
      expect(references).toHaveLength(2);
      expect(references).toEqual(
        expect.arrayContaining([
          { instance: "inst_1", stream: "media", recordKey: "media_1" },
          { instance: "inst_2", stream: "media", recordKey: "media_2" },
        ]),
      );
    });
  });

  describe("arrival order (private to the legacy view)", () => {
    const at = "2026-04-01T00:00:00.000Z";
    const put = (
      stream: string,
      rows: (Record<string, unknown> | string)[],
      semantics: "append_only" | "mutable_state" = "mutable_state",
    ) =>
      store.ingestBatch(
        rows.map((row) =>
          typeof row === "string"
            ? {
                instance: "inst_1",
                stream,
                key: row,
                data: null,
                emitted_at: at,
                op: "delete" as const,
              }
            : {
                instance: "inst_1",
                stream,
                key: String(row.id),
                data: row,
                emitted_at: at,
              },
        ),
        () => semantics,
        () => ["id"],
      );
    const order = (stream: string) => store.listArrivalOrder("inst_1", stream);

    it("moves a truly unchanged append_only key but not a conflicting one", () => {
      put(
        "messages",
        [
          { id: "a", v: 1 },
          { id: "b", v: 1 },
        ],
        "append_only",
      );
      const conflict = put("messages", [{ id: "a", v: 2 }], "append_only");
      expect(conflict.results).toEqual([
        { index: 0, outcome: "unchanged", flag: "append_only_conflict" },
      ]);
      expect(order("messages")).toEqual(["a", "b"]);
      put("messages", [{ id: "a", v: 1 }], "append_only");
      expect(order("messages")).toEqual(["b", "a"]);
    });

    it("lists only live keys after deletes and a replace", () => {
      put("playlists", [{ id: "a" }, { id: "b" }, { id: "c" }, { id: "d" }]);
      put("playlists", ["a", "missing"]);
      store.deleteRecord("inst_1", "playlists", "b", at, "mutable_state");
      expect(order("playlists")).toEqual(["c", "d"]);

      store.replaceStream({
        instance: "inst_1",
        stream: "playlists",
        method: "test_method",
        generation: 1,
        emittedAt: at,
        primaryKey: ["id"],
        envelopes: [
          {
            instance: "inst_1",
            stream: "playlists",
            key: "e",
            data: { id: "e" },
            emitted_at: at,
          },
          {
            instance: "inst_1",
            stream: "playlists",
            key: "d",
            data: { id: "d" },
            emitted_at: at,
          },
        ],
      });
      expect(order("playlists")).toEqual(["e", "d"]);
      expect(
        store
          .listRecords("playlists", {
            instanceIds: ["inst_1"],
            limit: 10,
            order: "asc",
          })
          .data.map((row) => row.recordKey)
          .sort(),
      ).toEqual(["d", "e"]);
    });

    it("forgets the order on reset and on connection delete", () => {
      put("playlists", [{ id: "a" }, { id: "b" }]);
      store.resetInstanceBinding({
        instance: "inst_1",
        expectedMethod: "test_method",
        expectedGeneration: 1,
        nextMethod: "test_method",
      });
      expect(order("playlists")).toEqual([]);

      store.ingestBatch(
        [
          {
            instance: "inst_1",
            stream: "playlists",
            key: "c",
            data: { id: "c" },
            emitted_at: at,
          },
        ],
        playlistsSemantics,
        playlistsPk,
        { method: "test_method", generation: 2 },
      );
      expect(order("playlists")).toEqual(["c"]);
      store.deleteConnection("inst_1");
      expect(order("playlists")).toEqual([]);
      expect(
        db.prepare("SELECT COUNT(*) AS n FROM pdpp_record_arrival").get(),
      ).toEqual({ n: 0 });
    });
  });

  describe("schema migration", () => {
    it("upgrades a raw v10 records database with rows and arrival order", async () => {
      const dir = await mkdtemp(join(tmpdir(), "pdpp-records-v10-"));
      const path = join(dir, "records.db");
      let historical: Database.Database | undefined;
      let upgraded: ReturnType<typeof createSqliteRecordStore> | undefined;
      try {
        historical = new Database(path);
        historical.exec(`
          CREATE TABLE pdpp_records (
            instance TEXT NOT NULL, stream TEXT NOT NULL, record_key TEXT NOT NULL,
            data TEXT, version INTEGER NOT NULL, emitted_at TEXT NOT NULL,
            deleted INTEGER NOT NULL DEFAULT 0, deleted_at TEXT, blob_id TEXT,
            PRIMARY KEY (instance, stream, record_key)
          );
          CREATE TABLE pdpp_record_changes (
            id INTEGER PRIMARY KEY AUTOINCREMENT, instance TEXT NOT NULL,
            stream TEXT NOT NULL, record_key TEXT NOT NULL, version INTEGER NOT NULL,
            data TEXT, emitted_at TEXT NOT NULL, deleted INTEGER NOT NULL DEFAULT 0,
            deleted_at TEXT, written_at INTEGER NOT NULL
          );
          CREATE TABLE pdpp_blobs (
            blob_id TEXT PRIMARY KEY, mime_type TEXT NOT NULL,
            size_bytes INTEGER NOT NULL, sha256 TEXT NOT NULL
          );
          CREATE TABLE pdpp_blob_bytes (blob_id TEXT PRIMARY KEY, bytes BLOB NOT NULL);
          CREATE TABLE pdpp_write_clock (id INTEGER PRIMARY KEY CHECK (id = 1), value INTEGER NOT NULL);
          CREATE TABLE pdpp_instance_binding (
            instance TEXT PRIMARY KEY, method TEXT, generation INTEGER NOT NULL,
            reset_clock INTEGER NOT NULL DEFAULT 0, source_id TEXT,
            label TEXT NOT NULL DEFAULT '', deleted_at TEXT
          );
          CREATE TABLE pdpp_blob_claims (
            blob_id TEXT NOT NULL, instance TEXT NOT NULL, generation INTEGER NOT NULL,
            PRIMARY KEY (blob_id, instance)
          );
          CREATE TABLE pdpp_store_metadata (id INTEGER PRIMARY KEY CHECK (id = 1), epoch TEXT NOT NULL);
          CREATE TABLE pdpp_stream_completion (
            instance TEXT NOT NULL, stream TEXT NOT NULL, method TEXT NOT NULL,
            generation INTEGER NOT NULL, source_collected_at TEXT NOT NULL,
            write_seq INTEGER NOT NULL, live_count INTEGER NOT NULL,
            PRIMARY KEY (instance, stream)
          );
          CREATE TABLE pdpp_record_arrival (
            instance TEXT NOT NULL, stream TEXT NOT NULL, record_key TEXT NOT NULL,
            generation INTEGER NOT NULL, arrival INTEGER NOT NULL,
            PRIMARY KEY (instance, stream, record_key)
          );
          CREATE TABLE pdpp_schema_version (
            id INTEGER PRIMARY KEY CHECK (id = 1), version INTEGER NOT NULL
          );
          INSERT INTO pdpp_schema_version VALUES (1, 10);
          INSERT INTO pdpp_write_clock VALUES (1, 4);
          INSERT INTO pdpp_instance_binding VALUES ('owner', 'messages', 1, 0, 'source', '', NULL);
          INSERT INTO pdpp_store_metadata VALUES (1, 'historical-epoch');
          INSERT INTO pdpp_records VALUES
            ('owner', 'messages', 'a', '{"id":"a","text":"A"}', 1, '2026-01-01T00:00:00Z', 0, NULL, NULL),
            ('owner', 'messages', 'b', '{"id":"b","text":"B"}', 1, '2026-01-01T00:00:00Z', 0, NULL, NULL);
          INSERT INTO pdpp_record_changes
            (instance, stream, record_key, version, data, emitted_at, written_at)
          VALUES
            ('owner', 'messages', 'a', 1, '{"id":"a","text":"A"}', '2026-01-01T00:00:00Z', 1),
            ('owner', 'messages', 'b', 1, '{"id":"b","text":"B"}', '2026-01-01T00:00:00Z', 2);
          INSERT INTO pdpp_record_arrival VALUES
            ('owner', 'messages', 'a', 1, 1), ('owner', 'messages', 'b', 1, 2);
        `);
        historical.close();
        historical = undefined;

        const dbAfterUpgrade = new Database(path);
        upgraded = createSqliteRecordStore(dbAfterUpgrade);
        expect(
          dbAfterUpgrade
            .prepare("SELECT version FROM pdpp_schema_version WHERE id = 1")
            .get(),
        ).toEqual({ version: 15 });
        // v14 gives the upgraded store a 32-byte sync token key.
        expect(upgraded.syncTokenScope().key).toHaveLength(32);
        expect(
          dbAfterUpgrade
            .prepare("SELECT value FROM pdpp_record_arrival_clock WHERE id = 1")
            .get(),
        ).toEqual({ value: 0 });
        expect(upgraded.getRecord("owner", "messages", "a")?.data).toEqual({
          id: "a",
          text: "A",
        });
        expect(upgraded.getRecord("owner", "messages", "b")?.data).toEqual({
          id: "b",
          text: "B",
        });
        expect(upgraded.listArrivalOrder("owner", "messages")).toEqual([
          "a",
          "b",
        ]);

        const before = dbAfterUpgrade
          .prepare("SELECT value FROM pdpp_write_clock WHERE id = 1")
          .get();
        const redelivery = upgraded.ingestBatch(
          [
            {
              instance: "owner",
              stream: "messages",
              key: "a",
              data: { id: "a", text: "A" },
              emitted_at: "2026-01-01T00:00:00Z",
            },
          ],
          () => "mutable_state",
          () => ["id"],
          { method: "messages", generation: 1 },
        );
        expect(redelivery.unchanged).toBe(1);
        expect(upgraded.listArrivalOrder("owner", "messages")).toEqual([
          "b",
          "a",
        ]);
        expect(
          dbAfterUpgrade
            .prepare("SELECT value FROM pdpp_record_arrival_clock WHERE id = 1")
            .get(),
        ).toEqual({ value: 1 });
        expect(
          dbAfterUpgrade
            .prepare("SELECT value FROM pdpp_write_clock WHERE id = 1")
            .get(),
        ).toEqual(before);
        expect(upgraded.getRecord("owner", "messages", "a")?.version).toBe(1);
      } finally {
        upgraded?.close();
        historical?.close();
        await rm(dir, { recursive: true, force: true });
      }
    });

    it("tracks a schema version and does not re-run migrations on reopen", () => {
      store.putBlobMeta({
        blobId: "blob_y",
        mimeType: "image/png",
        sizeBytes: 1,
        sha256: "00",
      });
      store.ingestBatch(
        [
          {
            instance: "inst_1",
            stream: "media",
            key: "media_1",
            data: { id: "media_1", blob_ref: { blob_id: "blob_y" } },
            emitted_at: "2026-04-01T00:00:00.000Z",
          },
        ],
        () => "append_only",
        () => ["id"],
      );
      // Reopening the same underlying db (without closing/recreating) must
      // not error or duplicate schema objects -- migrate() is idempotent.
      const reopened = createSqliteRecordStore(db);
      expect(reopened.findBlobReferences("blob_y")).toEqual([
        {
          instance: "inst_1",
          stream: "media",
          recordKey: "media_1",
        },
      ]);
      const version = db
        .prepare("SELECT version FROM pdpp_schema_version WHERE id = 1")
        .get() as { version: number };
      expect(version.version).toBeGreaterThan(0);
    });

    it("creates the v10 stream-summary index when upgrading a v9 database without it", () => {
      db.exec("DROP INDEX idx_pdpp_records_live_instance_stream_emitted_at");
      db.prepare(
        "UPDATE pdpp_schema_version SET version = 9 WHERE id = 1",
      ).run();

      const before = db
        .prepare(
          "SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = ?",
        )
        .get("idx_pdpp_records_live_instance_stream_emitted_at");
      expect(before).toBeUndefined();

      const upgraded = createSqliteRecordStore(db);
      const after = db
        .prepare(
          "SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = ?",
        )
        .get("idx_pdpp_records_live_instance_stream_emitted_at");
      const version = db
        .prepare("SELECT version FROM pdpp_schema_version WHERE id = 1")
        .get() as { version: number };

      expect(after).toBeDefined();
      expect(version.version).toBeGreaterThanOrEqual(10);
      upgraded.close();
    });

    it("persists the store epoch across reopen", () => {
      const first = db
        .prepare("SELECT epoch FROM pdpp_store_metadata WHERE id = 1")
        .get() as { epoch: string };
      expect(first.epoch).toBeTruthy();

      createSqliteRecordStore(db);
      const second = db
        .prepare("SELECT epoch FROM pdpp_store_metadata WHERE id = 1")
        .get() as { epoch: string };
      expect(second.epoch).toBe(first.epoch);
    });

    it("refuses to open a database with a newer schema version than this build supports", () => {
      db.prepare(
        "UPDATE pdpp_schema_version SET version = 9999 WHERE id = 1",
      ).run();
      expect(() => createSqliteRecordStore(db)).toThrow(
        /newer than this build supports/,
      );
    });
  });

  describe("reset fence (P8b, P8c, P10c)", () => {
    const A = { method: "method_a", generation: 1 };
    const bytes = (text: string) => new TextEncoder().encode(text);
    const envelope = (
      instance: string,
      key: string,
      emittedAt: string,
      extra: Record<string, unknown> = {},
    ): PdppRecordEnvelopeInput => ({
      instance,
      stream: "messages",
      key,
      data: { id: key, ...extra },
      emitted_at: emittedAt,
    });
    const count = (sql: string, ...params: unknown[]) =>
      (db.prepare(sql).get(...params) as { n: number }).n;
    const snapshot = () => ({
      records: count("SELECT COUNT(*) AS n FROM pdpp_records"),
      changes: count("SELECT COUNT(*) AS n FROM pdpp_record_changes"),
      blobs: count("SELECT COUNT(*) AS n FROM pdpp_blobs"),
      bytes: count("SELECT COUNT(*) AS n FROM pdpp_blob_bytes"),
      claims: count("SELECT COUNT(*) AS n FROM pdpp_blob_claims"),
      clock: count("SELECT value AS n FROM pdpp_write_clock WHERE id = 1"),
      binding: db
        .prepare("SELECT * FROM pdpp_instance_binding ORDER BY instance")
        .all(),
    });
    const seedA = () => {
      store.registerConnection({
        instance: "inst_a",
        sourceId: "https://test.invalid/method-a",
        method: A.method,
        label: "Method A",
      });
      const blob = store.storeBlobBytesForInstance({
        instance: "inst_a",
        ...A,
        bytes: bytes("A image"),
        mimeType: "image/png",
      });
      const result = store.ingestBatch(
        [
          envelope("inst_a", "a1", "2026-04-01T00:00:00.000Z", {
            blob_ref: { blob_id: blob.blobId },
          }),
          envelope("inst_a", "a2", "2026-04-02T00:00:00.000Z"),
        ],
        messagesSemantics,
        messagesPk,
        A,
      );
      expect(result.accepted).toBe(2);
      return blob;
    };
    const resetToB = (instance = "inst_a") =>
      store.resetInstanceBinding({
        instance,
        expectedMethod: "method_a",
        expectedGeneration: 1,
        nextMethod: "method_a",
      });

    it("rolls back every reset step when the transaction faults at its last write", () => {
      seedA();
      const before = snapshot();
      // The binding update is the reset's final statement, so the deletes
      // and the clock tick have already run when it aborts.
      db.exec(`CREATE TRIGGER fault_reset BEFORE UPDATE ON pdpp_instance_binding
        BEGIN SELECT RAISE(ABORT, 'injected reset fault'); END`);
      expect(() => resetToB()).toThrow("injected reset fault");
      expect(snapshot()).toEqual(before);
      db.exec("DROP TRIGGER fault_reset");
      expect(resetToB().binding).toMatchObject({
        method: "method_a",
        generation: 2,
      });
      expect(snapshot()).toMatchObject({
        records: 0,
        changes: 0,
        blobs: 0,
        bytes: 0,
        claims: 0,
      });
    });

    it("rolls back blob bytes and metadata when the upload claim write faults", () => {
      store.registerConnection({
        instance: "inst_a",
        sourceId: "https://test.invalid/method-a",
        method: A.method,
        label: "Method A",
      });
      const before = snapshot();
      db.exec(`CREATE TRIGGER fault_claim BEFORE INSERT ON pdpp_blob_claims
        BEGIN SELECT RAISE(ABORT, 'injected claim fault'); END`);
      expect(() =>
        store.storeBlobBytesForInstance({
          instance: "inst_a",
          ...A,
          bytes: bytes("never stored"),
          mimeType: "image/png",
        }),
      ).toThrow("injected claim fault");
      expect(snapshot()).toEqual(before);
    });

    it("expires a pre-reset list cursor instead of continuing with B rows", () => {
      seedA();
      const page1 = store.listRecords("messages", {
        instanceIds: ["inst_a"],
        limit: 1,
        order: "asc",
      });
      expect(page1.data.map((r) => r.recordKey)).toEqual(["a1"]);
      expect(page1.nextCursor).toBeDefined();
      resetToB();
      store.ingestBatch(
        [envelope("inst_a", "b1", "2026-04-03T00:00:00.000Z")],
        messagesSemantics,
        messagesPk,
        { method: "method_a", generation: 2 },
      );
      expect(() =>
        store.listRecords("messages", {
          instanceIds: ["inst_a"],
          limit: 1,
          order: "asc",
          cursor: page1.nextCursor,
        }),
      ).toThrow(CursorExpiredError);
      // A fresh listing after the reset pages normally.
      const fresh = store.listRecords("messages", {
        instanceIds: ["inst_a"],
        limit: 1,
        order: "asc",
      });
      expect(fresh.data.map((r) => r.recordKey)).toEqual(["b1"]);
    });

    it("keeps list snapshots valid across writes and unrelated instance resets", () => {
      seedA();
      store.registerConnection({
        instance: "inst_c",
        sourceId: "https://test.invalid/method-a",
        method: A.method,
        label: "Method A",
      });
      store.ingestBatch(
        [
          envelope("inst_c", "c1", "2026-04-01T00:00:00.000Z"),
          envelope("inst_c", "c2", "2026-04-02T00:00:00.000Z"),
        ],
        messagesSemantics,
        messagesPk,
        A,
      );
      const page1 = store.listRecords("messages", {
        instanceIds: ["inst_c"],
        limit: 1,
        order: "asc",
      });
      resetToB();
      store.ingestBatch(
        [envelope("inst_c", "c3", "2026-04-03T00:00:00.000Z")],
        messagesSemantics,
        messagesPk,
        A,
      );
      const page2 = store.listRecords("messages", {
        instanceIds: ["inst_c"],
        limit: 5,
        order: "asc",
        cursor: page1.nextCursor,
      });
      expect(page2.data.map((r) => r.recordKey)).toEqual(["c2"]);
    });

    it("rejects a minted list cursor reused against a different stream", () => {
      seedA();
      store.ingestBatch(
        [
          {
            instance: "inst_a",
            stream: "playlists",
            key: "pl_1",
            data: { id: "pl_1" },
            emitted_at: "2026-04-03T00:00:00.000Z",
          },
        ],
        playlistsSemantics,
        playlistsPk,
        A,
      );
      const page1 = store.listRecords("messages", {
        instanceIds: ["inst_a"],
        limit: 1,
        order: "asc",
      });
      expect(page1.nextCursor).toBeDefined();

      expect(() =>
        store.listRecords("playlists", {
          instanceIds: ["inst_a"],
          limit: 1,
          order: "asc",
          cursor: page1.nextCursor,
        }),
      ).toThrow(CursorExpiredError);
    });

    it("expires a pre-reset changes_since page cursor", () => {
      seedA();
      const page1 = createPdppSyncSessionService(store).read({
        stream: "messages",
        instanceIds: ["inst_a"],
        limit: 1,
      });
      expect(page1.nextCursor).toBeDefined();
      resetToB();
      expect(() =>
        createPdppSyncSessionService(store).read({
          stream: "messages",
          instanceIds: ["inst_a"],
          limit: 1,
          cursor: page1.nextCursor,
        }),
      ).toThrow(CursorExpiredError);
    });

    it("expires a changes_since token from an earlier reset epoch", () => {
      seedA();
      const session1 = createPdppSyncSessionService(store).read({
        stream: "messages",
        instanceIds: ["inst_a"],
        limit: 10,
      });
      expect(session1.nextChangesSince).toBeDefined();
      resetToB();

      expect(() =>
        createPdppSyncSessionService(store).read({
          stream: "messages",
          instanceIds: ["inst_a"],
          limit: 10,
          changesSince: session1.nextChangesSince,
        }),
      ).toThrow(CursorExpiredError);
    });

    it("rejects a changes_since token reused against a different stream", () => {
      seedA();
      const session1 = createPdppSyncSessionService(store).read({
        stream: "messages",
        instanceIds: ["inst_a"],
        limit: 10,
      });
      expect(session1.nextChangesSince).toBeDefined();

      expect(() =>
        createPdppSyncSessionService(store).read({
          stream: "playlists",
          instanceIds: ["inst_a"],
          limit: 10,
          changesSince: session1.nextChangesSince,
        }),
      ).toThrow(CursorExpiredError);
    });

    it("expires legacy list and changes_since tokens without store binding", () => {
      seedA();
      const legacyList = encodeCursor({
        kind: "list",
        order: "asc",
        sortValue: "2026-04-01T00:00:00.000Z",
        recordKey: "a1",
        horizon: "0",
      });
      expect(() =>
        store.listRecords("messages", {
          instanceIds: ["inst_a"],
          limit: 5,
          order: "asc",
          cursor: legacyList,
        }),
      ).toThrow(CursorExpiredError);

      const legacyChanges = encodeCursor({
        kind: "changes_since",
        horizon: "0",
        sinceHorizon: null,
        offset: 0,
      });
      expect(() =>
        createPdppSyncSessionService(store).read({
          stream: "messages",
          instanceIds: ["inst_a"],
          limit: 10,
          changesSince: legacyChanges,
        }),
      ).toThrow(CursorExpiredError);
    });

    it("expires a legacy list cursor without a horizon", () => {
      seedA();
      const legacy = encodeCursor({
        kind: "list",
        order: "asc",
        sortValue: "2026-04-01T00:00:00.000Z",
        recordKey: "a1",
      });
      expect(() =>
        store.listRecords("messages", {
          instanceIds: ["inst_a"],
          limit: 5,
          order: "asc",
          cursor: legacy,
        }),
      ).toThrow(CursorExpiredError);
    });

    it("keeps a blob shared with another instance through one reset", () => {
      const blob = seedA();
      store.registerConnection({
        instance: "inst_c",
        sourceId: "https://test.invalid/method-a",
        method: A.method,
        label: "Method A",
      });
      const shared = store.storeBlobBytesForInstance({
        instance: "inst_c",
        ...A,
        bytes: bytes("A image"),
        mimeType: "image/png",
      });
      expect(shared.blobId).toBe(blob.blobId);
      store.ingestBatch(
        [
          envelope("inst_c", "c1", "2026-04-01T00:00:00.000Z", {
            blob_ref: { blob_id: blob.blobId },
          }),
        ],
        messagesSemantics,
        messagesPk,
        A,
      );
      resetToB();
      expect(store.getBlobBytes(blob.blobId)).toEqual(bytes("A image"));
      resetToB("inst_c");
      expect(store.getBlobBytes(blob.blobId)).toBeUndefined();
      expect(store.getBlobMeta(blob.blobId)).toBeUndefined();
    });
  });
});

describe("v13 emitted-time order key", () => {
  it("backfills the key on upgrade so existing rows list and summarize by instant", async () => {
    const dir = await mkdtemp(join(tmpdir(), "pdpp-v13-"));
    const path = join(dir, "records.db");
    try {
      const before = new Database(path);
      const store = createTestBoundRecordStore(before);
      store.ingestBatch(
        [
          ["late", "2026-01-01T09:00:00Z"],
          ["early", "2026-01-01T10:00:00+02:00"],
        ].map(([key, emitted_at]) => ({
          instance: "inst_1",
          stream: "events",
          key: key!,
          data: { id: key },
          emitted_at: emitted_at!,
        })),
        () => "mutable_state",
        () => ["id"],
      );
      // Rewind to a v12 database: no key on any row.
      before.exec(`
        UPDATE pdpp_records SET emitted_key = NULL;
        UPDATE pdpp_record_changes SET emitted_key = NULL;
        UPDATE pdpp_schema_version SET version = 12;
      `);
      before.close();

      const after = new Database(path);
      try {
        const upgraded = createSqliteRecordStore(after);
        expect(
          after.prepare("SELECT version FROM pdpp_schema_version").get(),
        ).toEqual({ version: 15 });
        expect(
          upgraded
            .listRecords("events", {
              instanceIds: ["inst_1"],
              limit: 10,
              order: "asc",
            })
            .data.map((r) => r.recordKey),
        ).toEqual(["early", "late"]);
        // The latest emitted time is the latest instant, in its stored spelling.
        expect(upgraded.listStreams(["inst_1"])).toEqual([
          {
            stream: "events",
            recordCount: 2,
            lastUpdated: "2026-01-01T09:00:00Z",
          },
        ]);
      } finally {
        after.close();
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("v14 upgrade from an earlier v13", () => {
  it("rebuilds the live summary index as covering when an earlier v13 left it narrow", async () => {
    const dir = await mkdtemp(join(tmpdir(), "pdpp-v14-"));
    const path = join(dir, "records.db");
    try {
      const before = new Database(path);
      createTestBoundRecordStore(before);
      // An earlier v13 (this branch before its rebase, or #441's first v13)
      // built the summary index without `emitted_at`, and had no token key.
      before.exec(`
        DROP INDEX idx_pdpp_records_live_instance_stream_emitted_key;
        CREATE INDEX idx_pdpp_records_live_instance_stream_emitted_key
          ON pdpp_records (instance, stream, emitted_key) WHERE deleted = 0;
        UPDATE pdpp_store_metadata SET sync_token_key = NULL;
        UPDATE pdpp_schema_version SET version = 13;
      `);
      before.close();

      const after = new Database(path);
      try {
        const upgraded = createSqliteRecordStore(after);
        expect(upgraded.syncTokenScope().key).toHaveLength(32);
        const columns = (
          after
            .prepare(
              "PRAGMA index_info(idx_pdpp_records_live_instance_stream_emitted_key)",
            )
            .all() as { name: string }[]
        ).map((c) => c.name);
        expect(columns).toEqual([
          "instance",
          "stream",
          "emitted_key",
          "emitted_at",
        ]);
      } finally {
        after.close();
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("v15 sync session state table", () => {
  it("adds the table to a database an earlier build already stamped v14", async () => {
    const dir = await mkdtemp(join(tmpdir(), "pdpp-v15-"));
    const path = join(dir, "records.db");
    try {
      const before = new Database(path);
      createTestBoundRecordStore(before);
      // An earlier v14 had no session-state table.
      before.exec(`
        DROP TABLE IF EXISTS pdpp_sync_state;
        UPDATE pdpp_schema_version SET version = 14;
      `);
      before.close();

      const after = new Database(path);
      try {
        const upgraded = createSqliteRecordStore(after);
        expect(
          after.prepare("SELECT version FROM pdpp_schema_version").get(),
        ).toEqual({ version: 15 });
        upgraded.syncStates().put({
          id: "x",
          owner: "o",
          state: "{}",
          expiresAt: 2,
          now: 1,
          maxPerOwner: 1,
        });
        expect(upgraded.syncStates().get("x", 1)).toBe("{}");
      } finally {
        after.close();
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
