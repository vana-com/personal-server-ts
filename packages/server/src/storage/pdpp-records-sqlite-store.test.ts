import { describe, it, expect, beforeEach, afterEach } from "vitest";
import Database from "better-sqlite3";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
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

  it("reads a binding without creating a row", () => {
    const before = db
      .prepare("SELECT COUNT(*) AS n FROM pdpp_instance_binding")
      .get();
    expect(store.getInstanceBinding("inst_unseen")).toEqual({
      instance: "inst_unseen",
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

    const page1 = store.changesSince("playlists", {
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

    const page2 = store.changesSince("playlists", {
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
    const session1 = store.changesSince("playlists", {
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
    const session2 = store.changesSince("playlists", {
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
    const session1 = store.changesSince("playlists", {
      instanceIds: ["inst_1"],
      limit: 10,
      fields: ["id", "a"],
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
    const session2 = store.changesSince("playlists", {
      instanceIds: ["inst_1"],
      limit: 10,
      fields: ["id", "a"],
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

  describe("schema migration", () => {
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
      store.getInstanceBinding("inst_a");
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
        nextMethod: "method_b",
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
        method: "method_b",
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
      store.getInstanceBinding("inst_a");
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
        { method: "method_b", generation: 2 },
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

    it("keeps list cursors valid across writes and resets of instances they do not read", () => {
      seedA();
      store.getInstanceBinding("inst_c");
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
      expect(page2.data.map((r) => r.recordKey)).toEqual(["c2", "c3"]);
    });

    it("expires a pre-reset changes_since page cursor", () => {
      seedA();
      const page1 = store.changesSince("messages", {
        instanceIds: ["inst_a"],
        limit: 1,
      });
      expect(page1.nextCursor).toBeDefined();
      resetToB();
      expect(() =>
        store.changesSince("messages", {
          instanceIds: ["inst_a"],
          limit: 1,
          cursor: page1.nextCursor,
        }),
      ).toThrow(CursorExpiredError);
    });

    it("expires a legacy list cursor without a horizon only if a read instance was reset", () => {
      seedA();
      const legacy = encodeCursor({
        kind: "list",
        order: "asc",
        sortValue: "2026-04-01T00:00:00.000Z",
        recordKey: "a1",
      });
      const before = store.listRecords("messages", {
        instanceIds: ["inst_a"],
        limit: 5,
        order: "asc",
        cursor: legacy,
      });
      expect(before.data.map((r) => r.recordKey)).toEqual(["a2"]);
      resetToB();
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
      store.getInstanceBinding("inst_c");
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
