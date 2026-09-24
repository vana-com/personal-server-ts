import { describe, it, expect, beforeEach, afterEach } from "vitest";
import Database from "better-sqlite3";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
import type { PdppRecordStore } from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
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
  let store: PdppRecordStore;

  beforeEach(() => {
    db = new Database(":memory:");
    store = createSqliteRecordStore(db);
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
});
