import { afterEach, beforeEach, describe, expect, it } from "vitest";
import Database from "better-sqlite3";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createReplicaRecordStore } from "./pdpp-replica-canonical-port.js";

const emittedAt = "2026-10-20T10:00:00.000Z";
const binding = { method: "collector", generation: 1 };
const envelope = (instance = "account-a", content = "hello") => ({
  instance,
  stream: "messages",
  key: "same-key",
  data: { id: "same-key", content },
  emitted_at: emittedAt,
});
const semantics = () => "mutable_state" as const;
const primaryKey = () => ["id"];

/** The own-write log of a replication-enabled store, oldest first. */
function ownWrites(db: Database.Database) {
  return (
    db
      .prepare("SELECT * FROM pdpp_replica_own_writes ORDER BY sequence")
      .all() as {
      sequence: number;
      operation_id: string;
      writer_id: string;
      source_id: string | null;
      connection_id: string;
      method: string | null;
      generation: number | null;
      stream: string;
      record_key: string;
      operation: "upsert" | "delete";
      value_json: string;
      blob_ids_json: string;
    }[]
  ).map((row) => ({
    sequence: row.sequence,
    operationId: row.operation_id,
    writerId: row.writer_id,
    sourceId: row.source_id,
    connectionId: row.connection_id,
    method: row.method,
    generation: row.generation,
    stream: row.stream,
    recordKey: row.record_key,
    operation: row.operation,
    value: JSON.parse(row.value_json),
    blobIds: JSON.parse(row.blob_ids_json) as string[],
  }));
}

describe("own-write log (replication enabled)", () => {
  let db: Database.Database;
  let store: ReturnType<typeof createReplicaRecordStore>;
  beforeEach(() => {
    db = new Database(":memory:");
    store = createReplicaRecordStore(db);
    store.registerConnection({
      instance: "account-a",
      sourceId: "https://source.invalid/declaration",
      method: binding.method,
      label: "Account A",
    });
  });
  afterEach(() => {
    if (db.open) store.close();
  });

  it("captures the full accepted value with authoritative binding and stable identity", () => {
    expect(
      store.ingestBatch([envelope()], semantics, primaryKey, binding).accepted,
    ).toBe(1);
    expect(ownWrites(db)).toEqual([
      {
        sequence: 1,
        operationId: expect.any(String),
        writerId: store.getInstallationWriterId(),
        sourceId: "https://source.invalid/declaration",
        connectionId: "account-a",
        method: "collector",
        generation: 1,
        stream: "messages",
        recordKey: "same-key",
        operation: "upsert",
        value: {
          instance: "account-a",
          stream: "messages",
          recordKey: "same-key",
          version: 1,
          emittedAt,
          deleted: false,
          data: { id: "same-key", content: "hello" },
        },
        blobIds: [],
      },
    ]);
  });

  it("suppresses duplicates, append-only conflicts, schema rejects, and unclaimed blobs", () => {
    const first = envelope();
    store.ingestBatch([first], () => "append_only", primaryKey, binding);
    const before = ownWrites(db);
    expect(
      store.ingestBatch([first], () => "append_only", primaryKey, binding)
        .unchanged,
    ).toBe(1);
    expect(
      store.ingestBatch(
        [envelope("account-a", "different")],
        () => "append_only",
        primaryKey,
        binding,
      ).results[0],
    ).toMatchObject({ flag: "append_only_conflict" });
    expect(
      store.ingestBatch(
        [{ ...first, key: "bad", data: { id: "bad" } }],
        semantics,
        primaryKey,
        binding,
        () => "invalid schema",
      ).rejected,
    ).toHaveLength(1);
    expect(
      store.ingestBatch(
        [
          {
            ...first,
            key: "blob",
            data: { id: "blob", blob_ref: { blob_id: "missing" } },
          },
        ],
        semantics,
        primaryKey,
        binding,
      ).rejected,
    ).toHaveLength(1);
    expect(
      store.ingestBatch([first], semantics, primaryKey).rejected[0].reason,
    ).toBe("method_required");
    expect(ownWrites(db)).toEqual(before);
  });

  it("keeps identical canonical keys distinct across connections and retains old full values", () => {
    store.registerConnection({
      instance: "account-b",
      sourceId: "https://source.invalid/declaration",
      method: binding.method,
      label: "B",
    });
    store.ingestBatch([envelope()], semantics, primaryKey, binding);
    store.ingestBatch([envelope("account-b")], semantics, primaryKey, binding);
    store.ingestBatch(
      [envelope("account-a", "new value")],
      semantics,
      primaryKey,
      binding,
    );
    const mutations = ownWrites(db);
    expect(new Set(mutations.map((m) => m.operationId)).size).toBe(3);
    expect(
      mutations.map((m) => [
        m.connectionId,
        m.sourceId,
        m.recordKey,
        m.value.version,
      ]),
    ).toEqual([
      ["account-a", "https://source.invalid/declaration", "same-key", 1],
      ["account-b", "https://source.invalid/declaration", "same-key", 1],
      ["account-a", "https://source.invalid/declaration", "same-key", 2],
    ]);
    expect(
      mutations.map((m) => (m.value.deleted ? null : m.value.data.content)),
    ).toEqual(["hello", "hello", "new value"]);
  });

  it.each(["pdpp_replica_own_writes", "pdpp_record_changes"])(
    "rolls back an entire ingest batch when %s insertion aborts",
    (table) => {
      db.exec(`CREATE TRIGGER fail_insert BEFORE INSERT ON ${table}
      WHEN NEW.record_key = 'second'
      BEGIN SELECT RAISE(ABORT, 'injected failure'); END;`);
      expect(() =>
        store.ingestBatch(
          [
            envelope(),
            { ...envelope(), key: "second", data: { id: "second" } },
          ],
          semantics,
          primaryKey,
          binding,
        ),
      ).toThrow("injected failure");
      expect(
        store.getRecord("account-a", "messages", "same-key"),
      ).toBeUndefined();
      expect(
        store.getRecord("account-a", "messages", "second"),
      ).toBeUndefined();
      expect(ownWrites(db)).toEqual([]);
      expect(
        db.prepare("SELECT COUNT(*) AS n FROM pdpp_record_changes").get(),
      ).toEqual({ n: 0 });
      expect(db.prepare("SELECT value FROM pdpp_write_clock").get()).toEqual({
        value: 0,
      });
      expect(store.listArrivalOrder("account-a", "messages")).toEqual([]);
      db.exec("DROP TRIGGER fail_insert");
      expect(
        store.ingestBatch([envelope()], semantics, primaryKey, binding)
          .accepted,
      ).toBe(1);
      expect(ownWrites(db)).toHaveLength(1);
    },
  );

  it("captures owner deletion as a data-free tombstone and suppresses repeated or forbidden deletes", () => {
    store.ingestBatch([envelope()], semantics, primaryKey, binding);
    const deletedAt = "2026-10-20T12:00:00.000Z";
    expect(
      store.deleteRecord(
        "account-a",
        "messages",
        "same-key",
        deletedAt,
        "append_only",
      ),
    ).toBe(false);
    expect(
      store.deleteRecord(
        "account-a",
        "messages",
        "missing",
        deletedAt,
        "mutable_state",
      ),
    ).toBe(false);
    expect(
      store.deleteRecord(
        "account-a",
        "messages",
        "same-key",
        deletedAt,
        "mutable_state",
      ),
    ).toBe(true);
    expect(
      store.deleteRecord(
        "account-a",
        "messages",
        "same-key",
        deletedAt,
        "mutable_state",
      ),
    ).toBe(false);
    const page = ownWrites(db);
    expect(page).toHaveLength(2);
    expect(page[1]).toMatchObject({
      operation: "delete",
      sourceId: "https://source.invalid/declaration",
      method: "collector",
      generation: 1,
      blobIds: [],
      value: {
        instance: "account-a",
        stream: "messages",
        recordKey: "same-key",
        version: 2,
        emittedAt: deletedAt,
        deletedAt,
        deleted: true,
      },
    });
    expect(page[1].value).not.toHaveProperty("data");
  });

  it.each(["pdpp_replica_own_writes", "pdpp_record_changes"])(
    "rolls back an owner delete when %s insertion aborts",
    (table) => {
      store.ingestBatch([envelope()], semantics, primaryKey, binding);
      const before = ownWrites(db);
      const record = store.getRecord("account-a", "messages", "same-key");
      db.exec(`CREATE TRIGGER fail_delete BEFORE INSERT ON ${table}
      BEGIN SELECT RAISE(ABORT, 'delete failed'); END;`);
      expect(() =>
        store.deleteRecord(
          "account-a",
          "messages",
          "same-key",
          emittedAt,
          "mutable_state",
        ),
      ).toThrow("delete failed");
      expect(store.getRecord("account-a", "messages", "same-key")).toEqual(
        record,
      );
      expect(ownWrites(db)).toEqual(before);
      expect(
        db.prepare("SELECT COUNT(*) AS n FROM pdpp_record_changes").get(),
      ).toEqual({ n: 1 });
      expect(db.prepare("SELECT value FROM pdpp_write_clock").get()).toEqual({
        value: 1,
      });
      expect(store.listArrivalOrder("account-a", "messages")).toEqual([
        "same-key",
      ]);
    },
  );

  it("captures ingest deletes, blob references, and the actual generation", () => {
    store.resetInstanceBinding({
      instance: "account-a",
      expectedMethod: "collector",
      expectedGeneration: 1,
      nextMethod: "collector",
    });
    const current = { method: "collector", generation: 2 };
    const blob = store.storeBlobBytesForInstance({
      instance: "account-a",
      ...current,
      bytes: new Uint8Array([1, 2, 3]),
      mimeType: "application/octet-stream",
    });
    const value = {
      ...envelope(),
      data: {
        id: "same-key",
        blob_ref: {
          blob_id: blob.blobId,
          mime_type: blob.mimeType,
          size_bytes: 3,
        },
      },
    };
    store.ingestBatch([value], semantics, primaryKey, current);
    store.ingestBatch(
      [{ ...envelope(), op: "delete", data: null }],
      semantics,
      primaryKey,
      current,
    );
    const mutations = ownWrites(db);
    expect(
      mutations.map((m) => [m.generation, m.operation, m.blobIds]),
    ).toEqual([
      [2, "upsert", [blob.blobId]],
      [2, "delete", []],
    ]);
    expect(mutations[0].value).toMatchObject({ data: value.data });
    expect(mutations[1].value).toMatchObject({
      deleted: true,
      deletedAt: emittedAt,
    });
  });

  it("is append-only and survives history erasure without changing earlier evidence", () => {
    store.ingestBatch([envelope()], semantics, primaryKey, binding);
    const before = ownWrites(db);
    expect(() =>
      db.exec("UPDATE pdpp_replica_own_writes SET operation_id = 'changed'"),
    ).toThrow("append-only");
    expect(() => db.exec("DELETE FROM pdpp_replica_own_writes")).toThrow(
      "append-only",
    );
    store.resetInstanceBinding({
      instance: "account-a",
      expectedMethod: "collector",
      expectedGeneration: 1,
      nextMethod: "collector",
    });
    expect(
      db.prepare("SELECT COUNT(*) AS n FROM pdpp_record_changes").get(),
    ).toEqual({ n: 0 });
    store.deleteConnection("account-a");
    expect(ownWrites(db)).toEqual(before);
  });

  it.each(["sequence", "operation_id"])(
    "rejects REPLACE by %s even with recursive triggers disabled",
    (conflict) => {
      store.ingestBatch([envelope()], semantics, primaryKey, binding);
      const before = ownWrites(db);
      db.pragma("recursive_triggers = OFF");
      const columns =
        conflict === "sequence"
          ? "sequence, operation_id, writer_id, source_id, connection_id, method, generation, stream, record_key, operation, value_json, blob_ids_json"
          : "operation_id, writer_id, source_id, connection_id, method, generation, stream, record_key, operation, value_json, blob_ids_json";
      const values =
        conflict === "sequence"
          ? columns.replace(
              "sequence, operation_id,",
              "sequence, 'replacement-operation',",
            )
          : columns;
      expect(() =>
        db.exec(
          `INSERT OR REPLACE INTO pdpp_replica_own_writes (${columns}) SELECT ${values} FROM pdpp_replica_own_writes`,
        ),
      ).toThrow("append-only");
      expect(ownWrites(db)).toEqual(before);
    },
  );

  it("retains null legacy binding metadata on owner delete without inferring source from stream", () => {
    db.prepare(
      `INSERT INTO pdpp_records (instance, stream, record_key, data, version, emitted_at) VALUES ('legacy', 'source.scope', 'key', '{}', 1, ?)`,
    ).run(emittedAt);
    expect(
      store.deleteRecord(
        "legacy",
        "source.scope",
        "key",
        emittedAt,
        "mutable_state",
      ),
    ).toBe(true);
    expect(ownWrites(db)[0]).toMatchObject({
      sourceId: null,
      method: null,
      generation: null,
      connectionId: "legacy",
    });
  });

  it("upgrades a populated v11 database without fabricating mutations or replacing identity on reopen", () => {
    const directory = mkdtempSync(join(tmpdir(), "pdpp-journal-v11-"));
    const path = join(directory, "records.sqlite");
    let historical = new Database(path);
    let upgraded: ReturnType<typeof createReplicaRecordStore> | undefined;
    try {
      // Literal pre-journal v11 schema: no use of the current migration output.
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
          snapshot_sha256 TEXT, collection_time_basis TEXT,
          PRIMARY KEY (instance, stream)
        );
        CREATE TABLE pdpp_record_arrival (
          instance TEXT NOT NULL, stream TEXT NOT NULL, record_key TEXT NOT NULL,
          generation INTEGER NOT NULL, arrival INTEGER NOT NULL,
          PRIMARY KEY (instance, stream, record_key)
        );
        CREATE TABLE pdpp_record_arrival_clock (id INTEGER PRIMARY KEY CHECK (id = 1), value INTEGER NOT NULL);
        CREATE TABLE pdpp_schema_version (id INTEGER PRIMARY KEY CHECK (id = 1), version INTEGER NOT NULL);
        INSERT INTO pdpp_schema_version VALUES (1, 11);
        INSERT INTO pdpp_write_clock VALUES (1, 1);
        INSERT INTO pdpp_record_arrival_clock VALUES (1, 1);
        INSERT INTO pdpp_instance_binding VALUES ('account-a', 'collector', 1, 0, 'https://source.invalid/declaration', 'A', NULL);
        INSERT INTO pdpp_store_metadata VALUES (1, 'v11-epoch');
        INSERT INTO pdpp_records VALUES ('account-a', 'messages', 'same-key', '{"id":"same-key","content":"old"}', 1, '2026-10-20T10:00:00.000Z', 0, NULL, NULL);
        INSERT INTO pdpp_record_changes (instance, stream, record_key, version, data, emitted_at, written_at)
          VALUES ('account-a', 'messages', 'same-key', 1, '{"id":"same-key","content":"old"}', '2026-10-20T10:00:00.000Z', 1);
        INSERT INTO pdpp_record_arrival VALUES ('account-a', 'messages', 'same-key', 1, 1);
      `);
      const retained = [
        "pdpp_records",
        "pdpp_record_changes",
        "pdpp_instance_binding",
        "pdpp_store_metadata",
        "pdpp_write_clock",
        "pdpp_record_arrival",
        "pdpp_record_arrival_clock",
      ];
      const before = retained.map((table) =>
        historical.prepare(`SELECT * FROM ${table}`).all(),
      );
      historical.close();
      historical = new Database(path);
      upgraded = createReplicaRecordStore(historical);
      // The canonical v13 migration adds the derived `emitted_key` column.
      expect(
        retained.map((table) =>
          (
            historical.prepare(`SELECT * FROM ${table}`).all() as Record<
              string,
              unknown
            >[]
          ).map(({ emitted_key: _derived, ...row }) => row),
        ),
      ).toEqual(before);
      expect(
        upgraded.getRecord("account-a", "messages", "same-key"),
      ).toMatchObject({ version: 1, data: { id: "same-key", content: "old" } });
      expect(ownWrites(historical)).toEqual([]);
      const writer = upgraded.getInstallationWriterId();
      expect(writer.length).toBeGreaterThan(0);
      upgraded.close();
      historical = new Database(path);
      upgraded = createReplicaRecordStore(historical);
      expect(upgraded.getInstallationWriterId()).toBe(writer);
      expect(
        upgraded.ingestBatch([envelope()], semantics, primaryKey, binding)
          .accepted,
      ).toBe(1);
      expect(ownWrites(historical)).toMatchObject([
        {
          sequence: 1,
          writerId: writer,
          value: { version: 2, data: { id: "same-key", content: "hello" } },
        },
      ]);
    } finally {
      if (historical.open) historical.close();
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("reopens with identical IDs and values, shares identity across DB handles, and retries once", () => {
    const directory = mkdtempSync(join(tmpdir(), "pdpp-journal-"));
    const path = join(directory, "records.sqlite");
    const firstDb = new Database(path);
    const first = createReplicaRecordStore(firstDb);
    let second: ReturnType<typeof createReplicaRecordStore> | undefined;
    const readOwnWrites = () => {
      const reader = new Database(path, { readonly: true });
      try {
        return ownWrites(reader);
      } finally {
        reader.close();
      }
    };
    try {
      first.registerConnection({
        instance: "account-a",
        sourceId: "https://source.invalid/declaration",
        method: "collector",
        label: "A",
      });
      first.ingestBatch([envelope()], semantics, primaryKey, binding);
      const before = ownWrites(firstDb);
      const writer = first.getInstallationWriterId();
      second = createReplicaRecordStore(new Database(path));
      expect(second.getInstallationWriterId()).toBe(writer);
      expect(
        second.ingestBatch([envelope()], semantics, primaryKey, binding)
          .unchanged,
      ).toBe(1);
      expect(readOwnWrites()).toEqual(before);
      first.close();
      second.close();
      second = createReplicaRecordStore(new Database(path));
      expect(second.getInstallationWriterId()).toBe(writer);
      expect(readOwnWrites()).toEqual(before);
      expect(
        second.ingestBatch([envelope()], semantics, primaryKey, binding)
          .unchanged,
      ).toBe(1);
      expect(readOwnWrites()).toEqual(before);
      expect(store.getInstallationWriterId()).not.toBe(writer);
      second.close();
      second = createReplicaRecordStore(new Database(path, { readonly: true }));
      expect(readOwnWrites()).toEqual(before);
    } finally {
      if (firstDb.open) first.close();
      second?.close();
      rmSync(directory, { recursive: true, force: true });
    }
  });
});
