import { afterEach, beforeEach, describe, expect, it } from "vitest";
import Database from "better-sqlite3";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";

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

describe("canonical mutation journal", () => {
  let db: Database.Database;
  let store: ReturnType<typeof createSqliteRecordStore>;
  beforeEach(() => {
    db = new Database(":memory:");
    store = createSqliteRecordStore(db);
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
    const page = store.readMutationJournalPage({ limit: 10 });
    expect(page.hasMore).toBe(false);
    expect(page.nextAfterSequence).toBe(1);
    expect(page.mutations).toEqual([
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
    const before = store.readMutationJournalPage({ limit: 10 });
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
    expect(store.readMutationJournalPage({ limit: 10 })).toEqual(before);
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
    const { mutations } = store.readMutationJournalPage({ limit: 10 });
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

  it.each(["pdpp_mutation_journal", "pdpp_record_changes"])(
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
      expect(store.readMutationJournalPage({ limit: 10 }).mutations).toEqual(
        [],
      );
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
      expect(
        store.readMutationJournalPage({ limit: 10 }).mutations,
      ).toHaveLength(1);
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
    const page = store.readMutationJournalPage({ limit: 10 });
    expect(page.mutations).toHaveLength(2);
    expect(page.mutations[1]).toMatchObject({
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
    expect(page.mutations[1].value).not.toHaveProperty("data");
  });

  it.each(["pdpp_mutation_journal", "pdpp_record_changes"])(
    "rolls back an owner delete when %s insertion aborts",
    (table) => {
      store.ingestBatch([envelope()], semantics, primaryKey, binding);
      const before = store.readMutationJournalPage({ limit: 10 });
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
      expect(store.readMutationJournalPage({ limit: 10 })).toEqual(before);
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
    const { mutations } = store.readMutationJournalPage({ limit: 10 });
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

  it("pages by exclusive offset and supports resuming from an empty tail", () => {
    expect(store.readMutationJournalPage({ limit: 1 })).toEqual({
      mutations: [],
      hasMore: false,
      nextAfterSequence: 0,
    });
    store.ingestBatch([envelope()], semantics, primaryKey, binding);
    store.ingestBatch(
      [envelope("account-a", "v2")],
      semantics,
      primaryKey,
      binding,
    );
    const first = store.readMutationJournalPage({ limit: 1 });
    expect(first.mutations.map((m) => m.sequence)).toEqual([1]);
    expect(first.hasMore).toBe(true);
    const second = store.readMutationJournalPage({
      limit: 1,
      afterSequence: first.nextAfterSequence,
    });
    expect(second.mutations.map((m) => m.sequence)).toEqual([2]);
    expect(second.hasMore).toBe(false);
    expect(
      store.readMutationJournalPage({
        limit: 1,
        afterSequence: second.nextAfterSequence,
      }),
    ).toEqual({ mutations: [], hasMore: false, nextAfterSequence: 2 });
    store.ingestBatch(
      [envelope("account-a", "v3")],
      semantics,
      primaryKey,
      binding,
    );
    expect(
      store
        .readMutationJournalPage({
          limit: 1,
          afterSequence: second.nextAfterSequence,
        })
        .mutations.map((m) => m.sequence),
    ).toEqual([3]);
    expect(
      store.readMutationJournalPage({ limit: 1000 }).mutations,
    ).toHaveLength(3);
  });

  it("rejects invalid page bounds instead of issuing an unbounded read", () => {
    for (const limit of [0, -1, 1001, 1.5, NaN, Infinity]) {
      expect(() => store.readMutationJournalPage({ limit })).toThrow(
        RangeError,
      );
    }
    for (const afterSequence of [
      -1,
      0.5,
      NaN,
      Infinity,
      Number.MAX_SAFE_INTEGER + 1,
    ]) {
      expect(() =>
        store.readMutationJournalPage({ limit: 1, afterSequence }),
      ).toThrow(RangeError);
    }
  });

  it("is append-only and survives history erasure without changing earlier evidence", () => {
    store.ingestBatch([envelope()], semantics, primaryKey, binding);
    const before = store.readMutationJournalPage({ limit: 10 });
    expect(() =>
      db.exec("UPDATE pdpp_mutation_journal SET operation_id = 'changed'"),
    ).toThrow("append-only");
    expect(() => db.exec("DELETE FROM pdpp_mutation_journal")).toThrow(
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
    expect(store.readMutationJournalPage({ limit: 10 })).toEqual(before);
  });

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
    expect(
      store.readMutationJournalPage({ limit: 10 }).mutations[0],
    ).toMatchObject({
      sourceId: null,
      method: null,
      generation: 1,
      connectionId: "legacy",
    });
  });

  it("reopens with identical IDs and values, shares identity across DB handles, and retries once", () => {
    const directory = mkdtempSync(join(tmpdir(), "pdpp-journal-"));
    const path = join(directory, "records.sqlite");
    const firstDb = new Database(path);
    const first = createSqliteRecordStore(firstDb);
    let second: ReturnType<typeof createSqliteRecordStore> | undefined;
    try {
      first.registerConnection({
        instance: "account-a",
        sourceId: "https://source.invalid/declaration",
        method: "collector",
        label: "A",
      });
      first.ingestBatch([envelope()], semantics, primaryKey, binding);
      const before = first.readMutationJournalPage({ limit: 10 });
      const writer = first.getInstallationWriterId();
      second = createSqliteRecordStore(new Database(path));
      expect(second.getInstallationWriterId()).toBe(writer);
      expect(
        second.ingestBatch([envelope()], semantics, primaryKey, binding)
          .unchanged,
      ).toBe(1);
      expect(second.readMutationJournalPage({ limit: 10 })).toEqual(before);
      first.close();
      second.close();
      second = createSqliteRecordStore(new Database(path));
      expect(second.getInstallationWriterId()).toBe(writer);
      expect(second.readMutationJournalPage({ limit: 10 })).toEqual(before);
      expect(
        second.ingestBatch([envelope()], semantics, primaryKey, binding)
          .unchanged,
      ).toBe(1);
      expect(second.readMutationJournalPage({ limit: 10 })).toEqual(before);
      expect(store.getInstallationWriterId()).not.toBe(writer);
      second.close();
      second = createSqliteRecordStore(new Database(path, { readonly: true }));
      expect(second.readMutationJournalPage({ limit: 10 })).toEqual(before);
    } finally {
      if (firstDb.open) first.close();
      second?.close();
      rmSync(directory, { recursive: true, force: true });
    }
  });
});
