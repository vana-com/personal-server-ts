import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import Database from "better-sqlite3";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";

describe("pre-v4 historical blob retention", () => {
  let dir: string | undefined;
  afterEach(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  it.each(["overwrite", "tombstone", "history-only"] as const)(
    "preserves a history-only blob through migration and startup after %s, until explicit erase",
    (current) => {
      dir = mkdtempSync(join(tmpdir(), "pdpp-history-blob-gc-"));
      const path = join(dir, "pdpp.db");
      const bytes = Buffer.from("historical blob");
      const hash = createHash("sha256").update(bytes).digest("hex");
      const blobId = "blob_historical";
      const data = JSON.stringify({
        id: "record",
        blob_ref: { blob_id: blobId },
      });
      const legacy = new Database(path);
      legacy.exec(`
        CREATE TABLE pdpp_schema_version (id INTEGER PRIMARY KEY CHECK (id = 1), version INTEGER NOT NULL);
        INSERT INTO pdpp_schema_version VALUES (1, 3);
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
        CREATE TABLE pdpp_blob_bytes (
          blob_id TEXT PRIMARY KEY REFERENCES pdpp_blobs(blob_id), bytes BLOB NOT NULL
        );
        CREATE TABLE pdpp_write_clock (id INTEGER PRIMARY KEY CHECK (id = 1), value INTEGER NOT NULL);
        INSERT INTO pdpp_write_clock VALUES (1, 2);
      `);
      legacy
        .prepare(
          `INSERT INTO pdpp_record_changes
        (instance, stream, record_key, version, data, emitted_at, written_at)
        VALUES ('legacy', 'media', 'record', 1, ?, '2026-01-01T00:00:00.000Z', 1)`,
        )
        .run(data);
      if (current !== "history-only") {
        const deleted = current === "tombstone" ? 1 : 0;
        const latestData = deleted
          ? null
          : JSON.stringify({ id: "record", text: "replacement" });
        const deletedAt = deleted ? "2026-01-02T00:00:00.000Z" : null;
        legacy
          .prepare(
            `INSERT INTO pdpp_records
          VALUES ('legacy', 'media', 'record', ?, 2, '2026-01-02T00:00:00.000Z', ?, ?, NULL)`,
          )
          .run(latestData, deleted, deletedAt);
        legacy
          .prepare(
            `INSERT INTO pdpp_record_changes
          (instance, stream, record_key, version, data, emitted_at, deleted, deleted_at, written_at)
          VALUES ('legacy', 'media', 'record', 2, ?, '2026-01-02T00:00:00.000Z', ?, ?, 2)`,
          )
          .run(latestData, deleted, deletedAt);
      }
      for (const id of [blobId, "blob_orphan"]) {
        legacy
          .prepare("INSERT INTO pdpp_blobs VALUES (?, 'text/plain', ?, ?)")
          .run(id, bytes.length, hash);
        legacy
          .prepare("INSERT INTO pdpp_blob_bytes VALUES (?, ?)")
          .run(id, bytes);
      }
      legacy.close();

      // A real writable open runs all migrations and the automatic claim sweep.
      let db = new Database(path);
      let store = createSqliteRecordStore(db);
      try {
        expect(store.getBlobMeta(blobId)?.sha256).toBe(hash);
        expect(Buffer.from(store.getBlobBytes(blobId)!)).toEqual(bytes);
        expect(
          db
            .prepare("SELECT data FROM pdpp_record_changes WHERE version = 1")
            .get(),
        ).toEqual({ data });
        expect(
          db.prepare("SELECT version FROM pdpp_schema_version").get(),
        ).toEqual({ version: 15 });
        // The v4 reconstruction cannot manufacture a claim from this current row.
        expect(
          db.prepare("SELECT COUNT(*) AS n FROM pdpp_blob_claims").get(),
        ).toEqual({ n: 0 });
        expect(store.getBlobMeta("blob_orphan")).toBeUndefined();
        expect(store.getBlobBytes("blob_orphan")).toBeUndefined();
      } finally {
        store.close();
      }

      // A second writable open tests the current-schema startup sweep too.
      db = new Database(path);
      store = createSqliteRecordStore(db);
      try {
        expect(Buffer.from(store.getBlobBytes(blobId)!)).toEqual(bytes);
        // Both owner erase routes delete history first, then release its bytes.
        if (current === "tombstone") {
          store.deleteConnection("legacy");
        } else {
          store.resetInstanceBinding({
            instance: "legacy",
            expectedMethod: null,
            expectedGeneration: 1,
            nextMethod: null,
          });
        }
        expect(
          db.prepare("SELECT COUNT(*) AS n FROM pdpp_record_changes").get(),
        ).toEqual({ n: 0 });
        expect(store.getBlobMeta(blobId)).toBeUndefined();
        expect(store.getBlobBytes(blobId)).toBeUndefined();
      } finally {
        store.close();
      }
    },
  );
});
