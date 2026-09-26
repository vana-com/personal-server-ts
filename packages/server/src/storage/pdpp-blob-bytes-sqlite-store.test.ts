import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import Database from "better-sqlite3";
import { createTestBoundRecordStore } from "../__fixtures__/bound-record-store.js";
import { BlobConflictError } from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

describe("sqlite record store: blob bytes (in-memory db)", () => {
  it("stores bytes and derives blob_id from their content", () => {
    const db = new Database(":memory:");
    const store = createTestBoundRecordStore(db);
    const bytes = new Uint8Array([1, 2, 3, 4]);
    const meta = store.storeBlobBytes(bytes, "application/octet-stream");
    expect(meta.blobId).toBe(`sha256:${sha256Hex(bytes)}`);
    expect(meta.sizeBytes).toBe(4);
    expect(meta.sha256).toBe(sha256Hex(bytes));
    store.close();
  });

  it("reads back the exact bytes just stored", () => {
    const db = new Database(":memory:");
    const store = createTestBoundRecordStore(db);
    const bytes = new Uint8Array([9, 8, 7, 255, 0]);
    const meta = store.storeBlobBytes(bytes, "image/png");
    const readBack = store.getBlobBytes(meta.blobId);
    expect(readBack).toBeDefined();
    expect(Array.from(readBack!)).toEqual(Array.from(bytes));
    store.close();
  });

  it("re-storing identical bytes with the same mimeType is an idempotent no-op", () => {
    const db = new Database(":memory:");
    const store = createTestBoundRecordStore(db);
    const bytes = new Uint8Array([1, 2, 3]);
    const first = store.storeBlobBytes(bytes, "image/jpeg");
    const second = store.storeBlobBytes(bytes.slice(), "image/jpeg");
    expect(second).toEqual(first);
    store.close();
  });

  it("throws BlobConflictError when identical bytes are re-stored with a different mimeType, and does not corrupt the original", () => {
    const db = new Database(":memory:");
    const store = createTestBoundRecordStore(db);
    const bytes = new Uint8Array([1, 2, 3]);
    const meta = store.storeBlobBytes(bytes, "image/jpeg");
    expect(() => store.storeBlobBytes(bytes.slice(), "image/png")).toThrow(
      BlobConflictError,
    );
    expect(store.getBlobMeta(meta.blobId)?.mimeType).toBe("image/jpeg");
    expect(store.getBlobBytes(meta.blobId)?.byteLength).toBe(3);
    store.close();
  });

  it("returns undefined for a blob_id with metadata but no stored bytes (legacy/test fixture row)", () => {
    const db = new Database(":memory:");
    const store = createTestBoundRecordStore(db);
    store.putBlobMeta({
      blobId: "blob_legacy",
      mimeType: "image/jpeg",
      sizeBytes: 10,
      sha256: "deadbeef",
    });
    expect(store.getBlobBytes("blob_legacy")).toBeUndefined();
    store.close();
  });

  it("fails closed when stored bytes no longer match the recorded metadata (corruption)", () => {
    const db = new Database(":memory:");
    const store = createTestBoundRecordStore(db);
    const bytes = new Uint8Array([1, 2, 3]);
    const meta = store.storeBlobBytes(bytes, "application/octet-stream");
    store.putBlobMeta({ ...meta, sha256: "0".repeat(64) });
    expect(store.getBlobBytes(meta.blobId)).toBeUndefined();
    store.close();
  });

  it("fails closed when recorded sizeBytes no longer matches the stored payload length", () => {
    const db = new Database(":memory:");
    const store = createTestBoundRecordStore(db);
    const bytes = new Uint8Array([1, 2, 3]);
    const meta = store.storeBlobBytes(bytes, "application/octet-stream");
    store.putBlobMeta({ ...meta, sizeBytes: 999 });
    expect(store.getBlobBytes(meta.blobId)).toBeUndefined();
    store.close();
  });

  it("supports a genuine zero-byte blob distinctly from an absent one", () => {
    const db = new Database(":memory:");
    const store = createTestBoundRecordStore(db);
    const meta = store.storeBlobBytes(
      new Uint8Array(0),
      "application/octet-stream",
    );
    const readBack = store.getBlobBytes(meta.blobId);
    expect(readBack).toBeDefined();
    expect(readBack?.byteLength).toBe(0);
    store.close();
  });

  it("completes a metadata-only row (matching mimeType, no bytes yet) instead of reporting a false no-op", () => {
    const db = new Database(":memory:");
    const store = createTestBoundRecordStore(db);
    const bytes = new Uint8Array([1, 2, 3]);
    const blobId = `sha256:${sha256Hex(bytes)}`;
    store.putBlobMeta({
      blobId,
      mimeType: "image/jpeg",
      sizeBytes: bytes.byteLength,
      sha256: sha256Hex(bytes),
    });
    expect(store.getBlobBytes(blobId)).toBeUndefined();

    const meta = store.storeBlobBytes(bytes, "image/jpeg");
    expect(meta.blobId).toBe(blobId);
    const readBack = store.getBlobBytes(blobId);
    expect(readBack).toBeDefined();
    expect(Array.from(readBack!)).toEqual(Array.from(bytes));
    store.close();
  });

  it("does not return a false success when re-storing over existing corrupt bytes", () => {
    const db = new Database(":memory:");
    const store = createTestBoundRecordStore(db);
    const bytes = new Uint8Array([1, 2, 3]);
    const meta = store.storeBlobBytes(bytes, "application/octet-stream");
    store.putBlobMeta({ ...meta, sha256: "0".repeat(64) });
    expect(store.getBlobBytes(meta.blobId)).toBeUndefined();

    expect(() =>
      store.storeBlobBytes(bytes.slice(), "application/octet-stream"),
    ).toThrow(BlobConflictError);
    store.close();
  });

  it("rejects mismatched MIME type without changing the persisted content", () => {
    const db = new Database(":memory:");
    const store = createTestBoundRecordStore(db);
    const bytes = new Uint8Array([1, 2, 3]);
    const original = store.storeBlobBytes(bytes, "image/jpeg");

    expect(() => store.storeBlobBytes(bytes.slice(), "image/png")).toThrow(
      BlobConflictError,
    );

    expect(store.getBlobMeta(original.blobId)).toEqual(original);
    const readBack = store.getBlobBytes(original.blobId);
    expect(Array.from(readBack!)).toEqual(Array.from(bytes));
    store.close();
  });
});

describe("sqlite record store: storeBlobBytes transaction rollback (real on-disk database)", () => {
  let dir: string;

  afterEach(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  it("a failed byte insert inside the transaction leaves no partial metadata row behind", () => {
    dir = mkdtempSync(join(tmpdir(), "pdpp-blob-rollback-"));
    const dbPath = join(dir, "pdpp.db");
    const db = new Database(dbPath);
    const store = createTestBoundRecordStore(db);
    const bytes = new Uint8Array([1, 2, 3]);
    const blobId = `sha256:${sha256Hex(bytes)}`;

    // Force the byte insert to fail after the metadata insert has already
    // run inside the same transaction, by dropping the bytes table out from
    // under it. If the write is genuinely one transaction, the metadata
    // insert must roll back too -- no partial/orphaned pdpp_blobs row.
    db.exec("DROP TABLE pdpp_blob_bytes");

    expect(() =>
      store.storeBlobBytes(bytes, "application/octet-stream"),
    ).toThrow();
    expect(store.getBlobMeta(blobId)).toBeUndefined();

    store.close();
  });
});

describe("sqlite record store: blob bytes (real on-disk database)", () => {
  let dir: string;

  afterEach(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  it("persists blob bytes across a real close + reopen of the on-disk database", () => {
    dir = mkdtempSync(join(tmpdir(), "pdpp-blob-bytes-"));
    const dbPath = join(dir, "pdpp.db");
    const bytes = new Uint8Array([10, 20, 30, 40, 250]);

    const db1 = new Database(dbPath);
    const store1 = createTestBoundRecordStore(db1);
    const meta = store1.storeBlobBytesForInstance({
      instance: "inst_1",
      method: "method_a",
      generation: 1,
      bytes,
      mimeType: "application/pdf",
    });
    store1.close(); // closes the underlying db too

    const db2 = new Database(dbPath);
    const store2 = createTestBoundRecordStore(db2);
    const readBack = store2.getBlobBytes(meta.blobId);
    expect(readBack).toBeDefined();
    expect(Array.from(readBack!)).toEqual(Array.from(bytes));
    expect(store2.getBlobMeta(meta.blobId)).toEqual(meta);
    store2.close();
  });

  it("preserves a pre-migration (v2, metadata-only) database's records and blob metadata after opening with the v3 byte-table migration", () => {
    dir = mkdtempSync(join(tmpdir(), "pdpp-blob-migration-"));
    const dbPath = join(dir, "pdpp.db");

    // Build a v2-shaped database by hand: the exact schema this build's
    // migration array had before the byte-storage migration was added.
    const legacyDb = new Database(dbPath);
    legacyDb.exec(`
      CREATE TABLE pdpp_schema_version (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        version INTEGER NOT NULL
      );
      INSERT INTO pdpp_schema_version (id, version) VALUES (1, 2);

      CREATE TABLE pdpp_records (
        instance TEXT NOT NULL,
        stream TEXT NOT NULL,
        record_key TEXT NOT NULL,
        data TEXT,
        version INTEGER NOT NULL,
        emitted_at TEXT NOT NULL,
        deleted INTEGER NOT NULL DEFAULT 0,
        deleted_at TEXT,
        blob_id TEXT,
        PRIMARY KEY (instance, stream, record_key)
      );
      CREATE TABLE pdpp_record_changes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        instance TEXT NOT NULL,
        stream TEXT NOT NULL,
        record_key TEXT NOT NULL,
        version INTEGER NOT NULL,
        data TEXT,
        emitted_at TEXT NOT NULL,
        deleted INTEGER NOT NULL DEFAULT 0,
        deleted_at TEXT,
        written_at INTEGER NOT NULL
      );
      CREATE TABLE pdpp_blobs (
        blob_id TEXT PRIMARY KEY,
        mime_type TEXT NOT NULL,
        size_bytes INTEGER NOT NULL,
        sha256 TEXT NOT NULL
      );
      CREATE TABLE pdpp_write_clock (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        value INTEGER NOT NULL
      );
      INSERT INTO pdpp_write_clock (id, value) VALUES (1, 1);
    `);
    legacyDb
      .prepare(
        `INSERT INTO pdpp_records (instance, stream, record_key, data, version, emitted_at, deleted, deleted_at, blob_id)
         VALUES ('inst_1', 'media', 'media_1', '{"id":"media_1","blob_ref":{"blob_id":"blob_pre_existing"}}', 1, '2026-01-01T00:00:00.000Z', 0, NULL, 'blob_pre_existing')`,
      )
      .run();
    legacyDb
      .prepare(
        `INSERT INTO pdpp_blobs (blob_id, mime_type, size_bytes, sha256) VALUES ('blob_pre_existing', 'image/jpeg', 3, 'preexistinghash')`,
      )
      .run();
    legacyDb.close();

    // Opening with this build runs the v3 migration on top of the existing
    // v2 data. The pre-existing record and its blob metadata must survive
    // untouched; the pre-existing blob has no byte row (never had one) and
    // must fail closed, not fabricate bytes.
    const db = new Database(dbPath);
    const store = createTestBoundRecordStore(db);

    expect(store.getRecord("inst_1", "media", "media_1")?.data).toEqual({
      id: "media_1",
      blob_ref: { blob_id: "blob_pre_existing" },
    });
    expect(store.getBlobMeta("blob_pre_existing")).toEqual({
      blobId: "blob_pre_existing",
      mimeType: "image/jpeg",
      sizeBytes: 3,
      sha256: "preexistinghash",
    });
    expect(store.getBlobBytes("blob_pre_existing")).toBeUndefined();
    expect(store.getInstanceBinding("inst_1")).toMatchObject({
      method: null,
      generation: 1,
      empty: false,
    });
    expect(() =>
      store.ingestBatch(
        [
          {
            instance: "inst_1",
            stream: "media",
            key: "media_1",
            data: { id: "media_1", blob_ref: { blob_id: "blob_pre_existing" } },
            emitted_at: "2026-01-02T00:00:00.000Z",
          },
        ],
        () => "mutable_state",
        () => ["id"],
        { method: "method_a", generation: 1 },
      ),
    ).toThrow("binding_required");

    // The migrated database accepts new byte-backed blobs normally.
    const newBytes = new Uint8Array([1, 2, 3]);
    const newMeta = store.storeBlobBytes(newBytes, "text/plain");
    expect(store.getBlobBytes(newMeta.blobId)).toEqual(newBytes);

    const version = db
      .prepare("SELECT version FROM pdpp_schema_version WHERE id = 1")
      .get() as { version: number };
    expect(version.version).toBe(5);

    store.close();
  });
});

describe("metadata-only completion integrity", () => {
  it.each(["sha256", "sizeBytes"] as const)(
    "rejects incompatible %s before adding bytes",
    (field) => {
      const store = createTestBoundRecordStore(new Database(":memory:"));
      try {
        const bytes = new Uint8Array([1, 2, 3]);
        const correct = {
          blobId: `sha256:${sha256Hex(bytes)}`,
          sha256: sha256Hex(bytes),
          sizeBytes: bytes.length,
          mimeType: "image/jpeg",
        };
        const invalid = {
          ...correct,
          ...(field === "sha256"
            ? { sha256: "0".repeat(64) }
            : { sizeBytes: 99 }),
        };
        store.putBlobMeta(invalid);
        expect(() => store.storeBlobBytes(bytes, correct.mimeType)).toThrow(
          BlobConflictError,
        );
        expect(store.getBlobMeta(correct.blobId)).toEqual(invalid);
        store.putBlobMeta(correct);
        expect(store.getBlobBytes(correct.blobId)).toBeUndefined();
      } finally {
        store.close();
      }
    },
  );
});
