import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import {
  createSqliteRecordStore,
  noRetainedHistoryReferenceSql,
} from "./pdpp-records-sqlite-store.js";

const INDEX = "idx_pdpp_record_changes_blob_ref";
// The two statements `deleteUnclaimedBlobs` runs for the history check.
const CANDIDATES = `SELECT blob_id FROM pdpp_blobs b WHERE ${noRetainedHistoryReferenceSql("b.blob_id")}`;
const DELETE_BLOBS = `DELETE FROM pdpp_blobs WHERE ${noRetainedHistoryReferenceSql("pdpp_blobs.blob_id")}`;

function plan(db: Database.Database, sql: string): string[] {
  return (
    db.prepare(`EXPLAIN QUERY PLAN ${sql}`).all() as { detail: string }[]
  ).map((row) => row.detail);
}

function expectIndexedHistoryCheck(db: Database.Database, sql: string): void {
  const details = plan(db, sql);
  expect(details).toContain(
    `SEARCH pdpp_record_changes USING COVERING INDEX ${INDEX} (<expr>=?)`,
  );
  expect(details.some((d) => d.startsWith("SCAN pdpp_record_changes"))).toBe(
    false,
  );
}

describe("pdpp_record_changes blob reference index (v15)", () => {
  let dir: string | undefined;
  afterEach(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
    dir = undefined;
  });

  it("plans the history blob check as an index search, not a history scan", () => {
    dir = mkdtempSync(join(tmpdir(), "pdpp-blob-ref-index-"));
    const path = join(dir, "pdpp.db");
    createSqliteRecordStore(new Database(path)).close();

    const db = new Database(path);
    try {
      expectIndexedHistoryCheck(db, CANDIDATES);
      expectIndexedHistoryCheck(db, DELETE_BLOBS);
    } finally {
      db.close();
    }
  });

  it("adds the index to a v14 store without changing history rows", () => {
    dir = mkdtempSync(join(tmpdir(), "pdpp-blob-ref-index-"));
    const path = join(dir, "pdpp.db");
    createSqliteRecordStore(new Database(path)).close();

    // v15 adds only an index, so a v14 store is the v15 store without it,
    // stamped as version 14.
    const legacy = new Database(path);
    legacy.exec(`
      DROP INDEX ${INDEX};
      UPDATE pdpp_schema_version SET version = 14;
    `);
    const insertHistory = legacy.prepare(
      `INSERT INTO pdpp_record_changes
        (instance, stream, record_key, version, data, emitted_at, written_at)
      VALUES ('legacy', 'media', ?, 1, ?, '2026-01-01T00:00:00.000Z', ?)`,
    );
    insertHistory.run(
      "a",
      JSON.stringify({ id: "a", blob_ref: { blob_id: "blob_a" } }),
      1,
    );
    insertHistory.run("b", JSON.stringify({ id: "b" }), 2);
    legacy
      .prepare(
        `INSERT INTO pdpp_record_changes
          (instance, stream, record_key, version, data, emitted_at, deleted, deleted_at, written_at)
        VALUES ('legacy', 'media', 'c', 2, NULL, '2026-01-01T00:00:00.000Z', 1, '2026-01-02T00:00:00.000Z', 3)`,
      )
      .run();
    const historyBefore = legacy
      .prepare("SELECT * FROM pdpp_record_changes ORDER BY id")
      .all();
    legacy.close();

    const reopened = new Database(path);
    const store = createSqliteRecordStore(reopened);
    try {
      expect(
        reopened.prepare("SELECT version FROM pdpp_schema_version").get(),
      ).toEqual({ version: 15 });
      expect(
        reopened
          .prepare(
            "SELECT name FROM sqlite_master WHERE type = 'index' AND name = ?",
          )
          .get(INDEX),
      ).toEqual({ name: INDEX });
      expect(
        reopened.prepare("SELECT * FROM pdpp_record_changes ORDER BY id").all(),
      ).toEqual(historyBefore);
      expectIndexedHistoryCheck(reopened, CANDIDATES);
      expectIndexedHistoryCheck(reopened, DELETE_BLOBS);
    } finally {
      store.close();
    }
  });

  it("migrates a v14 store holding malformed history JSON and still keeps blobs that history references", () => {
    dir = mkdtempSync(join(tmpdir(), "pdpp-blob-ref-index-"));
    const path = join(dir, "pdpp.db");
    createSqliteRecordStore(new Database(path)).close();

    const bytes = Buffer.from("kept by history");
    const hash = createHash("sha256").update(bytes).digest("hex");
    const legacy = new Database(path);
    legacy.exec(`
      DROP INDEX ${INDEX};
      UPDATE pdpp_schema_version SET version = 14;
    `);
    const insertHistory = legacy.prepare(
      `INSERT INTO pdpp_record_changes
        (instance, stream, record_key, version, data, emitted_at, written_at)
      VALUES ('legacy', 'media', ?, 1, ?, '2026-01-01T00:00:00.000Z', ?)`,
    );
    // Truncated JSON: `json_extract` raises on this row; `json_valid` does not.
    insertHistory.run(
      "bad",
      '{"id":"bad","blob_ref":{"blob_id":"blob_keep"',
      1,
    );
    insertHistory.run(
      "ref",
      JSON.stringify({ id: "ref", blob_ref: { blob_id: "blob_keep" } }),
      2,
    );
    for (const id of ["blob_keep", "blob_orphan"]) {
      legacy
        .prepare("INSERT INTO pdpp_blobs VALUES (?, 'text/plain', ?, ?)")
        .run(id, bytes.length, hash);
      legacy
        .prepare("INSERT INTO pdpp_blob_bytes VALUES (?, ?)")
        .run(id, bytes);
    }
    legacy.close();

    // Opening runs the v15 migration and the startup blob sweep. Both must
    // succeed with the malformed row present.
    const reopened = new Database(path);
    const store = createSqliteRecordStore(reopened);
    try {
      expect(
        reopened.prepare("SELECT version FROM pdpp_schema_version").get(),
      ).toEqual({ version: 15 });
      expectIndexedHistoryCheck(reopened, CANDIDATES);
      expectIndexedHistoryCheck(reopened, DELETE_BLOBS);
      // Blob referenced only by the valid history row survives the sweep.
      expect(Buffer.from(store.getBlobBytes("blob_keep")!)).toEqual(bytes);
      // Unreferenced blob is collected.
      expect(store.getBlobBytes("blob_orphan")).toBeUndefined();
      // A malformed row written after migration still inserts.
      expect(() =>
        reopened
          .prepare(
            `INSERT INTO pdpp_record_changes
              (instance, stream, record_key, version, data, emitted_at, written_at)
            VALUES ('legacy', 'media', 'later', 1, '{"broken', '2026-01-03T00:00:00.000Z', 4)`,
          )
          .run(),
      ).not.toThrow();
    } finally {
      store.close();
    }

    // A second startup on the same file works too.
    const again = createSqliteRecordStore(new Database(path));
    try {
      expect(Buffer.from(again.getBlobBytes("blob_keep")!)).toEqual(bytes);
    } finally {
      again.close();
    }
  });
});
