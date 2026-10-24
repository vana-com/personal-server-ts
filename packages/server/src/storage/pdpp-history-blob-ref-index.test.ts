import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
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
    legacy
      .prepare(
        `INSERT INTO pdpp_record_changes
          (instance, stream, record_key, version, data, emitted_at, written_at)
        VALUES (?, 'media', ?, ?, ?, '2026-01-01T00:00:00.000Z', ?)`,
      )
      .run(
        "legacy",
        "a",
        1,
        JSON.stringify({ id: "a", blob_ref: { blob_id: "blob_a" } }),
        1,
      );
    legacy
      .prepare(
        `INSERT INTO pdpp_record_changes
          (instance, stream, record_key, version, data, emitted_at, written_at)
        VALUES (?, 'media', ?, ?, ?, '2026-01-01T00:00:00.000Z', ?)`,
      )
      .run("legacy", "b", 1, JSON.stringify({ id: "b" }), 2);
    legacy
      .prepare(
        `INSERT INTO pdpp_record_changes
          (instance, stream, record_key, version, data, emitted_at, deleted, deleted_at, written_at)
        VALUES (?, 'media', ?, ?, NULL, '2026-01-01T00:00:00.000Z', 1, '2026-01-02T00:00:00.000Z', ?)`,
      )
      .run("legacy", "c", 2, 3);
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
});
