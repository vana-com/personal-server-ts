import { describe, it, expect } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import Database from "better-sqlite3";
import { initializeDatabase } from "./index-schema.js";

describe("initializeDatabase", () => {
  it("returns a Database instance", () => {
    const db = initializeDatabase(":memory:");
    expect(db).toBeDefined();
    expect(typeof db.close).toBe("function");
    db.close();
  });

  it("creates data_files table", () => {
    const db = initializeDatabase(":memory:");
    const row = db
      .prepare(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='data_files'",
      )
      .get() as { name: string } | undefined;
    expect(row).toBeDefined();
    expect(row!.name).toBe("data_files");
    db.close();
  });

  it("has all expected columns", () => {
    const db = initializeDatabase(":memory:");
    const columns = db.prepare("PRAGMA table_info(data_files)").all() as {
      name: string;
    }[];
    const columnNames = columns.map((c) => c.name);
    expect(columnNames).toContain("id");
    expect(columnNames).toContain("file_id");
    expect(columnNames).toContain("schema_id");
    expect(columnNames).toContain("path");
    expect(columnNames).toContain("scope");
    expect(columnNames).toContain("collected_at");
    expect(columnNames).toContain("created_at");
    expect(columnNames).toContain("size_bytes");
    expect(columnNames).toContain("version");
    expect(columnNames).toContain("data_point_id");
    db.close();
  });

  it("sets WAL journal mode", async () => {
    const tempDir = await mkdtemp(join(tmpdir(), "schema-wal-"));
    const dbPath = join(tempDir, "wal-test.db");
    const db = initializeDatabase(dbPath);
    const result = db.pragma("journal_mode") as { journal_mode: string }[];
    expect(result[0]!.journal_mode).toBe("wal");
    db.close();
    await rm(tempDir, { recursive: true });
  });

  it("is idempotent when called twice on same path", async () => {
    const tempDir = await mkdtemp(join(tmpdir(), "schema-test-"));
    const dbPath = join(tempDir, "test.db");

    const db1 = initializeDatabase(dbPath);
    db1.close();

    const db2 = initializeDatabase(dbPath);
    const row = db2
      .prepare(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='data_files'",
      )
      .get() as { name: string } | undefined;
    expect(row).toBeDefined();
    db2.close();

    await rm(tempDir, { recursive: true });
  });

  it("sets the index schema version without dropping existing rows", async () => {
    const tempDir = await mkdtemp(join(tmpdir(), "schema-version-"));
    const dbPath = join(tempDir, "version-test.db");

    const db1 = initializeDatabase(dbPath);
    db1
      .prepare(
        "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
      )
      .run(
        "instagram/profile.json",
        "instagram.profile",
        "2026-01-21T10:00:00Z",
        42,
      );
    db1.close();

    const db2 = initializeDatabase(dbPath);
    const version = db2.pragma("user_version", { simple: true });
    const row = db2
      .prepare("SELECT path, scope, size_bytes FROM data_files WHERE path = ?")
      .get("instagram/profile.json") as
      | { path: string; scope: string; size_bytes: number }
      | undefined;

    expect(version).toBe(3);
    expect(row).toEqual({
      path: "instagram/profile.json",
      scope: "instagram.profile",
      size_bytes: 42,
    });
    db2.close();

    await rm(tempDir, { recursive: true });
  });

  it("migrates an existing v1 index by adding schema_id", async () => {
    const tempDir = await mkdtemp(join(tmpdir(), "schema-migrate-"));
    const dbPath = join(tempDir, "migrate-test.db");

    const legacy = new Database(dbPath);
    legacy.exec(`
      CREATE TABLE data_files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_id TEXT,
        path TEXT NOT NULL UNIQUE,
        scope TEXT NOT NULL,
        collected_at TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
        size_bytes INTEGER NOT NULL DEFAULT 0
      );
      PRAGMA user_version = 1;
    `);
    legacy
      .prepare(
        "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
      )
      .run(
        "instagram/profile.json",
        "instagram.profile",
        "2026-01-21T10:00:00Z",
        42,
      );
    legacy.close();

    const db = initializeDatabase(dbPath);
    const version = db.pragma("user_version", { simple: true });
    const row = db
      .prepare(
        "SELECT path, schema_id, version, data_point_id FROM data_files WHERE path = ?",
      )
      .get("instagram/profile.json") as
      | {
          path: string;
          schema_id: string | null;
          version: number;
          data_point_id: string | null;
        }
      | undefined;

    expect(version).toBe(3);
    expect(row).toEqual({
      path: "instagram/profile.json",
      schema_id: null,
      // v2→v3 migration backfills legacy rows with version 1 (the same
      // starting point as a fresh ingest of a brand-new scope), and leaves
      // data_point_id null so the sync worker will register the data point
      // on the next pass.
      version: 1,
      data_point_id: null,
    });
    db.close();

    await rm(tempDir, { recursive: true });
  });

  it("migrates an existing v2 index by adding version + data_point_id", async () => {
    const tempDir = await mkdtemp(join(tmpdir(), "schema-migrate-v2-"));
    const dbPath = join(tempDir, "migrate-v2.db");

    const legacy = new Database(dbPath);
    legacy.exec(`
      CREATE TABLE data_files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_id TEXT,
        schema_id TEXT,
        path TEXT NOT NULL UNIQUE,
        scope TEXT NOT NULL,
        collected_at TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
        size_bytes INTEGER NOT NULL DEFAULT 0
      );
      PRAGMA user_version = 2;
    `);
    legacy
      .prepare(
        "INSERT INTO data_files (path, scope, collected_at, size_bytes, schema_id) VALUES (?, ?, ?, ?, ?)",
      )
      .run(
        "instagram/profile.json",
        "instagram.profile",
        "2026-01-21T10:00:00Z",
        42,
        "0xschema",
      );
    legacy.close();

    const db = initializeDatabase(dbPath);
    expect(db.pragma("user_version", { simple: true })).toBe(3);
    const row = db
      .prepare(
        "SELECT path, schema_id, version, data_point_id FROM data_files WHERE path = ?",
      )
      .get("instagram/profile.json") as
      | {
          path: string;
          schema_id: string | null;
          version: number;
          data_point_id: string | null;
        }
      | undefined;
    expect(row).toEqual({
      path: "instagram/profile.json",
      schema_id: "0xschema",
      version: 1,
      data_point_id: null,
    });
    db.close();

    await rm(tempDir, { recursive: true });
  });
});
