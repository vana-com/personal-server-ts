import { describe, it, expect } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import Database from "better-sqlite3";
import { initializeDatabase } from "./index-schema.js";

function createHistoricalIndexBase(db: Database.Database, version: number) {
  db.exec(`
    CREATE TABLE data_files (
      id INTEGER PRIMARY KEY AUTOINCREMENT, file_id TEXT, schema_id TEXT,
      path TEXT NOT NULL UNIQUE, scope TEXT NOT NULL, collected_at TEXT NOT NULL,
      created_at TEXT, size_bytes INTEGER NOT NULL DEFAULT 0, version TEXT,
      cas_revision INTEGER, data_point_id TEXT, producer TEXT,
      producer_provenance TEXT
    );
    CREATE TABLE scope_revisions (scope TEXT PRIMARY KEY, revision INTEGER NOT NULL DEFAULT 0);
  `);
  db.pragma(`user_version = ${version}`);
}

function createV13TakeoverTables(db: Database.Database) {
  db.exec(`
    CREATE TABLE pdpp_instance_binding (
      instance TEXT PRIMARY KEY, generation INTEGER NOT NULL
    );
    CREATE TABLE legacy_scope_takeovers (
      scope TEXT NOT NULL, instance TEXT NOT NULL,
      superseded_version INTEGER NOT NULL, superseded_cas_revision INTEGER NOT NULL,
      superseded_collected_at TEXT NOT NULL, superseded_path TEXT NOT NULL,
      taken_over_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
      PRIMARY KEY (scope, instance, superseded_path)
    );
    CREATE TABLE legacy_scope_takeover_verdicts (
      scope TEXT NOT NULL, instance TEXT NOT NULL, legacy_version_id INTEGER NOT NULL,
      canonical_cursor TEXT NOT NULL, verdict TEXT NOT NULL, comparison_case TEXT NOT NULL,
      reason_counts_json TEXT NOT NULL, applied_exceptions_json TEXT NOT NULL,
      reason_json TEXT, legacy_bytes INTEGER NOT NULL, canonical_bytes INTEGER NOT NULL,
      byte_delta INTEGER NOT NULL, evaluated_at TEXT NOT NULL,
      PRIMARY KEY (scope, instance)
    );
  `);
}

function createV14TakeoverTables(db: Database.Database) {
  db.exec(`
    CREATE TABLE legacy_scope_takeovers (
      scope TEXT NOT NULL, instance TEXT NOT NULL, generation INTEGER NOT NULL,
      superseded_version INTEGER NOT NULL, superseded_cas_revision INTEGER NOT NULL,
      superseded_collected_at TEXT NOT NULL, superseded_path TEXT NOT NULL,
      taken_over_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
      PRIMARY KEY (scope, instance, generation, superseded_path)
    );
    CREATE TABLE legacy_scope_takeover_verdicts (
      scope TEXT NOT NULL, instance TEXT NOT NULL, generation INTEGER NOT NULL,
      legacy_version_id INTEGER NOT NULL, canonical_cursor TEXT NOT NULL,
      verdict TEXT NOT NULL, comparison_case TEXT NOT NULL,
      reason_counts_json TEXT NOT NULL DEFAULT '{}',
      applied_exceptions_json TEXT NOT NULL DEFAULT '[]', reason_json TEXT,
      legacy_bytes INTEGER NOT NULL, canonical_bytes INTEGER NOT NULL,
      byte_delta INTEGER NOT NULL, evaluated_at TEXT NOT NULL,
      PRIMARY KEY (scope, instance, generation)
    );
  `);
}

describe("initializeDatabase", () => {
  it("upgrades an owner-import canary index stamped version 5 without producer columns", async () => {
    const dir = await mkdtemp(join(tmpdir(), "ps-index-owner-import-v5-"));
    try {
      const path = join(dir, "index.db");
      const canary = new Database(path);
      canary.exec(`
        CREATE TABLE data_files (
          id INTEGER PRIMARY KEY AUTOINCREMENT, file_id TEXT, schema_id TEXT,
          path TEXT NOT NULL UNIQUE, scope TEXT NOT NULL, collected_at TEXT NOT NULL,
          created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
          size_bytes INTEGER NOT NULL DEFAULT 0, version INTEGER NOT NULL DEFAULT 1,
          data_point_id TEXT, after_tombstone_version INTEGER
        );
        INSERT INTO data_files (path, scope, collected_at, size_bytes, version)
          VALUES ('instagram/profile/a.json', 'instagram.profile', '2026-01-01T00:00:00Z', 7, 3);
        CREATE TABLE owner_import_operations (
          authority TEXT NOT NULL, owner TEXT NOT NULL, scope TEXT NOT NULL,
          operation TEXT NOT NULL, body_sha256 TEXT NOT NULL,
          state TEXT NOT NULL CHECK(state IN ('prepared', 'accepted', 'deleted', 'cancelled')),
          collected_at TEXT NOT NULL, path TEXT NOT NULL, envelope_bytes BLOB,
          metadata_json TEXT, receipt_json TEXT,
          PRIMARY KEY(authority, owner, scope, operation)
        );
        INSERT INTO owner_import_operations
          VALUES ('local', '0xowner', 'instagram.profile', 'op', 'hash', 'accepted',
                  '2026-01-01T00:00:00Z', 'instagram/profile/a.json', NULL, NULL, '{}');
      `);
      canary.pragma("user_version = 5");
      canary.close();

      const db = initializeDatabase(path);
      expect(db.pragma("user_version", { simple: true })).toBe(16);
      expect(
        db
          .prepare(
            "SELECT version, cas_revision, producer, producer_provenance FROM data_files",
          )
          .get(),
      ).toEqual({
        version: 3,
        cas_revision: 3,
        producer: null,
        producer_provenance: null,
      });
      expect(
        db
          .prepare("SELECT operation, state FROM owner_import_operations")
          .get(),
      ).toEqual({ operation: "op", state: "accepted" });
      db.close();
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

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

  it("creates the durable legacy scope takeover ledger", () => {
    const db = initializeDatabase(":memory:");
    const row = db
      .prepare(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='legacy_scope_takeovers'",
      )
      .get() as { name: string } | undefined;
    expect(row?.name).toBe("legacy_scope_takeovers");
    const columns = db
      .prepare("PRAGMA table_info(legacy_scope_takeovers)")
      .all() as { name: string }[];
    expect(columns.map((column) => column.name)).toEqual([
      "scope",
      "instance",
      "generation",
      "superseded_version",
      "superseded_cas_revision",
      "superseded_collected_at",
      "superseded_path",
      "taken_over_at",
    ]);
    db.close();
  });

  it("migrates a v8 takeover ledger without losing its recorded file", async () => {
    const dir = await mkdtemp(join(tmpdir(), "legacy-takeover-schema-"));
    try {
      const path = join(dir, "index.db");
      const old = initializeDatabase(path);
      old.exec(`DROP TABLE legacy_scope_takeovers;
        CREATE TABLE legacy_scope_takeovers (
          scope TEXT NOT NULL, superseded_version INTEGER NOT NULL,
          superseded_cas_revision INTEGER NOT NULL,
          superseded_collected_at TEXT NOT NULL, superseded_path TEXT NOT NULL,
          taken_over_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
          PRIMARY KEY (scope, superseded_path)
        );
        INSERT INTO legacy_scope_takeovers
          (scope, superseded_version, superseded_cas_revision, superseded_collected_at, superseded_path)
          VALUES ('oura.activity', 7, 9, '2026-01-01T00:00:00Z', 'oura/activity/old.json');
      `);
      old.pragma("user_version = 8");
      old.close();
      const migrated = initializeDatabase(path);
      expect(
        migrated
          .prepare(
            "SELECT scope, instance, generation, superseded_path FROM legacy_scope_takeovers",
          )
          .all(),
      ).toEqual([
        {
          scope: "oura.activity",
          instance: "",
          generation: 1,
          superseded_path: "oura/activity/old.json",
        },
      ]);
      expect(
        migrated
          .prepare(
            "SELECT name FROM sqlite_master WHERE name = 'legacy_scope_takeover_verdicts'",
          )
          .get(),
      ).toBeDefined();
      migrated.close();
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("migrates a v10 verdict row with comparison diagnostics", async () => {
    const dir = await mkdtemp(join(tmpdir(), "legacy-verdict-schema-"));
    try {
      const path = join(dir, "index.db");
      const old = initializeDatabase(path);
      old.exec(`DROP TABLE legacy_scope_takeover_verdicts;
        CREATE TABLE pdpp_instance_binding (
          instance TEXT PRIMARY KEY, generation INTEGER NOT NULL
        );
        INSERT INTO pdpp_instance_binding VALUES ('owner-1', 3);
        CREATE TABLE legacy_scope_takeover_verdicts (
          scope TEXT NOT NULL, instance TEXT NOT NULL,
          legacy_version_id INTEGER NOT NULL, canonical_cursor TEXT NOT NULL,
          verdict TEXT NOT NULL, reason_json TEXT,
          legacy_bytes INTEGER NOT NULL, canonical_bytes INTEGER NOT NULL,
          byte_delta INTEGER NOT NULL, evaluated_at TEXT NOT NULL,
          PRIMARY KEY (scope, instance)
        );
        INSERT INTO legacy_scope_takeover_verdicts VALUES
          ('oura.activity', 'owner-1', 42, '1:revision', 'covered', NULL,
           10, 10, 0, '2026-01-01T00:00:00Z');
      `);
      old.pragma("user_version = 10");
      old.close();
      const migrated = initializeDatabase(path);
      expect(
        migrated
          .prepare(
            "SELECT generation, legacy_version_id, comparison_case, reason_counts_json, applied_exceptions_json FROM legacy_scope_takeover_verdicts",
          )
          .get(),
      ).toEqual({
        generation: 3,
        legacy_version_id: 42,
        comparison_case: "same_time",
        reason_counts_json: "{}",
        applied_exceptions_json: "[]",
      });
      expect(migrated.pragma("user_version", { simple: true })).toBe(16);
      migrated.close();
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("upgrades a populated raw v13 index and preserves every verdict and takeover field", async () => {
    const dir = await mkdtemp(join(tmpdir(), "legacy-v13-index-"));
    const path = join(dir, "index.db");
    try {
      const historical = new Database(path);
      createHistoricalIndexBase(historical, 13);
      createV13TakeoverTables(historical);
      historical.exec(`
        INSERT INTO pdpp_instance_binding VALUES ('bound-owner', 4);
        INSERT INTO legacy_scope_takeovers
          (scope, instance, superseded_version, superseded_cas_revision,
           superseded_collected_at, superseded_path, taken_over_at)
        VALUES ('oura.activity', 'bound-owner', 22, 31, '2026-01-01T00:00:00Z',
          'oura/activity/old.json', '2026-02-01T00:00:00Z');
        INSERT INTO legacy_scope_takeovers
          (scope, instance, superseded_version, superseded_cas_revision,
           superseded_collected_at, superseded_path, taken_over_at)
        VALUES ('strava.activities', 'unbound-owner', 8, 9, '2026-03-01T00:00:00Z',
          'strava/activities/old.json', '2026-04-01T00:00:00Z');
        INSERT INTO legacy_scope_takeover_verdicts VALUES
          ('oura.activity', 'bound-owner', 71, 'cursor:71', 'not_covered', 'same_time',
           '{"field_mismatch":2}', '[{"id":"exception-1"}]',
           '{"reason":"field_mismatch"}', 123, 456, 333, '2026-05-01T00:00:00Z');
        INSERT INTO legacy_scope_takeover_verdicts VALUES
          ('strava.activities', 'unbound-owner', 8, 'cursor:8', 'covered', 'older_legacy',
           '{}', '[]', NULL, 10, 10, 0, '2026-05-02T00:00:00Z');
      `);
      historical.close();

      const expectedTakeovers = [
        {
          scope: "oura.activity",
          instance: "bound-owner",
          generation: 4,
          superseded_version: 22,
          superseded_cas_revision: 31,
          superseded_collected_at: "2026-01-01T00:00:00Z",
          superseded_path: "oura/activity/old.json",
          taken_over_at: "2026-02-01T00:00:00Z",
        },
        {
          scope: "strava.activities",
          instance: "unbound-owner",
          generation: 1,
          superseded_version: 8,
          superseded_cas_revision: 9,
          superseded_collected_at: "2026-03-01T00:00:00Z",
          superseded_path: "strava/activities/old.json",
          taken_over_at: "2026-04-01T00:00:00Z",
        },
      ];
      const expectedVerdicts = [
        {
          scope: "oura.activity",
          instance: "bound-owner",
          generation: 4,
          legacy_version_id: 71,
          canonical_cursor: "cursor:71",
          verdict: "not_covered",
          comparison_case: "same_time",
          reason_counts_json: '{"field_mismatch":2}',
          applied_exceptions_json: '[{"id":"exception-1"}]',
          reason_json: '{"reason":"field_mismatch"}',
          legacy_bytes: 123,
          canonical_bytes: 456,
          byte_delta: 333,
          evaluated_at: "2026-05-01T00:00:00Z",
        },
        {
          scope: "strava.activities",
          instance: "unbound-owner",
          generation: 1,
          legacy_version_id: 8,
          canonical_cursor: "cursor:8",
          verdict: "covered",
          comparison_case: "older_legacy",
          reason_counts_json: "{}",
          applied_exceptions_json: "[]",
          reason_json: null,
          legacy_bytes: 10,
          canonical_bytes: 10,
          byte_delta: 0,
          evaluated_at: "2026-05-02T00:00:00Z",
        },
      ];

      const upgraded = initializeDatabase(path);
      expect(upgraded.pragma("user_version", { simple: true })).toBe(16);
      expect(
        upgraded
          .prepare("SELECT * FROM legacy_scope_takeovers ORDER BY scope")
          .all(),
      ).toEqual(expectedTakeovers);
      expect(
        upgraded
          .prepare(
            "SELECT * FROM legacy_scope_takeover_verdicts ORDER BY scope",
          )
          .all(),
      ).toEqual(expectedVerdicts);
      upgraded.close();

      const reopened = initializeDatabase(path);
      expect(reopened.pragma("user_version", { simple: true })).toBe(16);
      expect(
        reopened
          .prepare("SELECT * FROM legacy_scope_takeovers ORDER BY scope")
          .all(),
      ).toEqual(expectedTakeovers);
      expect(
        reopened
          .prepare(
            "SELECT * FROM legacy_scope_takeover_verdicts ORDER BY scope",
          )
          .all(),
      ).toEqual(expectedVerdicts);
      reopened.close();
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("preserves multiple generation rows in an existing v14 index", async () => {
    const dir = await mkdtemp(join(tmpdir(), "legacy-v14-index-"));
    const path = join(dir, "index.db");
    try {
      const historical = new Database(path);
      createHistoricalIndexBase(historical, 14);
      createV14TakeoverTables(historical);
      historical.exec(`
        INSERT INTO legacy_scope_takeovers
          (scope, instance, generation, superseded_version, superseded_cas_revision,
           superseded_collected_at, superseded_path, taken_over_at)
        VALUES
          ('oura.activity', 'owner', 1, 2, 3, '2026-01-01T00:00:00Z', 'old-1.json', '2026-02-01T00:00:00Z'),
          ('oura.activity', 'owner', 2, 4, 5, '2026-03-01T00:00:00Z', 'old-2.json', '2026-04-01T00:00:00Z');
        INSERT INTO legacy_scope_takeover_verdicts
          (scope, instance, generation, legacy_version_id, canonical_cursor, verdict,
           comparison_case, reason_counts_json, applied_exceptions_json, reason_json,
           legacy_bytes, canonical_bytes, byte_delta, evaluated_at)
        VALUES
          ('oura.activity', 'owner', 1, 2, 'cursor-1', 'covered', 'same_time', '{}', '[]', NULL, 10, 10, 0, '2026-02-01T00:00:00Z'),
          ('oura.activity', 'owner', 2, 4, 'cursor-2', 'not_covered', 'same_time', '{"field_mismatch":1}', '["exception"]', '{"reason":"field_mismatch"}', 10, 11, 1, '2026-04-01T00:00:00Z');
      `);
      historical.close();

      const expected = {
        takeovers: [
          { generation: 1, superseded_path: "old-1.json" },
          { generation: 2, superseded_path: "old-2.json" },
        ],
        verdicts: [
          {
            generation: 1,
            reason_counts_json: "{}",
            applied_exceptions_json: "[]",
          },
          {
            generation: 2,
            reason_counts_json: '{"field_mismatch":1}',
            applied_exceptions_json: '["exception"]',
          },
        ],
      };
      const upgraded = initializeDatabase(path);
      expect(upgraded.pragma("user_version", { simple: true })).toBe(16);
      expect(
        upgraded
          .prepare(
            "SELECT generation, superseded_path FROM legacy_scope_takeovers ORDER BY generation",
          )
          .all(),
      ).toEqual(expected.takeovers);
      expect(
        upgraded
          .prepare(
            "SELECT generation, reason_counts_json, applied_exceptions_json FROM legacy_scope_takeover_verdicts ORDER BY generation",
          )
          .all(),
      ).toEqual(expected.verdicts);
      upgraded.close();
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("recovers when v14 rebuild committed but the user_version stamp did not", async () => {
    const dir = await mkdtemp(join(tmpdir(), "legacy-v13-rebuild-crash-"));
    const path = join(dir, "index.db");
    try {
      const crashPoint = new Database(path);
      createHistoricalIndexBase(crashPoint, 13);
      // This is the durable state after the v13-to-v14 transaction committed
      // and before ensureSchemaVersion wrote user_version=14.
      crashPoint.exec(`
        CREATE TABLE pdpp_instance_binding (
          instance TEXT PRIMARY KEY, generation INTEGER NOT NULL
        );
        INSERT INTO pdpp_instance_binding VALUES ('owner', 7);
      `);
      createV14TakeoverTables(crashPoint);
      crashPoint.exec(`
        INSERT INTO legacy_scope_takeovers
          (scope, instance, generation, superseded_version, superseded_cas_revision,
           superseded_collected_at, superseded_path, taken_over_at)
        VALUES ('oura.activity', 'owner', 7, 8, 9, '2026-01-01T00:00:00Z', 'old.json', '2026-02-01T00:00:00Z');
        INSERT INTO legacy_scope_takeover_verdicts
          (scope, instance, generation, legacy_version_id, canonical_cursor, verdict,
           comparison_case, reason_counts_json, applied_exceptions_json, reason_json,
           legacy_bytes, canonical_bytes, byte_delta, evaluated_at)
        VALUES ('oura.activity', 'owner', 7, 8, 'cursor', 'not_covered', 'same_time',
          '{"field_mismatch":1}', '[]', '{"reason":"field_mismatch"}', 10, 11, 1, '2026-02-01T00:00:00Z');
      `);
      crashPoint.close();

      const recovered = initializeDatabase(path);
      expect(recovered.pragma("user_version", { simple: true })).toBe(16);
      expect(
        recovered
          .prepare(
            "SELECT generation, superseded_path FROM legacy_scope_takeovers",
          )
          .all(),
      ).toEqual([{ generation: 7, superseded_path: "old.json" }]);
      expect(
        recovered
          .prepare(
            "SELECT generation, reason_counts_json FROM legacy_scope_takeover_verdicts",
          )
          .all(),
      ).toEqual([
        { generation: 7, reason_counts_json: '{"field_mismatch":1}' },
      ]);
      recovered.close();
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
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
    expect(columnNames).toContain("cas_revision");
    expect(columnNames).toContain("data_point_id");
    expect(columnNames).toContain("producer");
    expect(columnNames).toContain("producer_provenance");
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
      { path: string; scope: string; size_bytes: number } | undefined;

    expect(version).toBe(16);
    expect(row).toEqual({
      path: "instagram/profile.json",
      scope: "instagram.profile",
      size_bytes: 42,
    });
    db2.close();

    await rm(tempDir, { recursive: true });
  });

  it("migrates a v15 index by adding a null generation to every row", async () => {
    const tempDir = await mkdtemp(join(tmpdir(), "schema-v15-"));
    const dbPath = join(tempDir, "v15.db");
    try {
      const v15 = initializeDatabase(dbPath);
      v15.exec("ALTER TABLE data_files DROP COLUMN generation");
      v15
        .prepare(
          "INSERT INTO data_files (path, scope, collected_at, size_bytes, pdpp_origin) VALUES (?, ?, ?, ?, ?)",
        )
        .run(
          "oura/activity/a.json",
          "oura.activity",
          "2026-01-01T00:00:00Z",
          7,
          0,
        );
      v15.pragma("user_version = 15");
      v15.close();

      const db = initializeDatabase(dbPath);
      expect(db.pragma("user_version", { simple: true })).toBe(16);
      expect(
        db
          .prepare("SELECT path, pdpp_origin, generation FROM data_files")
          .get(),
      ).toEqual({
        path: "oura/activity/a.json",
        pdpp_origin: 0,
        generation: null,
      });
      db.close();
    } finally {
      await rm(tempDir, { recursive: true, force: true });
    }
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
        "SELECT path, schema_id, version, cas_revision, data_point_id FROM data_files WHERE path = ?",
      )
      .get("instagram/profile.json") as
      | {
          path: string;
          schema_id: string | null;
          version: number;
          cas_revision: number;
          data_point_id: string | null;
        }
      | undefined;

    expect(version).toBe(16);
    expect(row).toEqual({
      path: "instagram/profile.json",
      schema_id: null,
      // v2→v3 migration backfills legacy rows with version 1 (the same
      // starting point as a fresh ingest of a brand-new scope), and leaves
      // data_point_id null so the sync worker will register the data point
      // on the next pass.
      version: 1,
      cas_revision: 1,
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
    expect(db.pragma("user_version", { simple: true })).toBe(16);
    const row = db
      .prepare(
        "SELECT path, schema_id, version, cas_revision, data_point_id FROM data_files WHERE path = ?",
      )
      .get("instagram/profile.json") as
      | {
          path: string;
          schema_id: string | null;
          version: number;
          cas_revision: number;
          data_point_id: string | null;
        }
      | undefined;
    expect(row).toEqual({
      path: "instagram/profile.json",
      schema_id: "0xschema",
      version: 1,
      cas_revision: 1,
      data_point_id: null,
    });
    db.close();

    await rm(tempDir, { recursive: true });
  });

  it("migrates an existing v3 index by adding after_tombstone_version, null for every row", async () => {
    const tempDir = await mkdtemp(join(tmpdir(), "schema-v4-"));
    const dbPath = join(tempDir, "index.db");
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
        size_bytes INTEGER NOT NULL DEFAULT 0,
        version INTEGER NOT NULL DEFAULT 1,
        data_point_id TEXT
      );
      PRAGMA user_version = 3;
    `);
    legacy
      .prepare(
        "INSERT INTO data_files (path, scope, collected_at, size_bytes, version, data_point_id) VALUES (?, ?, ?, ?, ?, ?)",
      )
      .run(
        "instagram/profile.json",
        "instagram.profile",
        "2026-01-21T10:00:00Z",
        42,
        7,
        "0xdp",
      );
    legacy.close();

    const db = initializeDatabase(dbPath);
    expect(db.pragma("user_version", { simple: true })).toBe(16);
    const row = db
      .prepare(
        "SELECT path, version, cas_revision, data_point_id, after_tombstone_version FROM data_files WHERE path = ?",
      )
      .get("instagram/profile.json") as
      | {
          path: string;
          version: number;
          cas_revision: number;
          data_point_id: string | null;
          after_tombstone_version: number | null;
        }
      | undefined;
    // Nothing ingested before the column existed can claim to post-date a
    // tombstone.
    expect(row).toEqual({
      path: "instagram/profile.json",
      version: 7,
      cas_revision: 7,
      data_point_id: "0xdp",
      after_tombstone_version: null,
    });
    db.close();
    await rm(tempDir, { recursive: true });
  });

  it("migrates a v6 scope revision without closing it for writes", async () => {
    const tempDir = await mkdtemp(join(tmpdir(), "schema-migrate-v6-"));
    const dbPath = join(tempDir, "index.db");
    const legacy = new Database(dbPath);
    legacy.exec(`
      CREATE TABLE scope_revisions (
        scope TEXT PRIMARY KEY,
        cas_revision INTEGER NOT NULL
      );
      INSERT INTO scope_revisions (scope, cas_revision)
      VALUES ('instagram.profile', 4);
      PRAGMA user_version = 6;
    `);
    legacy.close();

    const db = initializeDatabase(dbPath);
    expect(db.pragma("user_version", { simple: true })).toBe(16);
    expect(
      db
        .prepare(
          "SELECT cas_revision, closed_for_writes FROM scope_revisions WHERE scope = ?",
        )
        .get("instagram.profile"),
    ).toEqual({ cas_revision: 4, closed_for_writes: 0 });
    db.close();
    await rm(tempDir, { recursive: true });
  });
});
