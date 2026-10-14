import Database from "better-sqlite3";

const CREATE_TABLE_SQL = `
CREATE TABLE IF NOT EXISTS data_files (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  file_id TEXT,
  schema_id TEXT,
  path TEXT NOT NULL UNIQUE,
  scope TEXT NOT NULL,
  collected_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
  size_bytes INTEGER NOT NULL DEFAULT 0,
  version INTEGER NOT NULL DEFAULT 1,
  cas_revision INTEGER NOT NULL DEFAULT 1,
  data_point_id TEXT,
  after_tombstone_version INTEGER,
  producer TEXT,
  producer_provenance TEXT
)`;

const CREATE_SCOPE_REVISIONS_SQL = `
CREATE TABLE IF NOT EXISTS scope_revisions (
  scope TEXT PRIMARY KEY,
  cas_revision INTEGER NOT NULL,
  closed_for_writes INTEGER NOT NULL DEFAULT 0
)`;

const CREATE_INDEXES_SQL = [
  "CREATE INDEX IF NOT EXISTS idx_data_files_scope ON data_files (scope)",
  "CREATE INDEX IF NOT EXISTS idx_data_files_collected_at ON data_files (collected_at)",
  "CREATE INDEX IF NOT EXISTS idx_data_files_file_id ON data_files (file_id)",
  "CREATE INDEX IF NOT EXISTS idx_data_files_schema_id ON data_files (schema_id)",
  "CREATE INDEX IF NOT EXISTS idx_data_files_data_point_id ON data_files (data_point_id)",
  "CREATE INDEX IF NOT EXISTS idx_data_files_scope_cas_revision ON data_files (scope, cas_revision)",
];

export const INDEX_SCHEMA_VERSION = 14;

const CREATE_LEGACY_SCOPE_TAKEOVERS_SQL = `
CREATE TABLE IF NOT EXISTS legacy_scope_takeovers (
  scope TEXT NOT NULL,
  instance TEXT NOT NULL DEFAULT '',
  generation INTEGER NOT NULL DEFAULT 1,
  superseded_version INTEGER NOT NULL,
  superseded_cas_revision INTEGER NOT NULL,
  superseded_collected_at TEXT NOT NULL,
  superseded_path TEXT NOT NULL,
  taken_over_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  PRIMARY KEY (scope, instance, generation, superseded_path)
)`;

const CREATE_LEGACY_SCOPE_VERDICTS_SQL = `
CREATE TABLE IF NOT EXISTS legacy_scope_takeover_verdicts (
  scope TEXT NOT NULL,
  instance TEXT NOT NULL,
  generation INTEGER NOT NULL DEFAULT 1,
  legacy_version_id INTEGER NOT NULL,
  canonical_cursor TEXT NOT NULL,
  verdict TEXT NOT NULL CHECK (verdict IN ('covered', 'not_covered')),
  comparison_case TEXT NOT NULL,
  reason_counts_json TEXT NOT NULL,
  applied_exceptions_json TEXT NOT NULL,
  reason_json TEXT,
  legacy_bytes INTEGER NOT NULL,
  canonical_bytes INTEGER NOT NULL,
  byte_delta INTEGER NOT NULL,
  evaluated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  PRIMARY KEY (scope, instance, generation)
)`;

const CREATE_LEGACY_SCOPE_RESETS_SQL = `
CREATE TABLE IF NOT EXISTS legacy_scope_takeover_resets (
  scope TEXT PRIMARY KEY,
  reset_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
)`;

function hasColumn(
  db: Database.Database,
  table: string,
  column: string,
): boolean {
  const rows = db.pragma(`table_info(${table})`) as Array<{ name: string }>;
  return rows.some((row) => row.name === column);
}

function hasTable(db: Database.Database, table: string): boolean {
  return (
    db
      .prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?")
      .get(table) !== undefined
  );
}

function migrateSchema(db: Database.Database, currentVersion: number): void {
  if (currentVersion < 2 && !hasColumn(db, "data_files", "schema_id")) {
    db.exec("ALTER TABLE data_files ADD COLUMN schema_id TEXT");
  }
  if (currentVersion < 3) {
    if (!hasColumn(db, "data_files", "version")) {
      // Pre-DPv2 rows get version 1 — the same default that fresh ingests
      // start at, so subsequent ingests of the same scope keep incrementing
      // from there without colliding with the legacy row.
      db.exec(
        "ALTER TABLE data_files ADD COLUMN version INTEGER NOT NULL DEFAULT 1",
      );
    }
    if (!hasColumn(db, "data_files", "data_point_id")) {
      db.exec("ALTER TABLE data_files ADD COLUMN data_point_id TEXT");
    }
  }
  if (
    currentVersion < 4 &&
    !hasColumn(db, "data_files", "after_tombstone_version")
  ) {
    // Null for every existing row: nothing ingested before this column
    // existed can claim to post-date a tombstone.
    db.exec(
      "ALTER TABLE data_files ADD COLUMN after_tombstone_version INTEGER",
    );
  }
  if (currentVersion < 5) {
    if (!hasColumn(db, "data_files", "producer")) {
      db.exec("ALTER TABLE data_files ADD COLUMN producer TEXT");
    }
    if (!hasColumn(db, "data_files", "producer_provenance")) {
      db.exec("ALTER TABLE data_files ADD COLUMN producer_provenance TEXT");
    }
  }
  if (currentVersion < 6) {
    if (!hasColumn(db, "data_files", "cas_revision")) {
      db.exec(
        "ALTER TABLE data_files ADD COLUMN cas_revision INTEGER NOT NULL DEFAULT 1",
      );
      db.exec("UPDATE data_files SET cas_revision = version");
    }
    db.exec(CREATE_SCOPE_REVISIONS_SQL);
    db.exec(`
      INSERT OR IGNORE INTO scope_revisions (scope, cas_revision)
      SELECT scope, MAX(cas_revision) FROM data_files GROUP BY scope
    `);
  }
  if (
    currentVersion < 7 &&
    !hasColumn(db, "scope_revisions", "closed_for_writes")
  ) {
    db.exec(
      "ALTER TABLE scope_revisions ADD COLUMN closed_for_writes INTEGER NOT NULL DEFAULT 0",
    );
  }
  if (
    currentVersion < 10 &&
    !hasColumn(db, "legacy_scope_takeovers", "instance")
  ) {
    db.exec("ALTER TABLE legacy_scope_takeovers ADD COLUMN instance TEXT");
  }
  if (
    currentVersion < 11 &&
    !hasColumn(db, "legacy_scope_takeover_verdicts", "comparison_case")
  ) {
    db.exec(
      "ALTER TABLE legacy_scope_takeover_verdicts ADD COLUMN comparison_case TEXT NOT NULL DEFAULT 'same_time'",
    );
  }
  if (
    currentVersion < 11 &&
    !hasColumn(db, "legacy_scope_takeover_verdicts", "reason_counts_json")
  ) {
    db.exec(
      "ALTER TABLE legacy_scope_takeover_verdicts ADD COLUMN reason_counts_json TEXT NOT NULL DEFAULT '{}'",
    );
  }
  if (
    currentVersion < 12 &&
    !hasColumn(db, "legacy_scope_takeover_verdicts", "applied_exceptions_json")
  ) {
    db.exec(
      "ALTER TABLE legacy_scope_takeover_verdicts ADD COLUMN applied_exceptions_json TEXT NOT NULL DEFAULT '[]'",
    );
  }
  if (currentVersion < 13) {
    const columns = db.pragma("table_info(legacy_scope_takeovers)") as Array<{
      name: string;
      pk: number;
    }>;
    if (columns.find((column) => column.name === "instance")?.pk !== 2) {
      db.transaction(() => {
        db.exec(
          "ALTER TABLE legacy_scope_takeovers RENAME TO legacy_scope_takeovers_old",
        );
        db.exec(CREATE_LEGACY_SCOPE_TAKEOVERS_SQL);
        db.exec(`INSERT INTO legacy_scope_takeovers
          (scope, instance, superseded_version, superseded_cas_revision,
           superseded_collected_at, superseded_path, taken_over_at)
          SELECT scope, COALESCE(instance, ''), superseded_version,
                 superseded_cas_revision, superseded_collected_at,
                 superseded_path, taken_over_at
          FROM legacy_scope_takeovers_old`);
        db.exec("DROP TABLE legacy_scope_takeovers_old");
      })();
    }
  }
  if (currentVersion < 14) {
    db.transaction(() => {
      db.exec(
        "ALTER TABLE legacy_scope_takeovers RENAME TO legacy_scope_takeovers_old",
      );
      db.exec(CREATE_LEGACY_SCOPE_TAKEOVERS_SQL);
      const takeoverGeneration = hasTable(db, "pdpp_instance_binding")
        ? "COALESCE((SELECT generation FROM pdpp_instance_binding WHERE instance = legacy_scope_takeovers_old.instance), 1)"
        : "1";
      db.exec(`INSERT INTO legacy_scope_takeovers
        (scope, instance, generation, superseded_version, superseded_cas_revision,
         superseded_collected_at, superseded_path, taken_over_at)
        SELECT scope, instance, ${takeoverGeneration}, superseded_version, superseded_cas_revision,
               superseded_collected_at, superseded_path, taken_over_at
        FROM legacy_scope_takeovers_old`);
      db.exec("DROP TABLE legacy_scope_takeovers_old");

      db.exec(
        "ALTER TABLE legacy_scope_takeover_verdicts RENAME TO legacy_scope_takeover_verdicts_old",
      );
      db.exec(CREATE_LEGACY_SCOPE_VERDICTS_SQL);
      const verdictGeneration = hasTable(db, "pdpp_instance_binding")
        ? "COALESCE((SELECT generation FROM pdpp_instance_binding WHERE instance = legacy_scope_takeover_verdicts_old.instance), 1)"
        : "1";
      db.exec(`INSERT INTO legacy_scope_takeover_verdicts
        (scope, instance, generation, legacy_version_id, canonical_cursor,
         verdict, comparison_case, reason_counts_json, applied_exceptions_json,
         reason_json, legacy_bytes, canonical_bytes, byte_delta, evaluated_at)
        SELECT scope, instance, ${verdictGeneration}, legacy_version_id, canonical_cursor, verdict,
               comparison_case, reason_counts_json, applied_exceptions_json,
               reason_json, legacy_bytes, canonical_bytes, byte_delta, evaluated_at
        FROM legacy_scope_takeover_verdicts_old`);
      db.exec("DROP TABLE legacy_scope_takeover_verdicts_old");
    })();
  }
}

function ensureSchemaVersion(db: Database.Database): void {
  const currentVersion = db.pragma("user_version", { simple: true }) as number;
  if (currentVersion > INDEX_SCHEMA_VERSION) {
    throw new Error(
      `Unsupported index.db schema version ${currentVersion}; runtime supports ${INDEX_SCHEMA_VERSION}`,
    );
  }
  migrateSchema(db, currentVersion);
  db.pragma(`user_version = ${INDEX_SCHEMA_VERSION}`);
}

/** Open/create SQLite database, run CREATE TABLE IF NOT EXISTS, set WAL mode */
export function initializeDatabase(dbPath: string): Database.Database {
  const db = new Database(dbPath);

  db.pragma("journal_mode = WAL");

  db.exec(CREATE_TABLE_SQL);
  db.exec(CREATE_SCOPE_REVISIONS_SQL);
  db.exec(CREATE_LEGACY_SCOPE_TAKEOVERS_SQL);
  db.exec(CREATE_LEGACY_SCOPE_VERDICTS_SQL);
  db.exec(CREATE_LEGACY_SCOPE_RESETS_SQL);
  ensureSchemaVersion(db);
  for (const sql of CREATE_INDEXES_SQL) {
    db.exec(sql);
  }

  return db;
}
