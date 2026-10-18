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
  data_point_id TEXT,
  after_tombstone_version INTEGER
)`;

const CREATE_INDEXES_SQL = [
  "CREATE INDEX IF NOT EXISTS idx_data_files_scope ON data_files (scope)",
  "CREATE INDEX IF NOT EXISTS idx_data_files_collected_at ON data_files (collected_at)",
  "CREATE INDEX IF NOT EXISTS idx_data_files_file_id ON data_files (file_id)",
  "CREATE INDEX IF NOT EXISTS idx_data_files_schema_id ON data_files (schema_id)",
  "CREATE INDEX IF NOT EXISTS idx_data_files_data_point_id ON data_files (data_point_id)",
];

export const INDEX_SCHEMA_VERSION = 5;

function hasColumn(
  db: Database.Database,
  table: string,
  column: string,
): boolean {
  const rows = db.pragma(`table_info(${table})`) as Array<{ name: string }>;
  return rows.some((row) => row.name === column);
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
  try {
    db.pragma("busy_timeout = 5000");
    const deadline = performance.now() + 5000;
    const pause = new Int32Array(new SharedArrayBuffer(4));
    for (;;) {
      try {
        if (db.pragma("journal_mode", { simple: true }) !== "wal") {
          db.pragma("journal_mode = WAL");
        }
        break;
      } catch (err) {
        if (
          (err as { code?: string }).code !== "SQLITE_BUSY" ||
          performance.now() >= deadline
        )
          throw err;
        Atomics.wait(pause, 0, 0, Math.min(50, deadline - performance.now()));
      }
    }
    db.pragma("synchronous = FULL");

    db.exec(CREATE_TABLE_SQL);
    ensureSchemaVersion(db);
    db.exec(`CREATE TABLE IF NOT EXISTS owner_import_operations (
    authority TEXT NOT NULL,
    owner TEXT NOT NULL,
    scope TEXT NOT NULL,
    operation TEXT NOT NULL,
    body_sha256 TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('prepared', 'accepted', 'deleted', 'cancelled')),
    collected_at TEXT NOT NULL,
    path TEXT NOT NULL,
    envelope_bytes BLOB,
    metadata_json TEXT,
    receipt_json TEXT,
    PRIMARY KEY(authority, owner, scope, operation)
  )`);
    db.exec(
      "CREATE UNIQUE INDEX IF NOT EXISTS idx_owner_import_operations_path ON owner_import_operations(path)",
    );
    db.exec(
      "CREATE INDEX IF NOT EXISTS idx_owner_import_operations_recovery ON owner_import_operations(operation) WHERE state = 'prepared' OR (state IN ('deleted', 'cancelled') AND metadata_json IS NOT NULL)",
    );
    for (const sql of CREATE_INDEXES_SQL) {
      db.exec(sql);
    }

    return db;
  } catch (err) {
    db.close();
    throw err;
  }
}
