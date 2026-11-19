/** Persistent main-database relations. No canonical body or cursor is rewritten. */
export const WORKSPACE_SCHEMA: readonly string[] = [
  `CREATE TABLE workspace_authority(connection TEXT PRIMARY KEY, incarnation TEXT NOT NULL, key_check TEXT NOT NULL, head TEXT NOT NULL) WITHOUT ROWID`,
  `CREATE TABLE workspaces(operation TEXT PRIMARY KEY, binding TEXT NOT NULL, phase TEXT NOT NULL DEFAULT 'collect', position INTEGER NOT NULL DEFAULT 0, schema_version INTEGER NOT NULL DEFAULT 1) WITHOUT ROWID`,
  `CREATE TABLE workspace_assert(ok INTEGER NOT NULL CHECK(ok=1))`,
  `CREATE TABLE workspace_cells(operation TEXT NOT NULL, relation TEXT NOT NULL, key TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(operation,relation,key)) WITHOUT ROWID`,
  `CREATE TABLE workspace_stage(operation TEXT NOT NULL, unit TEXT NOT NULL, relation TEXT NOT NULL, key TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(operation,unit,relation,key)) WITHOUT ROWID`,
  `CREATE TABLE workspace_receipts(operation TEXT NOT NULL, unit TEXT NOT NULL, digest TEXT NOT NULL, position INTEGER NOT NULL, PRIMARY KEY(operation,unit), UNIQUE(operation,position)) WITHOUT ROWID`,
  `CREATE TABLE body_values(id TEXT UNIQUE NOT NULL, operation TEXT NOT NULL, bytes INTEGER NOT NULL CHECK(bytes>=0), digest TEXT NOT NULL, encoding TEXT NOT NULL CHECK(encoding IN ('binary','utf8')), offset INTEGER NOT NULL DEFAULT 0, sealed INTEGER NOT NULL DEFAULT 0, aborted INTEGER NOT NULL DEFAULT 0)`,
  `CREATE INDEX body_values_operation ON body_values(operation,id)`,
  // Bounded chunk rows are the portable fallback when blob_open is unavailable.
  `CREATE TABLE body_value_chunks(value_id TEXT NOT NULL, offset INTEGER NOT NULL, body BLOB NOT NULL, PRIMARY KEY(value_id,offset)) WITHOUT ROWID`,
  `CREATE TABLE workspace_jobs(id INTEGER PRIMARY KEY AUTOINCREMENT, job TEXT NOT NULL UNIQUE)`,
];
