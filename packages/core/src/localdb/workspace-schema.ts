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

export const PARTIAL_WORKSPACE_SCHEMA = [
  `CREATE TABLE workspace_partial_keys(operation TEXT NOT NULL,stream TEXT NOT NULL,pk_hash TEXT NOT NULL,typed_key TEXT NOT NULL,last_naming INTEGER NOT NULL,last_removal INTEGER NOT NULL,removal_o INTEGER,removal_r TEXT,PRIMARY KEY(operation,stream,pk_hash)) WITHOUT ROWID`,
  `CREATE TABLE workspace_partial_streams(operation TEXT NOT NULL,stream TEXT NOT NULL,payload TEXT NOT NULL,primary_key TEXT NOT NULL,profile_key TEXT,profile_version TEXT NOT NULL,complete INTEGER NOT NULL,generation INTEGER NOT NULL,observed_at INTEGER NOT NULL,data_hash TEXT NOT NULL,blob_name TEXT NOT NULL,skip INTEGER NOT NULL,partial_version INTEGER NOT NULL,PRIMARY KEY(operation,stream)) WITHOUT ROWID`,
];

export const PARTIAL_STAGE_SCHEMA = [
  `CREATE TABLE workspace_partial_incoming(operation TEXT NOT NULL,op TEXT NOT NULL,stream TEXT NOT NULL,pk_hash TEXT NOT NULL,record_key TEXT NOT NULL,stamp_o INTEGER NOT NULL,stamp_r TEXT NOT NULL,body TEXT NOT NULL,body_sha256 TEXT NOT NULL,first_o INTEGER,stamp_n INTEGER NOT NULL,PRIMARY KEY(op,stream,pk_hash)) WITHOUT ROWID`,
  `CREATE INDEX workspace_partial_incoming_cleanup ON workspace_partial_incoming(operation,op,stream,pk_hash)`,
  `CREATE TABLE workspace_partial_deletions(operation TEXT NOT NULL,op TEXT NOT NULL,stream TEXT NOT NULL,pk_hash TEXT NOT NULL,record_key TEXT NOT NULL,stamp_o INTEGER NOT NULL,stamp_r TEXT NOT NULL,rank INTEGER NOT NULL,unit INTEGER NOT NULL,PRIMARY KEY(op,stream,pk_hash)) WITHOUT ROWID`,
  `CREATE INDEX workspace_partial_deletions_cleanup ON workspace_partial_deletions(operation,op,stream,pk_hash)`,
];

export const PARTIAL_PASS_SCHEMA = [
  `CREATE TABLE workspace_partial_passes(connection TEXT PRIMARY KEY,operation TEXT NOT NULL UNIQUE) WITHOUT ROWID`,
];
