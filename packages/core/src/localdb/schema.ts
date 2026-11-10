/**
 * Migration 1 of the local database, taken from the SQL proof. Shared SQL keeps
 * to SQLite 3.22: no UPSERT, RETURNING, JSON1, window functions or STRICT.
 * Each migration is one batch; `migrate` appends `PRAGMA user_version`.
 */
export const MIGRATIONS: readonly (readonly string[])[] = [
  [
    `CREATE TABLE db_meta (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  owner TEXT NOT NULL, network TEXT NOT NULL, device_id TEXT NOT NULL, created_at INTEGER NOT NULL);`,
    `CREATE TABLE write_ctx (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  origin TEXT NOT NULL CHECK (origin IN ('local','import','remote','refresh','purge')));`,
    `INSERT INTO write_ctx VALUES (1, 'local');`,
    `CREATE TABLE connections (
  connection_id TEXT PRIMARY KEY, connector TEXT NOT NULL, ns TEXT NOT NULL,
  generation INTEGER NOT NULL DEFAULT 1,
  control_state TEXT NOT NULL DEFAULT 'absent' CHECK (control_state IN ('absent','active','deleted','foreign')),
  control_version INTEGER NOT NULL DEFAULT 0,
  checkpoint TEXT, label TEXT, deleted_at INTEGER);`,
    `CREATE TABLE records (
  connection_id TEXT NOT NULL, stream TEXT NOT NULL, pk_hash TEXT NOT NULL,
  record_key TEXT NOT NULL, stamp_o INTEGER NOT NULL, stamp_r TEXT NOT NULL,
  body TEXT NOT NULL, body_sha256 TEXT NOT NULL, first_o INTEGER,
  PRIMARY KEY (connection_id, stream, pk_hash)) WITHOUT ROWID;`,
    `CREATE INDEX records_by_key ON records(connection_id, stream, record_key);`,
    `CREATE INDEX records_by_first ON records(first_o) WHERE first_o IS NOT NULL;`,
    `CREATE TABLE record_changes (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  connection_id TEXT NOT NULL, stream TEXT NOT NULL, pk_hash TEXT NOT NULL, record_key TEXT NOT NULL,
  op TEXT NOT NULL CHECK (op IN ('upsert','remove')),
  stamp_o INTEGER NOT NULL, stamp_r TEXT NOT NULL,
  origin TEXT NOT NULL);`,
    `CREATE INDEX record_changes_by_key ON record_changes(connection_id, stream, pk_hash, seq);`,
    `CREATE TABLE stream_state (
  connection_id TEXT NOT NULL, stream TEXT NOT NULL,
  primary_key TEXT NOT NULL, semantics TEXT NOT NULL, incremental INTEGER NOT NULL,
  profile_key TEXT, profile_version TEXT,
  complete INTEGER NOT NULL DEFAULT 0, needs_full INTEGER NOT NULL DEFAULT 0,
  floor_version TEXT, floor_o INTEGER, floor_r TEXT,
  last_delete_version INTEGER NOT NULL DEFAULT 0,
  head_version INTEGER NOT NULL DEFAULT 0, head_generation INTEGER, head_data_hash TEXT, head_blob TEXT,
  publish_watermark INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (connection_id, stream)) WITHOUT ROWID;`,
    `CREATE TABLE stream_versions (
  connection_id TEXT NOT NULL, stream TEXT NOT NULL, version INTEGER NOT NULL,
  generation INTEGER NOT NULL, head_blob TEXT NOT NULL, head_format INTEGER NOT NULL,
  record_count INTEGER NOT NULL, observed_at INTEGER NOT NULL, complete INTEGER NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('published','applied','delete')),
  PRIMARY KEY (connection_id, stream, version)) WITHOUT ROWID;`,
    `CREATE TABLE head_parts (
  connection_id TEXT NOT NULL, stream TEXT NOT NULL,
  prefix TEXT NOT NULL CHECK (prefix NOT GLOB '*[^01]*' AND length(prefix) <= 16),
  seq INTEGER NOT NULL, part_hash TEXT NOT NULL, bytes INTEGER NOT NULL, count INTEGER NOT NULL,
  PRIMARY KEY (connection_id, stream, prefix, seq)) WITHOUT ROWID;`,
    `CREATE TABLE runs (
  run_id TEXT PRIMARY KEY CHECK (run_id NOT GLOB '*[^A-Za-z0-9._-]*' AND length(run_id) BETWEEN 1 AND 128),
  connection_id TEXT NOT NULL, o INTEGER NOT NULL, generation INTEGER,
  artifact_version TEXT NOT NULL, collection_mode TEXT NOT NULL CHECK (collection_mode IN ('full_refresh','incremental')),
  state TEXT NOT NULL CHECK (state IN ('collecting','ended')),
  last_batch INTEGER NOT NULL DEFAULT -1);`,
    `CREATE TABLE run_streams (
  run_id TEXT NOT NULL, stream TEXT NOT NULL,
  delete_snapshot INTEGER NOT NULL,
  basis_version INTEGER, basis_generation INTEGER, basis_data_hash TEXT,
  primary_key TEXT, profile_key TEXT, profile_version TEXT,
  full_read INTEGER NOT NULL DEFAULT 0, foreign_checkpoint INTEGER NOT NULL DEFAULT 0,
  seed TEXT NOT NULL DEFAULT 'none' CHECK (seed IN ('none','merged','unresolved')),
  replace INTEGER NOT NULL DEFAULT 0,
  decision TEXT CHECK (decision IN ('publish','noop','refused','deferred','discarded')), reason TEXT,
  PRIMARY KEY (run_id, stream)) WITHOUT ROWID;`,
    `CREATE TABLE run_rows (
  run_id TEXT NOT NULL, stream TEXT NOT NULL, pk_hash TEXT NOT NULL, record_key TEXT NOT NULL,
  body TEXT NOT NULL, body_sha256 TEXT NOT NULL,
  PRIMARY KEY (run_id, stream, pk_hash)) WITHOUT ROWID;`,
    `CREATE TABLE blobs (
  blob_id TEXT PRIMARY KEY, mime_type TEXT NOT NULL, size_bytes INTEGER NOT NULL,
  generation INTEGER, bytes BLOB);`,
    `CREATE TABLE blob_refs (
  blob_id TEXT NOT NULL, connection_id TEXT NOT NULL, stream TEXT NOT NULL, pk_hash TEXT NOT NULL,
  PRIMARY KEY (blob_id, connection_id, stream, pk_hash)) WITHOUT ROWID;`,
    `CREATE TABLE import_ledger (
  source TEXT NOT NULL, connection_id TEXT NOT NULL, stream TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('imported','verified','retired','excluded')),
  rows INTEGER NOT NULL, fingerprint TEXT NOT NULL, reason TEXT, at INTEGER NOT NULL,
  PRIMARY KEY (source, connection_id, stream)) WITHOUT ROWID;`,
    `CREATE TABLE delete_intents (
  connector TEXT PRIMARY KEY, delete_id TEXT NOT NULL, intent TEXT NOT NULL);`,
    `CREATE TRIGGER records_key_type_conflict BEFORE INSERT ON records
WHEN (SELECT origin FROM write_ctx WHERE id = 1) <> 'remote'
 AND EXISTS (SELECT 1 FROM records x WHERE x.connection_id = NEW.connection_id
             AND x.stream = NEW.stream AND x.record_key = NEW.record_key AND x.pk_hash <> NEW.pk_hash)
BEGIN SELECT RAISE(ABORT, 'key_type_conflict'); END;`,
    `CREATE TRIGGER records_ai AFTER INSERT ON records BEGIN
  INSERT INTO record_changes(connection_id,stream,pk_hash,record_key,op,stamp_o,stamp_r,origin)
  VALUES (NEW.connection_id,NEW.stream,NEW.pk_hash,NEW.record_key,'upsert',NEW.stamp_o,NEW.stamp_r,
          (SELECT origin FROM write_ctx WHERE id = 1));
END;`,
    `CREATE TRIGGER records_au AFTER UPDATE OF stamp_o, stamp_r, body_sha256 ON records BEGIN
  INSERT INTO record_changes(connection_id,stream,pk_hash,record_key,op,stamp_o,stamp_r,origin)
  VALUES (NEW.connection_id,NEW.stream,NEW.pk_hash,NEW.record_key,'upsert',NEW.stamp_o,NEW.stamp_r,
          (SELECT origin FROM write_ctx WHERE id = 1));
END;`,
    `CREATE TRIGGER records_ad AFTER DELETE ON records BEGIN
  INSERT INTO record_changes(connection_id,stream,pk_hash,record_key,op,stamp_o,stamp_r,origin)
  VALUES (OLD.connection_id,OLD.stream,OLD.pk_hash,OLD.record_key,'remove',OLD.stamp_o,OLD.stamp_r,
          (SELECT origin FROM write_ctx WHERE id = 1));
  DELETE FROM blob_refs WHERE connection_id = OLD.connection_id AND stream = OLD.stream AND pk_hash = OLD.pk_hash;
END;`,
  ],
  [
    `ALTER TABLE import_ledger ADD COLUMN revision TEXT;`,
    `ALTER TABLE import_ledger ADD COLUMN generation INTEGER;`,
    `ALTER TABLE import_ledger ADD COLUMN highest_seq INTEGER;`,
  ],
  [
    `CREATE TABLE legacy_erase_intents (
      copy_key TEXT PRIMARY KEY, descriptor TEXT NOT NULL, at INTEGER NOT NULL
    ) WITHOUT ROWID;`,
  ],
  [
    // A connection can compact newer events while another retains older ones.
    // MIN(seq) alone cannot detect those holes. Retain only the deletion floor.
    `ALTER TABLE db_meta ADD COLUMN change_floor INTEGER NOT NULL DEFAULT 0`,
    `UPDATE db_meta SET change_floor=COALESCE((SELECT seq FROM sqlite_sequence WHERE name='record_changes'),0)`,
    `CREATE TRIGGER record_changes_compacted AFTER DELETE ON record_changes BEGIN
      UPDATE db_meta SET change_floor=MAX(change_floor,OLD.seq) WHERE id=1;
    END`,
  ],
];
