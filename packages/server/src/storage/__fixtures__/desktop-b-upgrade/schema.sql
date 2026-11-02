-- Actual B schema a0d50ef8fae5d7f75186c652d09244b19f736243; legacy15/PDPP14.
PRAGMA user_version = 15;
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
  cas_revision INTEGER NOT NULL DEFAULT 1,
  data_point_id TEXT,
  after_tombstone_version INTEGER,
  producer TEXT,
  producer_provenance TEXT
);
CREATE TABLE legacy_scope_takeover_resets (
  scope TEXT PRIMARY KEY,
  reset_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE TABLE legacy_scope_takeover_verdicts (
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
);
CREATE TABLE legacy_scope_takeovers (
  scope TEXT NOT NULL,
  instance TEXT NOT NULL DEFAULT '',
  generation INTEGER NOT NULL DEFAULT 1,
  method TEXT NOT NULL DEFAULT '',
  superseded_version INTEGER NOT NULL,
  superseded_cas_revision INTEGER NOT NULL,
  superseded_collected_at TEXT NOT NULL,
  superseded_path TEXT NOT NULL,
  replacement_cursor TEXT,
  taken_over_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  PRIMARY KEY (scope, instance, generation, superseded_path)
);
CREATE TABLE owner_import_operations (
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
  );
CREATE TABLE pdpp_blob_bytes (
  blob_id TEXT PRIMARY KEY REFERENCES pdpp_blobs (blob_id),
  bytes BLOB NOT NULL
);
CREATE TABLE pdpp_blob_claims (
  blob_id TEXT NOT NULL REFERENCES pdpp_blobs (blob_id),
  instance TEXT NOT NULL,
  generation INTEGER NOT NULL,
  PRIMARY KEY (blob_id, instance)
);
CREATE TABLE pdpp_blobs (
  blob_id TEXT PRIMARY KEY,
  mime_type TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  sha256 TEXT NOT NULL
);
CREATE TABLE pdpp_claude_transition (
    instance TEXT PRIMARY KEY,
    archive_instance TEXT NOT NULL UNIQUE,
    generation INTEGER NOT NULL,
    snapshots_json TEXT NOT NULL,
    conversations_covered INTEGER NOT NULL DEFAULT 0
  );
CREATE TABLE pdpp_instance_binding (
  instance TEXT PRIMARY KEY,
  method TEXT,
  generation INTEGER NOT NULL CHECK (generation > 0),
  reset_clock INTEGER NOT NULL DEFAULT 0
, source_id TEXT, label TEXT NOT NULL DEFAULT '', deleted_at TEXT);
CREATE TABLE pdpp_record_arrival (
  instance TEXT NOT NULL,
  stream TEXT NOT NULL,
  record_key TEXT NOT NULL,
  generation INTEGER NOT NULL,
  arrival INTEGER NOT NULL,
  PRIMARY KEY (instance, stream, record_key)
);
CREATE TABLE pdpp_record_arrival_clock (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  value INTEGER NOT NULL
);
CREATE TABLE pdpp_record_changes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  instance TEXT NOT NULL,
  stream TEXT NOT NULL,
  record_key TEXT NOT NULL,
  version INTEGER NOT NULL,
  data TEXT, -- JSON; NULL for a tombstone version
  emitted_at TEXT NOT NULL,
  deleted INTEGER NOT NULL DEFAULT 0,
  deleted_at TEXT,
  written_at INTEGER NOT NULL -- monotonic write sequence, for changes_since horizons
, emitted_key TEXT);
CREATE TABLE pdpp_records (
  instance TEXT NOT NULL,
  stream TEXT NOT NULL,
  record_key TEXT NOT NULL,
  data TEXT, -- JSON; NULL when deleted = 1
  version INTEGER NOT NULL,
  emitted_at TEXT NOT NULL,
  deleted INTEGER NOT NULL DEFAULT 0,
  deleted_at TEXT, blob_id TEXT, emitted_key TEXT,
  PRIMARY KEY (instance, stream, record_key)
);
CREATE TABLE pdpp_schema_version (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      version INTEGER NOT NULL
    );
CREATE TABLE pdpp_store_metadata (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  epoch TEXT NOT NULL
);
CREATE TABLE pdpp_stream_completion (
  instance TEXT NOT NULL,
  stream TEXT NOT NULL,
  method TEXT NOT NULL,
  generation INTEGER NOT NULL,
  source_collected_at TEXT NOT NULL,
  write_seq INTEGER NOT NULL,
  live_count INTEGER NOT NULL, snapshot_sha256 TEXT, collection_time_basis TEXT,
  PRIMARY KEY (instance, stream)
);
CREATE TABLE pdpp_write_clock (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  value INTEGER NOT NULL
);
CREATE TABLE scope_revisions (
  scope TEXT PRIMARY KEY,
  cas_revision INTEGER NOT NULL,
  closed_for_writes INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_data_files_collected_at ON data_files (collected_at);
CREATE INDEX idx_data_files_data_point_id ON data_files (data_point_id);
CREATE INDEX idx_data_files_file_id ON data_files (file_id);
CREATE INDEX idx_data_files_schema_id ON data_files (schema_id);
CREATE INDEX idx_data_files_scope ON data_files (scope);
CREATE INDEX idx_data_files_scope_cas_revision ON data_files (scope, cas_revision);
CREATE UNIQUE INDEX idx_owner_import_operations_path ON owner_import_operations(path);
CREATE INDEX idx_owner_import_operations_recovery ON owner_import_operations(operation) WHERE state = 'prepared' OR (state IN ('deleted', 'cancelled') AND metadata_json IS NOT NULL);
CREATE INDEX idx_pdpp_record_arrival_order
  ON pdpp_record_arrival (instance, stream, arrival);
CREATE INDEX idx_pdpp_record_changes_horizon
  ON pdpp_record_changes (stream, instance, written_at);
CREATE INDEX idx_pdpp_record_changes_lookup
  ON pdpp_record_changes (instance, stream, record_key, version);
CREATE INDEX idx_pdpp_record_changes_snapshot_key_order
  ON pdpp_record_changes (stream, emitted_key, record_key, instance, written_at);
CREATE INDEX idx_pdpp_record_changes_snapshot_latest
  ON pdpp_record_changes (instance, stream, record_key, written_at DESC, version DESC);
CREATE INDEX idx_pdpp_records_blob_id
  ON pdpp_records (blob_id);
CREATE INDEX idx_pdpp_records_live_instance_stream_emitted_at
  ON pdpp_records (instance, stream, emitted_at)
  WHERE deleted = 0;
CREATE INDEX idx_pdpp_records_live_instance_stream_emitted_key
  ON pdpp_records (instance, stream, emitted_key, emitted_at)
  WHERE deleted = 0;
CREATE INDEX idx_pdpp_records_stream
  ON pdpp_records (stream, instance, emitted_at);
