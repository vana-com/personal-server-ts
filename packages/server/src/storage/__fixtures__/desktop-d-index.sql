-- Generated using Desktop runtime D=4245639b6d2890243ff8ddf0f629566da5a1d6ba.
-- Legacy user_version15; PDPP14. Do not regenerate with the current runtime.
PRAGMA foreign_keys = OFF;
BEGIN TRANSACTION;
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
INSERT INTO "data_files" ("id","file_id","schema_id","path","scope","collected_at","created_at","size_bytes","version","cas_revision","data_point_id","after_tombstone_version","producer","producer_provenance") VALUES (1,NULL,NULL,'oura/sleep/legacy.json','oura.sleep','2026-10-20T12:00:00.000Z','2026-10-20T12:00:00.000Z',100,7,9,NULL,NULL,NULL,NULL);
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
INSERT INTO "legacy_scope_takeover_verdicts" ("scope","instance","generation","legacy_version_id","canonical_cursor","verdict","comparison_case","reason_counts_json","applied_exceptions_json","reason_json","legacy_bytes","canonical_bytes","byte_delta","evaluated_at") VALUES ('oura.sleep','oura-desktop',2,1,'canonical-legacy-view/11:desktop-completed-replacement','covered','canonical_newer','{}','[]',NULL,100,80,-20,'2026-10-21T12:00:00.000Z');
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
INSERT INTO "legacy_scope_takeovers" ("scope","instance","generation","method","superseded_version","superseded_cas_revision","superseded_collected_at","superseded_path","replacement_cursor","taken_over_at") VALUES ('oura.sleep','oura-desktop',2,'oura-browser',7,9,'2026-10-20T12:00:00.000Z','oura/sleep/legacy.json','1:canonical-legacy-view/11:desktop-completed-replacement','2026-10-21T12:00:00.000Z');
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
INSERT INTO "pdpp_blob_bytes" ("blob_id","bytes") VALUES ('sha256:36e8d39b15ce726596b2e44c020a0f0e833b4b1d942150665d91e363a29bf0e1',X'72657461696e6564204465736b746f7020686973746f7279206279746573');
INSERT INTO "pdpp_blob_bytes" ("blob_id","bytes") VALUES ('sha256:c7e4e957dd654dce51cb9e61a975d24773e07ff0575db32231e405d2bdce1563',X'6c697665204465736b746f7020626c6f62206279746573');
CREATE TABLE pdpp_blob_claims (
  blob_id TEXT NOT NULL REFERENCES pdpp_blobs (blob_id),
  instance TEXT NOT NULL,
  generation INTEGER NOT NULL,
  PRIMARY KEY (blob_id, instance)
);
INSERT INTO "pdpp_blob_claims" ("blob_id","instance","generation") VALUES ('sha256:c7e4e957dd654dce51cb9e61a975d24773e07ff0575db32231e405d2bdce1563','media-desktop',1);
CREATE TABLE pdpp_blobs (
  blob_id TEXT PRIMARY KEY,
  mime_type TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  sha256 TEXT NOT NULL
);
INSERT INTO "pdpp_blobs" ("blob_id","mime_type","size_bytes","sha256") VALUES ('sha256:36e8d39b15ce726596b2e44c020a0f0e833b4b1d942150665d91e363a29bf0e1','text/plain',30,'36e8d39b15ce726596b2e44c020a0f0e833b4b1d942150665d91e363a29bf0e1');
INSERT INTO "pdpp_blobs" ("blob_id","mime_type","size_bytes","sha256") VALUES ('sha256:c7e4e957dd654dce51cb9e61a975d24773e07ff0575db32231e405d2bdce1563','text/plain',23,'c7e4e957dd654dce51cb9e61a975d24773e07ff0575db32231e405d2bdce1563');
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
INSERT INTO "pdpp_instance_binding" ("instance","method","generation","reset_clock","source_id","label","deleted_at") VALUES ('oura-desktop','oura-browser',2,1,'https://registry.pdpp.dev/sources/oura','Oura',NULL);
INSERT INTO "pdpp_instance_binding" ("instance","method","generation","reset_clock","source_id","label","deleted_at") VALUES ('media-desktop','files',1,0,'https://example.test/files','Files',NULL);
CREATE TABLE pdpp_record_arrival (
  instance TEXT NOT NULL,
  stream TEXT NOT NULL,
  record_key TEXT NOT NULL,
  generation INTEGER NOT NULL,
  arrival INTEGER NOT NULL,
  PRIMARY KEY (instance, stream, record_key)
);
INSERT INTO "pdpp_record_arrival" ("instance","stream","record_key","generation","arrival") VALUES ('oura-desktop','sleep','kept-sleep',2,1);
INSERT INTO "pdpp_record_arrival" ("instance","stream","record_key","generation","arrival") VALUES ('oura-desktop','sleep','new-sleep',2,2);
INSERT INTO "pdpp_record_arrival" ("instance","stream","record_key","generation","arrival") VALUES ('oura-desktop','readiness','kept-readiness',2,1);
INSERT INTO "pdpp_record_arrival" ("instance","stream","record_key","generation","arrival") VALUES ('oura-desktop','readiness','new-readiness',2,2);
INSERT INTO "pdpp_record_arrival" ("instance","stream","record_key","generation","arrival") VALUES ('oura-desktop','activity','kept-activity',2,1);
INSERT INTO "pdpp_record_arrival" ("instance","stream","record_key","generation","arrival") VALUES ('oura-desktop','activity','new-activity',2,2);
INSERT INTO "pdpp_record_arrival" ("instance","stream","record_key","generation","arrival") VALUES ('media-desktop','files','history',1,2);
INSERT INTO "pdpp_record_arrival" ("instance","stream","record_key","generation","arrival") VALUES ('media-desktop','files','live',1,3);
CREATE TABLE pdpp_record_arrival_clock (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  value INTEGER NOT NULL
);
INSERT INTO "pdpp_record_arrival_clock" ("id","value") VALUES (1,15);
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
INSERT INTO "pdpp_record_changes" ("id","instance","stream","record_key","version","data","emitted_at","deleted","deleted_at","written_at","emitted_key") VALUES (1,'oura-desktop','sleep','old-sleep',1,'{"id":"old-sleep","day":"2026-10-20","score":88}','2026-10-20T12:00:00.000Z',0,NULL,2,'101792497627');
INSERT INTO "pdpp_record_changes" ("id","instance","stream","record_key","version","data","emitted_at","deleted","deleted_at","written_at","emitted_key") VALUES (2,'oura-desktop','sleep','kept-sleep',1,'{"id":"kept-sleep","day":"2026-10-20","score":88}','2026-10-20T12:00:00.000Z',0,NULL,3,'101792497627');
INSERT INTO "pdpp_record_changes" ("id","instance","stream","record_key","version","data","emitted_at","deleted","deleted_at","written_at","emitted_key") VALUES (3,'oura-desktop','readiness','old-readiness',1,'{"id":"old-readiness","day":"2026-10-20","score":88}','2026-10-20T12:00:00.000Z',0,NULL,4,'101792497627');
INSERT INTO "pdpp_record_changes" ("id","instance","stream","record_key","version","data","emitted_at","deleted","deleted_at","written_at","emitted_key") VALUES (4,'oura-desktop','readiness','kept-readiness',1,'{"id":"kept-readiness","day":"2026-10-20","score":88}','2026-10-20T12:00:00.000Z',0,NULL,5,'101792497627');
INSERT INTO "pdpp_record_changes" ("id","instance","stream","record_key","version","data","emitted_at","deleted","deleted_at","written_at","emitted_key") VALUES (5,'oura-desktop','activity','old-activity',1,'{"id":"old-activity","day":"2026-10-20","score":88}','2026-10-20T12:00:00.000Z',0,NULL,6,'101792497627');
INSERT INTO "pdpp_record_changes" ("id","instance","stream","record_key","version","data","emitted_at","deleted","deleted_at","written_at","emitted_key") VALUES (6,'oura-desktop','activity','kept-activity',1,'{"id":"kept-activity","day":"2026-10-20","score":88}','2026-10-20T12:00:00.000Z',0,NULL,7,'101792497627');
INSERT INTO "pdpp_record_changes" ("id","instance","stream","record_key","version","data","emitted_at","deleted","deleted_at","written_at","emitted_key") VALUES (7,'oura-desktop','sleep','new-sleep',1,'{"id":"new-sleep","day":"2026-10-20","score":88}','2026-10-21T12:00:00.000Z',0,NULL,8,'101792584027');
INSERT INTO "pdpp_record_changes" ("id","instance","stream","record_key","version","data","emitted_at","deleted","deleted_at","written_at","emitted_key") VALUES (8,'oura-desktop','sleep','old-sleep',2,NULL,'2026-10-21T12:00:00.000Z',1,'2026-10-21T12:00:00.000Z',9,'101792584027');
INSERT INTO "pdpp_record_changes" ("id","instance","stream","record_key","version","data","emitted_at","deleted","deleted_at","written_at","emitted_key") VALUES (9,'oura-desktop','readiness','new-readiness',1,'{"id":"new-readiness","day":"2026-10-20","score":88}','2026-10-21T12:00:00.000Z',0,NULL,10,'101792584027');
INSERT INTO "pdpp_record_changes" ("id","instance","stream","record_key","version","data","emitted_at","deleted","deleted_at","written_at","emitted_key") VALUES (10,'oura-desktop','readiness','old-readiness',2,NULL,'2026-10-21T12:00:00.000Z',1,'2026-10-21T12:00:00.000Z',11,'101792584027');
INSERT INTO "pdpp_record_changes" ("id","instance","stream","record_key","version","data","emitted_at","deleted","deleted_at","written_at","emitted_key") VALUES (11,'oura-desktop','activity','new-activity',1,'{"id":"new-activity","day":"2026-10-20","score":88}','2026-10-21T12:00:00.000Z',0,NULL,12,'101792584027');
INSERT INTO "pdpp_record_changes" ("id","instance","stream","record_key","version","data","emitted_at","deleted","deleted_at","written_at","emitted_key") VALUES (12,'oura-desktop','activity','old-activity',2,NULL,'2026-10-21T12:00:00.000Z',1,'2026-10-21T12:00:00.000Z',13,'101792584027');
INSERT INTO "pdpp_record_changes" ("id","instance","stream","record_key","version","data","emitted_at","deleted","deleted_at","written_at","emitted_key") VALUES (13,'media-desktop','files','history',1,'{"id":"history","blob_ref":{"blob_id":"sha256:36e8d39b15ce726596b2e44c020a0f0e833b4b1d942150665d91e363a29bf0e1"}}','2026-10-20T12:00:00.000Z',0,NULL,14,'101792497627');
INSERT INTO "pdpp_record_changes" ("id","instance","stream","record_key","version","data","emitted_at","deleted","deleted_at","written_at","emitted_key") VALUES (14,'media-desktop','files','history',2,'{"id":"history","text":"replacement"}','2026-10-21T12:00:00.000Z',0,NULL,15,'101792584027');
INSERT INTO "pdpp_record_changes" ("id","instance","stream","record_key","version","data","emitted_at","deleted","deleted_at","written_at","emitted_key") VALUES (15,'media-desktop','files','live',1,'{"id":"live","blob_ref":{"blob_id":"sha256:c7e4e957dd654dce51cb9e61a975d24773e07ff0575db32231e405d2bdce1563"}}','2026-10-20T12:00:00.000Z',0,NULL,16,'101792497627');
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
INSERT INTO "pdpp_records" ("instance","stream","record_key","data","version","emitted_at","deleted","deleted_at","blob_id","emitted_key") VALUES ('oura-desktop','sleep','old-sleep',NULL,2,'2026-10-21T12:00:00.000Z',1,'2026-10-21T12:00:00.000Z',NULL,'101792584027');
INSERT INTO "pdpp_records" ("instance","stream","record_key","data","version","emitted_at","deleted","deleted_at","blob_id","emitted_key") VALUES ('oura-desktop','sleep','kept-sleep','{"id":"kept-sleep","day":"2026-10-20","score":88}',1,'2026-10-20T12:00:00.000Z',0,NULL,NULL,'101792497627');
INSERT INTO "pdpp_records" ("instance","stream","record_key","data","version","emitted_at","deleted","deleted_at","blob_id","emitted_key") VALUES ('oura-desktop','readiness','old-readiness',NULL,2,'2026-10-21T12:00:00.000Z',1,'2026-10-21T12:00:00.000Z',NULL,'101792584027');
INSERT INTO "pdpp_records" ("instance","stream","record_key","data","version","emitted_at","deleted","deleted_at","blob_id","emitted_key") VALUES ('oura-desktop','readiness','kept-readiness','{"id":"kept-readiness","day":"2026-10-20","score":88}',1,'2026-10-20T12:00:00.000Z',0,NULL,NULL,'101792497627');
INSERT INTO "pdpp_records" ("instance","stream","record_key","data","version","emitted_at","deleted","deleted_at","blob_id","emitted_key") VALUES ('oura-desktop','activity','old-activity',NULL,2,'2026-10-21T12:00:00.000Z',1,'2026-10-21T12:00:00.000Z',NULL,'101792584027');
INSERT INTO "pdpp_records" ("instance","stream","record_key","data","version","emitted_at","deleted","deleted_at","blob_id","emitted_key") VALUES ('oura-desktop','activity','kept-activity','{"id":"kept-activity","day":"2026-10-20","score":88}',1,'2026-10-20T12:00:00.000Z',0,NULL,NULL,'101792497627');
INSERT INTO "pdpp_records" ("instance","stream","record_key","data","version","emitted_at","deleted","deleted_at","blob_id","emitted_key") VALUES ('oura-desktop','sleep','new-sleep','{"id":"new-sleep","day":"2026-10-20","score":88}',1,'2026-10-21T12:00:00.000Z',0,NULL,NULL,'101792584027');
INSERT INTO "pdpp_records" ("instance","stream","record_key","data","version","emitted_at","deleted","deleted_at","blob_id","emitted_key") VALUES ('oura-desktop','readiness','new-readiness','{"id":"new-readiness","day":"2026-10-20","score":88}',1,'2026-10-21T12:00:00.000Z',0,NULL,NULL,'101792584027');
INSERT INTO "pdpp_records" ("instance","stream","record_key","data","version","emitted_at","deleted","deleted_at","blob_id","emitted_key") VALUES ('oura-desktop','activity','new-activity','{"id":"new-activity","day":"2026-10-20","score":88}',1,'2026-10-21T12:00:00.000Z',0,NULL,NULL,'101792584027');
INSERT INTO "pdpp_records" ("instance","stream","record_key","data","version","emitted_at","deleted","deleted_at","blob_id","emitted_key") VALUES ('media-desktop','files','history','{"id":"history","text":"replacement"}',2,'2026-10-21T12:00:00.000Z',0,NULL,NULL,'101792584027');
INSERT INTO "pdpp_records" ("instance","stream","record_key","data","version","emitted_at","deleted","deleted_at","blob_id","emitted_key") VALUES ('media-desktop','files','live','{"id":"live","blob_ref":{"blob_id":"sha256:c7e4e957dd654dce51cb9e61a975d24773e07ff0575db32231e405d2bdce1563"}}',1,'2026-10-20T12:00:00.000Z',0,NULL,'sha256:c7e4e957dd654dce51cb9e61a975d24773e07ff0575db32231e405d2bdce1563','101792497627');
CREATE TABLE pdpp_schema_version (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      version INTEGER NOT NULL
    );
INSERT INTO "pdpp_schema_version" ("id","version") VALUES (1,14);
CREATE TABLE pdpp_store_metadata (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  epoch TEXT NOT NULL
);
INSERT INTO "pdpp_store_metadata" ("id","epoch") VALUES (1,'desktop-d-fixture-epoch');
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
INSERT INTO "pdpp_stream_completion" ("instance","stream","method","generation","source_collected_at","write_seq","live_count","snapshot_sha256","collection_time_basis") VALUES ('oura-desktop','sleep','oura-browser',2,'2026-10-21T12:00:00.000Z',9,2,NULL,NULL);
INSERT INTO "pdpp_stream_completion" ("instance","stream","method","generation","source_collected_at","write_seq","live_count","snapshot_sha256","collection_time_basis") VALUES ('oura-desktop','readiness','oura-browser',2,'2026-10-21T12:00:00.000Z',11,2,NULL,NULL);
INSERT INTO "pdpp_stream_completion" ("instance","stream","method","generation","source_collected_at","write_seq","live_count","snapshot_sha256","collection_time_basis") VALUES ('oura-desktop','activity','oura-browser',2,'2026-10-21T12:00:00.000Z',13,2,NULL,NULL);
CREATE TABLE pdpp_write_clock (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  value INTEGER NOT NULL
);
INSERT INTO "pdpp_write_clock" ("id","value") VALUES (1,17);
CREATE TABLE scope_revisions (
  scope TEXT PRIMARY KEY,
  cas_revision INTEGER NOT NULL,
  closed_for_writes INTEGER NOT NULL DEFAULT 0
);
INSERT INTO "scope_revisions" ("scope","cas_revision","closed_for_writes") VALUES ('oura.sleep',9,0);
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
COMMIT;
PRAGMA foreign_keys = ON;
