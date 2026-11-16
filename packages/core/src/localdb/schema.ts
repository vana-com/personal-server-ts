/** The statement every view trigger runs: add one to the connection's counter. */
const bumpView = (row: "NEW" | "OLD") =>
  `INSERT OR REPLACE INTO view_versions(connection_id, version) VALUES (${row}.connection_id, COALESCE((SELECT version FROM view_versions WHERE connection_id = ${row}.connection_id), 0) + 1);`;

/**
 * The same bump for the connections of the intent's connector that a reader
 * can reach: every read gate is `control_state = 'active'` and no intent. An
 * intent changes what a reader sees only for such a connection. One that is
 * deleted, as a purge leaves it and as the resolver marks it when it meets an
 * intent, stays unreadable whether the intent exists or not.
 */
const bumpConnector = (row: "NEW" | "OLD") =>
  `INSERT OR REPLACE INTO view_versions(connection_id, version) SELECT c.connection_id, COALESCE(v.version, 0) + 1 FROM connections c LEFT JOIN view_versions v ON v.connection_id = c.connection_id WHERE c.connector = ${row}.connector AND c.control_state = 'active';`;

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
  [`ALTER TABLE run_streams ADD COLUMN coverage_strategy TEXT`],
  [
    `ALTER TABLE run_rows ADD COLUMN op TEXT NOT NULL DEFAULT 'upsert' CHECK(op IN ('upsert','delete'))`,
    `ALTER TABLE run_streams ADD COLUMN semantics TEXT`,
    `UPDATE run_streams SET semantics=(SELECT s.semantics FROM stream_state s JOIN runs r ON r.connection_id=s.connection_id WHERE r.run_id=run_streams.run_id AND s.stream=run_streams.stream)`,
    `ALTER TABLE record_changes ADD COLUMN explicit_delete INTEGER NOT NULL DEFAULT 0`,
  ],
  [
    `ALTER TABLE runs ADD COLUMN begin_control_version INTEGER`,
    `ALTER TABLE runs ADD COLUMN begin_request TEXT`,
    `ALTER TABLE runs ADD COLUMN begin_response TEXT`,
    `ALTER TABLE runs ADD COLUMN end_response TEXT`,
  ],
  [
    // Staging checks every new row for a key conflict with rows already staged
    // by the connection's runs. Without this index each check scans all staged
    // rows, so a batch costs more than the one before it.
    `CREATE INDEX run_rows_by_key ON run_rows(stream, record_key)`,
  ],
  [
    // Durable link from a run's stream to the publication that covered it.
    // Existing rows stay 'unknown': no publication is inferred from a
    // watermark, which counts local changes, not time. `published_watermark`
    // is evidence only; never compare it with `runs.o`.
    `ALTER TABLE run_streams ADD COLUMN publication_state TEXT NOT NULL DEFAULT 'unknown' CHECK (publication_state IN ('unknown','pending','published','superseded'))`,
    `ALTER TABLE run_streams ADD COLUMN published_generation INTEGER`,
    `ALTER TABLE run_streams ADD COLUMN published_version INTEGER`,
    `ALTER TABLE run_streams ADD COLUMN published_data_hash TEXT`,
    `ALTER TABLE run_streams ADD COLUMN published_watermark INTEGER`,
    `ALTER TABLE run_streams ADD COLUMN publication_reason TEXT`,
  ],
  [
    // The rows one publish attempt sends, copied under the connection's slot
    // so the upload reads a copy that later writes cannot move. Local only,
    // never published or applied: an attempt deletes its rows when it ends,
    // and `openLocalDb` deletes any left by a crash.
    `CREATE TABLE publish_spool (
  attempt TEXT NOT NULL, connection_id TEXT NOT NULL, pk_hash TEXT NOT NULL,
  stamp_o INTEGER NOT NULL, stamp_r TEXT NOT NULL, first_o INTEGER,
  body_sha256 TEXT NOT NULL, body_bytes INTEGER NOT NULL, body TEXT NOT NULL,
  PRIMARY KEY (attempt, pk_hash)) WITHOUT ROWID;`,
    `CREATE INDEX publish_spool_by_connection ON publish_spool(connection_id)`,
  ],
  [
    // The newest stamp of a run that observed this row's body, when that is
    // newer than the stamp in the published bytes. Local only: never in a
    // part, and not watched by `records_au`, so moving it logs no change. NULL
    // means the row was last observed at its own stamp. Read it through
    // `SEEN_O` and `SEEN_R` in merge.ts, never as the bare column.
    `ALTER TABLE records ADD COLUMN seen_o INTEGER`,
    `ALTER TABLE records ADD COLUMN seen_r TEXT`,
  ],
  [
    // "Rows last observed before run R" (a full refresh's replace) is a range
    // on the effective observation. This holds it, in the same terms as
    // `seenStamp` in merge.ts, so that read seeks and does not scan the stream.
    `CREATE INDEX records_by_observation ON records(connection_id, stream, COALESCE(seen_o, stamp_o), COALESCE(seen_r, stamp_r))`,
  ],
  [
    // The bytes of `body`, set by `mergeIncoming` with the body. Local only:
    // never in a part, and not watched by `records_au`. NULL means the row was
    // written before this column existed; `bodySizes` in part-layout.ts
    // measures the body for those rows.
    `ALTER TABLE records ADD COLUMN body_bytes INTEGER`,
    // The size alone, in an index. A column after `body` is stored behind the
    // body's overflow pages, and a lookup in `records` reads a wide row page
    // for each key, so the column by itself leaves the size reads as slow as
    // measuring the body. This index answers them without touching `records`.
    `CREATE INDEX records_size ON records(connection_id, stream, pk_hash, body_bytes)`,
  ],
  [
    // What a reader sees of a connection, as one counter per connection. A
    // trigger bumps it in the same transaction as every change of a column the
    // read path uses, and only when the value differs (`IS NOT`), so a write
    // that keeps a value changes nothing and a listener that rewrites a value
    // cannot cause an event. Watched:
    //   records: the body hash, the stamp, the first-seen time and the
    //     effective seen time `COALESCE(seen_o, stamp_o)` (a run that saw the
    //     same body moves it, and so does un-writing that run);
    //   stream_state: the primary key and profile binding, completeness, the
    //     delete version and the installed head (version, generation, data
    //     hash, blob);
    //   stream_versions: a version row inserted, changed or deleted, which is
    //     what picks the head, its completeness and its observation time, and
    //     what a version listing reports (`record_count`) and a historical
    //     read checks (`head_format`);
    //   delete_intents: a connector's intent starting or ending to exist, which
    //     hides or restores the active connections of that connector to a
    //     reader (a deleted one is unreadable with or without the intent);
    //     replacing one intent with another of the same connector is
    //     bookkeeping and stays silent;
    //   connections: identity and control state.
    // Not watched: publish and apply bookkeeping no read shows (watermarks,
    // floors, `needs_full`, checkpoints, labels). Nothing prunes the counter,
    // unlike `record_changes`, so a compaction cannot erase a change. Local
    // only: never in a part.
    `CREATE TABLE view_versions (
  connection_id TEXT PRIMARY KEY, version INTEGER NOT NULL) WITHOUT ROWID`,
    `CREATE TRIGGER view_records_ai AFTER INSERT ON records BEGIN
  ${bumpView("NEW")}
END`,
    `CREATE TRIGGER view_records_au AFTER UPDATE OF stamp_o, stamp_r, body_sha256, seen_o, first_o ON records
WHEN OLD.stamp_o IS NOT NEW.stamp_o OR OLD.stamp_r IS NOT NEW.stamp_r OR OLD.body_sha256 IS NOT NEW.body_sha256
  OR OLD.first_o IS NOT NEW.first_o OR COALESCE(OLD.seen_o, OLD.stamp_o) IS NOT COALESCE(NEW.seen_o, NEW.stamp_o) BEGIN
  ${bumpView("NEW")}
END`,
    `CREATE TRIGGER view_records_ad AFTER DELETE ON records BEGIN
  ${bumpView("OLD")}
END`,
    `CREATE TRIGGER view_connections_ai AFTER INSERT ON connections BEGIN
  ${bumpView("NEW")}
END`,
    `CREATE TRIGGER view_connections_ad AFTER DELETE ON connections BEGIN
  ${bumpView("OLD")}
END`,
    `CREATE TRIGGER view_connections_au AFTER UPDATE OF generation, control_state, control_version, deleted_at ON connections
WHEN OLD.generation IS NOT NEW.generation OR OLD.control_state IS NOT NEW.control_state OR OLD.control_version IS NOT NEW.control_version OR OLD.deleted_at IS NOT NEW.deleted_at BEGIN
  ${bumpView("NEW")}
END`,
    `CREATE TRIGGER view_streams_ai AFTER INSERT ON stream_state BEGIN
  ${bumpView("NEW")}
END`,
    `CREATE TRIGGER view_streams_ad AFTER DELETE ON stream_state BEGIN
  ${bumpView("OLD")}
END`,
    `CREATE TRIGGER view_streams_au AFTER UPDATE OF primary_key, profile_key, profile_version, complete, last_delete_version, head_version, head_generation, head_data_hash, head_blob ON stream_state
WHEN OLD.primary_key IS NOT NEW.primary_key OR OLD.profile_key IS NOT NEW.profile_key OR OLD.profile_version IS NOT NEW.profile_version
  OR OLD.complete IS NOT NEW.complete OR OLD.last_delete_version IS NOT NEW.last_delete_version
  OR OLD.head_version IS NOT NEW.head_version OR OLD.head_generation IS NOT NEW.head_generation
  OR OLD.head_data_hash IS NOT NEW.head_data_hash OR OLD.head_blob IS NOT NEW.head_blob BEGIN
  ${bumpView("NEW")}
END`,
    // `INSERT OR REPLACE` removes a replaced row without firing a delete
    // trigger (recursive triggers are off), and an AFTER trigger cannot tell
    // the row it replaced. A BEFORE trigger sees the stored row, so it bumps
    // unless an identical row is already there.
    `CREATE TRIGGER view_versions_bi BEFORE INSERT ON stream_versions
WHEN NOT EXISTS (SELECT 1 FROM stream_versions o WHERE o.connection_id = NEW.connection_id AND o.stream = NEW.stream AND o.version = NEW.version
  AND o.generation IS NEW.generation AND o.head_blob IS NEW.head_blob AND o.head_format IS NEW.head_format AND o.record_count IS NEW.record_count
  AND o.complete IS NEW.complete AND o.observed_at IS NEW.observed_at AND o.kind IS NEW.kind) BEGIN
  ${bumpView("NEW")}
END`,
    `CREATE TRIGGER view_versions_au AFTER UPDATE OF generation, head_blob, head_format, record_count, complete, observed_at, kind ON stream_versions
WHEN OLD.generation IS NOT NEW.generation OR OLD.head_blob IS NOT NEW.head_blob OR OLD.head_format IS NOT NEW.head_format
  OR OLD.record_count IS NOT NEW.record_count OR OLD.complete IS NOT NEW.complete
  OR OLD.observed_at IS NOT NEW.observed_at OR OLD.kind IS NOT NEW.kind BEGIN
  ${bumpView("NEW")}
END`,
    `CREATE TRIGGER view_versions_ad AFTER DELETE ON stream_versions BEGIN
  ${bumpView("OLD")}
END`,
    // Every read of a connection hides it while its connector has an intent,
    // so the intent existing is part of the view. `INSERT OR REPLACE` of an
    // existing connector's intent fires no delete trigger (recursive triggers
    // are off), and an AFTER INSERT trigger cannot tell it from a first
    // insert, so a BEFORE trigger bumps only when no intent is stored yet.
    `CREATE TRIGGER view_intents_bi BEFORE INSERT ON delete_intents
WHEN NOT EXISTS (SELECT 1 FROM delete_intents o WHERE o.connector = NEW.connector) BEGIN
  ${bumpConnector("NEW")}
END`,
    `CREATE TRIGGER view_intents_ad AFTER DELETE ON delete_intents BEGIN
  ${bumpConnector("OLD")}
END`,
  ],
  [
    // Apply has no rollback. Set before an apply's first write to a
    // connection, cleared when an apply of the whole connection completes. A
    // begin never goes on offline while it is set: the registry cannot say
    // what the half-applied local data lacks.
    `ALTER TABLE connections ADD COLUMN apply_partial INTEGER NOT NULL DEFAULT 0`,
  ],
  [
    // The stream-sync log (stream-sync/src/log.ts). `log_state` is one row per
    // connection: the position this device has applied, the position the log
    // began after (`base`), the refs of positions base+1..position as JSON,
    // which is what the next segment this device writes lists, and the snapshot
    // pointer the log rests on (JSON, null before the first compaction).
    // `log_tombstones`
    // keeps the stamp of every delete and omission the log carried, and
    // its rank (an omission's cutoff 0, an explicit delete 2; an observation is
    // 1), so a reordered or repeated upsert cannot bring a deleted record back
    // and an observation at an omission's cutoff is not refused. Both
    // are local only, and empty until a connection runs with the log flag.
    `CREATE TABLE log_state (
  connection_id TEXT PRIMARY KEY, position INTEGER NOT NULL, base INTEGER NOT NULL,
  refs TEXT NOT NULL, snapshot TEXT) WITHOUT ROWID;`,
    `CREATE TABLE log_tombstones (
  connection_id TEXT NOT NULL, stream TEXT NOT NULL, pk_hash TEXT NOT NULL,
  stamp_o INTEGER NOT NULL, stamp_r TEXT NOT NULL, rank INTEGER NOT NULL,
  PRIMARY KEY (connection_id, stream, pk_hash)) WITHOUT ROWID;`,
  ],
  [
    // Publish while collecting (flag `publishWhileCollecting`). A run's batch
    // is admitted into `records` as it arrives, so an older run can admit a row
    // after a newer run deleted it. This remembers each delete by the stamp of
    // the run that made it (never the stamp of the row it removed), so admission
    // skips an upsert that an equal-or-newer delete already covers. Local only:
    // never published or applied. A tombstone is kept only while a collecting run
    // older than it exists (`compactTombstones` in admit.ts); with none open,
    // every later run starts later and carries a newer stamp.
    `CREATE TABLE record_tombstones (
  connection_id TEXT NOT NULL, stream TEXT NOT NULL, pk_hash TEXT NOT NULL,
  stamp_o INTEGER NOT NULL, stamp_r TEXT NOT NULL,
  PRIMARY KEY (connection_id, stream, pk_hash)) WITHOUT ROWID;`,
    // 1 = the run's batches were admitted into `records` as they arrived, so
    // run end does not merge its upserts again. Fixed at begin from the flag.
    `ALTER TABLE runs ADD COLUMN admitting INTEGER NOT NULL DEFAULT 0`,
    // The highest tombstone stamp compaction ever dropped for the connection.
    // A run that begins later takes an `o` that puts its stamp above it
    // (`clampRunStart` in admit.ts), so "a later run has a newer stamp" holds
    // even when the caller passes an old `observedAt`.
    `ALTER TABLE connections ADD COLUMN tombstone_wm_o INTEGER`,
    `ALTER TABLE connections ADD COLUMN tombstone_wm_r TEXT`,
    // 1 = some upserts of this stream were staged in `run_rows` and not
    // admitted (the connector check blocked them, or the stream's head or floor
    // changed between that check and the batch commit). Run end merges them.
    `ALTER TABLE run_streams ADD COLUMN unadmitted INTEGER NOT NULL DEFAULT 0`,
  ],
  [
    // A stream's first load, while its parts are still being applied. One row
    // per stream, written by apply in the same transaction as each part's
    // rows, so a reader that sees rows of the load sees the row that names
    // their head. It names the head (`version`, `generation`, `data_hash`) the
    // rows belong to and how many of its parts are applied. `failed` and
    // `last_error` say the apply stopped before the last part, and why; the
    // next part clears them. Completion, purge and a tombstone delete the row.
    // Local only: never in a part. A reader serves it only when asked to
    // (`progressiveFirstLoad`).
    `CREATE TABLE stream_partial (
  connection_id TEXT NOT NULL, stream TEXT NOT NULL,
  version INTEGER NOT NULL, generation INTEGER NOT NULL, data_hash TEXT NOT NULL, head_blob TEXT NOT NULL,
  observed_at INTEGER NOT NULL,
  parts_applied INTEGER NOT NULL, parts_total INTEGER NOT NULL, records_total INTEGER NOT NULL,
  failed INTEGER NOT NULL DEFAULT 0, last_error TEXT,
  PRIMARY KEY (connection_id, stream)) WITHOUT ROWID`,
    // The rows a stream held when its load began, which the load has not yet
    // matched with a part: rows of an earlier head, and local rows the
    // complete state keeps. They stay stored, because only the complete state
    // knows which go, and a partial view leaves them out until a part holds
    // their key. Gone with the row of `stream_partial` they belong to.
    `CREATE TABLE partial_hidden (
  connection_id TEXT NOT NULL, stream TEXT NOT NULL, pk_hash TEXT NOT NULL,
  PRIMARY KEY (connection_id, stream, pk_hash)) WITHOUT ROWID`,
    `CREATE TRIGGER partial_hidden_ad AFTER DELETE ON stream_partial BEGIN
  DELETE FROM partial_hidden WHERE connection_id = OLD.connection_id AND stream = OLD.stream;
END`,
    // Each part moves the row, and a screen shows the progress, so any change
    // of it is a change of the view. `INSERT OR REPLACE` fires no delete
    // trigger, so a BEFORE trigger bumps unless an identical row is stored.
    // A stream that reads as complete has no first load: whichever path
    // completes it (a head's last part, the log's apply) ends its row here, so
    // none of them has to remember to.
    `CREATE TRIGGER partial_complete_au AFTER UPDATE ON stream_state
WHEN NEW.complete = 1 BEGIN
  DELETE FROM stream_partial WHERE connection_id = NEW.connection_id AND stream = NEW.stream;
END`,
    `CREATE TRIGGER view_partial_bi BEFORE INSERT ON stream_partial
WHEN NOT EXISTS (SELECT 1 FROM stream_partial o WHERE o.connection_id = NEW.connection_id AND o.stream = NEW.stream
  AND o.version = NEW.version AND o.generation = NEW.generation AND o.data_hash = NEW.data_hash AND o.head_blob = NEW.head_blob
  AND o.observed_at = NEW.observed_at AND o.parts_applied = NEW.parts_applied AND o.parts_total = NEW.parts_total
  AND o.records_total = NEW.records_total AND o.failed = NEW.failed AND o.last_error IS NEW.last_error) BEGIN
  ${bumpView("NEW")}
END`,
    `CREATE TRIGGER view_partial_au AFTER UPDATE ON stream_partial BEGIN
  ${bumpView("NEW")}
END`,
    `CREATE TRIGGER view_partial_ad AFTER DELETE ON stream_partial BEGIN
  ${bumpView("OLD")}
END`,
  ],
  [
    // A log tombstone also keeps the canonical record key of the deletion it
    // records (log format 2): the key a record-level reader needs for a key it
    // never held, which the hash cannot give back. Local only. NULL only for a
    // tombstone written before the column; format 1 wrote none that shipped.
    `ALTER TABLE log_tombstones ADD COLUMN record_key TEXT`,
  ],
  [
    // A deletion in the log names its key as the typed primary-key values its
    // pk hash is computed from (log format 2). A run row holds the record's
    // data, which run end purges, and a change keeps only the lossy string
    // `record_key`; so an explicit delete keeps the values themselves, as
    // canonical JSON, from the run row that made it. NULL for a change made
    // before the column: its typed key is gone, and the log never carried it.
    `ALTER TABLE run_rows ADD COLUMN pk_values TEXT`,
    `ALTER TABLE record_changes ADD COLUMN pk_values TEXT`,
    // The types the stream's schema declares for its key fields (JSON array of
    // type names or null), from the latest run's declarations. With the record
    // key they give a delete made before `pk_values` its typed key back.
    `ALTER TABLE stream_state ADD COLUMN key_types TEXT`,
  ],
  [
    // The intake batch ordinal of the run that observed a record's body: the
    // order between two bodies of one key at one stamp (`mergeIncoming`). A run
    // that publishes while collecting can admit a key again in a later batch
    // with a changed body, at the same stamp; the later batch is the fresher
    // observation. 0 for a row from before the column and for a run's first batch.
    `ALTER TABLE records ADD COLUMN stamp_n INTEGER NOT NULL DEFAULT 0`,

    // The last registry per-stream head this device consumed completely:
    // `head_version` cannot say it, because the log's own rounds also advance
    // `head_version` (a local number above anything the registry holds). A row
    // is written only when a head's apply (or this device's own publish of a
    // head) finishes; the log never touches it. A row of a connection with no
    // log took its head as consumed. A connection that followed a log did not:
    // its `head_version` may be a log's local number, so its heads are read
    // once more.
    `ALTER TABLE stream_state ADD COLUMN consumed_version INTEGER NOT NULL DEFAULT 0`,
    `ALTER TABLE stream_state ADD COLUMN consumed_generation INTEGER`,
    `ALTER TABLE stream_state ADD COLUMN consumed_data_hash TEXT`,
    `UPDATE stream_state SET consumed_version = head_version, consumed_generation = head_generation,
        consumed_data_hash = head_data_hash
      WHERE head_version > 0 AND head_data_hash IS NOT NULL
        AND NOT EXISTS (SELECT 1 FROM log_state l WHERE l.connection_id = stream_state.connection_id)`,

    // The log replay a head admission owes. A per-stream head merged beside a
    // log can drop rows the log holds, so the head batch resets the log
    // cursor (`log_state`) and writes this row in the same batch: one row
    // per connection, present until a replay of the log has been validated
    // and finished. `position` and `last_ref` are the cursor the batch
    // replaced (0 and null for a device that held none): the evidence that a
    // registry log behind that position, or naming another segment there, is
    // not a continuation. Local only.
    `CREATE TABLE log_replay (
  connection_id TEXT PRIMARY KEY, position INTEGER NOT NULL, last_ref TEXT) WITHOUT ROWID;`,
  ],
  [
    // A key-ordered first load of the log (log-keyed.ts) writes its rows one
    // key range at a time and moves `log_state` in the last commit. Between
    // them the rows are in `records` and `log_tombstones` with no stream
    // version. This keeps, per connection, the position and refs that load
    // means to publish, written with its first range and deleted with its
    // last, so a retry that holds a shorter prefix cannot publish over those
    // rows. Local only.
    `CREATE TABLE log_keyed_pending (
  connection_id TEXT PRIMARY KEY, position INTEGER NOT NULL, base INTEGER NOT NULL,
  refs TEXT NOT NULL) WITHOUT ROWID`,
  ],
  [
    // The connection log is the only protocol, so the state the per-stream
    // head path kept beside it is gone: the parts a head was built from
    // (`head_parts`), the replay a head admission owed (`log_replay`) and the
    // registry head a device had consumed (`consumed_*`). Local only.
    `DROP TABLE IF EXISTS head_parts`,
    `DROP TABLE IF EXISTS log_replay`,
    `ALTER TABLE stream_state DROP COLUMN consumed_version`,
    `ALTER TABLE stream_state DROP COLUMN consumed_generation`,
    `ALTER TABLE stream_state DROP COLUMN consumed_data_hash`,
    // The copy a head publish attempt sent from (`publish_spool`) went with it.
    `DROP TABLE IF EXISTS publish_spool`,
  ],
  [
    // The stream meta the log said at each local version, beside its
    // `complete`. A run's end writes its own meta into `stream_state` before
    // its publish, so the publish compares the run with these. NULL on a row
    // written before this column: the stream's own meta stands in.
    `ALTER TABLE stream_versions ADD COLUMN primary_key TEXT`,
    `ALTER TABLE stream_versions ADD COLUMN profile_key TEXT`,
    `ALTER TABLE stream_versions ADD COLUMN profile_version TEXT`,
  ],
];
