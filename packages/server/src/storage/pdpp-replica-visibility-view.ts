import type { Database } from "better-sqlite3";
import {
  canonicalJson,
  type ReplicaOperation,
} from "@opendatalabs/personal-server-ts-core/replication/envelope";
import {
  planReplicaMerge,
  type MergeContext,
} from "@opendatalabs/personal-server-ts-core/replication/merge-plan";
import {
  replicaPendingMetadata,
  replicaConflictMetadata,
  replicaConnectionVisibility,
  replicaStateVisible,
  type ReplicaReader,
} from "@opendatalabs/personal-server-ts-core/replication/visibility-policy";
import {
  CursorExpiredError,
  InvalidCursorError,
  decodeCursor,
  encodeCursor,
  type ListRecordsOptions,
  type ListVisibleRecordsPage,
  type PdppVisibleRecord,
  type PdppBlobMeta,
  type StreamListing,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { replicaOperationDigest } from "./pdpp-replication-sqlite.js";

type Evidence = { op: ReplicaOperation; confirmed: boolean; pending: number };
type CanonicalRow = {
  instance: string;
  stream: string;
  record_key: string;
  data: string | null;
  version: number;
  emitted_at: string;
  deleted: number;
  deleted_at: string | null;
  blob_id: string | null;
};
type OverlayRow = {
  emitted_at: string;
  row_json: string | null;
  blob_id: string | null;
  blob_json: string | null;
  present: number;
  live: number;
  pending: number;
  base_live: number;
};

/** Bump when the derived view layout changes; construction then rebuilds it. */
const VIEW_SCHEMA = 8;
/**
 * Revisions are comparable only within one view layout, so the layout version
 * tags every cursor. 70d52db0 cursors carry an untagged revision and expire.
 */
const CURSOR_FORMAT = `v${VIEW_SCHEMA}`;
const LIFECYCLE =
  "('connection-register','connection-reset','connection-delete')";
// Canonical triggers ignore rewrites that change no stored value.
const recordChanged =
  "(OLD.version IS NOT NEW.version OR OLD.data IS NOT NEW.data OR OLD.emitted_at IS NOT NEW.emitted_at OR OLD.deleted IS NOT NEW.deleted OR OLD.deleted_at IS NOT NEW.deleted_at OR OLD.blob_id IS NOT NEW.blob_id)";
// Retained operations are indexed in place by these expressions; no copy of their JSON.
const operationExpressions = {
  instance: "json_extract(operation_json,'$.connectionId')",
  stream: "json_extract(operation_json,'$.declaration.stream')",
  record_key: "json_extract(operation_json,'$.recordKey')",
  kind: "json_extract(operation_json,'$.kind')",
  writer: "json_extract(operation_json,'$.revision.writerId')",
  operation_id: "json_extract(operation_json,'$.revision.operationId')",
  blob_id:
    "COALESCE(json_extract(operation_json,'$.blob.blobId'),json_extract(operation_json,'$.blobs[0].blobId'))",
};
const expression = (column: keyof typeof operationExpressions) =>
  operationExpressions[column];
const operationColumns = Object.entries(operationExpressions)
  .map(([column, sql]) => `${sql} AS ${column}`)
  .join(",");

/** Drops only derived view objects. Canonical, retained and pending tables stay. */
function dropViewObjects(db: Database) {
  const objects = db
    .prepare(
      "SELECT type,name FROM sqlite_master WHERE (type IN ('trigger','view','index') AND (name GLOB 'pdpp_replica_view*' OR name GLOB 'pdpp_replica_local*' OR name GLOB 'pdpp_records_summary_*')) OR (type='table' AND (name GLOB 'pdpp_replica_view*' OR name='pdpp_replica_local_view'))",
    )
    .all() as { type: "trigger" | "view" | "index" | "table"; name: string }[];
  const order = ["trigger", "view", "index", "table"];
  for (const { type, name } of objects.sort(
    (a, b) => order.indexOf(a.type) - order.indexOf(b.type),
  ))
    db.exec(`DROP ${type.toUpperCase()} IF EXISTS "${name}"`);
}

/**
 * Sparse owner preview, reconciled at mutation time. It persists only keys whose
 * owner-visible state differs from canonical: pending values, marked pending
 * removals and hidden equivocated keys. Without pending evidence or operation-ID
 * variants for a key's merge inputs, owner preview equals canonical by definition
 * and stores nothing. Reads never run the reducer.
 */
export function createReplicaVisibilityView(deps: {
  db: Database;
  owner: string;
  declarations: () => MergeContext["declarations"];
  unquarantinedRecordSql: (alias: string) => string;
  /** Optional synthesis-lane capability; absent means the reset fence alone. */
  integrityEpoch?: (connection: string) => number;
  blobsValid: (
    op: Extract<ReplicaOperation, { kind: "upsert" }>,
    evidence: ReplicaOperation[],
  ) => boolean;
}) {
  const { db } = deps;
  const hasBindingConflictFacts = !!db
    .prepare(
      "SELECT 1 FROM sqlite_master WHERE type='table' AND name='pdpp_replica_binding_conflicts'",
    )
    .get();
  const hasCopyFacts = !!db
    .prepare(
      "SELECT 1 FROM sqlite_master WHERE type='table' AND name='pdpp_replica_copies'",
    )
    .get();
  const localIdentitySql = (alias: string) =>
    `EXISTS (SELECT 1 FROM pdpp_instance_binding b WHERE b.instance=${alias}.instance AND b.deleted_at IS NULL AND b.source_id IS NOT NULL AND b.method IS NOT NULL AND b.source_id=${alias}.source_id AND b.method=${alias}.method AND b.generation=${alias}.generation)`;
  const localProjection = `SELECT j.connection_id,j.stream,j.record_key,json_extract(j.value_json,'$.emittedAt'),j.value_json,json_extract(j.value_json,'$.data.blob_ref.blob_id'),0,json_extract(j.value_json,'$.deleted'),NULL,j.sequence,j.generation,j.source_id,j.method FROM pdpp_mutation_journal j JOIN pdpp_instance_binding b ON b.instance=j.connection_id AND b.generation=j.generation AND b.source_id=j.source_id AND b.method=j.method WHERE b.source_id IS NOT NULL AND b.method IS NOT NULL AND b.deleted_at IS NULL AND j.writer_id=(SELECT writer_id FROM pdpp_installation_writer WHERE id=1) AND NOT EXISTS (SELECT 1 FROM pdpp_mutation_journal newer WHERE newer.connection_id=j.connection_id AND newer.generation=j.generation AND newer.stream=j.stream AND newer.record_key=j.record_key AND newer.source_id=j.source_id AND newer.method=j.method AND newer.writer_id=j.writer_id AND newer.sequence>j.sequence)`;
  // Whether a key can have an overlay row at all. Canonical writes and retained
  // record operations outside this predicate cannot change the owner preview.
  const touches = (instance: string, stream: string, key: string) =>
    `(EXISTS (SELECT 1 FROM pdpp_replica_view v WHERE v.instance=${instance} AND v.stream=${stream} AND v.record_key=${key}) OR EXISTS (SELECT 1 FROM pdpp_replica_view_pending p WHERE p.instance=${instance}) OR EXISTS (SELECT 1 FROM pdpp_replica_view_conflicts c WHERE c.instance=${instance}) OR EXISTS (SELECT 1 FROM pdpp_instance_binding b WHERE b.instance=${instance} AND b.deleted_at IS NOT NULL))`;
  // Trigger bodies use NOT EXISTS, never a conflict clause (OR IGNORE, OR
  // REPLACE, ...): an outer statement's conflict clause, including an upsert's,
  // overrides one inside a trigger. A receiver test checks every trigger body.
  const notDirtyKey = (alias: string) =>
    `NOT EXISTS (SELECT 1 FROM pdpp_replica_view_dirty_keys d WHERE d.instance=${alias}.instance AND d.stream=${alias}.stream AND d.record_key=${alias}.record_key)`;
  // Upserts that reference any of `blobIds` (a SQL value list or subquery),
  // restricted to keys that can have an overlay row.
  const markBlobDependents = (blobIds: string) =>
    `INSERT INTO pdpp_replica_view_dirty_keys SELECT DISTINCT o.instance,o.stream,o.record_key FROM pdpp_replica_view_operations o WHERE o.blob_id IN (${blobIds}) AND o.kind='upsert' AND o.record_key IS NOT NULL AND ${touches("o.instance", "o.stream", "o.record_key")} AND ${notDirtyKey("o")};`;
  const markLatest = (alias: string) =>
    // NOT EXISTS, not OR IGNORE: an outer statement's conflict clause
    // overrides one inside a trigger.
    `INSERT INTO pdpp_replica_view_dirty_latest SELECT ${alias}.instance,${alias}.stream WHERE NOT EXISTS (SELECT 1 FROM pdpp_replica_view_dirty_latest d WHERE d.instance=${alias}.instance AND d.stream=${alias}.stream);`;
  const hasOverlaySummary = (alias: string) =>
    `EXISTS (SELECT 1 FROM pdpp_replica_view_streams s WHERE s.preview=1 AND s.instance=${alias}.instance AND s.stream=${alias}.stream)`;
  const markKey = (alias: string) =>
    `INSERT INTO pdpp_replica_view_dirty_keys SELECT ${alias}.instance,${alias}.stream,${alias}.record_key WHERE ${touches(`${alias}.instance`, `${alias}.stream`, `${alias}.record_key`)} AND ${notDirtyKey(alias)};`;

  db.transaction(() => {
    const schema = db
      .prepare(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='pdpp_replica_view_schema'",
      )
      .get()
      ? (db.prepare("SELECT version FROM pdpp_replica_view_schema").get() as
          { version: number } | undefined)
      : undefined;
    const initialized = schema?.version === VIEW_SCHEMA;
    // Derived state only: an earlier view layout is dropped and rebuilt here, at
    // construction inside this write transaction, never during a read.
    if (!initialized) dropViewObjects(db);
    db.exec(`
      CREATE TABLE IF NOT EXISTS pdpp_replica_view_schema (version INTEGER NOT NULL);
      -- Sparse overlay. present: shown in owner pages; live: a visible value;
      -- base_live: canonical row was live when this row was derived.
      CREATE TABLE IF NOT EXISTS pdpp_replica_view (
        instance TEXT NOT NULL, stream TEXT NOT NULL, record_key TEXT NOT NULL,
        emitted_at TEXT NOT NULL, row_json TEXT, blob_id TEXT, blob_json TEXT,
        present INTEGER NOT NULL, live INTEGER NOT NULL, pending INTEGER NOT NULL, base_live INTEGER NOT NULL,
        PRIMARY KEY(instance,stream,record_key)
      );
      CREATE INDEX IF NOT EXISTS pdpp_replica_view_page ON pdpp_replica_view(instance,stream,emitted_at,record_key) WHERE present=1;
      CREATE INDEX IF NOT EXISTS pdpp_replica_view_blob ON pdpp_replica_view(blob_id) WHERE blob_id IS NOT NULL;
      CREATE INDEX IF NOT EXISTS pdpp_replica_canonical_page ON pdpp_records(instance,stream,emitted_at,record_key) WHERE deleted=0;
      CREATE INDEX IF NOT EXISTS pdpp_replica_pending_blob ON pdpp_replica_pending_bytes(blob_id,batch_id);
      -- One summary and one monotone cursor revision per (mode table, connection, stream).
      -- Mode 1 holds the overlay's deltas against mode 0, not a second count.
      CREATE TABLE IF NOT EXISTS pdpp_replica_view_streams (preview INTEGER NOT NULL, instance TEXT NOT NULL, stream TEXT NOT NULL, live_count INTEGER NOT NULL, row_count INTEGER NOT NULL, pending_count INTEGER NOT NULL, last_updated TEXT, revision INTEGER NOT NULL DEFAULT 1, PRIMARY KEY(preview,instance,stream));
      -- Active pending operations, one row per (batch, operation).
      CREATE TABLE IF NOT EXISTS pdpp_replica_view_pending (
        batch_id TEXT NOT NULL, digest TEXT NOT NULL, operation_json TEXT NOT NULL,
        instance TEXT NOT NULL, stream TEXT, record_key TEXT, kind TEXT NOT NULL,
        writer TEXT NOT NULL, operation_id TEXT NOT NULL, blob_id TEXT,
        PRIMARY KEY(batch_id,digest)
      );
      CREATE INDEX IF NOT EXISTS pdpp_replica_view_pending_key ON pdpp_replica_view_pending(instance,stream,record_key);
      CREATE INDEX IF NOT EXISTS pdpp_replica_view_pending_kind ON pdpp_replica_view_pending(instance,kind);
      CREATE INDEX IF NOT EXISTS pdpp_replica_view_pending_id ON pdpp_replica_view_pending(writer,operation_id);
      CREATE INDEX IF NOT EXISTS pdpp_replica_view_pending_blob ON pdpp_replica_view_pending(blob_id,instance) WHERE blob_id IS NOT NULL;
      -- Operation-ID variants (global equivocation), by digest.
      CREATE TABLE IF NOT EXISTS pdpp_replica_view_conflicts (writer TEXT NOT NULL, operation_id TEXT NOT NULL, instance TEXT NOT NULL, digest TEXT NOT NULL, PRIMARY KEY(writer,operation_id,digest));
      CREATE INDEX IF NOT EXISTS pdpp_replica_view_conflict_instance ON pdpp_replica_view_conflicts(instance);
      CREATE TABLE IF NOT EXISTS pdpp_replica_view_dirty_operations (digest TEXT PRIMARY KEY, operation_json TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS pdpp_replica_view_dirty_keys (instance TEXT NOT NULL, stream TEXT NOT NULL, record_key TEXT NOT NULL, PRIMARY KEY(instance,stream,record_key));
      CREATE TABLE IF NOT EXISTS pdpp_replica_view_dirty_connections (instance TEXT PRIMARY KEY);
      -- Streams whose owner-preview latest row may have moved; flush recomputes them.
      CREATE TABLE IF NOT EXISTS pdpp_replica_view_dirty_latest (instance TEXT NOT NULL, stream TEXT NOT NULL, PRIMARY KEY(instance,stream));
    `);
    for (const table of ["pdpp_replica_operations", "pdpp_replica_received"])
      db.exec(`
        CREATE INDEX IF NOT EXISTS pdpp_replica_view_ops_key_${table} ON ${table}(${expression("instance")},${expression("stream")},${expression("record_key")}) WHERE ${expression("record_key")} IS NOT NULL;
        CREATE INDEX IF NOT EXISTS pdpp_replica_view_ops_kind_${table} ON ${table}(${expression("instance")},${expression("kind")});
        CREATE INDEX IF NOT EXISTS pdpp_replica_view_ops_id_${table} ON ${table}(${expression("writer")},${expression("operation_id")});
        CREATE INDEX IF NOT EXISTS pdpp_replica_view_ops_blob_${table} ON ${table}(${expression("blob_id")},${expression("instance")}) WHERE ${expression("blob_id")} IS NOT NULL;
      `);
    db.exec(`
      CREATE VIEW IF NOT EXISTS pdpp_replica_view_operations AS
        SELECT digest,operation_json,${operationColumns},1 AS confirmed,0 AS pending FROM pdpp_replica_operations
        UNION ALL SELECT digest,operation_json,${operationColumns},1,0 FROM pdpp_replica_received
        UNION ALL SELECT digest,operation_json,instance,stream,record_key,kind,writer,operation_id,blob_id,0,1 FROM pdpp_replica_view_pending;
    `);
    for (const table of ["pdpp_replica_operations", "pdpp_replica_received"])
      db.exec(`
        CREATE TRIGGER IF NOT EXISTS pdpp_replica_view_retained_${table} AFTER INSERT ON ${table}
        WHEN json_extract(NEW.operation_json,'$.kind') NOT IN ('upsert','delete')
          OR EXISTS (SELECT 1 FROM pdpp_replica_view_operations o WHERE o.writer=json_extract(NEW.operation_json,'$.revision.writerId') AND o.operation_id=json_extract(NEW.operation_json,'$.revision.operationId') AND o.digest<>NEW.digest)
          OR ${touches("json_extract(NEW.operation_json,'$.connectionId')", "json_extract(NEW.operation_json,'$.declaration.stream')", "json_extract(NEW.operation_json,'$.recordKey')")}
        BEGIN
          INSERT INTO pdpp_replica_view_dirty_operations SELECT NEW.digest,NEW.operation_json WHERE NOT EXISTS (SELECT 1 FROM pdpp_replica_view_dirty_operations d WHERE d.digest=NEW.digest);
        END;
      `);
    db.exec(`
      CREATE TRIGGER IF NOT EXISTS pdpp_replica_view_record_insert AFTER INSERT ON pdpp_records BEGIN ${markKey("NEW")} END;
      CREATE TRIGGER IF NOT EXISTS pdpp_replica_view_record_update AFTER UPDATE ON pdpp_records WHEN ${recordChanged} BEGIN ${markKey("NEW")} END;
      CREATE TRIGGER IF NOT EXISTS pdpp_replica_view_record_delete AFTER DELETE ON pdpp_records BEGIN ${markKey("OLD")} END;
      CREATE TRIGGER IF NOT EXISTS pdpp_replica_view_binding AFTER UPDATE ON pdpp_instance_binding
      WHEN NEW.generation != OLD.generation OR NEW.deleted_at IS NOT OLD.deleted_at OR NEW.source_id IS NOT OLD.source_id OR NEW.method IS NOT OLD.method OR NEW.reset_clock IS NOT OLD.reset_clock BEGIN
        -- Binding and lifecycle changes expire every stream cursor of the connection.
        UPDATE pdpp_replica_view_streams SET revision=revision+1 WHERE instance=NEW.instance;
        INSERT INTO pdpp_replica_view_dirty_connections SELECT NEW.instance WHERE NOT EXISTS (SELECT 1 FROM pdpp_replica_view_dirty_connections d WHERE d.instance=NEW.instance);
      END;
      -- Blob bytes decide whether an upsert that references them is visible. Bytes
      -- can arrive or leave without any new record operation (a replayed claim,
      -- another connection's import, another pending batch), so their arrival
      -- and removal mark every dependent key the view can reach.
      CREATE TRIGGER IF NOT EXISTS pdpp_replica_view_bytes_received AFTER INSERT ON pdpp_replica_received_bytes BEGIN ${markBlobDependents("NEW.blob_id")} END;
      CREATE TRIGGER IF NOT EXISTS pdpp_replica_view_bytes_received_delete AFTER DELETE ON pdpp_replica_received_bytes BEGIN ${markBlobDependents("OLD.blob_id")} END;
      CREATE TRIGGER IF NOT EXISTS pdpp_replica_view_bytes_canonical AFTER INSERT ON pdpp_blob_bytes BEGIN ${markBlobDependents("NEW.blob_id")} END;
      CREATE TRIGGER IF NOT EXISTS pdpp_replica_view_bytes_canonical_delete AFTER DELETE ON pdpp_blob_bytes BEGIN ${markBlobDependents("OLD.blob_id")} END;
      CREATE TRIGGER IF NOT EXISTS pdpp_replica_view_bytes_pending AFTER INSERT ON pdpp_replica_pending_bytes BEGIN ${markBlobDependents("NEW.blob_id")} END;
      CREATE TRIGGER IF NOT EXISTS pdpp_replica_view_bytes_pending_delete AFTER DELETE ON pdpp_replica_pending_bytes BEGIN ${markBlobDependents("OLD.blob_id")} END;
      -- Pending bytes count only while their batch is pending.
      CREATE TRIGGER IF NOT EXISTS pdpp_replica_view_bytes_batch AFTER UPDATE OF state ON pdpp_replica_pending_batches WHEN NEW.state IS NOT OLD.state BEGIN
        ${markBlobDependents("SELECT blob_id FROM pdpp_replica_pending_bytes WHERE batch_id=NEW.id")}
      END;
      -- Mode 1's last_updated is the owner preview's latest row, derived at
      -- write time: overlay rows can mask any number of newer canonical rows.
      CREATE TRIGGER IF NOT EXISTS pdpp_replica_view_latest_overlay_insert AFTER INSERT ON pdpp_replica_view BEGIN ${markLatest("NEW")} END;
      CREATE TRIGGER IF NOT EXISTS pdpp_replica_view_latest_overlay_update AFTER UPDATE ON pdpp_replica_view BEGIN ${markLatest("NEW")} END;
      CREATE TRIGGER IF NOT EXISTS pdpp_replica_view_latest_overlay_delete AFTER DELETE ON pdpp_replica_view BEGIN ${markLatest("OLD")} END;
      CREATE TRIGGER IF NOT EXISTS pdpp_replica_view_latest_record_insert AFTER INSERT ON pdpp_records WHEN ${hasOverlaySummary("NEW")} BEGIN ${markLatest("NEW")} END;
      CREATE TRIGGER IF NOT EXISTS pdpp_replica_view_latest_record_update AFTER UPDATE ON pdpp_records WHEN ${recordChanged} AND ${hasOverlaySummary("NEW")} BEGIN ${markLatest("NEW")} END;
      CREATE TRIGGER IF NOT EXISTS pdpp_replica_view_latest_record_delete AFTER DELETE ON pdpp_records WHEN ${hasOverlaySummary("OLD")} BEGIN ${markLatest("OLD")} END;
      CREATE TRIGGER IF NOT EXISTS pdpp_replica_view_overlay_insert AFTER INSERT ON pdpp_replica_view BEGIN
        INSERT INTO pdpp_replica_view_streams VALUES (1,NEW.instance,NEW.stream,NEW.live-NEW.base_live,NEW.present-NEW.base_live,NEW.pending,NULL,1)
        ON CONFLICT(preview,instance,stream) DO UPDATE SET revision=revision+1,live_count=live_count+NEW.live-NEW.base_live,row_count=row_count+NEW.present-NEW.base_live,pending_count=pending_count+NEW.pending;
      END;
      CREATE TRIGGER IF NOT EXISTS pdpp_replica_view_overlay_update AFTER UPDATE ON pdpp_replica_view BEGIN
        UPDATE pdpp_replica_view_streams SET revision=revision+1,live_count=live_count+(NEW.live-NEW.base_live)-(OLD.live-OLD.base_live),row_count=row_count+(NEW.present-NEW.base_live)-(OLD.present-OLD.base_live),pending_count=pending_count+NEW.pending-OLD.pending
        WHERE preview=1 AND instance=OLD.instance AND stream=OLD.stream;
      END;
      CREATE TRIGGER IF NOT EXISTS pdpp_replica_view_overlay_delete AFTER DELETE ON pdpp_replica_view BEGIN
        UPDATE pdpp_replica_view_streams SET revision=revision+1,live_count=live_count-(OLD.live-OLD.base_live),row_count=row_count-(OLD.present-OLD.base_live),pending_count=pending_count-OLD.pending
        WHERE preview=1 AND instance=OLD.instance AND stream=OLD.stream;
      END;
    `);
    // The local journal projection exists only for connections with a durable
    // binding-conflict fact; the fact table is monotone.
    const localInitialized =
      hasBindingConflictFacts &&
      !!db
        .prepare(
          "SELECT 1 FROM sqlite_master WHERE type='trigger' AND name='pdpp_replica_local_conflict'",
        )
        .get();
    if (hasBindingConflictFacts) {
      const conflicted = (instance: string) =>
        `EXISTS (SELECT 1 FROM pdpp_replica_binding_conflicts f WHERE f.instance=${instance})`;
      db.exec(`
      CREATE TABLE IF NOT EXISTS pdpp_replica_local_view (instance TEXT NOT NULL,stream TEXT NOT NULL,record_key TEXT NOT NULL,emitted_at TEXT NOT NULL,row_json TEXT NOT NULL,blob_id TEXT,pending INTEGER NOT NULL,deleted INTEGER NOT NULL,blob_json TEXT,sequence INTEGER NOT NULL,generation INTEGER NOT NULL,source_id TEXT NOT NULL,method TEXT NOT NULL,PRIMARY KEY(instance,stream,record_key));
      CREATE INDEX IF NOT EXISTS pdpp_replica_local_page ON pdpp_replica_local_view(instance,stream,emitted_at,record_key) WHERE deleted=0;
      CREATE INDEX IF NOT EXISTS pdpp_replica_local_blob ON pdpp_replica_local_view(blob_id) WHERE deleted=0 AND blob_id IS NOT NULL;
      CREATE TRIGGER IF NOT EXISTS pdpp_replica_local_journal AFTER INSERT ON pdpp_mutation_journal
      WHEN ${conflicted("NEW.connection_id")} AND NEW.writer_id=(SELECT writer_id FROM pdpp_installation_writer WHERE id=1) AND EXISTS (SELECT 1 FROM pdpp_instance_binding b WHERE b.instance=NEW.connection_id AND b.generation=NEW.generation AND b.source_id=NEW.source_id AND b.method=NEW.method AND b.source_id IS NOT NULL AND b.method IS NOT NULL AND b.deleted_at IS NULL) BEGIN
        INSERT INTO pdpp_replica_local_view VALUES (NEW.connection_id,NEW.stream,NEW.record_key,json_extract(NEW.value_json,'$.emittedAt'),NEW.value_json,json_extract(NEW.value_json,'$.data.blob_ref.blob_id'),0,json_extract(NEW.value_json,'$.deleted'),NULL,NEW.sequence,NEW.generation,NEW.source_id,NEW.method)
        ON CONFLICT(instance,stream,record_key) DO UPDATE SET emitted_at=excluded.emitted_at,row_json=excluded.row_json,blob_id=excluded.blob_id,deleted=excluded.deleted,sequence=excluded.sequence,generation=excluded.generation,source_id=excluded.source_id,method=excluded.method WHERE excluded.sequence>pdpp_replica_local_view.sequence;
      END;
      CREATE TRIGGER IF NOT EXISTS pdpp_replica_local_binding AFTER UPDATE ON pdpp_instance_binding
      WHEN ${conflicted("NEW.instance")} AND (NEW.generation IS NOT OLD.generation OR NEW.source_id IS NOT OLD.source_id OR NEW.method IS NOT OLD.method OR NEW.deleted_at IS NOT OLD.deleted_at) BEGIN
        DELETE FROM pdpp_replica_local_view WHERE instance=NEW.instance;
        INSERT INTO pdpp_replica_local_view ${localProjection} AND j.connection_id=NEW.instance;
      END;
      CREATE TRIGGER IF NOT EXISTS pdpp_replica_local_conflict AFTER INSERT ON pdpp_replica_binding_conflicts BEGIN
        DELETE FROM pdpp_replica_local_view WHERE instance=NEW.instance;
        INSERT INTO pdpp_replica_local_view ${localProjection} AND j.connection_id=NEW.instance;
      END;
    `);
    }
    for (const [table, preview] of [
      ["pdpp_records", 0],
      ...(hasBindingConflictFacts
        ? [["pdpp_replica_local_view", 2] as const]
        : []),
    ] as const) {
      const latest = `SELECT emitted_at FROM ${table} WHERE instance=OLD.instance AND stream=OLD.stream AND deleted=0 ORDER BY emitted_at DESC,record_key DESC LIMIT 1`;
      db.exec(`
        CREATE TRIGGER IF NOT EXISTS ${table}_summary_insert AFTER INSERT ON ${table} BEGIN
          INSERT INTO pdpp_replica_view_streams VALUES (${preview},NEW.instance,NEW.stream,1-NEW.deleted,1-NEW.deleted,0,CASE WHEN NEW.deleted=0 THEN NEW.emitted_at ELSE NULL END,1)
          ON CONFLICT(preview,instance,stream) DO UPDATE SET revision=revision+1,
            live_count=live_count+1-NEW.deleted,row_count=row_count+1-NEW.deleted,
            last_updated=CASE WHEN NEW.deleted=0 AND (last_updated IS NULL OR NEW.emitted_at>last_updated) THEN NEW.emitted_at ELSE last_updated END;
        END;
        CREATE TRIGGER IF NOT EXISTS ${table}_summary_update AFTER UPDATE ON ${table} ${preview === 0 ? `WHEN ${recordChanged}` : ""} BEGIN
          UPDATE pdpp_replica_view_streams SET revision=revision+1,live_count=live_count+OLD.deleted-NEW.deleted,
            row_count=row_count+OLD.deleted-NEW.deleted,last_updated=(${latest}) WHERE preview=${preview} AND instance=OLD.instance AND stream=OLD.stream;
        END;
        CREATE TRIGGER IF NOT EXISTS ${table}_summary_delete AFTER DELETE ON ${table} BEGIN
          UPDATE pdpp_replica_view_streams SET revision=revision+1,live_count=live_count-(1-OLD.deleted),row_count=row_count-(1-OLD.deleted),last_updated=(${latest})
          WHERE preview=${preview} AND instance=OLD.instance AND stream=OLD.stream;
        END;
      `);
    }
    if (hasCopyFacts) {
      // Each copy contributes once per stream, regardless of operation count or
      // connections. Group identical connection sets to keep metadata reads off
      // the retained copies and their envelopes (including large backlogs).
      const copyStreams = (alias: string) => `
        INSERT INTO pdpp_replica_view_copy_streams
        SELECT ${alias}.id,${alias}.copy_key,stream,json_group_array(instance)
        FROM (SELECT DISTINCT json_extract(value,'$.declaration.stream') AS stream,
          json_extract(value,'$.connectionId') AS instance
          FROM json_each(${alias}.envelope_json,'$.operations')
          WHERE json_extract(value,'$.declaration.stream') IS NOT NULL
          ORDER BY stream,instance)
        WHERE ${alias}.state='quarantined' AND ${alias}.reason IN ('copy_conflict','finalized_conflict')
        GROUP BY stream;
        INSERT INTO pdpp_replica_view_copy_connections
        SELECT DISTINCT ${alias}.id,${alias}.copy_key,json_extract(value,'$.connectionId')
        FROM json_each(${alias}.envelope_json,'$.operations')
        WHERE ${alias}.state='quarantined' AND ${alias}.reason IN ('copy_conflict','finalized_conflict');`;
      db.exec(`
        CREATE TABLE IF NOT EXISTS pdpp_replica_view_copy_connections (
          id TEXT NOT NULL,copy_key TEXT NOT NULL,instance TEXT NOT NULL,
          PRIMARY KEY(id,copy_key,instance)
        );
        CREATE TABLE IF NOT EXISTS pdpp_replica_view_copy_streams (
          id TEXT NOT NULL,copy_key TEXT NOT NULL,stream TEXT NOT NULL,instances TEXT NOT NULL,
          PRIMARY KEY(id,copy_key,stream)
        );
        CREATE TABLE IF NOT EXISTS pdpp_replica_view_copy_counts (
          stream TEXT NOT NULL,instances TEXT NOT NULL,n INTEGER NOT NULL,
          PRIMARY KEY(stream,instances)
        );
        CREATE TABLE IF NOT EXISTS pdpp_replica_view_copy_groups (
          instance TEXT NOT NULL,stream TEXT NOT NULL,instances TEXT NOT NULL,
          PRIMARY KEY(instance,stream,instances)
        );
        CREATE TRIGGER IF NOT EXISTS pdpp_replica_view_copy_group_insert
        AFTER INSERT ON pdpp_replica_view_copy_counts BEGIN
          INSERT INTO pdpp_replica_view_copy_groups
          SELECT value,NEW.stream,NEW.instances FROM json_each(NEW.instances)
          WHERE NOT EXISTS (SELECT 1 FROM pdpp_replica_view_copy_groups g
            WHERE g.instance=value AND g.stream=NEW.stream AND g.instances=NEW.instances);
        END;
        CREATE TRIGGER IF NOT EXISTS pdpp_replica_view_copy_group_delete
        AFTER DELETE ON pdpp_replica_view_copy_counts BEGIN
          DELETE FROM pdpp_replica_view_copy_groups WHERE stream=OLD.stream AND instances=OLD.instances;
        END;
        CREATE TRIGGER IF NOT EXISTS pdpp_replica_view_copy_stream_insert
        AFTER INSERT ON pdpp_replica_view_copy_streams BEGIN
          INSERT INTO pdpp_replica_view_copy_counts SELECT NEW.stream,NEW.instances,0
          WHERE NOT EXISTS (SELECT 1 FROM pdpp_replica_view_copy_counts c
            WHERE c.stream=NEW.stream AND c.instances=NEW.instances);
          UPDATE pdpp_replica_view_copy_counts SET n=n+1 WHERE stream=NEW.stream AND instances=NEW.instances;
        END;
        CREATE TRIGGER IF NOT EXISTS pdpp_replica_view_copy_stream_delete
        AFTER DELETE ON pdpp_replica_view_copy_streams BEGIN
          UPDATE pdpp_replica_view_copy_counts SET n=n-1 WHERE stream=OLD.stream AND instances=OLD.instances;
          DELETE FROM pdpp_replica_view_copy_counts WHERE stream=OLD.stream AND instances=OLD.instances AND n=0;
        END;
        CREATE TRIGGER IF NOT EXISTS pdpp_replica_view_copy_insert AFTER INSERT ON pdpp_replica_copies BEGIN
          ${copyStreams("NEW")}
        END;
        CREATE TRIGGER IF NOT EXISTS pdpp_replica_view_copy_update
        AFTER UPDATE OF state,reason,envelope_json ON pdpp_replica_copies
        WHEN OLD.state IS NOT NEW.state OR OLD.reason IS NOT NEW.reason OR OLD.envelope_json IS NOT NEW.envelope_json BEGIN
          DELETE FROM pdpp_replica_view_copy_streams WHERE id=OLD.id AND copy_key=OLD.copy_key;
          DELETE FROM pdpp_replica_view_copy_connections WHERE id=OLD.id AND copy_key=OLD.copy_key;
          ${copyStreams("NEW")}
        END;
        CREATE TRIGGER IF NOT EXISTS pdpp_replica_view_copy_delete AFTER DELETE ON pdpp_replica_copies BEGIN
          DELETE FROM pdpp_replica_view_copy_streams WHERE id=OLD.id AND copy_key=OLD.copy_key;
          DELETE FROM pdpp_replica_view_copy_connections WHERE id=OLD.id AND copy_key=OLD.copy_key;
        END;
      `);
      if (!initialized)
        db.exec(`
        INSERT INTO pdpp_replica_view_copy_streams
        SELECT id,copy_key,stream,json_group_array(instance)
        FROM (SELECT DISTINCT c.id,c.copy_key,json_extract(op.value,'$.declaration.stream') AS stream,
          json_extract(op.value,'$.connectionId') AS instance
          FROM pdpp_replica_copies c,json_each(c.envelope_json,'$.operations') op
          WHERE c.state='quarantined' AND c.reason IN ('copy_conflict','finalized_conflict')
          AND json_extract(op.value,'$.declaration.stream') IS NOT NULL
          ORDER BY c.id,c.copy_key,stream,instance)
        GROUP BY id,copy_key,stream;
        INSERT INTO pdpp_replica_view_copy_connections
        SELECT DISTINCT c.id,c.copy_key,json_extract(op.value,'$.connectionId')
        FROM pdpp_replica_copies c,json_each(c.envelope_json,'$.operations') op
        WHERE c.state='quarantined' AND c.reason IN ('copy_conflict','finalized_conflict');
      `);
    }
    if (hasBindingConflictFacts && !localInitialized)
      db.exec(
        `DELETE FROM pdpp_replica_local_view; INSERT INTO pdpp_replica_local_view ${localProjection} AND j.connection_id IN (SELECT instance FROM pdpp_replica_binding_conflicts);`,
      );
    if (!initialized) {
      // One-time rebuild. Thereafter persisted dirty queues also cover downtime/restarts.
      // Only pending work, confirmed operation-ID variants and deleted bindings can
      // differ from canonical, so only they are reconciled; no canonical row is copied.
      db.exec(`
        INSERT INTO pdpp_replica_view_streams SELECT 0,instance,stream,SUM(1-deleted),SUM(1-deleted),0,MAX(CASE WHEN deleted=0 THEN emitted_at END),1 FROM pdpp_records GROUP BY instance,stream;
        INSERT OR IGNORE INTO pdpp_replica_view_dirty_operations
          SELECT o.digest,o.operation_json FROM pdpp_replica_view_operations o
          WHERE (o.writer,o.operation_id) IN (SELECT writer,operation_id FROM pdpp_replica_view_operations GROUP BY writer,operation_id HAVING COUNT(DISTINCT digest)>1);
        INSERT OR IGNORE INTO pdpp_replica_view_dirty_connections SELECT instance FROM pdpp_instance_binding WHERE deleted_at IS NOT NULL;
      `);
      for (const row of db
        .prepare(
          "SELECT id,envelope_json FROM pdpp_replica_pending_batches WHERE state='pending'",
        )
        .all() as { id: string; envelope_json: string }[]) {
        addPending(row.id, JSON.parse(row.envelope_json).operations);
      }
      db.exec("DELETE FROM pdpp_replica_view_schema");
      db.prepare("INSERT INTO pdpp_replica_view_schema VALUES (?)").run(
        VIEW_SCHEMA,
      );
    }
  }).immediate();

  function markOperation(digest: string, json: string) {
    db.prepare(
      "INSERT OR IGNORE INTO pdpp_replica_view_dirty_operations VALUES (?,?)",
    ).run(digest, json);
  }
  function addPending(batchId: string, operations: ReplicaOperation[]) {
    for (const op of operations) {
      const json = canonicalJson(op);
      const digest = replicaOperationDigest(op);
      const inserted = db
        .prepare(
          "INSERT OR IGNORE INTO pdpp_replica_view_pending VALUES (?,?,?,?,?,?,?,?,?,?)",
        )
        .run(
          batchId,
          digest,
          json,
          op.connectionId,
          "declaration" in op ? op.declaration.stream : null,
          "recordKey" in op ? op.recordKey : null,
          op.kind,
          op.revision.writerId,
          op.revision.operationId,
          op.kind === "blob-claim"
            ? op.blob.blobId
            : op.kind === "upsert"
              ? (op.blobs[0]?.blobId ?? null)
              : null,
        ).changes;
      if (inserted) markOperation(digest, json);
    }
  }
  function removePending(batchId: string) {
    for (const row of db
      .prepare(
        "SELECT digest,operation_json FROM pdpp_replica_view_pending WHERE batch_id=?",
      )
      .all(batchId) as { digest: string; operation_json: string }[])
      markOperation(row.digest, row.operation_json);
    db.prepare("DELETE FROM pdpp_replica_view_pending WHERE batch_id=?").run(
      batchId,
    );
  }
  /** Retained and pending evidence matching `where`, merged by operation value. */
  function evidence(where: string, ...args: unknown[]): Map<string, Evidence> {
    const merged = new Map<string, Evidence>();
    for (const row of db
      .prepare(
        `SELECT operation_json,confirmed,pending FROM pdpp_replica_view_operations WHERE ${where}`,
      )
      .all(...args) as {
      operation_json: string;
      confirmed: number;
      pending: number;
    }[]) {
      const entry = merged.get(row.operation_json) ?? {
        op: JSON.parse(row.operation_json) as ReplicaOperation,
        confirmed: false,
        pending: 0,
      };
      entry.confirmed ||= row.confirmed === 1;
      entry.pending += row.pending;
      merged.set(row.operation_json, entry);
    }
    return merged;
  }
  const ops = (entries: Map<string, Evidence>) =>
    [...entries.values()].map((entry) => entry.op);
  function dirtyKey(instance: string, stream: string, key: string) {
    db.prepare(
      "INSERT OR IGNORE INTO pdpp_replica_view_dirty_keys VALUES (?,?,?)",
    ).run(instance, stream, key);
  }
  /**
   * Pending lifecycle, pending blob claims and operation-ID variants can change
   * every key of a connection. A compatible registration already in force cannot.
   */
  function connectionInvolvement(instance: string) {
    const conflicts = !!db
      .prepare("SELECT 1 FROM pdpp_replica_view_conflicts WHERE instance=?")
      .get(instance);
    const pendingLifecycle = ops(
      evidence(`instance=? AND kind IN ${LIFECYCLE} AND pending=1`, instance),
    );
    const registrations = pendingLifecycle.some(
      (op) => op.kind === "connection-register",
    )
      ? ops(
          evidence(
            "instance=? AND kind='connection-register' AND confirmed=1",
            instance,
          ),
        )
      : [];
    const lifecycle = pendingLifecycle.some(
      (op) =>
        op.kind !== "connection-register" ||
        !registrations.some(
          (other) =>
            other.owner === op.owner &&
            other.sourceId === op.sourceId &&
            other.methodId === op.methodId,
        ),
    );
    const claims = !!db
      .prepare(
        "SELECT 1 FROM pdpp_replica_view_pending WHERE instance=? AND kind='blob-claim'",
      )
      .get(instance);
    return { all: conflicts || lifecycle, claims };
  }
  function flush(): void {
    if (!db.inTransaction) return db.transaction(flush).immediate();
    const dirtyOps = (
      db
        .prepare(
          "SELECT operation_json FROM pdpp_replica_view_dirty_operations",
        )
        .all() as { operation_json: string }[]
    ).map((row) => JSON.parse(row.operation_json) as ReplicaOperation);
    const connections = new Set(
      (
        db
          .prepare("SELECT instance FROM pdpp_replica_view_dirty_connections")
          .all() as { instance: string }[]
      ).map((row) => row.instance),
    );
    for (const op of dirtyOps) {
      const { writerId, operationId } = op.revision;
      const previous = db
        .prepare(
          "SELECT instance FROM pdpp_replica_view_conflicts WHERE writer=? AND operation_id=?",
        )
        .all(writerId, operationId) as { instance: string }[];
      const variants = db
        .prepare(
          "SELECT DISTINCT digest,instance FROM pdpp_replica_view_operations WHERE writer=? AND operation_id=?",
        )
        .all(writerId, operationId) as { digest: string; instance: string }[];
      db.prepare(
        "DELETE FROM pdpp_replica_view_conflicts WHERE writer=? AND operation_id=?",
      ).run(writerId, operationId);
      for (const row of previous) connections.add(row.instance);
      if (variants.length > 1)
        for (const variant of variants) {
          connections.add(variant.instance);
          db.prepare(
            "INSERT OR IGNORE INTO pdpp_replica_view_conflicts VALUES (?,?,?,?)",
          ).run(writerId, operationId, variant.instance, variant.digest);
        }
      if (op.kind === "upsert" || op.kind === "delete")
        dirtyKey(op.connectionId, op.declaration.stream, op.recordKey);
      else if (op.kind === "blob-claim") {
        for (const dependent of ops(
          evidence(
            "blob_id=? AND instance=? AND kind='upsert'",
            op.blob.blobId,
            op.connectionId,
          ),
        ))
          if (dependent.kind === "upsert")
            dirtyKey(
              dependent.connectionId,
              dependent.declaration.stream,
              dependent.recordKey,
            );
      } else if (op.kind === "connection-register") {
        // A compatible registration already in force does not change any key.
        // Operation-ID equivocation was handled globally above, before this shortcut.
        const json = canonicalJson(op);
        const established = [
          ...evidence(
            "instance=? AND kind='connection-register'",
            op.connectionId,
          ),
        ].some(
          ([other, entry]) =>
            (other !== json ||
              entry.pending > 1 ||
              (entry.confirmed && entry.pending > 0)) &&
            entry.op.owner === op.owner &&
            entry.op.sourceId === op.sourceId &&
            entry.op.methodId === op.methodId,
        );
        if (!established) connections.add(op.connectionId);
      } else if (op.kind.startsWith("connection-"))
        connections.add(op.connectionId);
    }
    for (const instance of connections) {
      // Lifecycle/equivocation changes can affect every key, once at WRITE time.
      // Otherwise only existing overlay and pending keys can change.
      db.prepare(
        "INSERT OR IGNORE INTO pdpp_replica_view_dirty_keys SELECT instance,stream,record_key FROM pdpp_replica_view WHERE instance=?",
      ).run(instance);
      db.prepare(
        "INSERT OR IGNORE INTO pdpp_replica_view_dirty_keys SELECT instance,stream,record_key FROM pdpp_replica_view_pending WHERE instance=? AND record_key IS NOT NULL",
      ).run(instance);
      const deleted = !!db
        .prepare(
          "SELECT 1 FROM pdpp_instance_binding WHERE instance=? AND deleted_at IS NOT NULL",
        )
        .get(instance);
      if (deleted || connectionInvolvement(instance).all) {
        db.prepare(
          "INSERT OR IGNORE INTO pdpp_replica_view_dirty_keys SELECT instance,stream,record_key FROM pdpp_records WHERE instance=?",
        ).run(instance);
        db.prepare(
          "INSERT OR IGNORE INTO pdpp_replica_view_dirty_keys SELECT DISTINCT instance,stream,record_key FROM pdpp_replica_view_operations WHERE instance=? AND record_key IS NOT NULL",
        ).run(instance);
      }
    }
    const involvement = new Map<
      string,
      ReturnType<typeof connectionInvolvement>
    >();
    // Cursor revisions advance in the summary triggers, only for rows that change.
    for (const row of db
      .prepare("SELECT * FROM pdpp_replica_view_dirty_keys")
      .all() as { instance: string; stream: string; record_key: string }[]) {
      if (!involvement.has(row.instance))
        involvement.set(row.instance, connectionInvolvement(row.instance));
      reconcileKey(
        row.instance,
        row.stream,
        row.record_key,
        involvement.get(row.instance)!,
      );
    }
    // The scan below can step over every masked canonical row of a stream,
    // so it runs here, once per changed stream, and never in a read.
    for (const row of db
      .prepare("SELECT instance,stream FROM pdpp_replica_view_dirty_latest")
      .all() as { instance: string; stream: string }[])
      db.prepare(
        `UPDATE pdpp_replica_view_streams SET last_updated=(${previewLatestSql}) WHERE preview=1 AND instance=@instance AND stream=@stream`,
      ).run(row);
    db.exec(
      "DELETE FROM pdpp_replica_view_dirty_operations; DELETE FROM pdpp_replica_view_dirty_keys; DELETE FROM pdpp_replica_view_dirty_connections; DELETE FROM pdpp_replica_view_dirty_latest;",
    );
  }
  /**
   * Latest owner-preview emitted_at of one stream: present overlay rows and
   * canonical live rows without an overlay row. Quarantine is not applied;
   * a read with quarantined keys in the stream recomputes it instead.
   */
  const previewLatestSql = `SELECT MAX(t) FROM (
    SELECT (SELECT r.emitted_at FROM pdpp_records r WHERE r.instance=@instance AND r.stream=@stream AND r.deleted=0 AND NOT EXISTS (SELECT 1 FROM pdpp_replica_view v WHERE v.instance=r.instance AND v.stream=r.stream AND v.record_key=r.record_key) ORDER BY r.emitted_at DESC,r.record_key DESC LIMIT 1) AS t
    UNION ALL SELECT (SELECT v.emitted_at FROM pdpp_replica_view v WHERE v.instance=@instance AND v.stream=@stream AND v.present=1 ORDER BY v.emitted_at DESC,v.record_key DESC LIMIT 1))`;
  function canonical(row: CanonicalRow): PdppVisibleRecord | undefined {
    return row.deleted
      ? undefined
      : {
          instance: row.instance,
          stream: row.stream,
          recordKey: row.record_key,
          data: JSON.parse(row.data!),
          version: row.version,
          emittedAt: row.emitted_at,
          deleted: false,
        };
  }
  /** Whether pending evidence or a variant reaches this key's merge inputs. */
  function involved(
    instance: string,
    stream: string,
    key: string,
    connection: ReturnType<typeof connectionInvolvement>,
  ): boolean {
    if (connection.all) return true;
    if (
      db
        .prepare(
          "SELECT 1 FROM pdpp_replica_view_pending WHERE instance=? AND stream=? AND record_key=?",
        )
        .get(instance, stream, key)
    )
      return true;
    return (
      connection.claims &&
      !!db
        .prepare(
          "SELECT 1 FROM pdpp_replica_view_operations o WHERE o.instance=? AND o.stream=? AND o.record_key=? AND o.blob_id IN (SELECT blob_id FROM pdpp_replica_view_pending WHERE instance=? AND kind='blob-claim')",
        )
        .get(instance, stream, key, instance)
    );
  }
  function reconcileKey(
    instance: string,
    stream: string,
    key: string,
    connection: ReturnType<typeof connectionInvolvement>,
  ) {
    const current = db
      .prepare(
        "SELECT * FROM pdpp_records WHERE instance=? AND stream=? AND record_key=?",
      )
      .get(instance, stream, key) as CanonicalRow | undefined;
    const local = db
      .prepare(
        "SELECT source_id,generation,deleted_at FROM pdpp_instance_binding WHERE instance=?",
      )
      .get(instance) as
      | {
          source_id: string | null;
          generation: number;
          deleted_at: string | null;
        }
      | undefined;
    const base = current && canonical(current);
    let row = base;
    let blobId = row ? current!.blob_id : null;
    let blobMeta: PdppBlobMeta | undefined;
    if (
      local?.source_id &&
      !local.deleted_at &&
      involved(instance, stream, key, connection)
    ) {
      const evidenceRows = evidence(
        "instance=? AND stream=? AND record_key=?",
        instance,
        stream,
        key,
      );
      // The conflict index carries global operation-ID variants, including other connections.
      const conflictOps: ReplicaOperation[] = [];
      for (const pair of db
        .prepare(
          "SELECT DISTINCT c2.writer,c2.operation_id FROM pdpp_replica_view_conflicts c JOIN pdpp_replica_view_conflicts c2 ON c.writer=c2.writer AND c.operation_id=c2.operation_id WHERE c.instance=?",
        )
        .all(instance) as { writer: string; operation_id: string }[])
        conflictOps.push(
          ...ops(
            evidence(
              "writer=? AND operation_id=?",
              pair.writer,
              pair.operation_id,
            ),
          ),
        );
      const lifecycleRows = evidence(
        `instance=? AND kind IN ${LIFECYCLE}`,
        instance,
      );
      const lifecycle = ops(lifecycleRows);
      const blobIds = [
        ...new Set(
          ops(evidenceRows).flatMap((op) =>
            op.kind === "upsert" ? op.blobs.map((blob) => blob.blobId) : [],
          ),
        ),
      ];
      const claims = blobIds.length
        ? ops(
            evidence(
              `instance=? AND kind='blob-claim' AND blob_id IN (${blobIds.map(() => "?").join(",")})`,
              instance,
              ...blobIds,
            ),
          )
        : [];
      const all = [
        ...ops(evidenceRows),
        ...lifecycle,
        ...claims,
        ...conflictOps,
      ];
      const plan = planReplicaMerge(
        { owner: deps.owner, declarations: deps.declarations() },
        all,
      );
      const blocked = plan.conflicts.some(
        (issue) =>
          ![
            "append_only_content_conflict",
            "incompatible_record_declaration",
          ].includes(issue.reason) &&
          issue.operations.some((op) => op.connectionId === instance),
      );
      const deletion = lifecycle.find((op) => op.kind === "connection-delete");
      const generation = Math.max(
        local.generation,
        1,
        ...lifecycle
          .filter((op) => op.kind === "connection-reset")
          .map((op) => op.generation),
      );
      const missingReset = plan.pending.some(
        (issue) =>
          issue.reason === "missing_generation_reset" &&
          issue.operations.some(
            (op) =>
              op.kind === "connection-reset" && op.connectionId === instance,
          ),
      );
      const provisionalLifecycle = [...lifecycleRows.values()].some(
        ({ op, confirmed, pending }) =>
          !confirmed &&
          pending > 0 &&
          (op.kind === "connection-delete" ||
            (op.kind === "connection-reset" &&
              op.generation > local.generation)),
      );
      const removal = (
        emittedAt: string,
        deletedAt: string,
      ): PdppVisibleRecord => ({
        instance,
        stream,
        recordKey: key,
        version: current?.version ?? 0,
        emittedAt,
        deletedAt,
        deleted: true,
        data: {},
        ...replicaPendingMetadata(),
      });
      if (blocked) {
        row = undefined;
        blobId = null;
      } else if (deletion || (generation > local.generation && !missingReset)) {
        // Recompute the value withdrawn by this lifecycle transition. In particular,
        // pending-only records have no canonical row to use as a removal marker.
        const before = planReplicaMerge(
          { owner: deps.owner, declarations: deps.declarations() },
          all.filter(
            (op) =>
              op.kind !== "connection-delete" &&
              !(
                op.kind === "connection-reset" &&
                op.generation === generation &&
                !deletion
              ),
          ),
        );
        const prior = before.records.find(
          (record) =>
            record.identity.connectionId === instance &&
            record.identity.stream === stream &&
            record.identity.recordKey === key,
        )?.winner;
        const withdrawn =
          prior?.kind === "upsert" && deps.blobsValid(prior, all)
            ? prior
            : undefined;
        row =
          provisionalLifecycle && (withdrawn || row)
            ? removal(
                withdrawn?.emittedAt ?? row!.emittedAt,
                withdrawn?.emittedAt ?? row!.emittedAt,
              )
            : undefined;
        blobId = null;
      }
      if (!blocked && !deletion) {
        const record = plan.records.find(
          (r) =>
            r.identity.connectionId === instance &&
            r.identity.stream === stream &&
            r.identity.recordKey === key &&
            r.identity.generation === generation,
        );
        if (record) {
          const winner = record.winner;
          const state = winner && evidenceRows.get(canonicalJson(winner));
          const pending = !!state && !state.confirmed && state.pending > 0;
          if (!winner) {
            row = undefined;
            blobId = null;
          } else if (winner.kind === "delete") {
            row = pending
              ? removal(winner.emittedAt, winner.deletedAt)
              : undefined;
            blobId = null;
          } else if (!deps.blobsValid(winner, all)) {
            row = undefined;
            blobId = null;
          } else {
            row = {
              instance,
              stream,
              recordKey: key,
              data: winner.data,
              version: current?.version ?? 0,
              emittedAt: winner.emittedAt,
              deleted: false,
              ...(pending ? replicaPendingMetadata() : {}),
            };
            const descriptor = winner.blobs[0];
            blobId = descriptor?.blobId ?? null;
            blobMeta = descriptor
              ? {
                  blobId: descriptor.blobId,
                  mimeType: descriptor.mimeType,
                  sizeBytes: descriptor.sizeBytes,
                  sha256: descriptor.sha256.slice(7),
                }
              : undefined;
          }
        }
      }
    } else if (local?.deleted_at) {
      row = undefined;
      blobId = null;
    }
    writeOverlay(instance, stream, key, current, base, row, blobId, blobMeta);
  }
  /** Persist the difference from canonical, or nothing when there is none. */
  function writeOverlay(
    instance: string,
    stream: string,
    key: string,
    current: CanonicalRow | undefined,
    base: PdppVisibleRecord | undefined,
    row: PdppVisibleRecord | undefined,
    blobId: string | null,
    blobMeta: PdppBlobMeta | undefined,
  ) {
    const same =
      row === undefined
        ? base === undefined
        : base !== undefined &&
          canonicalJson(row) === canonicalJson(base) &&
          blobId === current!.blob_id;
    if (same) {
      db.prepare(
        "DELETE FROM pdpp_replica_view WHERE instance=? AND stream=? AND record_key=?",
      ).run(instance, stream, key);
      return;
    }
    const overlay: OverlayRow = row
      ? {
          emitted_at: row.emittedAt,
          row_json: JSON.stringify(row),
          blob_id: blobId,
          blob_json: blobId && blobMeta ? JSON.stringify(blobMeta) : null,
          present: 1,
          live: row.deleted ? 0 : 1,
          pending: row.visibility === "pending" ? 1 : 0,
          base_live: base ? 1 : 0,
        }
      : {
          // A hidden key: canonical shows it, the owner preview must not.
          emitted_at: base!.emittedAt,
          row_json: null,
          blob_id: null,
          blob_json: null,
          present: 0,
          live: 0,
          pending: 0,
          base_live: 1,
        };
    // An unchanged row is not rewritten, so it advances no cursor revision.
    db.prepare(
      `INSERT INTO pdpp_replica_view VALUES (@instance,@stream,@key,@emitted_at,@row_json,@blob_id,@blob_json,@present,@live,@pending,@base_live)
       ON CONFLICT(instance,stream,record_key) DO UPDATE SET emitted_at=excluded.emitted_at,row_json=excluded.row_json,blob_id=excluded.blob_id,blob_json=excluded.blob_json,present=excluded.present,live=excluded.live,pending=excluded.pending,base_live=excluded.base_live
       WHERE emitted_at IS NOT excluded.emitted_at OR row_json IS NOT excluded.row_json OR blob_id IS NOT excluded.blob_id OR blob_json IS NOT excluded.blob_json OR present IS NOT excluded.present OR live IS NOT excluded.live OR pending IS NOT excluded.pending OR base_live IS NOT excluded.base_live`,
    ).run({ instance, stream, key, ...overlay });
  }
  function connectionVisibility(instance: string) {
    return replicaConnectionVisibility(
      hasBindingConflictFacts &&
        !!db
          .prepare(
            "SELECT 1 FROM pdpp_replica_binding_conflicts WHERE instance=?",
          )
          .get(instance),
    );
  }
  type Mode = "canonical" | "preview" | "local" | "hidden";
  function readBranch(
    instance: string,
    reader: ReplicaReader,
    preview: boolean,
  ): Mode {
    const conflict = connectionVisibility(instance);
    if (conflict)
      return replicaStateVisible(conflict.state, reader, undefined, "local")
        ? "local"
        : "hidden";
    return preview ? "preview" : "canonical";
  }
  const unquarantined = (alias = "r") => deps.unquarantinedRecordSql(alias);
  const overlaid = (alias = "r") =>
    `EXISTS (SELECT 1 FROM pdpp_replica_view v WHERE v.instance=${alias}.instance AND v.stream=${alias}.stream AND v.record_key=${alias}.record_key)`;
  const notOverlaid = (alias = "r") => `NOT ${overlaid(alias)}`;
  const canonicalJsonColumn = (alias = "r") =>
    `json_object('instance',${alias}.instance,'stream',${alias}.stream,'recordKey',${alias}.record_key,'data',json(${alias}.data),'version',${alias}.version,'emittedAt',${alias}.emitted_at,'deleted',json('false'))`;
  /**
   * Row sources of one mode, each an indexed keyset over (emitted_at, record_key).
   * Preview merges canonical rows with present overlay rows. A canonical row
   * that has an overlay row is `masked`: the overlay row replaces it. Masked
   * rows stay in the keyset so a page can step over them within its window.
   */
  function sources(mode: Exclude<Mode, "hidden">, alias = "r") {
    const source = (
      table: string,
      json: string,
      origin: Mode,
      filter: string,
      masked = "0",
    ) => ({
      table,
      columns: `${alias}.instance,${alias}.stream,${alias}.record_key,${alias}.emitted_at,${json} AS row_json,'${origin}' AS origin,(${masked}) AS masked`,
      filter,
      masked,
    });
    const canonicalSource = (masked?: string) =>
      source(
        "pdpp_records",
        canonicalJsonColumn(alias),
        "canonical",
        `${unquarantined(alias)} AND ${alias}.deleted=0`,
        masked,
      );
    if (mode === "canonical") return [canonicalSource()];
    if (mode === "local")
      return [
        source(
          "pdpp_replica_local_view",
          `${alias}.row_json`,
          "local",
          `${unquarantined(alias)} AND ${alias}.deleted=0 AND ${localIdentitySql(alias)}`,
        ),
      ];
    return [
      canonicalSource(overlaid(alias)),
      source(
        "pdpp_replica_view",
        `${alias}.row_json`,
        "preview",
        `${unquarantined(alias)} AND ${alias}.present=1`,
      ),
    ];
  }
  function visibleRow(row: {
    row_json: string;
    origin: Mode;
  }): PdppVisibleRecord {
    const value: PdppVisibleRecord = JSON.parse(row.row_json);
    return row.origin === "local" && !value.deleted
      ? { ...value, ...replicaConflictMetadata() }
      : value;
  }
  // Summary tables whose revisions bind a cursor in each read mode.
  const revisionTables: Record<Mode, number[]> = {
    canonical: [0],
    preview: [0, 1],
    local: [2],
    hidden: [],
  };
  /**
   * A cursor binds, per connection: read mode, reset fence, the host integrity
   * epoch when the store provides one, and the revisions of this stream's rows
   * in that mode. Other streams and hidden pending churn never move it.
   */
  function cursorRevision(
    stream: string,
    ids: string[],
    modes: Map<string, Mode>,
  ): string {
    return JSON.stringify([
      CURSOR_FORMAT,
      ...ids.map((instance) => {
        const mode = modes.get(instance)!;
        const fence =
          (
            db
              .prepare(
                "SELECT reset_clock FROM pdpp_instance_binding WHERE instance=?",
              )
              .get(instance) as { reset_clock: number } | undefined
          )?.reset_clock ?? 0;
        const revisions = revisionTables[mode].map(
          (table) =>
            (
              db
                .prepare(
                  "SELECT revision FROM pdpp_replica_view_streams WHERE preview=? AND instance=? AND stream=?",
                )
                .get(table, instance, stream) as
                { revision: number } | undefined
            )?.revision ?? 0,
        );
        return [
          instance,
          mode,
          fence,
          deps.integrityEpoch?.(instance) ?? null,
          ...revisions,
        ];
      }),
    ]);
  }
  function getRecord(
    instance: string,
    stream: string,
    key: string,
    reader: ReplicaReader = "owner",
    preview = true,
  ): PdppVisibleRecord | undefined {
    const mode = readBranch(instance, reader, preview);
    if (mode === "hidden") return undefined;
    if (mode === "preview") {
      const overlay = db
        .prepare(
          `SELECT r.row_json,r.present,(${unquarantined()}) AS visible FROM pdpp_replica_view r WHERE r.instance=? AND r.stream=? AND r.record_key=?`,
        )
        .get(instance, stream, key) as
        | { row_json: string | null; present: number; visible: number }
        | undefined;
      if (overlay)
        return overlay.present && overlay.visible
          ? JSON.parse(overlay.row_json!)
          : undefined;
    }
    const source = sources(mode === "preview" ? "canonical" : mode)[0];
    const row = db
      .prepare(
        `SELECT ${source.columns} FROM ${source.table} r WHERE r.instance=? AND r.stream=? AND r.record_key=? AND ${source.filter}`,
      )
      .get(instance, stream, key) as
      { row_json: string; origin: Mode } | undefined;
    return row && visibleRow(row);
  }
  function listRecords(
    stream: string,
    options: ListRecordsOptions,
    reader: ReplicaReader,
    preview: boolean,
  ): ListVisibleRecordsPage {
    return db
      .transaction(() => {
        const { epoch } = db
          .prepare("SELECT epoch FROM pdpp_store_metadata WHERE id=1")
          .get() as { epoch: string };
        const { value } = db
          .prepare("SELECT value FROM pdpp_write_clock WHERE id=1")
          .get() as { value: number };
        const ids = [...new Set(options.instanceIds)].sort();
        const modes = new Map(
          ids.map((instance) => [
            instance,
            readBranch(instance, reader, preview),
          ]),
        );
        const viewRevision = cursorRevision(stream, ids, modes);
        const cursor = options.cursor
          ? decodeCursor(options.cursor)
          : undefined;
        if (cursor && cursor.kind !== "list") throw new InvalidCursorError();
        if (
          cursor &&
          (cursor.viewRevision !== viewRevision ||
            cursor.epoch !== epoch ||
            cursor.stream !== stream ||
            cursor.view !== reader ||
            JSON.stringify(cursor.instanceIds) !== JSON.stringify(ids) ||
            typeof cursor.instance !== "string")
        )
          throw new CursorExpiredError();
        if (cursor && cursor.order !== options.order)
          throw new InvalidCursorError();
        const dir = options.order === "asc" ? "ASC" : "DESC",
          cmp = options.order === "asc" ? ">" : "<";
        const params: unknown[] = [];
        const branches = ids.flatMap((instance) => {
          const mode = modes.get(instance)!;
          if (mode === "hidden") return [];
          let boundary = "";
          const bounds: unknown[] = [];
          if (cursor) {
            const instanceOrder = Buffer.compare(
              Buffer.from(instance),
              Buffer.from(cursor.instance!),
            );
            const equal =
              options.order === "asc" ? instanceOrder > 0 : instanceOrder < 0;
            boundary = ` AND (r.emitted_at,r.record_key) ${equal ? cmp + "=" : cmp} (?,?)`;
            bounds.push(cursor.sortValue, cursor.recordKey);
          }
          return sources(mode).map((source) => {
            params.push(instance, stream, ...bounds, options.limit + 1);
            return `SELECT * FROM (SELECT ${source.columns} FROM ${source.table} r WHERE r.instance=? AND r.stream=? AND ${source.filter}${boundary} ORDER BY r.emitted_at ${dir},r.record_key ${dir} LIMIT ?)`;
          });
        });
        // Each source contributes at most limit+1 keyset rows, masked ones
        // included, so the merged window is exact and the work is bounded by
        // the page size, not by how many canonical rows an overlay masks. A
        // masked row and its overlay can share a position; the overlay sorts
        // first, so a window boundary between them loses nothing.
        const rows = branches.length
          ? (db
              .prepare(
                `SELECT * FROM (${branches.join(" UNION ALL ")}) ORDER BY emitted_at ${dir},record_key ${dir},instance ${dir},masked ASC LIMIT ?`,
              )
              .all(...params, options.limit + 1) as {
              instance: string;
              record_key: string;
              emitted_at: string;
              row_json: string;
              origin: Mode;
              masked: number;
            }[])
          : [];
        // The page may hold fewer than `limit` rows; the cursor then continues
        // after the last consumed position, visible or masked.
        const consumed = rows.slice(0, options.limit);
        const data = consumed
          .filter((raw) => !raw.masked)
          .map((raw) => {
            const row = visibleRow(raw);
            return options.fields && !row.deleted
              ? {
                  ...row,
                  data: Object.fromEntries(
                    options.fields
                      .filter((field) => field in row.data)
                      .map((field) => [field, row.data[field]]),
                  ),
                }
              : row;
          });
        const last = consumed[consumed.length - 1],
          hasMore = rows.length > options.limit;
        return {
          data,
          hasMore,
          horizon: String(value),
          nextCursor:
            hasMore && last
              ? encodeCursor({
                  kind: "list",
                  stream,
                  epoch,
                  viewRevision,
                  view: reader,
                  instanceIds: ids,
                  instance: last.instance,
                  order: options.order,
                  sortValue: last.emitted_at,
                  recordKey: last.record_key,
                  horizon: String(value),
                })
              : undefined,
        };
      })
      .deferred();
  }
  type Summary = {
    live_count: number;
    row_count: number;
    pending_count: number;
    last_updated: string | null;
  };
  function summary(table: number, instance: string, stream: string) {
    return db
      .prepare(
        "SELECT live_count,row_count,pending_count,last_updated FROM pdpp_replica_view_streams WHERE preview=? AND instance=? AND stream=?",
      )
      .get(table, instance, stream) as Summary | undefined;
  }
  /** Rows of this stream the shared quarantine predicate removes from the mode. */
  function quarantinedCounts(
    mode: Exclude<Mode, "hidden">,
    instance: string,
    stream: string,
  ) {
    const effective =
      mode === "preview"
        ? `SELECT DISTINCT q.record_key,COALESCE(v.present,1) AS present,COALESCE(v.live,1) AS live,COALESCE(v.pending,0) AS pending FROM pdpp_replica_quarantined_keys q LEFT JOIN pdpp_replica_view v ON v.instance=q.instance AND v.stream=q.stream AND v.record_key=q.record_key LEFT JOIN pdpp_records c ON c.instance=q.instance AND c.stream=q.stream AND c.record_key=q.record_key AND c.deleted=0 WHERE q.instance=? AND q.stream=? AND (v.record_key IS NOT NULL OR c.record_key IS NOT NULL) AND NOT (${unquarantined("q")})`
        : `SELECT DISTINCT r.record_key,1 AS present,1 AS live,0 AS pending FROM pdpp_replica_quarantined_keys q JOIN ${mode === "local" ? "pdpp_replica_local_view" : "pdpp_records"} r ON r.instance=q.instance AND r.stream=q.stream AND r.record_key=q.record_key WHERE q.instance=? AND r.stream=? AND r.deleted=0 AND NOT (${unquarantined("r")})`;
    return db
      .prepare(
        `SELECT COALESCE(SUM(present),0) AS rows,COALESCE(SUM(live),0) AS live,COALESCE(SUM(pending),0) AS pending FROM (${effective})`,
      )
      .get(instance, stream) as { rows: number; live: number; pending: number };
  }
  function latestVisible(
    mode: Exclude<Mode, "hidden">,
    instance: string,
    stream: string,
  ) {
    return sources(mode)
      .map(
        (source) =>
          (
            db
              .prepare(
                `SELECT r.emitted_at FROM ${source.table} r WHERE r.instance=? AND r.stream=? AND ${source.filter} AND NOT (${source.masked}) ORDER BY r.emitted_at DESC,r.record_key DESC LIMIT 1`,
              )
              .get(instance, stream) as { emitted_at: string } | undefined
          )?.emitted_at ?? null,
      )
      .reduce<string | null>(
        (latest, value) =>
          value !== null && (latest === null || value > latest)
            ? value
            : latest,
        null,
      );
  }
  function listStreams(
    ids: string[],
    preview = true,
    reader: ReplicaReader = "owner",
  ): (StreamListing & { copyConflicts?: number })[] {
    const copyCounts = new Map<string, number>();
    if (reader === "owner" && hasCopyFacts && ids.length) {
      // Indexed by the requested connections, then deduplicate groups before
      // summing: a copy on two requested connections still counts only once.
      const groups = db
        .prepare(
          `SELECT DISTINCT g.stream,g.instances,c.n
        FROM json_each(?) requested
        JOIN pdpp_replica_view_copy_groups g ON g.instance=requested.value
        JOIN pdpp_replica_view_copy_counts c ON c.stream=g.stream AND c.instances=g.instances`,
        )
        .all(JSON.stringify([...new Set(ids)])) as {
        stream: string;
        instances: string;
        n: number;
      }[];
      for (const { stream, n } of groups)
        copyCounts.set(stream, (copyCounts.get(stream) ?? 0) + n);
    }
    const combined = new Map<
      string,
      {
        count: number;
        last: string | null;
        pending: boolean;
        conflicted: boolean;
      }
    >();
    for (const instance of new Set(ids)) {
      const mode = readBranch(instance, reader, preview);
      if (mode === "hidden") continue;
      // The shared predicate on a null key checks the connection fence; individual
      // quarantined keys are subtracted through indexed quarantine-key lookups below.
      if (
        !db
          .prepare(
            `SELECT 1 FROM (SELECT ? AS instance,NULL AS stream,NULL AS record_key) r WHERE ${unquarantined()}`,
          )
          .get(instance)
      )
        continue;
      const tables = mode === "local" ? [2] : mode === "preview" ? [0, 1] : [0];
      const streams = (
        db
          .prepare(
            `SELECT DISTINCT stream FROM pdpp_replica_view_streams WHERE instance=? AND preview IN (${tables.join(",")})`,
          )
          .all(instance) as { stream: string }[]
      ).map((row) => row.stream);
      for (const stream of streams) {
        const counts = tables.map((table) => summary(table, instance, stream));
        const total = (field: "live_count" | "row_count" | "pending_count") =>
          counts.reduce((sum, row) => sum + (row?.[field] ?? 0), 0);
        const hidden = quarantinedCounts(mode, instance, stream);
        if (total("row_count") - hidden.rows <= 0) continue;
        // A quarantined key can hide the latest row; that read recomputes it
        // (its work grows with the rows it skips). Otherwise the summary holds
        // it: mode 1's latest is derived at write time, mode 0's and 2's by
        // their triggers.
        const last = hidden.rows
          ? latestVisible(mode, instance, stream)
          : ((counts[1] ?? counts[0])?.last_updated ?? null);
        const previous = combined.get(stream) ?? {
          count: 0,
          last: null,
          pending: false,
          conflicted: false,
        };
        combined.set(stream, {
          count: previous.count + total("live_count") - hidden.live,
          last:
            last && (previous.last === null || last > previous.last)
              ? last
              : previous.last,
          pending:
            previous.pending || total("pending_count") - hidden.pending > 0,
          conflicted: previous.conflicted || mode === "local",
        });
      }
    }
    for (const stream of copyCounts.keys())
      if (!combined.has(stream))
        combined.set(stream, {
          count: 0,
          last: null,
          pending: false,
          conflicted: false,
        });
    return [...combined].map(([stream, row]) => ({
      stream,
      recordCount: row.count,
      lastUpdated: row.last,
      ...(reader === "owner"
        ? { copyConflicts: copyCounts.get(stream) ?? 0 }
        : {}),
      ...(row.conflicted
        ? replicaConflictMetadata()
        : row.pending
          ? replicaPendingMetadata()
          : {}),
    }));
  }
  function blobReferenceQuery(
    id: string,
    reader: ReplicaReader,
    preview: boolean,
    onlyExists: boolean,
  ) {
    const selection = onlyExists
      ? "1"
      : "r.instance,r.stream,r.record_key AS recordKey";
    const normalFact = hasBindingConflictFacts
      ? "AND NOT EXISTS (SELECT 1 FROM pdpp_replica_binding_conflicts f WHERE f.instance=r.instance)"
      : "";
    const branches = [
      `SELECT ${selection} FROM pdpp_records r WHERE r.blob_id=? AND r.deleted=0 AND ${unquarantined()} ${preview ? `AND ${notOverlaid()}` : ""} ${normalFact}`,
    ];
    const args = [id];
    if (preview) {
      branches.push(
        `SELECT ${selection} FROM pdpp_replica_view r WHERE r.blob_id=? AND r.live=1 AND ${unquarantined()} ${normalFact}`,
      );
      args.push(id);
    }
    if (
      hasBindingConflictFacts &&
      replicaStateVisible("conflicted", reader, undefined, "local")
    ) {
      branches.push(
        `SELECT ${selection} FROM pdpp_replica_local_view r WHERE r.blob_id=? AND ${sources("local")[0].filter} AND EXISTS (SELECT 1 FROM pdpp_replica_binding_conflicts f WHERE f.instance=r.instance)`,
      );
      args.push(id);
    }
    return {
      sql: `${branches.join(" UNION ALL ")}${onlyExists ? " LIMIT 1" : ""}`,
      args,
    };
  }
  function findBlobReferences(
    id: string,
    reader: ReplicaReader = "owner",
    preview = true,
  ) {
    const query = blobReferenceQuery(id, reader, preview, false);
    return db.prepare(query.sql).all(...query.args) as {
      instance: string;
      stream: string;
      recordKey: string;
    }[];
  }
  function hasBlobReference(
    id: string,
    reader: ReplicaReader = "owner",
    preview = true,
  ) {
    const query = blobReferenceQuery(id, reader, preview, true);
    return !!db.prepare(query.sql).get(...query.args);
  }
  /** Descriptor of a pending blob; canonical blobs keep their metadata in pdpp_blobs. */
  function getBlobMeta(id: string): PdppBlobMeta | undefined {
    const row = db
      .prepare(
        `SELECT r.blob_json FROM pdpp_replica_view r WHERE r.blob_id=? AND r.blob_json IS NOT NULL AND r.live=1 AND ${unquarantined()} ${hasBindingConflictFacts ? "AND NOT EXISTS (SELECT 1 FROM pdpp_replica_binding_conflicts f WHERE f.instance=r.instance)" : ""} LIMIT 1`,
      )
      .get(id) as { blob_json: string } | undefined;
    return row ? JSON.parse(row.blob_json) : undefined;
  }
  /** Explicit host call after trusted declarations change: re-derive every overlay. */
  function reconcileAll() {
    db.exec(`INSERT OR IGNORE INTO pdpp_replica_view_dirty_connections SELECT DISTINCT instance FROM pdpp_replica_view;
      INSERT OR IGNORE INTO pdpp_replica_view_dirty_connections SELECT DISTINCT instance FROM pdpp_replica_view_pending;
      INSERT OR IGNORE INTO pdpp_replica_view_dirty_connections SELECT DISTINCT instance FROM pdpp_replica_view_conflicts;`);
    flush();
  }
  flush();
  return {
    flush,
    reconcileAll,
    addPending,
    removePending,
    connectionVisibility,
    hasBindingConflictFacts,
    getRecord,
    listRecords,
    listStreams,
    findBlobReferences,
    hasBlobReference,
    getBlobMeta,
  };
}
