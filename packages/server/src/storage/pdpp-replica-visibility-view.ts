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

type Evidence = { operation_json: string; confirmed: number; pending: number };
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

/** One durable current preview, reconciled at mutation time. Reads never run the reducer. */
export function createReplicaVisibilityView(deps: {
  db: Database;
  owner: string;
  declarations: () => MergeContext["declarations"];
  unquarantinedRecordSql: (alias: string) => string;
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
  const localIdentitySql = (alias: string) =>
    `EXISTS (SELECT 1 FROM pdpp_instance_binding b WHERE b.instance=${alias}.instance AND b.deleted_at IS NULL AND b.source_id IS NOT NULL AND b.method IS NOT NULL AND b.source_id=${alias}.source_id AND b.method=${alias}.method AND b.generation=${alias}.generation)`;
  const localProjection = `SELECT j.connection_id,j.stream,j.record_key,json_extract(j.value_json,'$.emittedAt'),j.value_json,json_extract(j.value_json,'$.data.blob_ref.blob_id'),0,json_extract(j.value_json,'$.deleted'),NULL,j.sequence,j.generation,j.source_id,j.method FROM pdpp_mutation_journal j JOIN pdpp_instance_binding b ON b.instance=j.connection_id AND b.generation=j.generation AND b.source_id=j.source_id AND b.method=j.method WHERE b.source_id IS NOT NULL AND b.method IS NOT NULL AND b.deleted_at IS NULL AND j.writer_id=(SELECT writer_id FROM pdpp_installation_writer WHERE id=1) AND NOT EXISTS (SELECT 1 FROM pdpp_mutation_journal newer WHERE newer.connection_id=j.connection_id AND newer.generation=j.generation AND newer.stream=j.stream AND newer.record_key=j.record_key AND newer.source_id=j.source_id AND newer.method=j.method AND newer.writer_id=j.writer_id AND newer.sequence>j.sequence)`;

  db.transaction(() => {
    const initialized = db
      .prepare(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='pdpp_replica_view_clock'",
      )
      .get();
    db.exec(`
      CREATE TABLE IF NOT EXISTS pdpp_replica_view_clock (id INTEGER PRIMARY KEY, revision INTEGER NOT NULL);
      INSERT OR IGNORE INTO pdpp_replica_view_clock VALUES (1,0);
      CREATE TABLE IF NOT EXISTS pdpp_replica_view_connection_clocks (instance TEXT PRIMARY KEY, canonical INTEGER NOT NULL DEFAULT 0, preview INTEGER NOT NULL DEFAULT 0, local INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE IF NOT EXISTS pdpp_replica_view (
        instance TEXT NOT NULL, stream TEXT NOT NULL, record_key TEXT NOT NULL,
        emitted_at TEXT NOT NULL, row_json TEXT NOT NULL, blob_id TEXT, pending INTEGER NOT NULL,
        deleted INTEGER NOT NULL, blob_json TEXT, PRIMARY KEY(instance,stream,record_key)
      );
      CREATE INDEX IF NOT EXISTS pdpp_replica_canonical_page ON pdpp_records(instance,stream,emitted_at,record_key) WHERE deleted=0;
      CREATE INDEX IF NOT EXISTS pdpp_replica_pending_blob ON pdpp_replica_pending_bytes(blob_id,batch_id);
      CREATE TABLE IF NOT EXISTS pdpp_replica_view_streams (preview INTEGER NOT NULL, instance TEXT NOT NULL, stream TEXT NOT NULL, live_count INTEGER NOT NULL, row_count INTEGER NOT NULL, pending_count INTEGER NOT NULL, last_updated TEXT, PRIMARY KEY(preview,instance,stream));
      CREATE INDEX IF NOT EXISTS pdpp_replica_view_page ON pdpp_replica_view(instance,stream,emitted_at,record_key);
      CREATE INDEX IF NOT EXISTS pdpp_replica_view_page_key ON pdpp_replica_view(instance,stream,pdpp_time_key(emitted_at),record_key);
      CREATE INDEX IF NOT EXISTS pdpp_replica_canonical_page_key ON pdpp_records(instance,stream,pdpp_time_key(emitted_at),record_key) WHERE deleted=0;
      CREATE INDEX IF NOT EXISTS pdpp_replica_view_blob ON pdpp_replica_view(blob_id) WHERE blob_id IS NOT NULL;
      CREATE TABLE IF NOT EXISTS pdpp_replica_view_evidence (
        operation_json TEXT PRIMARY KEY, confirmed INTEGER NOT NULL DEFAULT 0, pending INTEGER NOT NULL DEFAULT 0,
        instance TEXT GENERATED ALWAYS AS (json_extract(operation_json,'$.connectionId')) VIRTUAL,
        stream TEXT GENERATED ALWAYS AS (json_extract(operation_json,'$.declaration.stream')) VIRTUAL,
        record_key TEXT GENERATED ALWAYS AS (json_extract(operation_json,'$.recordKey')) VIRTUAL,
        kind TEXT GENERATED ALWAYS AS (json_extract(operation_json,'$.kind')) VIRTUAL,
        writer TEXT GENERATED ALWAYS AS (json_extract(operation_json,'$.revision.writerId')) VIRTUAL,
        operation_id TEXT GENERATED ALWAYS AS (json_extract(operation_json,'$.revision.operationId')) VIRTUAL,
        blob_id TEXT GENERATED ALWAYS AS (COALESCE(json_extract(operation_json,'$.blob.blobId'),json_extract(operation_json,'$.blobs[0].blobId'))) VIRTUAL
      );
      CREATE INDEX IF NOT EXISTS pdpp_replica_evidence_key ON pdpp_replica_view_evidence(instance,stream,record_key) WHERE confirmed=1 OR pending>0;
      CREATE INDEX IF NOT EXISTS pdpp_replica_evidence_lifecycle ON pdpp_replica_view_evidence(instance,kind) WHERE confirmed=1 OR pending>0;
      CREATE INDEX IF NOT EXISTS pdpp_replica_evidence_id ON pdpp_replica_view_evidence(writer,operation_id) WHERE confirmed=1 OR pending>0;
      CREATE INDEX IF NOT EXISTS pdpp_replica_evidence_blob ON pdpp_replica_view_evidence(blob_id,instance) WHERE confirmed=1 OR pending>0;
      CREATE TABLE IF NOT EXISTS pdpp_replica_view_pending (batch_id TEXT NOT NULL, operation_json TEXT NOT NULL, PRIMARY KEY(batch_id,operation_json));
      CREATE TABLE IF NOT EXISTS pdpp_replica_view_conflicts (writer TEXT NOT NULL, operation_id TEXT NOT NULL, instance TEXT NOT NULL, operation_json TEXT NOT NULL, PRIMARY KEY(writer,operation_id,operation_json));
      CREATE INDEX IF NOT EXISTS pdpp_replica_view_conflict_instance ON pdpp_replica_view_conflicts(instance);
      CREATE TABLE IF NOT EXISTS pdpp_replica_view_dirty_operations (operation_json TEXT PRIMARY KEY);
      CREATE TABLE IF NOT EXISTS pdpp_replica_view_dirty_keys (instance TEXT NOT NULL, stream TEXT NOT NULL, record_key TEXT NOT NULL, PRIMARY KEY(instance,stream,record_key));
      CREATE TABLE IF NOT EXISTS pdpp_replica_view_dirty_connections (instance TEXT PRIMARY KEY);
      CREATE TRIGGER IF NOT EXISTS pdpp_replica_view_evidence_insert AFTER INSERT ON pdpp_replica_view_evidence BEGIN
        INSERT INTO pdpp_replica_view_dirty_operations SELECT NEW.operation_json WHERE NOT EXISTS (SELECT 1 FROM pdpp_replica_view_dirty_operations WHERE operation_json=NEW.operation_json);
      END;
      CREATE TRIGGER IF NOT EXISTS pdpp_replica_view_evidence_update AFTER UPDATE ON pdpp_replica_view_evidence BEGIN
        INSERT INTO pdpp_replica_view_dirty_operations SELECT NEW.operation_json WHERE NOT EXISTS (SELECT 1 FROM pdpp_replica_view_dirty_operations WHERE operation_json=NEW.operation_json);
      END;
      CREATE TRIGGER IF NOT EXISTS pdpp_replica_view_journal AFTER INSERT ON pdpp_replica_operations BEGIN
        INSERT INTO pdpp_replica_view_evidence(operation_json,confirmed) VALUES (NEW.operation_json,1) ON CONFLICT(operation_json) DO UPDATE SET confirmed=1;
      END;
      CREATE TRIGGER IF NOT EXISTS pdpp_replica_view_received AFTER INSERT ON pdpp_replica_received BEGIN
        INSERT INTO pdpp_replica_view_evidence(operation_json,confirmed) VALUES (NEW.operation_json,1) ON CONFLICT(operation_json) DO UPDATE SET confirmed=1;
      END;
      CREATE TRIGGER IF NOT EXISTS pdpp_replica_view_record_insert AFTER INSERT ON pdpp_records BEGIN
        INSERT INTO pdpp_replica_view_connection_clocks(instance,canonical) VALUES (NEW.instance,1) ON CONFLICT(instance) DO UPDATE SET canonical=canonical+1;
        INSERT INTO pdpp_replica_view_dirty_keys SELECT NEW.instance,NEW.stream,NEW.record_key WHERE NOT EXISTS (SELECT 1 FROM pdpp_replica_view_dirty_keys WHERE instance=NEW.instance AND stream=NEW.stream AND record_key=NEW.record_key);
      END;
      CREATE TRIGGER IF NOT EXISTS pdpp_replica_view_record_update AFTER UPDATE ON pdpp_records BEGIN
        INSERT INTO pdpp_replica_view_connection_clocks(instance,canonical) VALUES (NEW.instance,1) ON CONFLICT(instance) DO UPDATE SET canonical=canonical+1;
        INSERT INTO pdpp_replica_view_dirty_keys SELECT NEW.instance,NEW.stream,NEW.record_key WHERE NOT EXISTS (SELECT 1 FROM pdpp_replica_view_dirty_keys WHERE instance=NEW.instance AND stream=NEW.stream AND record_key=NEW.record_key);
      END;
      CREATE TRIGGER IF NOT EXISTS pdpp_replica_view_record_delete AFTER DELETE ON pdpp_records BEGIN
        INSERT INTO pdpp_replica_view_connection_clocks(instance,canonical) VALUES (OLD.instance,1) ON CONFLICT(instance) DO UPDATE SET canonical=canonical+1;
        INSERT INTO pdpp_replica_view_dirty_keys SELECT OLD.instance,OLD.stream,OLD.record_key WHERE NOT EXISTS (SELECT 1 FROM pdpp_replica_view_dirty_keys WHERE instance=OLD.instance AND stream=OLD.stream AND record_key=OLD.record_key);
      END;
      CREATE TRIGGER IF NOT EXISTS pdpp_replica_view_binding AFTER UPDATE ON pdpp_instance_binding
      WHEN NEW.generation != OLD.generation OR NEW.deleted_at IS NOT OLD.deleted_at OR NEW.source_id IS NOT OLD.source_id OR NEW.method IS NOT OLD.method OR NEW.reset_clock IS NOT OLD.reset_clock BEGIN
        INSERT INTO pdpp_replica_view_connection_clocks(instance,canonical) VALUES (NEW.instance,1) ON CONFLICT(instance) DO UPDATE SET canonical=canonical+1;
        INSERT INTO pdpp_replica_view_dirty_connections SELECT NEW.instance WHERE NOT EXISTS (SELECT 1 FROM pdpp_replica_view_dirty_connections WHERE instance=NEW.instance);
      END;
    `);
    const localInitialized =
      hasBindingConflictFacts &&
      db
        .prepare(
          "SELECT 1 FROM sqlite_master WHERE type='table' AND name='pdpp_replica_local_view'",
        )
        .get();
    if (hasBindingConflictFacts)
      db.exec(`
      CREATE TABLE IF NOT EXISTS pdpp_replica_local_view (instance TEXT NOT NULL,stream TEXT NOT NULL,record_key TEXT NOT NULL,emitted_at TEXT NOT NULL,row_json TEXT NOT NULL,blob_id TEXT,pending INTEGER NOT NULL,deleted INTEGER NOT NULL,blob_json TEXT,sequence INTEGER NOT NULL,generation INTEGER NOT NULL,source_id TEXT NOT NULL,method TEXT NOT NULL,PRIMARY KEY(instance,stream,record_key));
      CREATE INDEX IF NOT EXISTS pdpp_replica_local_page ON pdpp_replica_local_view(instance,stream,emitted_at,record_key) WHERE deleted=0;
      CREATE INDEX IF NOT EXISTS pdpp_replica_local_page_key ON pdpp_replica_local_view(instance,stream,pdpp_time_key(emitted_at),record_key) WHERE deleted=0;
      CREATE INDEX IF NOT EXISTS pdpp_replica_local_blob ON pdpp_replica_local_view(blob_id) WHERE deleted=0 AND blob_id IS NOT NULL;
      CREATE TRIGGER IF NOT EXISTS pdpp_replica_local_journal AFTER INSERT ON pdpp_mutation_journal
      WHEN NEW.writer_id=(SELECT writer_id FROM pdpp_installation_writer WHERE id=1) AND EXISTS (SELECT 1 FROM pdpp_instance_binding b WHERE b.instance=NEW.connection_id AND b.generation=NEW.generation AND b.source_id=NEW.source_id AND b.method=NEW.method AND b.source_id IS NOT NULL AND b.method IS NOT NULL AND b.deleted_at IS NULL) BEGIN
        INSERT INTO pdpp_replica_local_view VALUES (NEW.connection_id,NEW.stream,NEW.record_key,json_extract(NEW.value_json,'$.emittedAt'),NEW.value_json,json_extract(NEW.value_json,'$.data.blob_ref.blob_id'),0,json_extract(NEW.value_json,'$.deleted'),NULL,NEW.sequence,NEW.generation,NEW.source_id,NEW.method)
        ON CONFLICT(instance,stream,record_key) DO UPDATE SET emitted_at=excluded.emitted_at,row_json=excluded.row_json,blob_id=excluded.blob_id,deleted=excluded.deleted,sequence=excluded.sequence,generation=excluded.generation,source_id=excluded.source_id,method=excluded.method WHERE excluded.sequence>pdpp_replica_local_view.sequence;
      END;
      CREATE TRIGGER IF NOT EXISTS pdpp_replica_local_binding AFTER UPDATE ON pdpp_instance_binding
      WHEN NEW.generation IS NOT OLD.generation OR NEW.source_id IS NOT OLD.source_id OR NEW.method IS NOT OLD.method OR NEW.deleted_at IS NOT OLD.deleted_at BEGIN
        DELETE FROM pdpp_replica_local_view WHERE instance=NEW.instance;
        INSERT INTO pdpp_replica_local_view ${localProjection} AND j.connection_id=NEW.instance;
      END;
    `);
    if (hasBindingConflictFacts)
      for (const [event, alias] of [
        ["INSERT", "NEW"],
        ["UPDATE", "NEW"],
        ["DELETE", "OLD"],
      ] as const)
        db.exec(
          `CREATE TRIGGER IF NOT EXISTS pdpp_replica_local_clock_${event} AFTER ${event} ON pdpp_replica_local_view BEGIN INSERT INTO pdpp_replica_view_connection_clocks(instance,local) VALUES (${alias}.instance,1) ON CONFLICT(instance) DO UPDATE SET local=local+1; END;`,
        );
    for (const [table, preview] of [
      ["pdpp_records", 0],
      ["pdpp_replica_view", 1],
      ...(hasBindingConflictFacts
        ? [["pdpp_replica_local_view", 2] as const]
        : []),
    ] as const) {
      const pending = (alias: string) =>
        preview === 1 ? `${alias}.pending` : "0";
      const visible = (alias: string) =>
        preview === 1 ? "1" : `(1-${alias}.deleted)`;
      const latest = `SELECT emitted_at FROM ${table} WHERE instance=OLD.instance AND stream=OLD.stream ${preview === 1 ? "" : "AND deleted=0"} ORDER BY emitted_at DESC,record_key DESC LIMIT 1`;
      db.exec(`
        CREATE TRIGGER IF NOT EXISTS ${table}_summary_insert AFTER INSERT ON ${table} BEGIN
          INSERT INTO pdpp_replica_view_streams VALUES (${preview},NEW.instance,NEW.stream,1-NEW.deleted,${visible("NEW")},${pending("NEW")},CASE WHEN ${visible("NEW")} THEN NEW.emitted_at ELSE NULL END)
          ON CONFLICT(preview,instance,stream) DO UPDATE SET
            live_count=live_count+1-NEW.deleted,row_count=row_count+${visible("NEW")},pending_count=pending_count+${pending("NEW")},
            last_updated=CASE WHEN ${visible("NEW")} AND (last_updated IS NULL OR NEW.emitted_at>last_updated) THEN NEW.emitted_at ELSE last_updated END;
        END;
        CREATE TRIGGER IF NOT EXISTS ${table}_summary_update AFTER UPDATE ON ${table} BEGIN
          UPDATE pdpp_replica_view_streams SET live_count=live_count+OLD.deleted-NEW.deleted,
            row_count=row_count+${visible("NEW")}-${visible("OLD")},pending_count=pending_count+${pending("NEW")}-${pending("OLD")},
            last_updated=(${latest}) WHERE preview=${preview} AND instance=OLD.instance AND stream=OLD.stream;
        END;
        CREATE TRIGGER IF NOT EXISTS ${table}_summary_delete AFTER DELETE ON ${table} BEGIN
          UPDATE pdpp_replica_view_streams SET live_count=live_count-(1-OLD.deleted),row_count=row_count-${visible("OLD")},pending_count=pending_count-${pending("OLD")},last_updated=(${latest})
          WHERE preview=${preview} AND instance=OLD.instance AND stream=OLD.stream;
        END;
      `);
    }
    if (hasBindingConflictFacts && !localInitialized)
      db.exec(`INSERT INTO pdpp_replica_local_view ${localProjection};`);
    if (!initialized) {
      // One-time migration. Thereafter persisted dirty queues also cover downtime/restarts.
      db.exec(
        `INSERT INTO pdpp_replica_view_streams SELECT 0,instance,stream,SUM(1-deleted),SUM(1-deleted),0,MAX(CASE WHEN deleted=0 THEN emitted_at END) FROM pdpp_records GROUP BY instance,stream;`,
      );
      db.exec(`INSERT INTO pdpp_replica_view_evidence(operation_json,confirmed)
        SELECT operation_json,1 FROM pdpp_replica_operations WHERE true ON CONFLICT(operation_json) DO UPDATE SET confirmed=1;
        INSERT INTO pdpp_replica_view_evidence(operation_json,confirmed)
        SELECT operation_json,1 FROM pdpp_replica_received WHERE true ON CONFLICT(operation_json) DO UPDATE SET confirmed=1;
        INSERT OR IGNORE INTO pdpp_replica_view_dirty_keys SELECT instance,stream,record_key FROM pdpp_records;
      `);
      for (const row of db
        .prepare(
          "SELECT id,envelope_json FROM pdpp_replica_pending_batches WHERE state='pending'",
        )
        .all() as { id: string; envelope_json: string }[]) {
        addPending(row.id, JSON.parse(row.envelope_json).operations);
      }
    }
  }).immediate();

  function addPending(batchId: string, operations: ReplicaOperation[]) {
    for (const op of operations) {
      const json = canonicalJson(op);
      if (
        !db
          .prepare(
            "INSERT OR IGNORE INTO pdpp_replica_view_pending VALUES (?,?)",
          )
          .run(batchId, json).changes
      )
        continue;
      db.prepare(
        "INSERT INTO pdpp_replica_view_evidence(operation_json,pending) VALUES (?,1) ON CONFLICT(operation_json) DO UPDATE SET pending=pending+1",
      ).run(json);
    }
  }
  function removePending(batchId: string) {
    for (const row of db
      .prepare(
        "SELECT operation_json FROM pdpp_replica_view_pending WHERE batch_id=?",
      )
      .all(batchId) as { operation_json: string }[]) {
      db.prepare(
        "UPDATE pdpp_replica_view_evidence SET pending=pending-1 WHERE operation_json=?",
      ).run(row.operation_json);
    }
    db.prepare("DELETE FROM pdpp_replica_view_pending WHERE batch_id=?").run(
      batchId,
    );
  }
  const active = "(confirmed=1 OR pending>0)";
  const operations = (sql: string, ...args: unknown[]): ReplicaOperation[] =>
    (db.prepare(sql).all(...args) as { operation_json: string }[]).map((row) =>
      JSON.parse(row.operation_json),
    );
  function dirtyKey(instance: string, stream: string, key: string) {
    db.prepare(
      "INSERT OR IGNORE INTO pdpp_replica_view_dirty_keys VALUES (?,?,?)",
    ).run(instance, stream, key);
  }
  function dirtyConnection(instance: string) {
    db.prepare(
      "INSERT OR IGNORE INTO pdpp_replica_view_dirty_connections VALUES (?)",
    ).run(instance);
  }
  function flush(): void {
    if (!db.inTransaction) return db.transaction(flush).immediate();
    const dirtyOps = operations(
      "SELECT operation_json FROM pdpp_replica_view_dirty_operations",
    );
    const connections = new Set(
      (
        db
          .prepare("SELECT instance FROM pdpp_replica_view_dirty_connections")
          .all() as { instance: string }[]
      ).map((row) => row.instance),
    );
    let changed = dirtyOps.length > 0 || connections.size > 0;
    for (const op of dirtyOps) {
      const { writerId, operationId } = op.revision;
      const previous = db
        .prepare(
          "SELECT instance FROM pdpp_replica_view_conflicts WHERE writer=? AND operation_id=?",
        )
        .all(writerId, operationId) as { instance: string }[];
      const variants = operations(
        `SELECT operation_json FROM pdpp_replica_view_evidence WHERE writer=? AND operation_id=? AND ${active}`,
        writerId,
        operationId,
      );
      db.prepare(
        "DELETE FROM pdpp_replica_view_conflicts WHERE writer=? AND operation_id=?",
      ).run(writerId, operationId);
      for (const row of previous) connections.add(row.instance);
      if (variants.length > 1)
        for (const variant of variants) {
          connections.add(variant.connectionId);
          db.prepare(
            "INSERT INTO pdpp_replica_view_conflicts VALUES (?,?,?,?)",
          ).run(
            writerId,
            operationId,
            variant.connectionId,
            canonicalJson(variant),
          );
        }
      if (op.kind === "upsert" || op.kind === "delete")
        dirtyKey(op.connectionId, op.declaration.stream, op.recordKey);
      else if (op.kind === "blob-claim") {
        for (const dependent of operations(
          `SELECT operation_json FROM pdpp_replica_view_evidence WHERE blob_id=? AND instance=? AND kind='upsert' AND ${active}`,
          op.blob.blobId,
          op.connectionId,
        )) {
          if (dependent.kind === "upsert")
            dirtyKey(
              dependent.connectionId,
              dependent.declaration.stream,
              dependent.recordKey,
            );
        }
      } else if (op.kind === "connection-register") {
        // A compatible registration already in force does not change any key.
        // Operation-ID equivocation was handled globally above, before this shortcut.
        const established = operations(
          `SELECT operation_json FROM pdpp_replica_view_evidence WHERE instance=? AND kind='connection-register' AND ${active} AND (operation_json<>? OR pending>1 OR (confirmed=1 AND pending>0))`,
          op.connectionId,
          canonicalJson(op),
        ).some(
          (other) =>
            other.owner === op.owner &&
            other.sourceId === op.sourceId &&
            other.methodId === op.methodId,
        );
        if (!established) connections.add(op.connectionId);
      } else if (op.kind.startsWith("connection-"))
        connections.add(op.connectionId);
    }
    for (const instance of connections) {
      // Lifecycle/equivocation changes can affect every key, once at WRITE time.
      db.prepare(
        `INSERT OR IGNORE INTO pdpp_replica_view_dirty_keys SELECT instance,stream,record_key FROM pdpp_records WHERE instance=?`,
      ).run(instance);
      db.prepare(
        `INSERT OR IGNORE INTO pdpp_replica_view_dirty_keys SELECT instance,stream,record_key FROM pdpp_replica_view WHERE instance=?`,
      ).run(instance);
      db.prepare(
        `INSERT OR IGNORE INTO pdpp_replica_view_dirty_keys SELECT instance,stream,record_key FROM pdpp_replica_view_evidence WHERE instance=? AND record_key IS NOT NULL AND ${active}`,
      ).run(instance);
    }
    const touched = new Set(connections);
    for (const row of db
      .prepare("SELECT * FROM pdpp_replica_view_dirty_keys")
      .all() as { instance: string; stream: string; record_key: string }[]) {
      changed = true;
      touched.add(row.instance);
      reconcileKey(row.instance, row.stream, row.record_key);
    }
    db.exec(
      "DELETE FROM pdpp_replica_view_dirty_operations; DELETE FROM pdpp_replica_view_dirty_keys; DELETE FROM pdpp_replica_view_dirty_connections;",
    );
    for (const instance of touched)
      db.prepare(
        "INSERT INTO pdpp_replica_view_connection_clocks(instance,preview) VALUES (?,1) ON CONFLICT(instance) DO UPDATE SET preview=preview+1",
      ).run(instance);
    if (changed)
      db.prepare(
        "UPDATE pdpp_replica_view_clock SET revision=revision+1 WHERE id=1",
      ).run();
  }
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
  function reconcileKey(instance: string, stream: string, key: string) {
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
    let row = current && canonical(current);
    let blobId = row ? current!.blob_id : null;
    let blobMeta: PdppBlobMeta | undefined;
    if (blobId) {
      const meta = db
        .prepare(
          "SELECT mime_type,size_bytes,sha256 FROM pdpp_blobs WHERE blob_id=?",
        )
        .get(blobId) as
        { mime_type: string; size_bytes: number; sha256: string } | undefined;
      if (meta)
        blobMeta = {
          blobId,
          mimeType: meta.mime_type,
          sizeBytes: meta.size_bytes,
          sha256: meta.sha256,
        };
    }
    if (local?.source_id && !local.deleted_at) {
      const evidenceRows = db
        .prepare(
          `SELECT operation_json,confirmed,pending FROM pdpp_replica_view_evidence WHERE instance=? AND stream=? AND record_key=? AND ${active}`,
        )
        .all(instance, stream, key) as Evidence[];
      // The conflict index carries global operation-ID variants, including other connections.
      const conflictOps = operations(
        "SELECT c2.operation_json FROM pdpp_replica_view_conflicts c JOIN pdpp_replica_view_conflicts c2 ON c.writer=c2.writer AND c.operation_id=c2.operation_id WHERE c.instance=?",
        instance,
      );
      const lifecycle = operations(
        `SELECT operation_json FROM pdpp_replica_view_evidence WHERE instance=? AND kind IN ('connection-register','connection-reset','connection-delete') AND ${active}`,
        instance,
      );
      const claims = operations(
        `SELECT operation_json FROM pdpp_replica_view_evidence WHERE instance=? AND kind='blob-claim' AND blob_id IN (SELECT blob_id FROM pdpp_replica_view_evidence WHERE instance=? AND stream=? AND record_key=? AND ${active}) AND ${active}`,
        instance,
        instance,
        stream,
        key,
      );
      const all = [
        ...evidenceRows.map(
          (e) => JSON.parse(e.operation_json) as ReplicaOperation,
        ),
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
      const provisionalLifecycle = lifecycle.some((op) => {
        const state = db
          .prepare(
            "SELECT confirmed,pending FROM pdpp_replica_view_evidence WHERE operation_json=?",
          )
          .get(canonicalJson(op)) as Evidence;
        return (
          !state.confirmed &&
          state.pending > 0 &&
          (op.kind === "connection-delete" ||
            (op.kind === "connection-reset" &&
              op.generation > local.generation))
        );
      });
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
        )?.current;
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
          const winner = record.current;
          const state =
            winner &&
            evidenceRows.find(
              (e) => e.operation_json === canonicalJson(winner),
            );
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
    if (!row)
      db.prepare(
        "DELETE FROM pdpp_replica_view WHERE instance=? AND stream=? AND record_key=?",
      ).run(instance, stream, key);
    else
      db.prepare(
        "INSERT INTO pdpp_replica_view VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(instance,stream,record_key) DO UPDATE SET emitted_at=excluded.emitted_at,row_json=excluded.row_json,blob_id=excluded.blob_id,pending=excluded.pending,deleted=excluded.deleted,blob_json=excluded.blob_json",
      ).run(
        instance,
        stream,
        key,
        row.emittedAt,
        JSON.stringify(row),
        blobId,
        row.visibility === "pending" ? 1 : 0,
        row.deleted ? 1 : 0,
        blobId && blobMeta ? JSON.stringify(blobMeta) : null,
      );
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
  const tableFor = (mode: Mode) =>
    mode === "local"
      ? "pdpp_replica_local_view"
      : mode === "preview"
        ? "pdpp_replica_view"
        : "pdpp_records";
  function rowFilter(mode: Mode, alias = "r") {
    return `${deps.unquarantinedRecordSql(alias)} ${mode === "preview" ? "" : `AND ${alias}.deleted=0`} ${mode === "local" ? `AND ${localIdentitySql(alias)}` : ""}`;
  }
  function selectedColumns(mode: Mode, alias = "r") {
    const json =
      mode === "canonical"
        ? `json_object('instance',${alias}.instance,'stream',${alias}.stream,'recordKey',${alias}.record_key,'data',json(${alias}.data),'version',${alias}.version,'emittedAt',${alias}.emitted_at,'deleted',json('false'))`
        : `${alias}.row_json`;
    return `${alias}.instance,${alias}.stream,${alias}.record_key,${alias}.emitted_at,pdpp_time_key(${alias}.emitted_at) AS emitted_key,${json} AS row_json,'${mode}' AS origin`;
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
  function getRecord(
    instance: string,
    stream: string,
    key: string,
    reader: ReplicaReader = "owner",
    preview = true,
  ): PdppVisibleRecord | undefined {
    const mode = readBranch(instance, reader, preview);
    if (mode === "hidden") return undefined;
    const row = db
      .prepare(
        `SELECT ${selectedColumns(mode)} FROM ${tableFor(mode)} r WHERE r.instance=? AND r.stream=? AND r.record_key=? AND ${rowFilter(mode)}`,
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
        const clocks = ids.length
          ? (db
              .prepare(
                `SELECT c.*,b.reset_clock AS fence FROM pdpp_replica_view_connection_clocks c LEFT JOIN pdpp_instance_binding b ON b.instance=c.instance WHERE c.instance IN (${ids.map(() => "?").join(",")})`,
              )
              .all(...ids) as {
              instance: string;
              canonical: number;
              preview: number;
              local: number;
              fence: number;
            }[])
          : [];
        const viewRevision = JSON.stringify(
          ids.map((instance) => {
            const clock = clocks.find((row) => row.instance === instance),
              mode = modes.get(instance)!;
            const revision =
              mode === "hidden"
                ? []
                : mode === "local"
                  ? [clock?.local ?? 0]
                  : mode === "preview"
                    ? [clock?.canonical ?? 0, clock?.preview ?? 0]
                    : [clock?.canonical ?? 0];
            return [instance, mode, clock?.fence ?? 0, ...revision];
          }),
        );
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
          params.push(instance, stream);
          let boundary = "";
          if (cursor) {
            const instanceOrder = Buffer.compare(
              Buffer.from(instance),
              Buffer.from(cursor.instance!),
            );
            const equal =
              options.order === "asc" ? instanceOrder > 0 : instanceOrder < 0;
            boundary = ` AND (pdpp_time_key(r.emitted_at),r.record_key) ${equal ? cmp + "=" : cmp} (pdpp_time_key(?),?)`;
            params.push(cursor.sortValue, cursor.recordKey);
          }
          params.push(options.limit + 1);
          return [
            `SELECT * FROM (SELECT ${selectedColumns(mode)} FROM ${tableFor(mode)} r WHERE r.instance=? AND r.stream=? AND ${rowFilter(mode)}${boundary} ORDER BY pdpp_time_key(r.emitted_at) ${dir},r.record_key ${dir} LIMIT ?)`,
          ];
        });
        const rows = branches.length
          ? (db
              .prepare(
                `SELECT * FROM (${branches.join(" UNION ALL ")}) ORDER BY emitted_key ${dir},record_key ${dir},instance ${dir} LIMIT ?`,
              )
              .all(...params, options.limit + 1) as {
              row_json: string;
              origin: Mode;
            }[])
          : [];
        const data = rows.slice(0, options.limit).map((raw) => {
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
        const last = data[data.length - 1],
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
                  sortValue: last.emittedAt,
                  recordKey: last.recordKey,
                  horizon: String(value),
                })
              : undefined,
        };
      })
      .deferred();
  }
  function listStreams(
    ids: string[],
    preview = true,
    reader: ReplicaReader = "owner",
  ): StreamListing[] {
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
            `SELECT 1 FROM (SELECT ? AS instance,NULL AS stream,NULL AS record_key) r WHERE ${deps.unquarantinedRecordSql("r")}`,
          )
          .get(instance)
      )
        continue;
      const summaries = db
        .prepare(
          "SELECT * FROM pdpp_replica_view_streams WHERE preview=? AND instance=? AND row_count>0",
        )
        .all(mode === "local" ? 2 : mode === "preview" ? 1 : 0, instance) as {
        stream: string;
        live_count: number;
        row_count: number;
        pending_count: number;
        last_updated: string | null;
      }[];
      for (const summary of summaries) {
        const table = tableFor(mode),
          pending = mode === "preview" ? "r.pending" : "0";
        const hidden = db
          .prepare(
            `SELECT COUNT(*) AS rows,COALESCE(SUM(1-deleted),0) AS live,COALESCE(SUM(pending),0) AS pending FROM (SELECT DISTINCT r.record_key,r.deleted,${pending} AS pending FROM pdpp_replica_quarantined_keys q JOIN ${table} r ON r.instance=q.instance AND r.stream=q.stream AND r.record_key=q.record_key WHERE q.instance=? AND r.stream=? ${mode === "preview" ? "" : "AND r.deleted=0"} AND NOT (${deps.unquarantinedRecordSql("r")}))`,
          )
          .get(instance, summary.stream) as {
          rows: number;
          live: number;
          pending: number;
        };
        if (summary.row_count - hidden.rows <= 0) continue;
        let last = summary.last_updated;
        if (hidden.rows)
          last =
            (
              db
                .prepare(
                  `SELECT r.emitted_at FROM ${table} r WHERE r.instance=? AND r.stream=? AND ${rowFilter(mode)} ORDER BY r.emitted_at DESC,r.record_key DESC LIMIT 1`,
                )
                .get(instance, summary.stream) as
                { emitted_at: string } | undefined
            )?.emitted_at ?? null;
        const previous = combined.get(summary.stream) ?? {
          count: 0,
          last: null,
          pending: false,
          conflicted: false,
        };
        combined.set(summary.stream, {
          count: previous.count + summary.live_count - hidden.live,
          last:
            last && (previous.last === null || last > previous.last)
              ? last
              : previous.last,
          pending:
            previous.pending || summary.pending_count - hidden.pending > 0,
          conflicted: previous.conflicted || mode === "local",
        });
      }
    }
    return [...combined].map(([stream, row]) => ({
      stream,
      recordCount: row.count,
      lastUpdated: row.last,
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
    const normal: Mode = preview ? "preview" : "canonical";
    const selection = onlyExists
      ? "1"
      : "r.instance,r.stream,r.record_key AS recordKey";
    const normalFact = hasBindingConflictFacts
      ? "AND NOT EXISTS (SELECT 1 FROM pdpp_replica_binding_conflicts f WHERE f.instance=r.instance)"
      : "";
    const branches = [
      `SELECT ${selection} FROM ${tableFor(normal)} r WHERE r.blob_id=? AND ${rowFilter(normal)} ${normalFact}`,
    ];
    const args = [id];
    if (
      hasBindingConflictFacts &&
      replicaStateVisible("conflicted", reader, undefined, "local")
    ) {
      branches.push(
        `SELECT ${selection} FROM pdpp_replica_local_view r WHERE r.blob_id=? AND ${rowFilter("local")} AND EXISTS (SELECT 1 FROM pdpp_replica_binding_conflicts f WHERE f.instance=r.instance)`,
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
  function getBlobMeta(id: string): PdppBlobMeta | undefined {
    const row = db
      .prepare(
        `SELECT r.blob_json FROM pdpp_replica_view r WHERE r.blob_id=? AND r.blob_json IS NOT NULL AND ${rowFilter("preview")} ${hasBindingConflictFacts ? "AND NOT EXISTS (SELECT 1 FROM pdpp_replica_binding_conflicts f WHERE f.instance=r.instance)" : ""} LIMIT 1`,
      )
      .get(id) as { blob_json: string } | undefined;
    return row ? JSON.parse(row.blob_json) : undefined;
  }
  function reconcileAll() {
    db.exec(`INSERT OR IGNORE INTO pdpp_replica_view_dirty_connections SELECT DISTINCT instance FROM pdpp_replica_view_evidence WHERE confirmed=1 OR pending>0;
      INSERT OR IGNORE INTO pdpp_replica_view_dirty_connections SELECT DISTINCT instance FROM pdpp_replica_view;`);
    flush();
  }
  flush();
  return {
    flush,
    reconcileAll,
    addPending,
    removePending,
    dirtyConnection,
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
