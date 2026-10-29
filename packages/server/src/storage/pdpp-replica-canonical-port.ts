import type { Database } from "better-sqlite3";
import { createHash, randomUUID } from "node:crypto";
import type { DeclarationBinding } from "@opendatalabs/personal-server-ts-core/replication/envelope";
import {
  CursorExpiredError,
  InvalidCursorError,
  type StreamSemantics,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import {
  BINARY_CHUNKS_MIGRATION,
  binaryLength,
  clearMalformedManifest,
  readBinary,
  verifyBinary,
  writeCanonicalBinary,
} from "./pdpp-binary-chunks.js";
import { REPLICA_COPY_MIGRATION } from "./pdpp-replica-copies.js";
import {
  RECEIVER_MIGRATION,
  REPLICA_FACT_REMOVAL_MIGRATION,
  REPLICA_INTEGRITY_MIGRATION,
} from "./pdpp-replication-receiver.js";
import {
  createReplicationJournal,
  REPLICATION_MIGRATION,
  REPLICA_BLOB_CLAIM_INDEX_MIGRATION,
  type ReplicationExport,
} from "./pdpp-replication-sqlite.js";
import {
  currentReplicaWriterIdentity,
  REPLICA_WRITER_IDENTITY_MIGRATION,
} from "./pdpp-replica-writer-identity.js";
import {
  createSqliteRecordStore,
  PdppBindingError,
  type CanonicalBlobBytes,
  type SqliteRecordStoreOptions,
} from "./pdpp-records-sqlite-store.js";
import { admitReplication, captureWrites } from "./pdpp-replication-door.js";

/**
 * The replica schema. It is versioned by `pdpp_replica_schema_version`, apart
 * from the canonical `MIGRATIONS` chain, and only `ensureReplicaSchema` applies
 * it. A database that never enabled replication has none of these tables, and
 * a canonical build that knows nothing of them still opens one that did.
 */
export const REPLICA_MIGRATIONS: readonly string[] = [
  // r1: installation writer and the log of its own writes. The owner's local view
  // of a binding-conflicted connection projects the log
  // (pdpp-replica-visibility-view.ts).
  `
CREATE TABLE IF NOT EXISTS pdpp_installation_writer (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  writer_id TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS pdpp_replica_own_writes (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  operation_id TEXT NOT NULL UNIQUE,
  writer_id TEXT NOT NULL,
  source_id TEXT,
  connection_id TEXT NOT NULL,
  method TEXT,
  generation INTEGER CHECK (generation > 0),
  stream TEXT NOT NULL,
  record_key TEXT NOT NULL,
  operation TEXT NOT NULL CHECK (operation IN ('upsert', 'delete')),
  value_json TEXT NOT NULL,
  blob_ids_json TEXT NOT NULL
);
-- REPLACE's implicit delete need not fire DELETE triggers. Guard both identities
-- before insertion as well, independent of recursive_triggers configuration.
CREATE TRIGGER IF NOT EXISTS pdpp_replica_own_writes_no_replace BEFORE INSERT ON pdpp_replica_own_writes
WHEN EXISTS (SELECT 1 FROM pdpp_replica_own_writes
             WHERE sequence = NEW.sequence OR operation_id = NEW.operation_id)
BEGIN SELECT RAISE(ABORT, 'local write log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS pdpp_replica_own_writes_no_update BEFORE UPDATE ON pdpp_replica_own_writes
BEGIN SELECT RAISE(ABORT, 'local write log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS pdpp_replica_own_writes_no_delete BEFORE DELETE ON pdpp_replica_own_writes
BEGIN SELECT RAISE(ABORT, 'local write log is append-only'); END;
`,
  REPLICATION_MIGRATION,
  RECEIVER_MIGRATION,
  // Earlier builds also created the persistent trigger
  // `pdpp_canonical_chunks_delete` on `pdpp_blobs` here. It would fire on a
  // plain open's blob deletes, so `ensureReplicaSchema` drops it and the
  // port recreates it as a TEMP trigger. See `CANONICAL_CHUNKS_TRIGGER`.
  BINARY_CHUNKS_MIGRATION,
  // Integrity fences and binding-conflict facts.
  REPLICA_INTEGRITY_MIGRATION,
  // Batch copies, finalized facts, dispositions, receipts.
  REPLICA_COPY_MIGRATION,
  // Removing a quarantine fact raises the integrity epoch.
  REPLICA_FACT_REMOVAL_MIGRATION,
  // Indexed blob-claim existence lookup for captureBlob.
  REPLICA_BLOB_CLAIM_INDEX_MIGRATION,
  // Writer ids derived from the registered server key (host contract §3.2).
  REPLICA_WRITER_IDENTITY_MIGRATION,
];

/**
 * Apply the replica schema. Call it only when replication is enabled, after
 * the canonical store migrated the database. Idempotent.
 */
export function ensureReplicaSchema(db: Database): void {
  db.transaction(() => {
    db.exec(`
      CREATE TABLE IF NOT EXISTS pdpp_replica_schema_version (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        version INTEGER NOT NULL
      );
      INSERT OR IGNORE INTO pdpp_replica_schema_version (id, version) VALUES (1, 0);
    `);
    const { version } = db
      .prepare("SELECT version FROM pdpp_replica_schema_version WHERE id = 1")
      .get() as { version: number };
    if (version > REPLICA_MIGRATIONS.length)
      throw new Error(
        `PDPP replica schema version ${version} is newer than this build supports (${REPLICA_MIGRATIONS.length}). Refusing to open.`,
      );
    for (let v = version; v < REPLICA_MIGRATIONS.length; v++) {
      db.exec(REPLICA_MIGRATIONS[v]);
      if (v === 0)
        db.prepare(
          "INSERT OR IGNORE INTO pdpp_installation_writer (id, writer_id) VALUES (1, ?)",
        ).run(randomUUID());
    }
    db.prepare(
      "UPDATE pdpp_replica_schema_version SET version = ? WHERE id = 1",
    ).run(REPLICA_MIGRATIONS.length);
    // A database a canary build opened has the chunk trigger as a persistent
    // object. Replica triggers on canonical tables must exist only on a
    // connection that enabled replication, so remove it.
    db.exec("DROP TRIGGER IF EXISTS pdpp_canonical_chunks_delete");
    // A plain open can delete a blob without clearing its replica chunks.
    // Clear what such deletes left, on every enabled open.
    db.exec(`
      DELETE FROM pdpp_binary_chunks WHERE namespace='canonical' AND blob_id NOT IN (SELECT blob_id FROM pdpp_blobs);
      DELETE FROM pdpp_binary_manifests WHERE namespace='canonical' AND blob_id NOT IN (SELECT blob_id FROM pdpp_blobs);
    `);
  }).immediate();
}

/**
 * Deleting a canonical blob deletes its replica chunks. TEMP, so it lives on
 * the connection that enabled replication and never fires for a plain open's
 * writes; a plain open leaves the chunks, and the next enabled open clears
 * them (see `ensureReplicaSchema`).
 */
const CANONICAL_CHUNKS_TRIGGER = `CREATE TEMP TRIGGER IF NOT EXISTS pdpp_canonical_chunks_delete AFTER DELETE ON pdpp_blobs BEGIN DELETE FROM pdpp_binary_chunks WHERE namespace='canonical' AND blob_id=OLD.blob_id; DELETE FROM pdpp_binary_manifests WHERE namespace='canonical' AND blob_id=OLD.blob_id; END`;

function assertReplicaSchema(db: Database): void {
  const row = db
    .prepare(
      "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'pdpp_replica_schema_version'",
    )
    .get()
    ? (db
        .prepare("SELECT version FROM pdpp_replica_schema_version WHERE id = 1")
        .get() as { version: number } | undefined)
    : undefined;
  if (row?.version !== REPLICA_MIGRATIONS.length)
    throw new Error("Readonly PDPP replica store requires the current schema");
}

/**
 * Shared read predicate for canonical, replica-preview, and known-local
 * projections. A key fact hides rows of exactly its generation. Without
 * `generationSql` that is the binding's current generation (canonical rows).
 * With it, it is the row's own generation, for overlay and local rows that can
 * belong to a generation a pending reset introduces. Both halves use
 * equality, so an overlay row and the canonical row of one generation always
 * agree.
 */
export function unquarantinedRecordSql(
  alias: string,
  generationSql?: string,
): string {
  const connection = `NOT EXISTS (SELECT 1 FROM pdpp_replica_quarantined_connections q WHERE q.instance = ${alias}.instance)`;
  const key = (scope: string) =>
    `NOT EXISTS (SELECT 1 FROM pdpp_replica_quarantined_keys q ${scope} q.instance=${alias}.instance AND q.stream=${alias}.stream AND q.record_key=${alias}.record_key`;
  return generationSql === undefined
    ? `${connection} AND ${key("JOIN pdpp_instance_binding b ON b.instance=q.instance AND b.generation=q.generation WHERE")})`
    : `${connection} AND ${key("WHERE")} AND q.generation = (${generationSql}))`;
}

/** What a list or changes token is bound to besides its stream and store. */
export interface ReplicaCursorBinding {
  query: string;
  integrity: Record<string, number>;
  visibilityEpoch: string;
}

/**
 * Everything the canonical store does for replication. The store calls it
 * only when one was supplied; without it the store reads and writes exactly
 * the canonical tables. Capture methods run inside the caller's canonical
 * write transaction.
 */
export interface ReplicaCanonicalPort {
  unquarantinedRecordSql(alias: string, generationSql?: string): string;
  replicaVisibilityEpoch(instanceIds?: string[]): string;
  assertKeyWritable(instance: string, stream: string, recordKey: string): void;
  assertConnectionWritable(instance: string): void;
  /**
   * Strava and Claude method transitions change a connection's method and
   * generation without journaling a lifecycle operation, so a replica could not
   * follow them. Refuse them while replication is enabled.
   */
  assertMethodTransitionAllowed(): void;
  assertStreamWritable(
    instance: string,
    stream: string,
    generation: number,
  ): void;
  /** Log and capture the current row of one key after a canonical write. */
  recordWritten(
    instance: string,
    stream: string,
    recordKey: string,
    semantics?: StreamSemantics,
    primaryKey?: string[],
    declaration?: DeclarationBinding,
  ): void;
  /**
   * Let the receiver reconcile keys written since the last settle. The store
   * calls it once its own bookkeeping for the write (arrival entries, the
   * completion receipt) is done, so reconciliation has the last word on a key
   * a local write left in conflict.
   */
  settleLocalWrites(): void;
  captureInvalidation(instance: string, stream: string): void;
  captureCompletion(instance: string, stream: string): void;
  captureLifecycle(
    instance: string,
    kind: "connection-register" | "connection-reset" | "connection-delete",
  ): void;
  captureBlob(instance: string, blobId: string): void;
  /** Tell the visibility view that canonical state moved. */
  notifyVisibility(): void;
  /**
   * Runs a top-level canonical mutation in a write transaction that starts
   * from derived state matching canonical rows (see the visibility view).
   */
  exclusive<T>(write: () => T): T;
  /** The read counterpart of `exclusive`: a snapshot over matching derived state. */
  snapshot<T>(read: () => T): T;
  cursorBinding(
    instanceIds: string[],
    fields: string[] | undefined,
  ): ReplicaCursorBinding;
  /**
   * A token is refused for another connection set or projection, and expires
   * when any read connection's integrity epoch moved since page 1. A token
   * minted before integrity binding expires: it may span a quarantine.
   */
  assertCursorIntegrity(
    payload: {
      query?: string;
      integrity?: Record<string, number>;
      visibilityEpoch?: string;
    },
    instanceIds: string[],
    fields: string[] | undefined,
  ): void;
  /** Canonical blob bytes; values above 1 MiB are chunked. */
  blobBytes: CanonicalBlobBytes;
}

/**
 * Build the replica port of a canonical database. Applies the replica schema
 * first (readonly handles must already have it).
 */
export function createReplicaCanonicalPort(db: Database) {
  if (db.readonly) assertReplicaSchema(db);
  else {
    // Refuse behind a closed door before any replica write.
    admitReplication(db);
    ensureReplicaSchema(db);
    db.exec(CANONICAL_CHUNKS_TRIGGER);
    // Older replication builds stored large canonical blobs only in the
    // replica chunk tables. Materialize those bytes in main's canonical table
    // before a flag-off or main build can be used to read the database.
    db.transaction(() => {
      const missing = db
        .prepare(
          `SELECT m.blob_id, b.size_bytes, b.sha256
           FROM pdpp_binary_manifests m
           JOIN pdpp_blobs b ON b.blob_id = m.blob_id
           LEFT JOIN pdpp_blob_bytes c ON c.blob_id = m.blob_id
           WHERE m.namespace = 'canonical' AND c.blob_id IS NULL`,
        )
        .all() as { blob_id: string; size_bytes: number; sha256: string }[];
      for (const blob of missing) {
        if (
          !verifyBinary(
            db,
            "canonical",
            blob.blob_id,
            `sha256:${blob.sha256}`,
            blob.size_bytes,
          )
        )
          continue;
        const bytes = readBinary(db, "canonical", blob.blob_id);
        if (bytes) writeCanonicalBinary(db, blob.blob_id, bytes);
      }
    }).immediate();
  }
  const writerId = (
    db
      .prepare("SELECT writer_id FROM pdpp_installation_writer WHERE id = 1")
      .get() as { writer_id: string }
  ).writer_id;
  // Captured operations name the derived operation writer. Before the first
  // enable they name the installation writer and stay local: no receiver
  // accepts them, and enabling refuses a journal that has them.
  let journalObserver: (() => void) | undefined;
  const journal = createReplicationJournal(
    db,
    () => currentReplicaWriterIdentity(db)?.operationWriter ?? writerId,
    () => journalObserver?.(),
  );
  const insertLocalWrite = db.prepare(`
    INSERT INTO pdpp_replica_own_writes
      (operation_id, writer_id, source_id, connection_id, method, generation,
       stream, record_key, operation, value_json, blob_ids_json)
    VALUES (@operation_id, @writer_id, @source_id, @connection_id, @method, @generation,
            @stream, @record_key, @operation, @value_json, @blob_ids_json)
  `);
  let visibilityObserver: (() => void) | undefined;
  let writeBoundary: (<T>(write: () => T) => T) | undefined;
  let readBoundary: (<T>(read: () => T) => T) | undefined;
  let localWriteObserver:
    ((instance: string, stream: string, recordKey: string) => void) | undefined;
  // Keys written since the last settle. A TEMP table, so a rolled-back write
  // (at any transaction or savepoint depth) takes its queued key with it and is
  // never reconciled. It lives on this connection only and is not part of the
  // database file.
  db.exec(
    "CREATE TEMP TABLE IF NOT EXISTS pdpp_replica_unsettled_writes (instance TEXT NOT NULL, stream TEXT NOT NULL, record_key TEXT NOT NULL, PRIMARY KEY (instance, stream, record_key))",
  );
  const queueLocalWrite = db.prepare(
    "INSERT OR IGNORE INTO pdpp_replica_unsettled_writes VALUES (?, ?, ?)",
  );
  const takeLocalWrites = db.prepare(
    "DELETE FROM pdpp_replica_unsettled_writes RETURNING instance, stream, record_key",
  );

  function replicaIntegrityEpoch(connectionKey: string): number {
    return (
      db
        .prepare(
          `SELECT coalesce((SELECT fences FROM pdpp_replica_integrity_fences WHERE instance = ?), 0)
           + coalesce((SELECT reset_clock FROM pdpp_instance_binding WHERE instance = ?), 0) AS epoch`,
        )
        .get(connectionKey, connectionKey) as { epoch: number }
    ).epoch;
  }
  function replicaVisibilityEpoch(instanceIds?: string[]): string {
    if (instanceIds) {
      const ids = [...new Set(instanceIds)].sort();
      const state = ids.map((id) => [id, replicaIntegrityEpoch(id)]);
      return createHash("sha256").update(JSON.stringify(state)).digest("hex");
    }
    const exists = db
      .prepare(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='pdpp_replica_visibility_epoch'",
      )
      .get();
    if (!exists) return "uninitialized";
    const row = db
      .prepare("SELECT epoch FROM pdpp_replica_visibility_epoch WHERE id=1")
      .get() as { epoch: number } | undefined;
    return row ? String(row.epoch) : "uninitialized";
  }
  function fenceReplicaConnection(connectionKey: string): void {
    if (!db.inTransaction)
      throw new Error("an integrity fence requires the hiding transaction");
    db.prepare(
      "INSERT INTO pdpp_replica_integrity_fences VALUES (?, 1) ON CONFLICT(instance) DO UPDATE SET fences = fences + 1",
    ).run(connectionKey);
  }
  function cursorBinding(
    instanceIds: string[],
    fields: string[] | undefined,
  ): ReplicaCursorBinding {
    const ids = [...new Set(instanceIds)].sort();
    const integrity = Object.fromEntries(
      ids.map((id) => [id, replicaIntegrityEpoch(id)]),
    );
    return {
      query: createHash("sha256")
        .update(JSON.stringify([ids, fields ? [...fields].sort() : null]))
        .digest("hex"),
      integrity,
      visibilityEpoch: replicaVisibilityEpoch(ids),
    };
  }

  const port: ReplicaCanonicalPort = {
    unquarantinedRecordSql,
    replicaVisibilityEpoch,
    assertKeyWritable(instance, stream, recordKey) {
      if (
        db
          .prepare(
            "SELECT 1 FROM pdpp_replica_quarantined_keys q JOIN pdpp_instance_binding b ON q.instance = b.instance AND q.generation = b.generation WHERE q.instance = ? AND q.stream = ? AND q.record_key = ?",
          )
          .get(instance, stream, recordKey)
      )
        throw new PdppBindingError("replica_integrity_quarantine");
    },
    assertConnectionWritable(instance) {
      if (
        db
          .prepare(
            "SELECT 1 FROM pdpp_replica_quarantined_connections WHERE instance = ?",
          )
          .get(instance)
      )
        throw new PdppBindingError("replica_integrity_quarantine");
    },
    assertMethodTransitionAllowed() {
      if (db.prepare("SELECT 1 FROM pdpp_replica_settings").get())
        throw new PdppBindingError("replica_method_transition_unsupported");
    },
    assertStreamWritable(instance, stream, generation) {
      if (
        db
          .prepare(
            "SELECT 1 FROM pdpp_replica_quarantined_keys WHERE instance = ? AND stream = ? AND generation = ? LIMIT 1",
          )
          .get(instance, stream, generation)
      )
        throw new PdppBindingError("replica_integrity_quarantine");
    },
    recordWritten(instance, stream, recordKey, semantics, primaryKey, decl) {
      // Do not use getInstanceBinding's synthetic defaults for a missing legacy row.
      const binding = db
        .prepare(
          "SELECT source_id, method, generation FROM pdpp_instance_binding WHERE instance = ?",
        )
        .get(instance) as
        | {
            source_id: string | null;
            method: string | null;
            generation: number;
          }
        | undefined;
      const row = db
        .prepare(
          "SELECT * FROM pdpp_records WHERE instance = ? AND stream = ? AND record_key = ?",
        )
        .get(instance, stream, recordKey) as {
        version: number;
        data: string | null;
        emitted_at: string;
        deleted: number;
        deleted_at: string | null;
        blob_id: string | null;
      };
      const value = row.deleted
        ? {
            instance,
            stream,
            recordKey,
            version: row.version,
            deletedAt: row.deleted_at ?? row.emitted_at,
            emittedAt: row.emitted_at,
            deleted: true,
          }
        : {
            instance,
            stream,
            recordKey,
            data: row.data ? JSON.parse(row.data) : {},
            version: row.version,
            emittedAt: row.emitted_at,
            deleted: false,
          };
      const blobId = row.deleted ? null : row.blob_id;
      insertLocalWrite.run({
        operation_id: randomUUID(),
        writer_id: writerId,
        source_id: binding?.source_id ?? null,
        connection_id: instance,
        method: binding?.method ?? null,
        generation: binding?.generation ?? null,
        stream,
        record_key: recordKey,
        operation: row.deleted ? "delete" : "upsert",
        value_json: JSON.stringify(value),
        blob_ids_json: JSON.stringify(blobId ? [blobId] : []),
      });
      journal.captureRecord(
        instance,
        stream,
        recordKey,
        semantics,
        primaryKey,
        decl,
      );
      queueLocalWrite.run(instance, stream, recordKey);
      visibilityObserver?.();
    },
    settleLocalWrites() {
      const writes = takeLocalWrites.all() as {
        instance: string;
        stream: string;
        record_key: string;
      }[];
      for (const { instance, stream, record_key } of writes)
        localWriteObserver?.(instance, stream, record_key);
    },
    captureInvalidation: journal.captureInvalidation,
    captureCompletion: journal.captureCompletion,
    captureLifecycle: (instance, kind) =>
      journal.captureLifecycle(instance, kind),
    captureBlob: journal.captureBlob,
    notifyVisibility: () => visibilityObserver?.(),
    exclusive: (write) => {
      const captured = () => captureWrites(db, write);
      return writeBoundary
        ? writeBoundary(captured)
        : db.transaction(captured).immediate();
    },
    snapshot: (read) =>
      readBoundary ? readBoundary(read) : db.transaction(read).deferred(),
    cursorBinding,
    assertCursorIntegrity(payload, instanceIds, fields) {
      const current = cursorBinding(instanceIds, fields);
      if (payload.query !== undefined && payload.query !== current.query)
        throw new InvalidCursorError();
      if (
        payload.query === undefined ||
        JSON.stringify(payload.integrity) !==
          JSON.stringify(current.integrity) ||
        payload.visibilityEpoch !== current.visibilityEpoch
      )
        throw new CursorExpiredError();
    },
    blobBytes: {
      has: (blobId) =>
        db
          .prepare("SELECT 1 FROM pdpp_blob_bytes WHERE blob_id = ?")
          .get(blobId) !== undefined ||
        binaryLength(db, "canonical", blobId) !== undefined,
      // A forged or incomplete manifest cannot force a whole-value allocation.
      readVerified: (meta) => {
        const hasChunkCopy =
          db
            .prepare(
              "SELECT 1 FROM pdpp_binary_manifests WHERE namespace = 'canonical' AND blob_id = ?",
            )
            .get(meta.blobId) !== undefined;
        if (
          verifyBinary(
            db,
            "canonical",
            meta.blobId,
            `sha256:${meta.sha256}`,
            meta.sizeBytes,
          )
        ) {
          const chunked = readBinary(db, "canonical", meta.blobId);
          if (chunked) return chunked;
        }
        if (hasChunkCopy) return undefined;
        const row = db
          .prepare("SELECT bytes FROM pdpp_blob_bytes WHERE blob_id = ?")
          .get(meta.blobId) as { bytes: Buffer } | undefined;
        if (!row || row.bytes.length !== meta.sizeBytes) return undefined;
        const bytes = new Uint8Array(row.bytes);
        return createHash("sha256").update(bytes).digest("hex") === meta.sha256
          ? (bytes as Uint8Array<ArrayBuffer>)
          : undefined;
      },
      // A malformed manifest vetoes every reader; a blob write repairs it.
      clearMalformed: (blobId) =>
        clearMalformedManifest(db, "canonical", blobId),
      write: (blobId, bytes) => writeCanonicalBinary(db, blobId, bytes),
    },
  };

  return {
    port,
    writerId,
    exporter: journal.exporter as ReplicationExport,
    setReplicaVisibilityObserver(observer: () => void) {
      visibilityObserver = observer;
    },
    /** The visibility view's `exclusive` and `snapshot`: where canonical transactions begin. */
    setReplicaWriteBoundary(
      write: <T>(write: () => T) => T,
      read: <T>(read: () => T) => T,
    ) {
      writeBoundary = write;
      readBoundary = read;
    },
    /**
     * Called for each operation appended to the local journal (a record,
     * blob, completion or lifecycle write; never an import), inside the
     * write's transaction. The observer must defer its effect past the
     * transaction: a rolled-back write may still have called it.
     */
    setReplicaJournalObserver(observer: () => void) {
      journalObserver = observer;
    },
    /** Called for each locally written key when the store settles, inside the write's transaction. */
    setReplicaLocalWriteObserver(
      observer: (instance: string, stream: string, recordKey: string) => void,
    ) {
      localWriteObserver = observer;
    },
    replicaIntegrityEpoch,
    replicaVisibilityEpoch,
    fenceReplicaConnection,
    replicaBindingConflict(connectionId: string): boolean {
      return !!db
        .prepare(
          "SELECT 1 FROM pdpp_replica_binding_conflicts WHERE instance = ?",
        )
        .get(connectionId);
    },
    /**
     * Record that a connection's evidence disagrees with its binding. The
     * fact is append-only and puts the connection in the conflicted state
     * (the visibility view hides it from apps; the owner sees local rows),
     * and it raises the integrity epoch in the same transaction. Idempotent:
     * returns true only when this call recorded it.
     */
    markReplicaBindingConflict(input: {
      connectionId: string;
      reason: "source_binding_conflict" | "local_mapping_conflict";
      evidence: unknown;
    }): boolean {
      return db.transaction(() => {
        const recorded =
          db
            .prepare(
              "INSERT OR IGNORE INTO pdpp_replica_binding_conflicts VALUES (?, ?, ?)",
            )
            .run(
              input.connectionId,
              input.reason,
              JSON.stringify(input.evidence),
            ).changes > 0;
        if (!recorded) return false;
        fenceReplicaConnection(input.connectionId);
        return true;
      })();
    },
    cursorBinding,
  };
}

/**
 * The canonical store with replication enabled: replica schema applied,
 * captures, quarantine guards and integrity-bound cursors on. Only the
 * replication composition and replica tests construct it.
 */
export function createReplicaRecordStore(
  db: Database,
  options: Omit<SqliteRecordStoreOptions, "replica"> = {},
) {
  let replica: ReturnType<typeof createReplicaCanonicalPort> | undefined;
  const store = createSqliteRecordStore(db, {
    ...options,
    replica: () => (replica = createReplicaCanonicalPort(db)).port,
  });
  const r = replica!;
  return Object.assign(store, {
    unquarantinedRecordSql,
    replication: r.exporter,
    getInstallationWriterId: () => r.writerId,
    setReplicaVisibilityObserver: r.setReplicaVisibilityObserver,
    setReplicaWriteBoundary: r.setReplicaWriteBoundary,
    setReplicaLocalWriteObserver: r.setReplicaLocalWriteObserver,
    setReplicaJournalObserver: r.setReplicaJournalObserver,
    replicaIntegrityEpoch: r.replicaIntegrityEpoch,
    replicaVisibilityEpoch: r.replicaVisibilityEpoch,
    fenceReplicaConnection: r.fenceReplicaConnection,
    replicaBindingConflict: r.replicaBindingConflict,
    markReplicaBindingConflict: r.markReplicaBindingConflict,
    cursorBinding: r.cursorBinding,
  });
}

export type ReplicaRecordStore = ReturnType<typeof createReplicaRecordStore>;
