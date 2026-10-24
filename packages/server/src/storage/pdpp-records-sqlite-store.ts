import { RECEIVER_MIGRATION } from "./pdpp-replication-receiver.js";
import {
  parseTime,
  timeSortKey,
} from "@opendatalabs/personal-server-ts-core/pdpp";
import {
  createMemorySyncStateStore,
  decodeCursor,
  decodeListCursor,
  encodeCursor,
  listSnapshotPage,
  LIST_ORDER_COLUMNS,
  compareRecordIdentity,
  InvalidCursorSyntaxError,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import type { DataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import type { Database } from "better-sqlite3";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import {
  createReplicationJournal,
  REPLICATION_MIGRATION,
  type ReplicationExport,
} from "./pdpp-replication-sqlite.js";
import {
  encodeRecordKey,
  planIngest,
  RecordKeyError,
  summarizeIngest,
  CursorExpiredError,
  InvalidCursorError,
  BlobConflictError,
  type PdppRecordStore,
  type CanonicalMutation,
  type MutationJournalReader,
  type MutationJournalPageOptions,
  type MutationJournalPage,
  type ChangesSinceOptions,
  type ChangesSincePage,
  type IngestOutcome,
  type IngestResult,
  type ListRecordsOptions,
  type ListRecordsPage,
  type PdppBlobMeta,
  type PdppRecordEnvelopeInput,
  type PdppRecordRow,
  type PdppStoredRecord,
  type RecordDataValidator,
  type StreamListing,
  type StreamSemantics,
  type SyncBudget,
  type SyncPreparationRequest,
  type SyncPreparationResult,
  type SyncStateStore,
  type SyncTokenScope,
  type SyncWindow,
  type RecordIdentity,
  type SyncWindowChange,
  type SyncWindowRequest,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import {
  isCompletionTime,
  liveSnapshotDigest,
  parseCompletionRequest,
  StreamCompletionError,
  type NativeStreamCompletionReceipt,
  type StreamCompletionRequest,
  type StreamDeclarationResolver,
} from "./pdpp-stream-completion.js";

export {
  StreamCompletionError,
  type NativeStreamCompletionReceipt,
  type StreamCompletionFailure,
  type StreamCompletionProof,
  type StreamCompletionRequest,
  type StreamDeclarationResolver,
} from "./pdpp-stream-completion.js";

export interface PdppInstanceBinding {
  instance: string;
  sourceId: string | null;
  label: string;
  deletedAt: string | null;
  method: string | null;
  generation: number;
  resetClock: number;
  empty?: boolean;
}

export interface ClaudeTransition {
  instance: string;
  archiveInstance: string;
  conversationsCovered: boolean;
  generation: number;
  snapshots: Partial<
    Record<"claude.conversations" | "claude.projects", DataFileEnvelope>
  >;
}

export interface ClaudeTransitionInput {
  instance: string;
  expectedGeneration: number;
  expectedWriteClock: number;
  snapshots: ClaudeTransition["snapshots"];
}

/** Outcome of a P7 stream replace. `applied: false` means nothing was written. */
export interface ReplaceStreamResult extends IngestResult {
  applied: boolean;
  /** Live keys tombstoned because the snapshot lacked them. */
  deleted: number;
}

/** One P7 completion receipt, see migration v7. */
export interface StreamCompletionReceipt {
  instance: string;
  stream: string;
  method: string;
  generation: number;
  sourceCollectedAt: string;
  /** Write clock value when the replace committed. */
  writeSeq: number;
  liveCount: number;
}

/** Compatibility export; the portable temporal policy owns RFC3339 validity. */
export function isRfc3339DateTime(value: unknown): value is string {
  return parseTime(value, "date-time") !== null;
}

export class PdppBindingError extends Error {
  constructor(public readonly reason: string) {
    super(reason);
  }
}

function blobIdForBytes(bytes: Uint8Array): string {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

/**
 * Schema migrations for the desktop SQLite backend of the PDPP record
 * persistence index, applied in order and tracked in `pdpp_schema_version`
 * so re-opening an existing database never re-runs or reinterprets an
 * already-applied migration (C7: "no schema version, no ALTER path").
 *
 * `pdpp_records` holds current state (one row per instance+stream+record_key).
 * `pdpp_record_changes` holds full version history for mutable_state streams
 * (append_only streams only ever have one history row per key, at version 1,
 * since duplicates are no-ops). `pdpp_blobs` holds blob metadata,
 * `pdpp_blob_bytes` holds bytes, and `pdpp_blob_claims` ties pending uploads
 * to an instance generation.
 */
const MIGRATIONS: string[] = [
  // v1: initial schema.
  `
CREATE TABLE IF NOT EXISTS pdpp_records (
  instance TEXT NOT NULL,
  stream TEXT NOT NULL,
  record_key TEXT NOT NULL,
  data TEXT, -- JSON; NULL when deleted = 1
  version INTEGER NOT NULL,
  emitted_at TEXT NOT NULL,
  deleted INTEGER NOT NULL DEFAULT 0,
  deleted_at TEXT,
  PRIMARY KEY (instance, stream, record_key)
);

CREATE TABLE IF NOT EXISTS pdpp_record_changes (
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
);

CREATE INDEX IF NOT EXISTS idx_pdpp_record_changes_lookup
  ON pdpp_record_changes (instance, stream, record_key, version);

CREATE INDEX IF NOT EXISTS idx_pdpp_record_changes_horizon
  ON pdpp_record_changes (stream, instance, written_at);

CREATE INDEX IF NOT EXISTS idx_pdpp_records_stream
  ON pdpp_records (stream, instance, emitted_at);

CREATE TABLE IF NOT EXISTS pdpp_blobs (
  blob_id TEXT PRIMARY KEY,
  mime_type TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  sha256 TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS pdpp_write_clock (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  value INTEGER NOT NULL
);
INSERT OR IGNORE INTO pdpp_write_clock (id, value) VALUES (1, 0);
`,
  // v2: blob_ref reverse index (C2 fix — blob authorization must be able to
  // find the record that references a blob_id, not trust field-name
  // presence alone). Extracted from data.blob_ref.blob_id at write time so
  // lookup is an indexed column read, not a per-request JSON scan.
  `
ALTER TABLE pdpp_records ADD COLUMN blob_id TEXT;

CREATE INDEX IF NOT EXISTS idx_pdpp_records_blob_id
  ON pdpp_records (blob_id);
`,
  // v3: actual blob byte storage, separate from `pdpp_blobs` metadata so an
  // existing metadata-only row (legacy fixture, or a blob whose bytes were
  // never ingested by this store) is untouched by this migration and simply
  // has no matching pdpp_blob_bytes row -- getBlobBytes reports that as
  // "unavailable", not as corruption.
  `
CREATE TABLE IF NOT EXISTS pdpp_blob_bytes (
  blob_id TEXT PRIMARY KEY REFERENCES pdpp_blobs (blob_id),
  bytes BLOB NOT NULL
);
`,
  // v4: persist the method generation and generation-scoped blob claims.
  // Existing instances remain unbound until their owner resets them.
  `
CREATE TABLE IF NOT EXISTS pdpp_instance_binding (
  instance TEXT PRIMARY KEY,
  method TEXT,
  generation INTEGER NOT NULL CHECK (generation > 0),
  reset_clock INTEGER NOT NULL DEFAULT 0
);

INSERT OR IGNORE INTO pdpp_instance_binding (instance, method, generation, reset_clock)
SELECT DISTINCT instance, NULL, 1, 0 FROM pdpp_records;

CREATE TABLE IF NOT EXISTS pdpp_blob_claims (
  blob_id TEXT NOT NULL REFERENCES pdpp_blobs (blob_id),
  instance TEXT NOT NULL,
  generation INTEGER NOT NULL,
  PRIMARY KEY (blob_id, instance)
);

INSERT OR IGNORE INTO pdpp_blob_claims (blob_id, instance, generation)
SELECT DISTINCT r.blob_id, r.instance, b.generation
FROM pdpp_records r
JOIN pdpp_instance_binding b ON b.instance = r.instance
JOIN pdpp_blobs m ON m.blob_id = r.blob_id
WHERE r.blob_id IS NOT NULL AND r.deleted = 0;
`,
  // v5: database epoch for opaque cursor binding. Tokens from a different
  // records DB, a rebuilt records DB, or a pre-epoch implementation expire
  // instead of being interpreted against this store.
  `
CREATE TABLE IF NOT EXISTS pdpp_store_metadata (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  epoch TEXT NOT NULL
);
`,
  // v6: the instance handle is also the connection id. Keep its source,
  // owner-facing label, and deletion tombstone on the existing binding row.
  `
ALTER TABLE pdpp_instance_binding ADD COLUMN source_id TEXT;
ALTER TABLE pdpp_instance_binding ADD COLUMN label TEXT NOT NULL DEFAULT '';
ALTER TABLE pdpp_instance_binding ADD COLUMN deleted_at TEXT;
`,
  // v7: completion evidence for P7. A row says the stream's current live set
  // is exactly what one full replace by `method` in `generation` delivered,
  // collected at the producer's `source_collected_at`. Only `replaceStream`
  // writes it; any other write to the stream deletes it.
  `
CREATE TABLE IF NOT EXISTS pdpp_stream_completion (
  instance TEXT NOT NULL,
  stream TEXT NOT NULL,
  method TEXT NOT NULL,
  generation INTEGER NOT NULL,
  source_collected_at TEXT NOT NULL,
  write_seq INTEGER NOT NULL,
  live_count INTEGER NOT NULL,
  PRIMARY KEY (instance, stream)
);
`,
  // v8: arrival order for the legacy view. Desktop served a stream in the
  // order each live key last arrived, and an unchanged re-delivery moved a
  // key to the end without a new version. A row holds the latest arrival of
  // one live key in the generation that wrote it. It is not record state:
  // no version, emitted_at, history row or write clock moves with it. Rows
  // stored before v8 have none, and none is guessed for them.
  `
CREATE TABLE IF NOT EXISTS pdpp_record_arrival (
  instance TEXT NOT NULL,
  stream TEXT NOT NULL,
  record_key TEXT NOT NULL,
  generation INTEGER NOT NULL,
  arrival INTEGER NOT NULL,
  PRIMARY KEY (instance, stream, record_key)
);

CREATE INDEX IF NOT EXISTS idx_pdpp_record_arrival_order
  ON pdpp_record_arrival (instance, stream, arrival);
`,
  // v9: native completion receipts (completeStreams). A receipt may now carry
  // the digest of the live set it describes and how its time was taken. Both
  // are null on every receipt P7 writes and on every receipt stored before
  // v9, which stay producer-asserted and are never relabeled. The columns are
  // added by `addCompletionProofColumns`, which keeps one that already exists
  // only if it is a compatible nullable TEXT column, so a database whose
  // version was only rewound can be upgraded again.
  "",
  // v10: cover the stream-summary query so it need not visit JSON record rows.
  `
CREATE INDEX IF NOT EXISTS idx_pdpp_records_live_instance_stream_emitted_at
  ON pdpp_records (instance, stream, emitted_at)
  WHERE deleted = 0;
`,
  // v11: monotonic cursor for arrival-only ordering changes in the legacy view.
  `
CREATE TABLE IF NOT EXISTS pdpp_record_arrival_clock (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  value INTEGER NOT NULL
);
INSERT OR IGNORE INTO pdpp_record_arrival_clock (id, value) VALUES (1, 0);
`,
  // v12: ordered history traversal and one-key as-of lookup. The horizon
  // index alone scans an instance's full history for every outer row.
  `
CREATE INDEX IF NOT EXISTS idx_pdpp_record_changes_snapshot_order
  ON pdpp_record_changes (stream, emitted_at, record_key, instance, written_at);
CREATE INDEX IF NOT EXISTS idx_pdpp_record_changes_snapshot_latest
  ON pdpp_record_changes (instance, stream, record_key, written_at DESC, version DESC);
`,
  // v13: an `emitted_key` that orders emitted time by instant rather than by
  // timestamp text, for list order, list seeks and the latest stream time.
  // `migrateToV13` applies it.
  "",
  // v14: the secret that seals sync tokens, beside the epoch so a rebuilt
  // records DB expires every token the old one issued, and the
  // identity-ordered history index sync pages seek in. It also rebuilds the
  // live summary index an earlier v13 left without `emitted_at`, and adds
  // the table that holds sync session state behind opaque handles.
  // `migrateToV14` applies it.
  "",
  // v14: one recoverable export-to-live transition per Claude connection.
  `CREATE TABLE IF NOT EXISTS pdpp_claude_transition (
    instance TEXT PRIMARY KEY,
    archive_instance TEXT NOT NULL UNIQUE,
    generation INTEGER NOT NULL,
    snapshots_json TEXT NOT NULL,
    conversations_covered INTEGER NOT NULL DEFAULT 0
  );`,
  // v15: retained-history blob-reference index from main (#472).
  `CREATE INDEX IF NOT EXISTS idx_pdpp_record_changes_blob_ref
    ON pdpp_record_changes (CAST(CASE WHEN json_valid(data) THEN json_extract(data, '$.blob_ref.blob_id') END AS TEXT));`,
  // v16: sync session state behind opaque handles (`sync-session.ts`).
  `
CREATE TABLE IF NOT EXISTS pdpp_sync_state (
  id TEXT PRIMARY KEY,
  owner TEXT NOT NULL,
  state TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pdpp_sync_state_owner
  ON pdpp_sync_state (owner);
CREATE INDEX IF NOT EXISTS idx_pdpp_sync_state_expires
  ON pdpp_sync_state (expires_at);
`,
  // v17: bounded sync work. A session's prepared candidate set, walked by
  // key, and an index of deletions alone for the deletion-after-horizon test.
  `
CREATE TABLE IF NOT EXISTS pdpp_sync_preparation (
  id TEXT PRIMARY KEY,
  owner TEXT NOT NULL,
  high INTEGER NOT NULL,
  rows INTEGER NOT NULL DEFAULT 0,
  done INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pdpp_sync_preparation_owner
  ON pdpp_sync_preparation (owner, expires_at);
CREATE INDEX IF NOT EXISTS idx_pdpp_sync_preparation_expires
  ON pdpp_sync_preparation (expires_at);
CREATE TABLE IF NOT EXISTS pdpp_sync_candidate (
  preparation TEXT NOT NULL,
  record_key TEXT NOT NULL,
  instance TEXT NOT NULL,
  PRIMARY KEY (preparation, record_key, instance)
);
CREATE INDEX IF NOT EXISTS idx_pdpp_record_changes_deleted
  ON pdpp_record_changes (instance, stream, record_key, written_at)
  WHERE deleted = 1;
`,
  // v18: a preparation keeps its own progress, written with its candidates.
  // Every sync session walks its candidate set, so the v14 identity index
  // has no reader left and is dropped.
  // `migrateToV17` applies it.
  "",
  // v19: append-only canonical mutation journal for replication.
  `
CREATE TABLE IF NOT EXISTS pdpp_installation_writer (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  writer_id TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS pdpp_mutation_journal (
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
CREATE TRIGGER IF NOT EXISTS pdpp_mutation_journal_no_replace BEFORE INSERT ON pdpp_mutation_journal
WHEN EXISTS (SELECT 1 FROM pdpp_mutation_journal
             WHERE sequence = NEW.sequence OR operation_id = NEW.operation_id)
BEGIN SELECT RAISE(ABORT, 'mutation journal is append-only'); END;
CREATE TRIGGER IF NOT EXISTS pdpp_mutation_journal_no_update BEFORE UPDATE ON pdpp_mutation_journal
BEGIN SELECT RAISE(ABORT, 'mutation journal is append-only'); END;
CREATE TRIGGER IF NOT EXISTS pdpp_mutation_journal_no_delete BEFORE DELETE ON pdpp_mutation_journal
BEGIN SELECT RAISE(ABORT, 'mutation journal is append-only'); END;
`,
  REPLICATION_MIGRATION,
  RECEIVER_MIGRATION,
  // v22: cover replica-aware stream summaries, including the quarantine key.
  `
DROP INDEX IF EXISTS idx_pdpp_records_live_instance_stream_emitted_key;
CREATE INDEX idx_pdpp_records_live_instance_stream_emitted_key
  ON pdpp_records (instance, stream, emitted_key, emitted_at, record_key)
  WHERE deleted = 0;
`,
];

function addCompletionProofColumns(db: Database): void {
  // `table_xinfo`, unlike `table_info`, also lists generated columns.
  const existing = new Map(
    (
      db.prepare("PRAGMA table_xinfo(pdpp_stream_completion)").all() as {
        name: string;
        type: string;
        notnull: number;
        dflt_value: string | null;
        pk: number;
        hidden: number;
      }[]
    ).map((column) => [column.name, column]),
  );
  for (const name of ["snapshot_sha256", "collection_time_basis"]) {
    const column = existing.get(name);
    if (!column) {
      db.exec(`ALTER TABLE pdpp_stream_completion ADD COLUMN ${name} TEXT`);
    } else if (
      column.type.toUpperCase() !== "TEXT" ||
      column.notnull !== 0 ||
      column.dflt_value !== null ||
      column.pk !== 0 ||
      column.hidden !== 0
    ) {
      throw new Error(
        `pdpp_stream_completion.${name} exists with an incompatible definition; v9 needs a nullable TEXT column with no default. Refusing to open.`,
      );
    }
  }
}

/** `emitted_key` is `timeSortKey(emitted_at)`, written by SQL on every insert. */
function registerTimeKey(db: Database): void {
  db.function("pdpp_time_key", { deterministic: true }, (value: unknown) =>
    timeSortKey(String(value)),
  );
}

function migrateToV13(db: Database): void {
  for (const table of ["pdpp_records", "pdpp_record_changes"]) {
    const columns = db.prepare(`PRAGMA table_info(${table})`).all() as {
      name: string;
    }[];
    if (!columns.some((c) => c.name === "emitted_key")) {
      db.exec(`ALTER TABLE ${table} ADD COLUMN emitted_key TEXT`);
    }
    db.exec(
      `UPDATE ${table} SET emitted_key = pdpp_time_key(emitted_at) WHERE emitted_key IS NULL`,
    );
  }
  db.exec(`
DROP INDEX IF EXISTS idx_pdpp_record_changes_snapshot_order;
CREATE INDEX IF NOT EXISTS idx_pdpp_record_changes_snapshot_key_order
  ON pdpp_record_changes (stream, emitted_key, record_key, instance, written_at);
CREATE INDEX IF NOT EXISTS idx_pdpp_records_live_instance_stream_emitted_key
  ON pdpp_records (instance, stream, emitted_key, emitted_at)
  WHERE deleted = 0;
`);
}

/** Sync session state behind opaque handles (`sync-session.ts`). */
function sqliteSyncStates(db: Database): SyncStateStore {
  const put = db.prepare(`INSERT OR REPLACE INTO pdpp_sync_state
    (id, owner, state, expires_at) VALUES (?, ?, ?, ?)`);
  // Bounded per write: a backlog of expired states drains over later writes.
  const dropExpired = db.prepare(`DELETE FROM pdpp_sync_state WHERE rowid IN (
    SELECT rowid FROM pdpp_sync_state INDEXED BY idx_pdpp_sync_state_expires
    WHERE expires_at <= ? LIMIT 100)`);
  // rowid grows with each insert or replace, so it orders states by age.
  const evict = db.prepare(`DELETE FROM pdpp_sync_state WHERE rowid IN (
    SELECT rowid FROM pdpp_sync_state WHERE owner = ?
    ORDER BY rowid DESC LIMIT -1 OFFSET ?)`);
  const get = db.prepare(
    "SELECT state FROM pdpp_sync_state WHERE id = ? AND expires_at > ?",
  );
  const del = db.prepare("DELETE FROM pdpp_sync_state WHERE id = ?");
  const delIf = db.prepare(
    "DELETE FROM pdpp_sync_state WHERE id = ? AND state = ?",
  );
  const putTx = db.transaction(
    (entry: Parameters<SyncStateStore["put"]>[0]): boolean => {
      if (entry.expect !== undefined) {
        const current =
          (get.get(entry.id, entry.now) as { state: string } | undefined)
            ?.state ?? null;
        if (current !== entry.expect) return false;
      }
      put.run(entry.id, entry.owner, entry.state, entry.expiresAt);
      dropExpired.run(entry.now);
      evict.run(entry.owner, entry.maxPerOwner);
      return true;
    },
  );
  return {
    // IMMEDIATE takes the write lock before the compare, so another
    // connection cannot change the state between the compare and the write.
    put: (entry) => putTx.immediate(entry),
    get: (id, now) =>
      (get.get(id, now) as { state: string } | undefined)?.state,
    delete: (id, expected) =>
      void (expected === undefined ? del.run(id) : delIf.run(id, expected)),
  };
}

function migrateToV14(db: Database): void {
  const columns = db
    .prepare("PRAGMA table_info(pdpp_store_metadata)")
    .all() as { name: string }[];
  if (!columns.some((c) => c.name === "sync_token_key")) {
    db.exec("ALTER TABLE pdpp_store_metadata ADD COLUMN sync_token_key TEXT");
  }
  db.prepare(
    "UPDATE pdpp_store_metadata SET sync_token_key = ? WHERE id = 1 AND sync_token_key IS NULL",
  ).run(randomBytes(32).toString("base64"));
  // An earlier v13 built the live summary index without `emitted_at`, so
  // rebuild it as the covering index v13 now creates.
  db.exec(`
CREATE INDEX IF NOT EXISTS idx_pdpp_record_changes_sync_identity
  ON pdpp_record_changes (stream, record_key, instance, written_at);
DROP INDEX IF EXISTS idx_pdpp_records_live_instance_stream_emitted_key;
CREATE INDEX idx_pdpp_records_live_instance_stream_emitted_key
  ON pdpp_records (instance, stream, emitted_key, emitted_at)
  WHERE deleted = 0;
CREATE TABLE IF NOT EXISTS pdpp_sync_state (
  id TEXT PRIMARY KEY,
  owner TEXT NOT NULL,
  state TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pdpp_sync_state_owner
  ON pdpp_sync_state (owner);
CREATE INDEX IF NOT EXISTS idx_pdpp_sync_state_expires
  ON pdpp_sync_state (expires_at);
`);
}

function migrateToV17(db: Database): void {
  const columns = db
    .prepare("PRAGMA table_info(pdpp_sync_preparation)")
    .all() as { name: string }[];
  if (!columns.some((c) => c.name === "cursor_instance")) {
    db.exec(
      "ALTER TABLE pdpp_sync_preparation ADD COLUMN cursor_instance INTEGER NOT NULL DEFAULT 0",
    );
  }
  if (!columns.some((c) => c.name === "cursor_written")) {
    db.exec(
      "ALTER TABLE pdpp_sync_preparation ADD COLUMN cursor_written INTEGER",
    );
  }
  db.exec("DROP INDEX IF EXISTS idx_pdpp_record_changes_sync_identity");
}

function migrate(db: Database): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS pdpp_schema_version (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      version INTEGER NOT NULL
    );
    INSERT OR IGNORE INTO pdpp_schema_version (id, version) VALUES (1, 0);
  `);
  const current = db
    .prepare("SELECT version FROM pdpp_schema_version WHERE id = 1")
    .get() as { version: number };

  const applyFrom = db.transaction((fromVersion: number) => {
    for (let v = fromVersion; v < MIGRATIONS.length; v++) {
      db.exec(MIGRATIONS[v]);
      if (v === 8) addCompletionProofColumns(db);
      if (v === 4) {
        db.prepare(
          "INSERT OR IGNORE INTO pdpp_store_metadata (id, epoch) VALUES (1, ?)",
        ).run(randomUUID());
      }
      if (v === 12) migrateToV13(db);
      if (v === 13) migrateToV14(db);
      if (v === 17) migrateToV17(db);
      if (v === 19) {
        db.prepare(
          "INSERT OR IGNORE INTO pdpp_installation_writer (id, writer_id) VALUES (1, ?)",
        ).run(randomUUID());
      }
    }
    db.prepare("UPDATE pdpp_schema_version SET version = ? WHERE id = 1").run(
      MIGRATIONS.length,
    );
  });

  if (current.version < MIGRATIONS.length) {
    applyFrom(current.version);
  } else if (current.version > MIGRATIONS.length) {
    // A newer schema version than this code knows how to read. Refuse to
    // guess at compatibility rather than silently reinterpreting unknown
    // state (matches the AS store's UnsupportedAuthStateError precedent).
    throw new Error(
      `pdpp_records database schema version ${current.version} is newer than this build supports (${MIGRATIONS.length}). Refusing to open — upgrade this build before opening this database.`,
    );
  }
}

function sweepStaleBlobClaims(db: Database): void {
  db.transaction(() => {
    // A Claude transition archive is retained history, not a registered
    // instance: it has no binding row, so only the transition ledger vouches
    // for its claims. Erasing the connection drops the ledger row and claims.
    db.exec(`
      DELETE FROM pdpp_blob_claims
      WHERE NOT EXISTS (
        SELECT 1 FROM pdpp_instance_binding b
        WHERE b.instance = pdpp_blob_claims.instance
          AND b.generation = pdpp_blob_claims.generation
      )
      AND NOT EXISTS (
        SELECT 1 FROM pdpp_claude_transition t
        WHERE t.archive_instance = pdpp_blob_claims.instance
      );
    `);
    collectStartupUnclaimedBlobs(db);
  })();
}

/**
 * Automatic (startup) blob collection. A history row whose JSON cannot be
 * parsed may reference any blob, so collection is skipped while one exists.
 * Explicit owner erasure calls `deleteUnclaimedBlobs` directly and is not
 * gated here.
 */
function collectStartupUnclaimedBlobs(db: Database): void {
  const { found } = db
    .prepare(
      "SELECT EXISTS (SELECT 1 FROM pdpp_record_changes WHERE NOT json_valid(data)) AS found",
    )
    .get() as { found: number };
  if (found === 1) {
    const { count } = db
      .prepare(
        "SELECT COUNT(*) AS count FROM pdpp_record_changes WHERE NOT json_valid(data)",
      )
      .get() as { count: number };
    console.warn(
      `[pdpp-records] skipped startup blob collection: ${count} history row(s) hold invalid JSON, so their blob references cannot be read`,
    );
    return;
  }
  deleteUnclaimedBlobs(db);
}

/**
 * `NOT EXISTS` predicate: no retained history row references `blobId`.
 * The expression must match the v15 index `idx_pdpp_record_changes_blob_ref`
 * exactly, so the planner searches by blob id rather than scanning history.
 */
export function noRetainedHistoryReferenceSql(blobId: string): string {
  return `NOT EXISTS (SELECT 1 FROM pdpp_record_changes WHERE CAST(CASE WHEN json_valid(data) THEN json_extract(data, '$.blob_ref.blob_id') END AS TEXT) = ${blobId})`;
}

function deleteUnclaimedBlobs(db: Database): void {
  // Claims reconstructed by v4 only cover current records. Retained history
  // independently owns its bytes, even after overwrite or tombstone. Explicit
  // owner erasure removes that history before calling this collector.
  db.exec(`
    DELETE FROM pdpp_blob_bytes
    WHERE blob_id IN (
      SELECT blob_id FROM pdpp_blobs b
      WHERE NOT EXISTS (SELECT 1 FROM pdpp_blob_claims c WHERE c.blob_id = b.blob_id)
        AND NOT EXISTS (SELECT 1 FROM pdpp_records r WHERE r.blob_id = b.blob_id AND r.deleted = 0)
        AND ${noRetainedHistoryReferenceSql("b.blob_id")}
    );
    DELETE FROM pdpp_blobs
    WHERE NOT EXISTS (SELECT 1 FROM pdpp_blob_claims c WHERE c.blob_id = pdpp_blobs.blob_id)
      AND NOT EXISTS (SELECT 1 FROM pdpp_records r WHERE r.blob_id = pdpp_blobs.blob_id AND r.deleted = 0)
      AND ${noRetainedHistoryReferenceSql("pdpp_blobs.blob_id")};
  `);
}

interface BindingRowDb {
  instance: string;
  source_id: string | null;
  label: string;
  deleted_at: string | null;
  method: string | null;
  generation: number;
  reset_clock: number;
}

function toBinding(row: BindingRowDb): PdppInstanceBinding {
  return {
    instance: row.instance,
    sourceId: row.source_id,
    label: row.label,
    deletedAt: row.deleted_at,
    method: row.method,
    generation: row.generation,
    resetClock: row.reset_clock,
  };
}

function ensureBinding(db: Database, instance: string): BindingRowDb {
  db.prepare(
    "INSERT OR IGNORE INTO pdpp_instance_binding (instance, method, generation, reset_clock) VALUES (?, NULL, 1, 0)",
  ).run(instance);
  return db
    .prepare("SELECT * FROM pdpp_instance_binding WHERE instance = ?")
    .get(instance) as BindingRowDb;
}

// A horizon that is not a non-negative integer would compare false against
// every reset_clock and pass the P10c fence, so it is refused.
function parseHorizon(value: unknown): number {
  const horizon = Number(value);
  if (!/^\d+$/.test(String(value)) || !Number.isSafeInteger(horizon)) {
    throw new InvalidCursorError();
  }
  return horizon;
}

function parseOffset(value: unknown): number {
  const offset = Number(value);
  if (!/^(0|[1-9]\d*)$/.test(String(value)) || !Number.isSafeInteger(offset)) {
    throw new InvalidCursorError();
  }
  return offset;
}

function instanceHasRecords(db: Database, instance: string): boolean {
  const row = db
    .prepare(
      `SELECT EXISTS(SELECT 1 FROM pdpp_records WHERE instance = ?)
        OR EXISTS(SELECT 1 FROM pdpp_record_changes WHERE instance = ?) AS has_records`,
    )
    .get(instance, instance) as { has_records: number };
  return row.has_records === 1;
}

function extractBlobId(data: Record<string, unknown> | null): string | null {
  if (!data) return null;
  const blobRef = data.blob_ref as { blob_id?: unknown } | undefined;
  if (
    blobRef &&
    typeof blobRef === "object" &&
    typeof blobRef.blob_id === "string"
  ) {
    return blobRef.blob_id;
  }
  return null;
}

interface RecordRowDb {
  instance: string;
  stream: string;
  record_key: string;
  data: string | null;
  version: number;
  emitted_at: string;
  deleted: number;
  deleted_at: string | null;
}

function toRow(db: RecordRowDb): PdppRecordRow {
  if (db.deleted) {
    return {
      instance: db.instance,
      stream: db.stream,
      recordKey: db.record_key,
      version: db.version,
      deletedAt: db.deleted_at ?? db.emitted_at,
      emittedAt: db.emitted_at,
      deleted: true,
    };
  }
  return {
    instance: db.instance,
    stream: db.stream,
    recordKey: db.record_key,
    data: db.data ? JSON.parse(db.data) : {},
    version: db.version,
    emittedAt: db.emitted_at,
    deleted: false,
  };
}

/**
 * SQLite-backed PdppRecordStore for desktop persistence. Requires
 * `better-sqlite3` (already a `packages/server` dependency in this repo).
 * A readonly database must already have the current schema; no migration,
 * journal-mode change or stale-blob sweep runs. SQLite rejects write methods.
 */
// Shared read predicate for canonical, replica-preview, and known-local projections.
function unquarantinedRecordSql(alias: string): string {
  return `NOT EXISTS (SELECT 1 FROM pdpp_replica_quarantined_connections q WHERE q.instance = ${alias}.instance) AND NOT EXISTS (SELECT 1 FROM pdpp_replica_quarantined_keys q JOIN pdpp_instance_binding b ON b.instance=q.instance AND b.generation=q.generation WHERE q.instance=${alias}.instance AND q.stream=${alias}.stream AND q.record_key=${alias}.record_key)`;
}

export function createSqliteRecordStore(db: Database): PdppRecordStore &
  MutationJournalReader & {
    /** Internal synchronous observer, called after journal capture in the write transaction. */
    setReplicaVisibilityObserver(observer: () => void): void;
    unquarantinedRecordSql(alias: string): string;
    changesSince(
      stream: string,
      options: ChangesSinceOptions,
    ): ChangesSincePage;
    changesSinceForInstances(
      stream: string,
      options: ChangesSinceOptions,
      visibleInstanceIds: string[],
    ): ChangesSincePage;
    changesSince(
      stream: string,
      options: ChangesSinceOptions,
    ): ChangesSincePage;
    changesSinceForInstances(
      stream: string,
      options: ChangesSinceOptions,
      visibleInstanceIds: string[],
    ): ChangesSincePage;
    replication: ReplicationExport;
    transitionClaudeToLive(input: ClaudeTransitionInput): PdppInstanceBinding;
    claudeTransition(instance: string): ClaudeTransition | null;
    listClaudeTransitions(): ClaudeTransition[];
    clearClaudeTransitionScope(scope: string): void;
    confirmClaudeTransition(instance: string, generation: number): void;
    transitionWriteClock(): number;
    listConnections(sourceId: string): PdppInstanceBinding[];
    registerConnection(input: {
      instance: string;
      sourceId: string;
      method: string;
      label: string;
    }): PdppInstanceBinding;
    deleteConnection(instance: string): PdppInstanceBinding;
    getInstanceBinding(instance: string): PdppInstanceBinding;
    /**
     * Run synchronous reads against one SQLite read snapshot. A write from any
     * connection that commits while `read` runs stays invisible to it, so the
     * bindings, listings and pages it sees belong to one point in time.
     */
    readSnapshot<T>(read: () => T): T;
    resetInstanceBinding(input: {
      instance: string;
      expectedMethod: string | null;
      expectedGeneration: number;
      nextMethod: string | null;
    }): { binding: PdppInstanceBinding; alreadyReset: boolean };
    storeBlobBytesForInstance(input: {
      instance: string;
      method: string;
      generation: number;
      bytes: Uint8Array;
      mimeType: string;
    }): PdppBlobMeta;
    replaceStream(input: {
      instance: string;
      stream: string;
      method: string;
      generation: number;
      emittedAt: string;
      envelopes: PdppRecordEnvelopeInput[];
      primaryKey: string[];
      validateData?: RecordDataValidator;
      sourceCollectedAt?: string;
      completionPolicy?: "preserve_if_unchanged";
    }): ReplaceStreamResult;
    /** Completion receipts of one instance, as stored. */
    listStreamCompletions(instance: string): StreamCompletionReceipt[];
    /**
     * Metadata-only completion: proves, for each requested stream, that the
     * live set SQLite holds is exactly the one the digest names, then stores
     * every receipt in one immediate transaction. It writes no rows, history,
     * arrival or clock. The binding must already be registered, undeleted and
     * equal to the request's source, method and generation; nothing is
     * registered here. The caller is not authenticated at this seam.
     * Throws `PdppBindingError` for the binding and `StreamCompletionError`
     * for a malformed request, declaration, stored data or receipt, or a
     * conflicting proof. SQLite failures (busy, trigger aborts) propagate
     * unchanged. Any throw rolls the transaction back.
     */
    completeStreams(
      request: StreamCompletionRequest,
      declarations: StreamDeclarationResolver,
    ): { receipts: NativeStreamCompletionReceipt[] };
    /**
     * Live record keys of one stream in the order each last arrived in the
     * current generation, for the legacy view only. A key with no arrival
     * since v8 is absent.
     */
    listArrivalOrder(instance: string, stream: string): string[];
  } {
  // Insert statements call it, so even a readonly handle must register it
  // before they are prepared.
  registerTimeKey(db);
  if (db.readonly) {
    const current = db
      .prepare("SELECT version FROM pdpp_schema_version WHERE id = 1")
      .get() as { version: number } | undefined;
    if (current?.version !== MIGRATIONS.length) {
      throw new Error(
        "Readonly PDPP store requires the current schema version",
      );
    }
  } else {
    db.pragma("journal_mode = WAL");
    migrate(db);
    sweepStaleBlobClaims(db);
  }

  const writerId = (
    db
      .prepare("SELECT writer_id FROM pdpp_installation_writer WHERE id = 1")
      .get() as {
      writer_id: string;
    }
  ).writer_id;
  const replica = createReplicationJournal(db, writerId);
  const insertMutationStmt = db.prepare(`
    INSERT INTO pdpp_mutation_journal
      (operation_id, writer_id, source_id, connection_id, method, generation,
       stream, record_key, operation, value_json, blob_ids_json)
    VALUES (@operation_id, @writer_id, @source_id, @connection_id, @method, @generation,
            @stream, @record_key, @operation, @value_json, @blob_ids_json)
  `);

  let replicaVisibilityObserver: (() => void) | undefined;
  function journalMutation(
    instance: string,
    stream: string,
    recordKey: string,
    semantics?: StreamSemantics,
    primaryKey?: string[],
  ): void {
    const binding = db
      .prepare(
        "SELECT source_id, method, generation FROM pdpp_instance_binding WHERE instance = ?",
      )
      .get(instance) as
      Pick<BindingRowDb, "source_id" | "method" | "generation"> | undefined;
    const record = toRow(
      getCurrentStmt.get(instance, stream, recordKey) as RecordRowDb,
    );
    const blobId = record.deleted ? null : extractBlobId(record.data);
    insertMutationStmt.run({
      operation_id: randomUUID(),
      writer_id: writerId,
      source_id: binding?.source_id ?? null,
      connection_id: instance,
      method: binding?.method ?? null,
      generation: binding?.generation ?? null,
      stream,
      record_key: recordKey,
      operation: record.deleted ? "delete" : "upsert",
      value_json: JSON.stringify(record),
      blob_ids_json: JSON.stringify(blobId ? [blobId] : []),
    });
    replica.captureRecord(instance, stream, recordKey, semantics, primaryKey);
    replicaVisibilityObserver?.();
  }

  function readMutationJournalPage(
    options: MutationJournalPageOptions,
  ): MutationJournalPage {
    const afterSequence = options.afterSequence ?? 0;
    if (
      !Number.isSafeInteger(afterSequence) ||
      afterSequence < 0 ||
      !Number.isSafeInteger(options.limit) ||
      options.limit < 1 ||
      options.limit > 1000
    ) {
      throw new RangeError("Invalid mutation journal offset or limit");
    }
    const rows = db
      .prepare(
        "SELECT * FROM pdpp_mutation_journal WHERE sequence > ? ORDER BY sequence LIMIT ?",
      )
      .all(afterSequence, options.limit + 1) as Array<{
      sequence: number;
      operation_id: string;
      writer_id: string;
      source_id: string | null;
      connection_id: string;
      method: string | null;
      generation: number | null;
      stream: string;
      record_key: string;
      operation: CanonicalMutation["operation"];
      value_json: string;
      blob_ids_json: string;
    }>;
    const mutations = rows
      .slice(0, options.limit)
      .map((row): CanonicalMutation => ({
        sequence: row.sequence,
        operationId: row.operation_id,
        writerId: row.writer_id,
        sourceId: row.source_id,
        connectionId: row.connection_id,
        method: row.method,
        generation: row.generation,
        stream: row.stream,
        recordKey: row.record_key,
        operation: row.operation,
        value: JSON.parse(row.value_json),
        blobIds: JSON.parse(row.blob_ids_json),
      }));
    return {
      mutations,
      hasMore: rows.length > options.limit,
      nextAfterSequence: mutations.at(-1)?.sequence ?? afterSequence,
    };
  }

  const nextWriteSeq = db.prepare(
    "UPDATE pdpp_write_clock SET value = value + 1 WHERE id = 1 RETURNING value",
  );
  const readWriteClockStmt = db.prepare(
    "SELECT value FROM pdpp_write_clock WHERE id = 1",
  );
  const readWriteClock = () =>
    (readWriteClockStmt.get() as { value: number }).value;

  const getCurrentStmt = db.prepare(
    "SELECT * FROM pdpp_records WHERE instance = ? AND stream = ? AND record_key = ?",
  );
  const upsertCurrentStmt = db.prepare(`
    INSERT INTO pdpp_records (instance, stream, record_key, data, version, emitted_at, emitted_key, deleted, deleted_at, blob_id)
    VALUES (@instance, @stream, @record_key, @data, @version, @emitted_at, pdpp_time_key(@emitted_at), @deleted, @deleted_at, @blob_id)
    ON CONFLICT (instance, stream, record_key) DO UPDATE SET
      data = excluded.data,
      version = excluded.version,
      emitted_at = excluded.emitted_at,
      emitted_key = excluded.emitted_key,
      deleted = excluded.deleted,
      deleted_at = excluded.deleted_at,
      blob_id = excluded.blob_id
  `);
  const insertHistoryStmt = db.prepare(`
    INSERT INTO pdpp_record_changes
      (instance, stream, record_key, version, data, emitted_at, emitted_key, deleted, deleted_at, written_at)
    VALUES (@instance, @stream, @record_key, @version, @data, @emitted_at, pdpp_time_key(@emitted_at), @deleted, @deleted_at, @written_at)
  `);
  const putBlobStmt = db.prepare(`
    INSERT INTO pdpp_blobs (blob_id, mime_type, size_bytes, sha256)
    VALUES (@blob_id, @mime_type, @size_bytes, @sha256)
    ON CONFLICT (blob_id) DO UPDATE SET
      mime_type = excluded.mime_type, size_bytes = excluded.size_bytes, sha256 = excluded.sha256
  `);
  const getBlobStmt = db.prepare("SELECT * FROM pdpp_blobs WHERE blob_id = ?");
  const findBlobRefsStmt = db.prepare(
    `SELECT r.instance, r.stream, r.record_key FROM pdpp_records r WHERE r.blob_id = ? AND r.deleted = 0 AND ${unquarantinedRecordSql("r")}`,
  );
  const insertBlobBytesStmt = db.prepare(
    "INSERT INTO pdpp_blob_bytes (blob_id, bytes) VALUES (@blob_id, @bytes)",
  );
  const getBlobBytesStmt = db.prepare(
    "SELECT bytes FROM pdpp_blob_bytes WHERE blob_id = ?",
  );
  const dropCompletionStmt = db.prepare(
    "DELETE FROM pdpp_stream_completion WHERE instance = ? AND stream = ?",
  );
  function dropCompletion(instance: string, stream: string): void {
    if (dropCompletionStmt.run(instance, stream).changes > 0)
      replica.captureInvalidation(instance, stream);
  }

  const noteArrivalStmt = db.prepare(`
    INSERT INTO pdpp_record_arrival (instance, stream, record_key, generation, arrival)
    VALUES (@instance, @stream, @record_key, @generation, (
      SELECT COALESCE(MAX(arrival), 0) + 1 FROM pdpp_record_arrival
      WHERE instance = @instance AND stream = @stream
    ))
    ON CONFLICT (instance, stream, record_key) DO UPDATE SET
      generation = excluded.generation,
      arrival = excluded.arrival
  `);
  const forgetArrivalStmt = db.prepare(
    "DELETE FROM pdpp_record_arrival WHERE instance = ? AND stream = ? AND record_key = ?",
  );

  /** `recordKey` is now the last live key of its stream to arrive. */
  function noteArrival(
    instance: string,
    stream: string,
    recordKey: string,
    generation: number,
  ): void {
    noteArrivalStmt.run({
      instance,
      stream,
      record_key: recordKey,
      generation,
    });
    db.prepare(
      "UPDATE pdpp_record_arrival_clock SET value = value + 1 WHERE id = 1",
    ).run();
  }

  function latestVersion(
    instance: string,
    stream: string,
    recordKey: string,
  ): number {
    const row = getCurrentStmt.get(instance, stream, recordKey) as
      RecordRowDb | undefined;
    return row?.version ?? 0;
  }

  function ingestBatch(
    envelopes: PdppRecordEnvelopeInput[],
    streamSemantics: (stream: string, instance: string) => StreamSemantics,
    primaryKeyFields: (stream: string, instance: string) => string[],
    binding?: { method: string; generation: number },
    validateData?: RecordDataValidator,
  ): IngestResult {
    const results: IngestOutcome[] = [];

    // The whole batch is one SQLite transaction: a thrown error rolls back
    // every write from this call, never leaving partial version/
    // record_changes state. A rejected envelope is an outcome, not a
    // failure: it writes nothing and the rest of the batch proceeds.
    // Reads inside the transaction see earlier writes of the same batch, so
    // two envelopes for one key are decided in order.
    const runBatch = db.transaction(() => {
      if (!binding) {
        // P8a: every canonical write names its method and generation. A write
        // without them (the sync importer, which has no method identity)
        // cannot be checked against the binding or the blob claims, so it is
        // refused whether or not the instance has a binding row yet.
        envelopes.forEach((_, index) =>
          results.push({
            index,
            outcome: "rejected",
            reason: "method_required",
          }),
        );
        return;
      }
      const { generation } = binding;
      if (envelopes.length > 0) {
        checkBinding(binding.method, generation, envelopes);
      }
      envelopes.forEach((envelope, index) => {
        const semantics = streamSemantics(envelope.stream, envelope.instance);
        const primaryKey = primaryKeyFields(envelope.stream, envelope.instance);
        const plan = planIngest(
          index,
          envelope,
          semantics,
          primaryKey,
          (recordKey) => {
            const row = getCurrentStmt.get(
              envelope.instance,
              envelope.stream,
              recordKey,
            ) as RecordRowDb | undefined;
            return row
              ? {
                  deleted: row.deleted === 1,
                  data: row.data ? JSON.parse(row.data) : null,
                }
              : undefined;
          },
          validateData,
        );
        results.push(plan.outcome);
        if (!plan.write) {
          // An equal re-delivery is still an arrival. A delete of a missing
          // key and an append_only conflict are not.
          if (
            plan.outcome.outcome === "unchanged" &&
            !plan.outcome.flag &&
            envelope.op !== "delete"
          ) {
            noteArrival(
              envelope.instance,
              envelope.stream,
              encodeRecordKey(envelope.key),
              generation,
            );
          }
          return;
        }

        const { recordKey, data } = plan.write;
        const blobId = extractBlobId(data);
        if (
          binding &&
          blobId &&
          !blobClaimedByCurrentGeneration(blobId, envelope.instance)
        ) {
          results[results.length - 1] = {
            index,
            outcome: "rejected",
            reason: "blob_unclaimed",
          };
          return;
        }
        writeVersion(
          envelope.instance,
          envelope.stream,
          recordKey,
          data,
          envelope.emitted_at,
        );
        journalMutation(
          envelope.instance,
          envelope.stream,
          recordKey,
          semantics,
          primaryKey,
        );
        if (data === null) {
          forgetArrivalStmt.run(envelope.instance, envelope.stream, recordKey);
        } else {
          noteArrival(
            envelope.instance,
            envelope.stream,
            recordKey,
            generation,
          );
        }
      });
    });

    runBatch();
    return summarizeIngest(results);
  }

  function blobClaimedByCurrentGeneration(
    blobId: string,
    instance: string,
  ): boolean {
    return !!db
      .prepare(
        "SELECT 1 FROM pdpp_blob_claims WHERE blob_id = ? AND instance = ? AND generation = (SELECT generation FROM pdpp_instance_binding WHERE instance = ?)",
      )
      .get(blobId, instance, instance);
  }

  /** Writes the next version of a key: `data === null` is a tombstone. */
  function writeVersion(
    instance: string,
    stream: string,
    recordKey: string,
    data: Record<string, unknown> | null,
    emittedAt: string,
  ): void {
    if (
      db
        .prepare(
          "SELECT 1 FROM pdpp_replica_quarantined_keys q JOIN pdpp_instance_binding b ON q.instance = b.instance AND q.generation = b.generation WHERE q.instance = ? AND q.stream = ? AND q.record_key = ?",
        )
        .get(instance, stream, recordKey)
    ) {
      throw new PdppBindingError("replica_integrity_quarantine");
    }
    const deleted = data === null;
    const version = latestVersion(instance, stream, recordKey) + 1;
    const writtenAt = nextWriteSeq.get() as { value: number };
    // The stream no longer holds what a replace delivered. `replaceStream`
    // writes its own receipt after its writes.
    dropCompletion(instance, stream);
    const dataJson = deleted ? null : JSON.stringify(data);
    const deletedAt = deleted ? emittedAt : null;
    upsertCurrentStmt.run({
      instance,
      stream,
      record_key: recordKey,
      data: dataJson,
      version,
      emitted_at: emittedAt,
      deleted: deleted ? 1 : 0,
      deleted_at: deletedAt,
      blob_id: extractBlobId(data),
    });
    insertHistoryStmt.run({
      instance,
      stream,
      record_key: recordKey,
      version,
      data: dataJson,
      emitted_at: emittedAt,
      deleted: deleted ? 1 : 0,
      deleted_at: deletedAt,
      written_at: writtenAt.value,
    });
  }

  // P7: the records are the complete live set of (instance, stream) from a
  // covered full refresh by the bound method. Under Q1 every live row of the
  // instance was written by that method in this generation, so a live key the
  // snapshot lacks has no other evidence and is tombstoned. Any rejected
  // record rejects the whole request before anything is written.
  //
  // With `sourceCollectedAt`, an applied replace also stores its completion
  // receipt in the same transaction. Without it there is no receipt, and an
  // older one is deleted: it would describe a collection that is no longer
  // the latest.
  function replaceStream(input: {
    instance: string;
    stream: string;
    method: string;
    generation: number;
    emittedAt: string;
    envelopes: PdppRecordEnvelopeInput[];
    primaryKey: string[];
    validateData?: RecordDataValidator;
    sourceCollectedAt?: string;
    completionPolicy?: "preserve_if_unchanged";
  }): ReplaceStreamResult {
    if (
      input.sourceCollectedAt !== undefined &&
      !isRfc3339DateTime(input.sourceCollectedAt)
    ) {
      throw new TypeError("invalid_source_collected_at");
    }
    if (
      input.completionPolicy !== undefined &&
      (input.completionPolicy !== "preserve_if_unchanged" ||
        input.sourceCollectedAt !== undefined)
    ) {
      throw new TypeError("invalid_completion_policy");
    }
    return db.transaction((): ReplaceStreamResult => {
      checkInstanceBinding(input.instance, input.method, input.generation);
      checkStreamQuarantine(input.instance, input.stream, input.generation);

      const seen = new Set<string>();
      /** Live keys of the snapshot, in the order it delivered them. */
      const snapshotOrder: string[] = [];
      const results: IngestOutcome[] = [];
      const writes: {
        recordKey: string;
        data: Record<string, unknown> | null;
        emittedAt: string;
      }[] = [];
      input.envelopes.forEach((envelope, index) => {
        const reject = (reason: string) =>
          results.push({ index, outcome: "rejected", reason });
        let recordKey: string;
        try {
          recordKey = encodeRecordKey(envelope.key);
        } catch (err) {
          if (err instanceof RecordKeyError) return reject(err.message);
          throw err;
        }
        if (seen.has(recordKey)) return reject("duplicate key in snapshot");
        seen.add(recordKey);

        const plan = planIngest(
          index,
          envelope,
          "mutable_state",
          input.primaryKey,
          (key) => {
            const row = getCurrentStmt.get(
              input.instance,
              input.stream,
              key,
            ) as RecordRowDb | undefined;
            return row
              ? {
                  deleted: row.deleted === 1,
                  data: row.data ? JSON.parse(row.data) : null,
                }
              : undefined;
          },
          input.validateData,
        );
        if (plan.outcome.outcome === "rejected") {
          return void results.push(plan.outcome);
        }
        if (envelope.op !== "delete") snapshotOrder.push(recordKey);
        if (!plan.write) return void results.push(plan.outcome);
        const blobId = extractBlobId(plan.write.data);
        if (blobId && !blobClaimedByCurrentGeneration(blobId, input.instance)) {
          return reject("blob_unclaimed");
        }
        results.push(plan.outcome);
        writes.push({
          recordKey,
          data: plan.write.data,
          emittedAt: envelope.emitted_at,
        });
      });

      const summary = summarizeIngest(results);
      if (summary.rejected.length > 0) {
        return { ...summary, applied: false, deleted: 0 };
      }

      const preserved = input.completionPolicy
        ? validReceiptOfUnchangedSet(input, writes.length, seen)
        : false;

      for (const write of writes) {
        writeVersion(
          input.instance,
          input.stream,
          write.recordKey,
          write.data,
          write.emittedAt,
        );
        journalMutation(
          input.instance,
          input.stream,
          write.recordKey,
          "mutable_state",
          input.primaryKey,
        );
      }
      const missing = (
        db
          .prepare(
            "SELECT record_key FROM pdpp_records WHERE instance = ? AND stream = ? AND deleted = 0",
          )
          .all(input.instance, input.stream) as { record_key: string }[]
      ).filter(({ record_key }) => !seen.has(record_key));
      for (const { record_key } of missing) {
        writeVersion(
          input.instance,
          input.stream,
          record_key,
          null,
          input.emittedAt,
        );
        journalMutation(
          input.instance,
          input.stream,
          record_key,
          "mutable_state",
          input.primaryKey,
        );
      }
      // Desktop rebuilt a fully refreshed stream in emit order, unchanged
      // keys included.
      db.prepare(
        "DELETE FROM pdpp_record_arrival WHERE instance = ? AND stream = ?",
      ).run(input.instance, input.stream);
      for (const recordKey of snapshotOrder) {
        noteArrival(input.instance, input.stream, recordKey, input.generation);
      }
      if (!preserved) dropCompletion(input.instance, input.stream);
      if (input.sourceCollectedAt !== undefined) {
        db.prepare(
          `INSERT INTO pdpp_stream_completion
             (instance, stream, method, generation, source_collected_at, write_seq, live_count)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
        ).run(
          input.instance,
          input.stream,
          input.method,
          input.generation,
          input.sourceCollectedAt,
          readWriteClock(),
          (
            db
              .prepare(
                "SELECT COUNT(*) AS n FROM pdpp_records WHERE instance = ? AND stream = ? AND deleted = 0",
              )
              .get(input.instance, input.stream) as { n: number }
          ).n,
        );
      }
      if (input.sourceCollectedAt !== undefined)
        replica.captureCompletion(input.instance, input.stream);
      return { ...summary, applied: true, deleted: missing.length };
    })();
  }

  // Under `preserve_if_unchanged`: true when this replace writes nothing to
  // the stream's rows, no live key is missing from the snapshot, and the
  // stream's current receipt still describes the live set. The receipt is then
  // left as stored. Changed content is judged by `planIngest` (`writes` is
  // empty only when every snapshot key is live and equal), and a retained
  // extra key shows up as a live key the snapshot lacks. Anything else,
  // including a stale or tampered receipt, returns false and the caller drops
  // the receipt as P7 always has.
  function validReceiptOfUnchangedSet(
    input: {
      instance: string;
      stream: string;
      method: string;
      generation: number;
      primaryKey: string[];
    },
    writeCount: number,
    seen: Set<string>,
  ): boolean {
    if (writeCount > 0) return false;
    const rows = db
      .prepare(
        "SELECT record_key, data FROM pdpp_records WHERE instance = ? AND stream = ? AND deleted = 0",
      )
      .all(input.instance, input.stream) as {
      record_key: string;
      data: string;
    }[];
    if (rows.some((row) => !seen.has(row.record_key))) return false;
    const prior = db
      .prepare(
        "SELECT * FROM pdpp_stream_completion WHERE instance = ? AND stream = ?",
      )
      .get(input.instance, input.stream) as CompletionRowDb | undefined;
    if (!prior) return false;
    const binding = db
      .prepare("SELECT source_id FROM pdpp_instance_binding WHERE instance = ?")
      .get(input.instance) as { source_id: string };
    try {
      return receiptInvariantsHold(prior, {
        method: input.method,
        generation: input.generation,
        liveCount: rows.length,
        clock: readWriteClock(),
        lastChange: lastChangeSeq(input.instance, input.stream),
        digest: () =>
          liveSnapshotDigest(
            { ...input, sourceId: binding.source_id },
            input.primaryKey,
            rows.map((row) => ({
              recordKey: row.record_key,
              dataJson: row.data,
            })),
          ),
      });
    } catch (error) {
      // A live set the digest cannot describe cannot match a native receipt.
      if (error instanceof StreamCompletionError) return false;
      throw error;
    }
  }

  function checkBinding(
    method: string,
    generation: number,
    envelopes: PdppRecordEnvelopeInput[],
  ): void {
    const instances = new Set(envelopes.map((envelope) => envelope.instance));
    if (instances.size !== 1) throw new PdppBindingError("invalid_request");
    checkInstanceBinding([...instances][0], method, generation);
  }

  /** Check every write against the connection's registered method/generation. */
  function checkInstanceBinding(
    instance: string,
    method: string,
    generation: number,
  ): void {
    // Only a named method may write.
    if (typeof method !== "string" || method.length === 0) {
      throw new PdppBindingError("method_required");
    }
    checkConnectionQuarantine(instance);
    const current = ensureBinding(db, instance);
    if (current.deleted_at !== null) {
      throw new PdppBindingError("connection_deleted");
    }
    if (current.source_id === null) {
      throw new PdppBindingError("connection_required");
    }
    if (current.generation !== generation) {
      throw new PdppBindingError("binding_generation_mismatch");
    }
    if (current.method !== method) {
      throw new PdppBindingError("instance_bound_to_other_method");
    }
  }

  function checkConnectionQuarantine(instance: string): void {
    if (
      db
        .prepare(
          "SELECT 1 FROM pdpp_replica_quarantined_connections WHERE instance = ?",
        )
        .get(instance)
    ) {
      throw new PdppBindingError("replica_integrity_quarantine");
    }
  }

  function checkStreamQuarantine(
    instance: string,
    stream: string,
    generation: number,
  ): void {
    if (
      db
        .prepare(
          "SELECT 1 FROM pdpp_replica_quarantined_keys WHERE instance = ? AND stream = ? AND generation = ? LIMIT 1",
        )
        .get(instance, stream, generation)
    ) {
      throw new PdppBindingError("replica_integrity_quarantine");
    }
  }

  // Read-only: an instance with no row reports the row `ensureBinding` would
  // create, without creating it.
  function getInstanceBinding(instance: string): PdppInstanceBinding {
    const row = (db
      .prepare("SELECT * FROM pdpp_instance_binding WHERE instance = ?")
      .get(instance) as BindingRowDb | undefined) ?? {
      instance,
      source_id: null,
      label: "",
      deleted_at: null,
      method: null,
      generation: 1,
      reset_clock: 0,
    };
    return {
      ...toBinding(row),
      empty: !instanceHasRecords(db, instance),
    };
  }

  function resetInstanceBinding(input: {
    instance: string;
    expectedMethod: string | null;
    expectedGeneration: number;
    nextMethod: string | null;
  }): { binding: PdppInstanceBinding; alreadyReset: boolean } {
    return db.transaction(() => {
      const current = ensureBinding(db, input.instance);
      if (current.deleted_at !== null) {
        throw new PdppBindingError("connection_deleted");
      }
      if (input.instance.startsWith("conn_") && current.source_id === null) {
        throw new PdppBindingError("connection_required");
      }
      if (
        current.method !== input.expectedMethod ||
        current.generation !== input.expectedGeneration
      ) {
        const alreadyReset =
          current.method === input.nextMethod &&
          current.generation === input.expectedGeneration + 1 &&
          !instanceHasRecords(db, input.instance);
        if (alreadyReset)
          return { binding: toBinding(current), alreadyReset: true };
        throw new PdppBindingError("binding_generation_mismatch");
      }

      // A registered connection has one method for its lifetime. Reset may
      // erase its data and advance the generation, but it cannot rebind the
      // connection to another method.
      if (current.source_id !== null && current.method !== input.nextMethod) {
        throw new PdppBindingError("connection_conflict");
      }

      eraseInstanceData(input.instance);
      const resetClock = (nextWriteSeq.get() as { value: number }).value;
      db.prepare(
        "UPDATE pdpp_instance_binding SET method = ?, generation = ?, reset_clock = ? WHERE instance = ?",
      ).run(
        input.nextMethod,
        input.expectedGeneration + 1,
        resetClock,
        input.instance,
      );
      replica.captureLifecycle(input.instance, "connection-reset");
      replicaVisibilityObserver?.();
      return {
        binding: toBinding(ensureBinding(db, input.instance)),
        alreadyReset: false,
      };
    })();
  }

  function transitionWriteClock(): number {
    return (
      db.prepare("SELECT value FROM pdpp_write_clock WHERE id = 1").get() as {
        value: number;
      }
    ).value;
  }

  function claudeTransition(instance: string): ClaudeTransition | null {
    const row = db
      .prepare("SELECT * FROM pdpp_claude_transition WHERE instance = ?")
      .get(instance) as
      | {
          instance: string;
          archive_instance: string;
          generation: number;
          snapshots_json: string;
          conversations_covered: number;
        }
      | undefined;
    return row
      ? {
          instance: row.instance,
          archiveInstance: row.archive_instance,
          conversationsCovered: row.conversations_covered === 1,
          generation: row.generation,
          snapshots: JSON.parse(
            row.snapshots_json,
          ) as ClaudeTransition["snapshots"],
        }
      : null;
  }

  function listClaudeTransitions(): ClaudeTransition[] {
    return (
      db
        .prepare(
          "SELECT instance FROM pdpp_claude_transition ORDER BY instance",
        )
        .all() as { instance: string }[]
    ).map((row) => claudeTransition(row.instance)!);
  }

  function confirmClaudeTransition(instance: string, generation: number): void {
    db.prepare(
      "UPDATE pdpp_claude_transition SET conversations_covered = 1 WHERE instance = ? AND generation = ?",
    ).run(instance, generation);
  }

  function clearClaudeTransitionScope(scope: string): void {
    if (scope !== "claude.conversations" && scope !== "claude.projects") return;
    db.transaction(() => {
      for (const transition of listClaudeTransitions()) {
        delete transition.snapshots[scope];
        db.prepare(
          "UPDATE pdpp_claude_transition SET snapshots_json = ? WHERE instance = ?",
        ).run(JSON.stringify(transition.snapshots), transition.instance);
        const streams =
          scope === "claude.conversations"
            ? ["conversations", "messages"]
            : ["projects", "project_documents"];
        if (Object.keys(transition.snapshots).length === 0)
          streams.push("account_profile");
        for (const table of [
          "pdpp_records",
          "pdpp_record_changes",
          "pdpp_stream_completion",
          "pdpp_record_arrival",
        ]) {
          for (const stream of streams)
            db.prepare(
              `DELETE FROM ${table} WHERE instance = ? AND stream = ?`,
            ).run(transition.archiveInstance, stream);
        }
        db.prepare(
          `DELETE FROM pdpp_blob_claims WHERE instance = ?
          AND NOT EXISTS (SELECT 1 FROM pdpp_records r WHERE r.instance = pdpp_blob_claims.instance AND r.blob_id = pdpp_blob_claims.blob_id)
          AND NOT EXISTS (SELECT 1 FROM pdpp_record_changes c WHERE c.instance = pdpp_blob_claims.instance AND json_extract(c.data, '$.blob_ref.blob_id') = pdpp_blob_claims.blob_id)`,
        ).run(transition.archiveInstance);
      }
      deleteUnclaimedBlobs(db);
    })();
  }

  function transitionClaudeToLive(
    input: ClaudeTransitionInput,
  ): PdppInstanceBinding {
    return db.transaction(() => {
      const current = getInstanceBinding(input.instance);
      if (current.deletedAt !== null)
        throw new PdppBindingError("connection_deleted");
      const previous = claudeTransition(input.instance);
      // Replaying the same intent must not erase a successful live import.
      if (
        previous &&
        previous.generation === input.expectedGeneration + 1 &&
        current.method === "anthropic-live" &&
        current.generation === previous.generation
      )
        return current;
      if (
        current.method !== "anthropic" ||
        current.sourceId !== "https://registry.pdpp.dev/sources/claude"
      )
        throw new PdppBindingError("connection_conflict");
      if (
        current.generation !== input.expectedGeneration ||
        transitionWriteClock() !== input.expectedWriteClock
      )
        throw new PdppBindingError("binding_generation_mismatch");
      if (previous || listConnections(current.sourceId).length !== 1)
        throw new PdppBindingError("connection_conflict");
      const archive = `retired-claude:${randomUUID()}`;
      const generation = current.generation + 1;
      db.prepare(
        "INSERT INTO pdpp_claude_transition (instance, archive_instance, generation, snapshots_json) VALUES (?, ?, ?, ?)",
      ).run(
        input.instance,
        archive,
        generation,
        JSON.stringify(input.snapshots),
      );
      // An archive is deliberately not a registered connection and cannot mint
      // owner tokens or accept writes. Blob claims keep the old bytes alive.
      for (const table of [
        "pdpp_records",
        "pdpp_record_changes",
        "pdpp_blob_claims",
        "pdpp_stream_completion",
        "pdpp_record_arrival",
      ]) {
        db.prepare(`UPDATE ${table} SET instance = ? WHERE instance = ?`).run(
          archive,
          input.instance,
        );
      }
      const clock = (nextWriteSeq.get() as { value: number }).value;
      db.prepare(
        "UPDATE pdpp_instance_binding SET method = 'anthropic-live', generation = ?, reset_clock = ? WHERE instance = ?",
      ).run(generation, clock, input.instance);
      return getInstanceBinding(input.instance);
    })();
  }

  function listConnections(sourceId: string): PdppInstanceBinding[] {
    const rows = db
      .prepare(
        "SELECT * FROM pdpp_instance_binding WHERE source_id = ? AND deleted_at IS NULL ORDER BY instance",
      )
      .all(sourceId) as BindingRowDb[];
    return rows.map(toBinding);
  }

  function registerConnection(input: {
    instance: string;
    sourceId: string;
    method: string;
    label: string;
  }): PdppInstanceBinding {
    return db.transaction(() => {
      const current = ensureBinding(db, input.instance);
      if (current.deleted_at !== null) {
        throw new PdppBindingError("connection_deleted");
      }
      if (
        current.source_id !== null &&
        (current.source_id !== input.sourceId ||
          current.method !== input.method)
      ) {
        throw new PdppBindingError("connection_conflict");
      }
      if (current.method !== null && current.method !== input.method) {
        throw new PdppBindingError("connection_conflict");
      }
      db.prepare(
        "UPDATE pdpp_instance_binding SET source_id = ?, method = ?, label = ? WHERE instance = ?",
      ).run(input.sourceId, input.method, input.label, input.instance);
      if (current.source_id === null)
        replica.captureLifecycle(input.instance, "connection-register");
      replicaVisibilityObserver?.();
      return getInstanceBinding(input.instance);
    })();
  }

  function deleteConnection(instance: string): PdppInstanceBinding {
    return db.transaction(() => {
      const current = ensureBinding(db, instance);
      if (current.deleted_at !== null) return toBinding(current);
      eraseInstanceData(instance);
      const resetClock = (nextWriteSeq.get() as { value: number }).value;
      const deletedAt = new Date().toISOString();
      db.prepare(
        "UPDATE pdpp_instance_binding SET deleted_at = ?, generation = generation + 1, reset_clock = ? WHERE instance = ?",
      ).run(deletedAt, resetClock, instance);
      replica.captureLifecycle(instance, "connection-delete");
      replicaVisibilityObserver?.();
      return getInstanceBinding(instance);
    })();
  }

  function eraseInstanceData(instance: string): void {
    const transition = claudeTransition(instance);
    if (transition) {
      db.prepare("DELETE FROM pdpp_claude_transition WHERE instance = ?").run(
        instance,
      );
      eraseInstanceData(transition.archiveInstance);
    }
    db.prepare("DELETE FROM pdpp_records WHERE instance = ?").run(instance);
    db.prepare("DELETE FROM pdpp_record_changes WHERE instance = ?").run(
      instance,
    );
    db.prepare("DELETE FROM pdpp_blob_claims WHERE instance = ?").run(instance);
    db.prepare("DELETE FROM pdpp_stream_completion WHERE instance = ?").run(
      instance,
    );
    db.prepare("DELETE FROM pdpp_record_arrival WHERE instance = ?").run(
      instance,
    );
    deleteUnclaimedBlobs(db);
  }

  function listStreamCompletions(instance: string): StreamCompletionReceipt[] {
    const rows = db
      .prepare(
        "SELECT * FROM pdpp_stream_completion WHERE instance = ? ORDER BY stream",
      )
      .all(instance) as {
      instance: string;
      stream: string;
      method: string;
      generation: number;
      source_collected_at: string;
      write_seq: number;
      live_count: number;
    }[];
    return rows.map((row) => ({
      instance: row.instance,
      stream: row.stream,
      method: row.method,
      generation: row.generation,
      sourceCollectedAt: row.source_collected_at,
      writeSeq: row.write_seq,
      liveCount: row.live_count,
    }));
  }

  type CompletionRowDb = {
    instance: string;
    stream: string;
    method: string;
    generation: number;
    source_collected_at: string;
    write_seq: number;
    live_count: number;
    snapshot_sha256: string | null;
    collection_time_basis: string | null;
  };

  function lastChangeSeq(instance: string, stream: string): number {
    return (
      db
        .prepare(
          "SELECT COALESCE(MAX(written_at), 0) AS seq FROM pdpp_record_changes WHERE instance = ? AND stream = ?",
        )
        .get(instance, stream) as { seq: number }
    ).seq;
  }

  /**
   * Whether a stored receipt still describes the live set it was written
   * for. It never compares the write clock to the global one: unrelated
   * writes move that without touching this stream.
   */
  function receiptInvariantsHold(
    prior: CompletionRowDb,
    expected: {
      method: string;
      generation: number;
      liveCount: number;
      clock: number;
      lastChange: number;
      /** The digest of the current live set, asked for only by a native receipt. */
      digest: () => string;
    },
  ): boolean {
    const native = prior.snapshot_sha256 !== null;
    return (
      prior.method === expected.method &&
      prior.generation === expected.generation &&
      prior.live_count === expected.liveCount &&
      Number.isSafeInteger(prior.write_seq) &&
      prior.write_seq >= 0 &&
      prior.write_seq <= expected.clock &&
      prior.write_seq >= expected.lastChange &&
      (native
        ? isCompletionTime(prior.source_collected_at)
        : isRfc3339DateTime(prior.source_collected_at)) &&
      native === (prior.collection_time_basis !== null) &&
      (!native ||
        (prior.snapshot_sha256 === expected.digest() &&
          prior.collection_time_basis === "host_run_finished"))
    );
  }

  function completeStreams(
    rawRequest: StreamCompletionRequest,
    declarations: StreamDeclarationResolver,
  ): { receipts: NativeStreamCompletionReceipt[] } {
    const request = parseCompletionRequest(rawRequest);
    return db
      .transaction(() => {
        const binding = db
          .prepare("SELECT * FROM pdpp_instance_binding WHERE instance = ?")
          .get(request.instance) as BindingRowDb | undefined;
        if (!binding || binding.source_id === null) {
          throw new PdppBindingError("connection_required");
        }
        if (binding.deleted_at !== null) {
          throw new PdppBindingError("connection_deleted");
        }
        if (binding.source_id !== request.sourceId) {
          throw new PdppBindingError("source_mismatch");
        }
        if (binding.generation !== request.generation) {
          throw new PdppBindingError("binding_generation_mismatch");
        }
        if (binding.method !== request.method) {
          throw new PdppBindingError("instance_bound_to_other_method");
        }

        checkConnectionQuarantine(request.instance);
        const clock = readWriteClock();
        const requestedAt = Date.parse(request.sourceCollectedAt);
        // Validate every stream before the first receipt is written.
        const writes: { stream: string; kind: "insert" | "update" | "keep" }[] =
          [];
        for (const proof of request.streams) {
          checkStreamQuarantine(
            request.instance,
            proof.stream,
            request.generation,
          );
          const primaryKey = declarations(request.sourceId, proof.stream);
          if (primaryKey === undefined) {
            throw new StreamCompletionError("unknown_stream");
          }
          if (
            primaryKey.length === 0 ||
            !primaryKey.every((field) => typeof field === "string" && field)
          ) {
            throw new StreamCompletionError("invalid_declaration");
          }
          const rows = db
            .prepare(
              "SELECT record_key, data FROM pdpp_records WHERE instance = ? AND stream = ? AND deleted = 0",
            )
            .all(request.instance, proof.stream) as {
            record_key: string;
            data: string;
          }[];
          if (rows.length !== proof.liveCount) {
            throw new StreamCompletionError("snapshot_conflict");
          }
          const digest = liveSnapshotDigest(
            { ...request, stream: proof.stream },
            primaryKey,
            rows.map((row) => ({
              recordKey: row.record_key,
              dataJson: row.data,
            })),
          );
          if (digest !== proof.snapshotSha256) {
            throw new StreamCompletionError("snapshot_conflict");
          }

          const prior = db
            .prepare(
              "SELECT * FROM pdpp_stream_completion WHERE instance = ? AND stream = ?",
            )
            .get(request.instance, proof.stream) as CompletionRowDb | undefined;
          if (!prior) {
            writes.push({ stream: proof.stream, kind: "insert" });
            continue;
          }
          // A receipt is deleted by every write that could invalidate it, so a
          // stored one that disagrees with the live data was tampered with.
          const native = prior.snapshot_sha256 !== null;
          if (
            !receiptInvariantsHold(prior, {
              method: request.method,
              generation: request.generation,
              liveCount: rows.length,
              clock,
              lastChange: lastChangeSeq(request.instance, proof.stream),
              digest: () => digest,
            })
          ) {
            throw new StreamCompletionError("invalid_prior_receipt");
          }
          const priorAt = Date.parse(prior.source_collected_at);
          if (requestedAt < priorAt) {
            throw new StreamCompletionError("time_conflict");
          }
          if (requestedAt === priorAt) {
            // Same instant: an exact replay keeps its bytes. A digest-less
            // receipt cannot be relabeled as native proof at its own time.
            if (!native) throw new StreamCompletionError("time_conflict");
            writes.push({ stream: proof.stream, kind: "keep" });
          } else {
            writes.push({ stream: proof.stream, kind: "update" });
          }
        }

        for (const [index, write] of writes.entries()) {
          const proof = request.streams[index];
          if (write.kind === "insert") {
            db.prepare(
              `INSERT INTO pdpp_stream_completion
               (instance, stream, method, generation, source_collected_at, write_seq, live_count, snapshot_sha256, collection_time_basis)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            ).run(
              request.instance,
              proof.stream,
              request.method,
              request.generation,
              request.sourceCollectedAt,
              clock,
              proof.liveCount,
              proof.snapshotSha256,
              request.collectionTimeBasis,
            );
          } else if (write.kind === "update") {
            db.prepare(
              `UPDATE pdpp_stream_completion
                SET source_collected_at = ?, write_seq = ?, snapshot_sha256 = ?, collection_time_basis = ?
              WHERE instance = ? AND stream = ?`,
            ).run(
              request.sourceCollectedAt,
              clock,
              proof.snapshotSha256,
              request.collectionTimeBasis,
              request.instance,
              proof.stream,
            );
          }
        }

        for (const write of writes) {
          if (write.kind !== "keep")
            replica.captureCompletion(request.instance, write.stream);
        }
        return {
          receipts: request.streams.map((proof) => {
            const row = db
              .prepare(
                "SELECT * FROM pdpp_stream_completion WHERE instance = ? AND stream = ?",
              )
              .get(request.instance, proof.stream) as CompletionRowDb;
            return {
              instance: row.instance,
              stream: row.stream,
              method: row.method,
              generation: row.generation,
              sourceCollectedAt: row.source_collected_at,
              writeSeq: row.write_seq,
              liveCount: row.live_count,
              snapshotSha256: row.snapshot_sha256 as string,
              collectionTimeBasis: "host_run_finished" as const,
            };
          }),
        };
      })
      .immediate();
  }

  function listArrivalOrder(instance: string, stream: string): string[] {
    const rows = db
      .prepare(
        `SELECT a.record_key FROM pdpp_record_arrival a
         JOIN pdpp_instance_binding b
           ON b.instance = a.instance AND b.generation = a.generation
         WHERE a.instance = ? AND a.stream = ?
         ORDER BY a.arrival`,
      )
      .all(instance, stream) as { record_key: string }[];
    return rows.map((row) => row.record_key);
  }

  function getRecord(
    instance: string,
    stream: string,
    recordKey: string,
  ): PdppStoredRecord | undefined {
    const row = db
      .prepare(
        `SELECT r.* FROM pdpp_records r WHERE r.instance=? AND r.stream=? AND r.record_key=? AND ${unquarantinedRecordSql("r")}`,
      )
      .get(instance, stream, recordKey) as RecordRowDb | undefined;
    if (!row || row.deleted) return undefined;
    return toRow(row) as PdppStoredRecord;
  }

  function changesSince(
    stream: string,
    options: ChangesSinceOptions,
    visibleInstanceIds: string[] = options.instanceIds,
  ): ChangesSincePage {
    let horizon: number;
    let sinceHorizon: number | null;
    let offset = 0;
    if (options.cursor) {
      const payload = decodeCursor(options.cursor);
      if (payload.kind !== "changes_since") throw new InvalidCursorError();
      assertCursorScope(payload, stream);
      horizon = parseHorizon(payload.horizon);
      sinceHorizon =
        payload.sinceHorizon === null
          ? null
          : parseHorizon(payload.sinceHorizon);
      offset = parseOffset(payload.offset);
    } else if (options.changesSince) {
      let payload;
      try {
        payload = decodeCursor(options.changesSince);
      } catch (error) {
        if (error instanceof InvalidCursorSyntaxError)
          throw new CursorExpiredError();
        throw error;
      }
      if (payload.kind !== "changes_since") throw new InvalidCursorError();
      assertCursorScope(payload, stream);
      sinceHorizon = parseHorizon(payload.horizon);
      horizon = readWriteClock();
    } else {
      sinceHorizon = null;
      horizon = readWriteClock();
    }
    assertNotResetSince(options.instanceIds, [
      horizon,
      sinceHorizon ?? horizon,
    ]);

    const ids = [...new Set(visibleInstanceIds)].filter((id) =>
      options.instanceIds.includes(id),
    );
    const changed: PdppRecordRow[] = [];
    for (const entry of ids.length ? snapshotRows(stream, ids, horizon) : []) {
      if (sinceHorizon !== null) {
        const wroteSincePrior = db
          .prepare(
            `SELECT 1 FROM pdpp_record_changes
          WHERE stream=? AND instance=? AND record_key=? AND written_at>? AND written_at<=? LIMIT 1`,
          )
          .get(
            entry.stream,
            entry.instance,
            entry.record_key,
            sinceHorizon,
            horizon,
          );
        if (!wroteSincePrior) continue;
      }
      const previous =
        sinceHorizon === null
          ? undefined
          : (db
              .prepare(
                `SELECT * FROM pdpp_record_changes
        WHERE stream=? AND instance=? AND record_key=? AND written_at<=?
        ORDER BY version DESC LIMIT 1`,
              )
              .get(
                entry.stream,
                entry.instance,
                entry.record_key,
                sinceHorizon,
              ) as RecordRowDb | undefined);
      const after = toRow(entry as RecordRowDb);
      const before = previous ? toRow(previous) : undefined;
      const visible = (row: PdppRecordRow | undefined) =>
        row !== undefined && (!options.isVisible || options.isVisible(row));
      if (!visible(after)) continue;
      if (before && !visible(before)) {
        changed.push(after);
        continue;
      }
      const project = (row: PdppRecordRow | undefined) => {
        if (!row || row.deleted) return row;
        if (!options.fields) return row.data;
        return Object.fromEntries(
          options.fields
            .filter((field) => field in row.data)
            .map((field) => [field, row.data[field]]),
        );
      };
      if (JSON.stringify(project(after)) !== JSON.stringify(project(before)))
        changed.push(after);
    }
    changed.sort(compareRecordIdentity);
    const page = changed.slice(offset, offset + options.limit);
    const hasMore = offset + options.limit < changed.length;
    if (options.expireOnErasure && horizon < readWriteClock()) {
      const erasure =
        db.prepare(`SELECT 1 FROM pdpp_record_changes INDEXED BY idx_pdpp_record_changes_snapshot_latest
        WHERE instance=? AND stream=? AND record_key=? AND written_at>? AND deleted=1 LIMIT 1`);
      if (
        page.some(
          (row) =>
            !row.deleted &&
            erasure.get(row.instance, stream, row.recordKey, horizon) !==
              undefined,
        )
      )
        throw new CursorExpiredError();
    }
    return {
      data: page,
      hasMore,
      nextCursor: hasMore
        ? encodeCursor({
            kind: "changes_since",
            stream,
            epoch: cursorEpoch(),
            horizon: String(horizon),
            sinceHorizon: sinceHorizon === null ? null : String(sinceHorizon),
            offset: offset + options.limit,
          })
        : undefined,
      nextChangesSince: hasMore
        ? undefined
        : encodeCursor({
            kind: "changes_since",
            stream,
            epoch: cursorEpoch(),
            horizon: String(horizon),
            sinceHorizon: null,
            offset: 0,
          }),
    };
  }

  // P10c: a token whose horizon is below the reset_clock of any instance it
  // reads spans a reset. `null` means the token predates horizons, so any
  // reset of a read instance expires it.
  function assertNotResetSince(
    instanceIds: string[],
    horizons: Array<number | null>,
  ): void {
    if (instanceIds.length === 0) return;
    const resetClocks = db
      .prepare(
        `SELECT reset_clock FROM pdpp_instance_binding
         WHERE instance IN (${instanceIds.map(() => "?").join(",")}) AND reset_clock > 0`,
      )
      .all(...instanceIds) as { reset_clock: number }[];
    if (
      resetClocks.some(({ reset_clock }) =>
        horizons.some((h) => h === null || h < reset_clock),
      )
    ) {
      throw new CursorExpiredError();
    }
  }

  function cursorEpoch(): string {
    const row = db
      .prepare("SELECT epoch FROM pdpp_store_metadata WHERE id = 1")
      .get() as { epoch: string } | undefined;
    if (!row) throw new CursorExpiredError();
    return row.epoch;
  }

  function assertCursorScope(
    payload: { stream?: string; epoch?: string },
    stream: string,
  ): void {
    if (payload.stream !== stream) {
      throw new CursorExpiredError();
    }
    if (payload.epoch !== cursorEpoch()) {
      throw new CursorExpiredError();
    }
  }

  /** Latest version of each complete identity at one fixed write horizon. */
  function* snapshotRows(
    stream: string,
    instanceIds: string[],
    horizon: number,
    options: {
      order?: "asc" | "desc";
      after?: { val: string; key: string; instance: string } | null;
      liveOnly?: boolean;
    } = {},
  ): Generator<RecordRowDb & { written_at: number }> {
    const dir = options.order === "desc" ? "DESC" : "ASC";
    const comparison = options.order === "desc" ? "<" : ">";
    let sql = `SELECT c.* FROM pdpp_record_changes c INDEXED BY idx_pdpp_record_changes_snapshot_key_order
      WHERE c.stream = ? AND c.instance IN (${instanceIds.map(() => "?").join(",")}) AND c.written_at <= ? AND ${unquarantinedRecordSql("c")}
      AND c.version = (
        SELECT c2.version FROM pdpp_record_changes c2 INDEXED BY idx_pdpp_record_changes_snapshot_latest
        WHERE c2.instance = c.instance AND c2.stream = c.stream AND c2.record_key = c.record_key AND c2.written_at <= ?
        ORDER BY c2.written_at DESC, c2.version DESC LIMIT 1
      )`;
    const params: unknown[] = [stream, ...instanceIds, horizon, horizon];
    if (options.liveOnly) sql += " AND c.deleted = 0";
    if (options.after) {
      sql += ` AND (c.emitted_key, c.record_key, c.instance) ${comparison} (?, ?, ?)`;
      params.push(
        timeSortKey(options.after.val),
        options.after.key,
        options.after.instance,
      );
    }
    sql += ` ORDER BY ${LIST_ORDER_COLUMNS.map((column) => `c.${column} ${dir}`).join(", ")}`;
    for (const row of db.prepare(sql).iterate(...params))
      yield row as RecordRowDb & { written_at: number };
  }

  function listRecords(
    stream: string,
    options: ListRecordsOptions,
  ): ListRecordsPage {
    let startAfter: { val: string; key: string; instance: string } | null =
      null;
    let horizon: number;
    if (options.cursor) {
      const payload = decodeListCursor(options.cursor);
      assertCursorScope(payload, stream);
      if (payload.order !== options.order) throw new InvalidCursorError();
      horizon = parseHorizon(payload.horizon);
      assertNotResetSince(options.instanceIds, [horizon]);
      startAfter = {
        val: payload.sortValue ?? "",
        key: payload.recordKey,
        instance: payload.instance,
      };
    } else {
      horizon = readWriteClock();
    }

    // The generator holds at most one raw row beyond the visible client page.
    function* rows(): Generator<PdppStoredRecord> {
      for (const row of snapshotRows(stream, options.instanceIds, horizon, {
        order: options.order,
        after: startAfter,
        liveOnly: true,
      })) {
        yield toRow(row) as PdppStoredRecord;
      }
    }
    const hasLaterWrites = horizon < readWriteClock();
    const erasure =
      db.prepare(`SELECT 1 FROM pdpp_record_changes INDEXED BY idx_pdpp_record_changes_snapshot_latest
      WHERE instance = ? AND stream = ? AND record_key = ? AND written_at > ? AND deleted = 1 LIMIT 1`);
    return listSnapshotPage(
      rows(),
      options,
      {
        stream,
        epoch: cursorEpoch(),
        horizon: String(horizon),
      },
      (row) =>
        hasLaterWrites &&
        erasure.get(row.instance, row.stream, row.recordKey, horizon) !==
          undefined,
      (instance, recordKey) => {
        const row = versionAtStmt.get(instance, stream, recordKey, horizon) as
          RecordRowDb | undefined;
        return row ? toRow(row) : undefined;
      },
    );
  }

  function deleteRecord(
    instance: string,
    stream: string,
    recordKey: string,
    deletedAt: string,
    streamSemantics: StreamSemantics,
  ): boolean {
    if (streamSemantics === "append_only") return false;
    let result = false;
    const run = db.transaction(() => {
      const existing = getCurrentStmt.get(instance, stream, recordKey) as
        RecordRowDb | undefined;
      if (!existing || existing.deleted) return;

      const version = existing.version + 1;
      const writtenAt = nextWriteSeq.get() as { value: number };
      dropCompletion(instance, stream);
      upsertCurrentStmt.run({
        instance,
        stream,
        record_key: recordKey,
        data: null,
        version,
        emitted_at: deletedAt,
        deleted: 1,
        deleted_at: deletedAt,
        blob_id: null,
      });
      insertHistoryStmt.run({
        instance,
        stream,
        record_key: recordKey,
        version,
        data: null,
        emitted_at: deletedAt,
        deleted: 1,
        deleted_at: deletedAt,
        written_at: writtenAt.value,
      });
      journalMutation(instance, stream, recordKey, streamSemantics);
      forgetArrivalStmt.run(instance, stream, recordKey);
      result = true;
    });
    run();
    return result;
  }

  const versionAtStmt = db.prepare(
    `SELECT * FROM pdpp_record_changes INDEXED BY idx_pdpp_record_changes_snapshot_latest
     WHERE instance = ? AND stream = ? AND record_key = ? AND written_at <= ?
     ORDER BY written_at DESC, version DESC LIMIT 1`,
  );
  const deletedAfterStmt =
    lazy(`SELECT 1 FROM pdpp_record_changes INDEXED BY idx_pdpp_record_changes_deleted
      WHERE instance = ? AND stream = ? AND record_key = ? AND written_at > ? AND deleted = 1 LIMIT 1`);

  // The candidate set's primary key is unique, so each seek visits one
  // index entry: no group, sort or skip over versions.
  const seekStmts = new Map<string, { get(...params: unknown[]): unknown }>();
  function seek(direction: "asc" | "desc", hasAfter: boolean) {
    const key = `${direction}:${hasAfter}`;
    let stmt = seekStmts.get(key);
    if (!stmt) {
      const dir = direction === "desc" ? "DESC" : "ASC";
      const cmp = direction === "desc" ? "<" : ">";
      stmt = db.prepare(
        "SELECT record_key, instance FROM pdpp_sync_candidate WHERE preparation = ?" +
          (hasAfter ? ` AND (record_key, instance) ${cmp} (?, ?)` : "") +
          ` ORDER BY record_key ${dir}, instance ${dir} LIMIT 1`,
      );
      seekStmts.set(key, stmt);
    }
    return stmt;
  }

  function readSyncWindow<T>(
    stream: string,
    request: SyncWindowRequest,
    read: (window: SyncWindow) => T,
  ): T {
    // One read transaction: the clock, the reset fence and every history
    // lookup `read` makes belong to the same committed state.
    return db.transaction(() => {
      const clock = readWriteClock();
      const high =
        request.high === undefined ? clock : parseHorizon(request.high);
      const low = request.low === null ? null : parseHorizon(request.low);
      // A horizon past this store's clock was never issued by it.
      if (high > clock || (low !== null && low > high)) {
        throw new CursorExpiredError();
      }
      assertNotResetSince(request.instanceIds, [high, low ?? high]);
      const versionAt = (instance: string, recordKey: string, at: number) => {
        const row = versionAtStmt.get(instance, stream, recordKey, at) as
          RecordRowDb | undefined;
        return row ? toRow(row) : undefined;
      };

      const preparation = preparationRow.get(request.preparation) as
        { done: number; expires_at: number } | undefined;
      // Unfinished, released, evicted or expired: not walkable.
      if (!preparation?.done || preparation.expires_at <= request.now) {
        throw new CursorExpiredError();
      }

      // One seek on the candidate set's primary key per call. SQLite's
      // BINARY text order is `compareRecordIdentity`'s code-point order.
      function next(
        direction: "asc" | "desc",
        after: RecordIdentity | undefined,
        budget: SyncBudget,
      ): RecordIdentity | undefined | null {
        if (!budget.spend()) return null;
        const row = (
          after
            ? seek(direction, true).get(
                request.preparation,
                after.recordKey,
                after.instance,
              )
            : seek(direction, false).get(request.preparation)
        ) as { record_key: string; instance: string } | undefined;
        return row
          ? { recordKey: row.record_key, instance: row.instance }
          : undefined;
      }

      function change({
        recordKey,
        instance,
      }: RecordIdentity): SyncWindowChange | undefined {
        const after = versionAt(instance, recordKey, high);
        if (!after) return undefined;
        return {
          after,
          before: () =>
            low === null ? undefined : versionAt(instance, recordKey, low),
          deletedAfterHigh: () =>
            high < clock &&
            deletedAfterStmt.get(instance, stream, recordKey, high) !==
              undefined,
        };
      }

      return read({
        high: String(high),
        next,
        change,
        versionAtHigh: (instance, recordKey) =>
          versionAt(instance, recordKey, high),
      });
    })();
  }

  // Prepared on first use: a database at an older schema version than these
  // statements need still opens, migrates, and only then runs them.
  function lazy(sql: string) {
    let stmt: ReturnType<Database["prepare"]> | undefined;
    const get = () => (stmt ??= db.prepare(sql));
    return {
      get: (...params: unknown[]) => get().get(...params),
      all: (...params: unknown[]) => get().all(...params),
      run: (...params: unknown[]) => get().run(...params),
    };
  }
  const preparationRow = lazy(
    "SELECT * FROM pdpp_sync_preparation WHERE id = ?",
  );
  const insertPreparation = lazy(`INSERT INTO pdpp_sync_preparation
    (id, owner, high, rows, done, expires_at) VALUES (?, ?, ?, 0, 0, ?)`);
  const updatePreparation = lazy(
    "UPDATE pdpp_sync_preparation SET rows = ?, done = ?, expires_at = ?, cursor_instance = ?, cursor_written = ? WHERE id = ?",
  );
  const expirePreparation = lazy(
    "UPDATE pdpp_sync_preparation SET expires_at = 0 WHERE id = ?",
  );
  const ownerPreparations = lazy(`SELECT COUNT(*) AS count,
    COALESCE(SUM(rows), 0) AS rows FROM pdpp_sync_preparation
    INDEXED BY idx_pdpp_sync_preparation_owner WHERE owner = ? AND expires_at > ?`);
  // rowid orders preparations by age.
  const evictPreparations =
    db.prepare(`UPDATE pdpp_sync_preparation SET expires_at = 0
    WHERE rowid IN (SELECT rowid FROM pdpp_sync_preparation
      INDEXED BY idx_pdpp_sync_preparation_owner WHERE owner = ? AND expires_at > ?
      ORDER BY rowid DESC LIMIT -1 OFFSET ?)`);
  const preparationWrites = lazy(`SELECT id, record_key, written_at
    FROM pdpp_record_changes INDEXED BY idx_pdpp_record_changes_horizon
    WHERE stream = ? AND instance = ? AND written_at > ? AND written_at <= ?
    ORDER BY written_at LIMIT ?`);
  const addCandidate = lazy(
    "INSERT OR IGNORE INTO pdpp_sync_candidate (preparation, record_key, instance) VALUES (?, ?, ?)",
  );
  const expiredPreparations = lazy(`SELECT id FROM pdpp_sync_preparation
    INDEXED BY idx_pdpp_sync_preparation_expires WHERE expires_at <= ? LIMIT 4`);
  const dropCandidates =
    db.prepare(`DELETE FROM pdpp_sync_candidate WHERE rowid IN (
    SELECT rowid FROM pdpp_sync_candidate WHERE preparation = ? LIMIT ?)`);
  const dropPreparation = lazy(
    "DELETE FROM pdpp_sync_preparation WHERE id = ?",
  );
  /** Candidate rows one write may delete while sweeping expired preparations. */
  const SWEEP_ROWS = 1000;

  /** Frees expired preparations in bounded steps; the rest wait for later writes. */
  function sweepPreparations(now: number): void {
    let left = SWEEP_ROWS;
    for (const { id } of expiredPreparations.all(now) as { id: string }[]) {
      const dropped = dropCandidates.run(id, left).changes;
      left -= dropped;
      if (left <= 0) return;
      dropPreparation.run(id);
    }
  }

  const prepareTx = db.transaction(
    (
      stream: string,
      request: SyncPreparationRequest,
    ): SyncPreparationResult => {
      sweepPreparations(request.now);
      let row = preparationRow.get(request.id) as
        | {
            high: number;
            rows: number;
            done: number;
            expires_at: number;
            cursor_instance: number;
            cursor_written: number | null;
          }
        | undefined;
      if (row && row.expires_at <= request.now) {
        expirePreparation.run(request.id);
        throw new CursorExpiredError();
      }
      if (!row) {
        // A session that already started has lost its preparation:
        // expired, evicted or swept.
        if (request.high !== undefined) throw new CursorExpiredError();
        const high = readWriteClock();
        insertPreparation.run(
          request.id,
          request.owner,
          high,
          request.expiresAt,
        );
        evictPreparations.run(request.owner, request.now, request.maxPerOwner);
        row = {
          high,
          rows: 0,
          done: 0,
          expires_at: request.expiresAt,
          cursor_instance: 0,
          cursor_written: null,
        };
      }
      const low = request.low === null ? null : parseHorizon(request.low);
      const high = row.high;
      assertNotResetSince(request.instanceIds, [high, low ?? high]);
      const instanceIds = [...new Set(request.instanceIds)].sort();
      let rows = row.rows;
      let i = row.cursor_instance;
      // write sequence numbers start at 1, so 0 reads a first sync from the start
      let after = row.cursor_written ?? low ?? 0;
      let done = row.done === 1;
      const owner = ownerPreparations.get(request.owner, request.now) as {
        rows: number;
      };
      let ownerRows = owner.rows;
      while (!done) {
        if (i >= instanceIds.length) {
          done = true;
          break;
        }
        // One row at a time from the horizon index (each written_at is
        // unique), so a spent budget stops the scan at once.
        if (!request.budget.spend()) break;
        const write = preparationWrites.get(
          stream,
          instanceIds[i],
          after,
          high,
          1,
        ) as { id: number; record_key: string; written_at: number } | undefined;
        if (!write) {
          i += 1;
          after = low ?? 0;
          request.budget.progressed();
          continue;
        }
        after = write.written_at;
        if (
          addCandidate.run(request.id, write.record_key, instanceIds[i])
            .changes > 0
        ) {
          rows += 1;
          ownerRows += 1;
          if (ownerRows > request.maxRowsPerOwner) {
            expirePreparation.run(request.id);
            throw new CursorExpiredError();
          }
        }
        request.budget.progressed();
      }
      // Progress and candidates commit together.
      updatePreparation.run(
        rows,
        done ? 1 : 0,
        request.expiresAt,
        i,
        after,
        request.id,
      );
      return { high: String(high), done };
    },
  );

  function prepareSyncWindow(
    stream: string,
    request: SyncPreparationRequest,
  ): SyncPreparationResult {
    if (db.readonly) {
      throw new Error("a readonly store cannot prepare a sync window");
    }
    try {
      return prepareTx.immediate(stream, request);
    } catch (err) {
      // An expiry decided inside the transaction must survive its rollback.
      if (err instanceof CursorExpiredError) expirePreparation.run(request.id);
      throw err;
    }
  }

  const touchPreparation = lazy(
    "UPDATE pdpp_sync_preparation SET expires_at = ? WHERE id = ? AND expires_at > ?",
  );
  const touchTx = db.transaction(
    (id: string, expiresAt: number, now: number) => {
      sweepPreparations(now);
      touchPreparation.run(expiresAt <= now ? 0 : expiresAt, id, now);
    },
  );
  const sweepTx = db.transaction((now: number) => sweepPreparations(now));

  // A readonly handle cannot persist session state; it keeps it in process.
  const syncStates: SyncStateStore = db.readonly
    ? createMemorySyncStateStore()
    : sqliteSyncStates(db);

  function syncTokenScope(): SyncTokenScope {
    const row = db
      .prepare(
        "SELECT epoch, sync_token_key FROM pdpp_store_metadata WHERE id = 1",
      )
      .get() as { epoch: string; sync_token_key: string | null } | undefined;
    if (!row?.sync_token_key) throw new CursorExpiredError();
    return {
      epoch: row.epoch,
      key: new Uint8Array(Buffer.from(row.sync_token_key, "base64")),
    };
  }

  function listStreams(instanceIds: string[]): StreamListing[] {
    const placeholders = instanceIds.map(() => "?").join(",");
    const rows = db
      .prepare(
        // SQLite takes a bare column from the row that holds the single MAX.
        `SELECT stream, COUNT(*) as count, emitted_at as last_updated, MAX(emitted_key)
         FROM pdpp_records r WHERE deleted = 0 AND instance IN (${placeholders}) AND ${unquarantinedRecordSql("r")}

         GROUP BY stream`,
      )
      .all(...instanceIds) as Array<{
      stream: string;
      count: number;
      last_updated: string | null;
    }>;
    return rows.map((r) => ({
      stream: r.stream,
      recordCount: r.count,
      lastUpdated: r.last_updated,
    }));
  }

  function getBlobMeta(blobId: string): PdppBlobMeta | undefined {
    const row = getBlobStmt.get(blobId) as
      | {
          blob_id: string;
          mime_type: string;
          size_bytes: number;
          sha256: string;
        }
      | undefined;
    if (!row) return undefined;
    return {
      blobId: row.blob_id,
      mimeType: row.mime_type,
      sizeBytes: row.size_bytes,
      sha256: row.sha256,
    };
  }

  /** True only when a stored bytes row actually hash/size-matches `meta`. */
  function storedBytesVerify(meta: PdppBlobMeta): boolean {
    const row = getBlobBytesStmt.get(meta.blobId) as
      { bytes: Buffer } | undefined;
    if (!row) return false;
    const stored = new Uint8Array(row.bytes);
    if (stored.byteLength !== meta.sizeBytes) return false;
    return createHash("sha256").update(stored).digest("hex") === meta.sha256;
  }

  function storeBlobBytes(bytes: Uint8Array, mimeType: string): PdppBlobMeta {
    const blobId = blobIdForBytes(bytes);
    const sha256 = blobId.slice("sha256:".length);
    const candidate: PdppBlobMeta = {
      blobId,
      mimeType,
      sizeBytes: bytes.byteLength,
      sha256,
    };

    // The existing-row read and the write both happen inside one
    // transaction, not a check-then-upsert outside it -- otherwise two
    // concurrent writers for the same content could both see "no existing
    // row" and race to insert, or one could complete a metadata-only row
    // while another concurrently overwrites it.
    const run = db.transaction((): PdppBlobMeta => {
      const existing = getBlobMeta(blobId);

      if (existing) {
        if (
          existing.mimeType !== mimeType ||
          existing.sha256 !== sha256 ||
          existing.sizeBytes !== bytes.byteLength
        ) {
          throw new BlobConflictError(blobId, existing);
        }
        const bytesRow = getBlobBytesStmt.get(blobId) as
          { bytes: Buffer } | undefined;
        if (!bytesRow) {
          // Metadata-only row (legacy/test fixture via putBlobMeta, or a
          // prior write that never got this far): complete it with real
          // bytes now instead of reporting a false "already stored" no-op.
          insertBlobBytesStmt.run({
            blob_id: existing.blobId,
            bytes: Buffer.from(bytes),
          });
          return existing;
        }
        if (!storedBytesVerify(existing)) {
          // Bytes present but corrupt relative to their own metadata.
          // Refuse rather than report success over broken content, and
          // rather than silently repair -- the row stays exactly as it was
          // (the transaction makes no writes on this branch).
          throw new BlobConflictError(blobId, existing);
        }
        // Verified idempotent no-op: content and mimeType both match.
        return existing;
      }

      putBlobStmt.run({
        blob_id: candidate.blobId,
        mime_type: candidate.mimeType,
        size_bytes: candidate.sizeBytes,
        sha256: candidate.sha256,
      });
      insertBlobBytesStmt.run({
        blob_id: candidate.blobId,
        bytes: Buffer.from(bytes),
      });
      return candidate;
    });

    return run();
  }

  function storeBlobBytesForInstance(input: {
    instance: string;
    method: string;
    generation: number;
    bytes: Uint8Array;
    mimeType: string;
  }): PdppBlobMeta {
    return db.transaction(() => {
      const binding = ensureBinding(db, input.instance);
      if (binding.deleted_at !== null) {
        throw new PdppBindingError("connection_deleted");
      }
      if (binding.source_id === null) {
        throw new PdppBindingError("connection_required");
      }
      if (binding.generation !== input.generation) {
        throw new PdppBindingError("binding_generation_mismatch");
      }
      if (binding.method !== input.method) {
        throw new PdppBindingError("instance_bound_to_other_method");
      }
      const meta = storeBlobBytes(input.bytes, input.mimeType);
      db.prepare(
        `INSERT INTO pdpp_blob_claims (blob_id, instance, generation)
         VALUES (?, ?, ?)
         ON CONFLICT (blob_id, instance) DO UPDATE SET generation = excluded.generation`,
      ).run(meta.blobId, input.instance, input.generation);
      replica.captureBlob(input.instance, meta.blobId);
      replicaVisibilityObserver?.();
      return meta;
    })();
  }

  function getBlobBytes(blobId: string): Uint8Array<ArrayBuffer> | undefined {
    const meta = getBlobMeta(blobId);
    if (!meta) return undefined;
    const row = getBlobBytesStmt.get(blobId) as { bytes: Buffer } | undefined;
    if (!row) return undefined;
    const bytes = new Uint8Array(row.bytes);
    if (bytes.byteLength !== meta.sizeBytes) return undefined;
    const actualHash = createHash("sha256").update(bytes).digest("hex");
    if (actualHash !== meta.sha256) return undefined;
    return bytes as Uint8Array<ArrayBuffer>;
  }

  return {
    unquarantinedRecordSql,
    setReplicaVisibilityObserver: (observer: () => void) => {
      replicaVisibilityObserver = observer;
    },
    replication: replica.exporter,
    getInstallationWriterId: () => writerId,
    readMutationJournalPage,
    transitionClaudeToLive,
    claudeTransition,
    listClaudeTransitions,
    clearClaudeTransitionScope,
    confirmClaudeTransition,
    transitionWriteClock,
    listConnections,
    registerConnection,
    deleteConnection,
    ingestBatch,
    getInstanceBinding,
    readSnapshot: <T>(read: () => T): T => db.transaction(read).deferred(),
    resetInstanceBinding,
    storeBlobBytesForInstance,
    replaceStream,
    listStreamCompletions,
    completeStreams,
    listArrivalOrder,
    getRecord,
    listRecords,
    deleteRecord,
    readSyncWindow,
    syncTokenScope,
    syncStates: () => syncStates,
    prepareSyncWindow,
    touchSyncPreparation: (id, expiresAt, now) => {
      if (!db.readonly) touchTx.immediate(id, expiresAt, now);
    },
    sweepSyncPreparations: (now) => {
      if (!db.readonly) sweepTx.immediate(now);
    },
    inspectSyncState: () => {
      const count = (table: string) =>
        (
          db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get() as {
            n: number;
          }
        ).n;
      return {
        states: db.readonly ? 0 : count("pdpp_sync_state"),
        preparations: count("pdpp_sync_preparation"),
        candidates: count("pdpp_sync_candidate"),
      };
    },
    changesSince: (stream: string, options: ChangesSinceOptions) =>
      changesSince(stream, options),
    changesSinceForInstances: (
      stream: string,
      options: ChangesSinceOptions,
      visibleInstanceIds: string[],
    ) => changesSince(stream, options, visibleInstanceIds),
    listStreams,
    putBlobMeta: (meta: PdppBlobMeta) =>
      putBlobStmt.run({
        blob_id: meta.blobId,
        mime_type: meta.mimeType,
        size_bytes: meta.sizeBytes,
        sha256: meta.sha256,
      }),
    getBlobMeta,
    storeBlobBytes,
    getBlobBytes,
    findBlobReferences: (blobId: string) => {
      const rows = findBlobRefsStmt.all(blobId) as Array<{
        instance: string;
        stream: string;
        record_key: string;
      }>;
      return rows.map((row) => ({
        instance: row.instance,
        stream: row.stream,
        recordKey: row.record_key,
      }));
    },
    close: () => db.close(),
  };
}
