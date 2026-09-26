import type { Database } from "better-sqlite3";
import { createHash } from "node:crypto";
import {
  encodeRecordKey,
  planIngest,
  RecordKeyError,
  summarizeIngest,
  decodeCursor,
  encodeCursor,
  InvalidCursorSyntaxError,
  CursorExpiredError,
  InvalidCursorError,
  BlobConflictError,
  type PdppRecordStore,
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
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";

export interface PdppInstanceBinding {
  instance: string;
  method: string | null;
  generation: number;
  resetClock: number;
  empty?: boolean;
}

/** Outcome of a P7 stream replace. `applied: false` means nothing was written. */
export interface ReplaceStreamResult extends IngestResult {
  applied: boolean;
  /** Live keys tombstoned because the snapshot lacked them. */
  deleted: number;
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
];

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
    db.exec(`
      DELETE FROM pdpp_blob_claims
      WHERE NOT EXISTS (
        SELECT 1 FROM pdpp_instance_binding b
        WHERE b.instance = pdpp_blob_claims.instance
          AND b.generation = pdpp_blob_claims.generation
      );
    `);
    deleteUnclaimedBlobs(db);
  })();
}

function deleteUnclaimedBlobs(db: Database): void {
  db.exec(`
    DELETE FROM pdpp_blob_bytes
    WHERE blob_id IN (
      SELECT blob_id FROM pdpp_blobs b
      WHERE NOT EXISTS (SELECT 1 FROM pdpp_blob_claims c WHERE c.blob_id = b.blob_id)
        AND NOT EXISTS (SELECT 1 FROM pdpp_records r WHERE r.blob_id = b.blob_id AND r.deleted = 0)
    );
    DELETE FROM pdpp_blobs
    WHERE NOT EXISTS (SELECT 1 FROM pdpp_blob_claims c WHERE c.blob_id = pdpp_blobs.blob_id)
      AND NOT EXISTS (SELECT 1 FROM pdpp_records r WHERE r.blob_id = pdpp_blobs.blob_id AND r.deleted = 0);
  `);
}

interface BindingRowDb {
  instance: string;
  method: string | null;
  generation: number;
  reset_clock: number;
}

function toBinding(row: BindingRowDb): PdppInstanceBinding {
  return {
    instance: row.instance,
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
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new InvalidCursorError();
  }
  return value;
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

function projectFields(
  data: Record<string, unknown>,
  fields: string[] | undefined,
): Record<string, unknown> {
  if (!fields) return data;
  const projected: Record<string, unknown> = {};
  for (const field of fields) {
    if (field in data) projected[field] = data[field];
  }
  return projected;
}

/**
 * SQLite-backed PdppRecordStore for desktop persistence. Requires
 * `better-sqlite3` (already a `packages/server` dependency in this repo).
 */
export function createSqliteRecordStore(db: Database): PdppRecordStore & {
  getInstanceBinding(instance: string): PdppInstanceBinding;
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
  }): ReplaceStreamResult;
} {
  db.pragma("journal_mode = WAL");
  migrate(db);
  sweepStaleBlobClaims(db);

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
    INSERT INTO pdpp_records (instance, stream, record_key, data, version, emitted_at, deleted, deleted_at, blob_id)
    VALUES (@instance, @stream, @record_key, @data, @version, @emitted_at, @deleted, @deleted_at, @blob_id)
    ON CONFLICT (instance, stream, record_key) DO UPDATE SET
      data = excluded.data,
      version = excluded.version,
      emitted_at = excluded.emitted_at,
      deleted = excluded.deleted,
      deleted_at = excluded.deleted_at,
      blob_id = excluded.blob_id
  `);
  const insertHistoryStmt = db.prepare(`
    INSERT INTO pdpp_record_changes
      (instance, stream, record_key, version, data, emitted_at, deleted, deleted_at, written_at)
    VALUES (@instance, @stream, @record_key, @version, @data, @emitted_at, @deleted, @deleted_at, @written_at)
  `);
  const putBlobStmt = db.prepare(`
    INSERT INTO pdpp_blobs (blob_id, mime_type, size_bytes, sha256)
    VALUES (@blob_id, @mime_type, @size_bytes, @sha256)
    ON CONFLICT (blob_id) DO UPDATE SET
      mime_type = excluded.mime_type, size_bytes = excluded.size_bytes, sha256 = excluded.sha256
  `);
  const getBlobStmt = db.prepare("SELECT * FROM pdpp_blobs WHERE blob_id = ?");
  const findBlobRefsStmt = db.prepare(
    "SELECT instance, stream, record_key FROM pdpp_records WHERE blob_id = ? AND deleted = 0",
  );
  const insertBlobBytesStmt = db.prepare(
    "INSERT INTO pdpp_blob_bytes (blob_id, bytes) VALUES (@blob_id, @bytes)",
  );
  const getBlobBytesStmt = db.prepare(
    "SELECT bytes FROM pdpp_blob_bytes WHERE blob_id = ?",
  );

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
      let shouldBind = false;
      if (binding && envelopes.length > 0) {
        shouldBind = checkBinding(
          binding.method,
          binding.generation,
          envelopes,
        );
      } else if (envelopes.length > 0) {
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
      let wroteAny = false;
      envelopes.forEach((envelope, index) => {
        const plan = planIngest(
          index,
          envelope,
          streamSemantics(envelope.stream, envelope.instance),
          primaryKeyFields(envelope.stream, envelope.instance),
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
        if (!plan.write) return;

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
        wroteAny = true;
        writeVersion(
          envelope.instance,
          envelope.stream,
          recordKey,
          data,
          envelope.emitted_at,
        );
      });
      if (shouldBind && binding && wroteAny) {
        bindMethod(envelopes[0].instance, binding);
      }
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
    const deleted = data === null;
    const version = latestVersion(instance, stream, recordKey) + 1;
    const writtenAt = nextWriteSeq.get() as { value: number };
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

  function bindMethod(
    instance: string,
    binding: { method: string; generation: number },
  ): void {
    db.prepare(
      "UPDATE pdpp_instance_binding SET method = ? WHERE instance = ? AND generation = ? AND method IS NULL",
    ).run(binding.method, instance, binding.generation);
  }

  // P7: the records are the complete live set of (instance, stream) from a
  // covered full refresh by the bound method. Under Q1 every live row of the
  // instance was written by that method in this generation, so a live key the
  // snapshot lacks has no other evidence and is tombstoned. Any rejected
  // record rejects the whole request before anything is written.
  function replaceStream(input: {
    instance: string;
    stream: string;
    method: string;
    generation: number;
    emittedAt: string;
    envelopes: PdppRecordEnvelopeInput[];
    primaryKey: string[];
    validateData?: RecordDataValidator;
  }): ReplaceStreamResult {
    return db.transaction((): ReplaceStreamResult => {
      const shouldBind = checkInstanceBinding(
        input.instance,
        input.method,
        input.generation,
      );

      const seen = new Set<string>();
      const results: IngestOutcome[] = [];
      const writes: {
        recordKey: string;
        data: Record<string, unknown>;
        emittedAt: string;
      }[] = [];
      input.envelopes.forEach((envelope, index) => {
        const reject = (reason: string) =>
          results.push({ index, outcome: "rejected", reason });
        if (envelope.op === "delete") {
          return reject("replace records must be upserts");
        }
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
        if (!plan.write) return void results.push(plan.outcome);
        const blobId = extractBlobId(plan.write.data);
        if (blobId && !blobClaimedByCurrentGeneration(blobId, input.instance)) {
          return reject("blob_unclaimed");
        }
        results.push(plan.outcome);
        writes.push({
          recordKey,
          data: plan.write.data!,
          emittedAt: envelope.emitted_at,
        });
      });

      const summary = summarizeIngest(results);
      if (summary.rejected.length > 0) {
        return { ...summary, applied: false, deleted: 0 };
      }

      for (const write of writes) {
        writeVersion(
          input.instance,
          input.stream,
          write.recordKey,
          write.data,
          write.emittedAt,
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
      }
      if (shouldBind && (writes.length > 0 || missing.length > 0)) {
        bindMethod(input.instance, input);
      }
      return { ...summary, applied: true, deleted: missing.length };
    })();
  }

  function checkBinding(
    method: string,
    generation: number,
    envelopes: PdppRecordEnvelopeInput[],
  ): boolean {
    const instances = new Set(envelopes.map((envelope) => envelope.instance));
    if (instances.size !== 1) throw new PdppBindingError("invalid_request");
    return checkInstanceBinding([...instances][0], method, generation);
  }

  /** P8a checks (2) and (3); true when this write binds an empty instance. */
  function checkInstanceBinding(
    instance: string,
    method: string,
    generation: number,
  ): boolean {
    // Only a named method may bind or write; an empty one would bind "".
    if (typeof method !== "string" || method.length === 0) {
      throw new PdppBindingError("method_required");
    }
    const current = ensureBinding(db, instance);
    if (current.generation !== generation) {
      throw new PdppBindingError("binding_generation_mismatch");
    }
    if (current.method === method) return false;
    if (current.method !== null) {
      throw new PdppBindingError("instance_bound_to_other_method");
    }
    if (instanceHasRecords(db, instance)) {
      throw new PdppBindingError("binding_required");
    }
    return true;
  }

  // Read-only: an instance with no row reports the row `ensureBinding` would
  // create, without creating it.
  function getInstanceBinding(instance: string): PdppInstanceBinding {
    const row = (db
      .prepare("SELECT * FROM pdpp_instance_binding WHERE instance = ?")
      .get(instance) as BindingRowDb | undefined) ?? {
      instance,
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

      db.prepare("DELETE FROM pdpp_records WHERE instance = ?").run(
        input.instance,
      );
      db.prepare("DELETE FROM pdpp_record_changes WHERE instance = ?").run(
        input.instance,
      );
      db.prepare("DELETE FROM pdpp_blob_claims WHERE instance = ?").run(
        input.instance,
      );
      deleteUnclaimedBlobs(db);
      const resetClock = (nextWriteSeq.get() as { value: number }).value;
      db.prepare(
        "UPDATE pdpp_instance_binding SET method = ?, generation = ?, reset_clock = ? WHERE instance = ?",
      ).run(
        input.nextMethod,
        input.expectedGeneration + 1,
        resetClock,
        input.instance,
      );
      return {
        binding: toBinding(ensureBinding(db, input.instance)),
        alreadyReset: false,
      };
    })();
  }

  function getRecord(
    instance: string,
    stream: string,
    recordKey: string,
  ): PdppStoredRecord | undefined {
    const row = getCurrentStmt.get(instance, stream, recordKey) as
      RecordRowDb | undefined;
    if (!row || row.deleted) return undefined;
    return toRow(row) as PdppStoredRecord;
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

  function listRecords(
    stream: string,
    options: ListRecordsOptions,
  ): ListRecordsPage {
    let startAfter: { val: string; key: string } | null = null;
    let horizon: number;
    if (options.cursor) {
      const payload = decodeCursor(options.cursor);
      if (payload.kind !== "list") throw new InvalidCursorError();
      if (payload.order !== options.order) throw new InvalidCursorError();
      const cursorHorizon =
        payload.horizon === undefined ? null : parseHorizon(payload.horizon);
      assertNotResetSince(options.instanceIds, [cursorHorizon]);
      // A legacy cursor that survives the fence read no reset instance; it
      // is anchored at the current clock from here on.
      horizon = cursorHorizon ?? readWriteClock();
      startAfter = { val: payload.sortValue ?? "", key: payload.recordKey };
    } else {
      horizon = readWriteClock();
    }

    const placeholders = options.instanceIds.map(() => "?").join(",");
    const dir = options.order === "asc" ? "ASC" : "DESC";
    const cmp = options.order === "asc" ? ">" : "<";

    let sql = `
      SELECT * FROM pdpp_records
      WHERE stream = ? AND deleted = 0 AND instance IN (${placeholders})
    `;
    const params: unknown[] = [stream, ...options.instanceIds];
    if (startAfter) {
      sql += ` AND (emitted_at ${cmp} ? OR (emitted_at = ? AND record_key ${cmp} ?))`;
      params.push(startAfter.val, startAfter.val, startAfter.key);
    }
    sql += ` ORDER BY emitted_at ${dir}, record_key ${dir} LIMIT ?`;
    params.push(options.limit + 1);

    const rows = db.prepare(sql).all(...params) as RecordRowDb[];
    const hasMore = rows.length > options.limit;
    const page = rows.slice(0, options.limit);
    const last = page[page.length - 1];

    return {
      data: page.map((row) => {
        const stored = toRow(row) as PdppStoredRecord;
        return { ...stored, data: projectFields(stored.data, options.fields) };
      }),
      hasMore,
      nextCursor:
        hasMore && last
          ? encodeCursor({
              kind: "list",
              order: options.order,
              sortValue: last.emitted_at,
              recordKey: last.record_key,
              horizon: String(horizon),
            })
          : undefined,
      horizon: String(horizon),
    };
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
      result = true;
    });
    run();
    return result;
  }

  function changesSince(
    stream: string,
    options: ChangesSinceOptions,
  ): ChangesSincePage {
    let horizon: number;
    let sinceHorizon: number | null;
    let offset = 0;

    if (options.cursor) {
      const payload = decodeCursor(options.cursor);
      if (payload.kind !== "changes_since") throw new InvalidCursorError();
      horizon = parseHorizon(payload.horizon);
      sinceHorizon =
        payload.sinceHorizon !== null
          ? parseHorizon(payload.sinceHorizon)
          : null;
      offset = parseOffset(payload.offset);
    } else if (options.changesSince) {
      let payload;
      try {
        payload = decodeCursor(options.changesSince);
      } catch (err) {
        if (err instanceof InvalidCursorSyntaxError)
          throw new CursorExpiredError();
        throw err;
      }
      if (payload.kind !== "changes_since") throw new InvalidCursorError();
      sinceHorizon = parseHorizon(payload.horizon);
      horizon = (nextWriteSeq.get() as { value: number }).value;
    } else {
      sinceHorizon = null;
      horizon = (nextWriteSeq.get() as { value: number }).value;
    }

    assertNotResetSince(options.instanceIds, [
      horizon,
      sinceHorizon ?? horizon,
    ]);

    const placeholders = options.instanceIds.map(() => "?").join(",");

    // Latest history row per key, as of the horizon.
    const latestRows = db
      .prepare(
        `
        SELECT c.* FROM pdpp_record_changes c
        WHERE c.stream = ? AND c.instance IN (${placeholders}) AND c.written_at <= ?
        AND c.version = (
          SELECT MAX(c2.version) FROM pdpp_record_changes c2
          WHERE c2.stream = c.stream AND c2.instance = c.instance
            AND c2.record_key = c.record_key AND c2.written_at <= ?
        )
      `,
      )
      .all(stream, ...options.instanceIds, horizon, horizon) as Array<{
      instance: string;
      stream: string;
      record_key: string;
      version: number;
      data: string | null;
      emitted_at: string;
      deleted: number;
      deleted_at: string | null;
      written_at: number;
    }>;

    const changed: PdppRecordRow[] = [];
    for (const entry of latestRows) {
      if (sinceHorizon !== null) {
        const wroteSincePrior = db
          .prepare(
            `SELECT 1 FROM pdpp_record_changes
             WHERE stream = ? AND instance = ? AND record_key = ?
             AND written_at > ? AND written_at <= ? LIMIT 1`,
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

      if (entry.deleted) {
        changed.push({
          instance: entry.instance,
          stream: entry.stream,
          recordKey: entry.record_key,
          version: entry.version,
          deletedAt: entry.deleted_at ?? entry.emitted_at,
          emittedAt: entry.emitted_at,
          deleted: true,
        });
        continue;
      }

      const currentData = entry.data ? JSON.parse(entry.data) : {};
      const projectedNow = projectFields(currentData, options.fields);

      if (sinceHorizon !== null && options.fields) {
        const priorRow = db
          .prepare(
            `SELECT * FROM pdpp_record_changes
             WHERE stream = ? AND instance = ? AND record_key = ? AND written_at <= ?
             ORDER BY version DESC LIMIT 1`,
          )
          .get(entry.stream, entry.instance, entry.record_key, sinceHorizon) as
          { data: string | null; deleted: number } | undefined;
        if (priorRow && !priorRow.deleted) {
          const priorData = priorRow.data ? JSON.parse(priorRow.data) : {};
          const priorProjected = projectFields(priorData, options.fields);
          if (JSON.stringify(priorProjected) === JSON.stringify(projectedNow)) {
            continue;
          }
        }
      }

      // Return the RAW (unprojected) data here, not `projectedNow`.
      // `projectedNow`/`priorProjected` above exist only to decide
      // eligibility (did the grant-authorized projection change) without
      // leaking a hidden-field change. A caller enforcing time_constraint
      // against `data` needs the real field value; projecting here would
      // silently break that filter for any grant whose fields don't happen
      // to include the time_constraint field. Response field projection is
      // the caller's job, applied after any filtering on real values.
      changed.push({
        instance: entry.instance,
        stream: entry.stream,
        recordKey: entry.record_key,
        data: currentData,
        version: entry.version,
        emittedAt: entry.emitted_at,
        deleted: false,
      });
    }

    changed.sort((a, b) => a.recordKey.localeCompare(b.recordKey));
    const page = changed.slice(offset, offset + options.limit);
    const hasMore = offset + options.limit < changed.length;

    return {
      data: page,
      hasMore,
      nextCursor: hasMore
        ? encodeCursor({
            kind: "changes_since",
            horizon: String(horizon),
            sinceHorizon: sinceHorizon !== null ? String(sinceHorizon) : null,
            offset: offset + options.limit,
          })
        : undefined,
      nextChangesSince: hasMore
        ? undefined
        : encodeCursor({
            kind: "changes_since",
            horizon: String(horizon),
            sinceHorizon: null,
            offset: 0,
          }),
    };
  }

  function listStreams(instanceIds: string[]): StreamListing[] {
    const placeholders = instanceIds.map(() => "?").join(",");
    const rows = db
      .prepare(
        `SELECT stream, COUNT(*) as count, MAX(emitted_at) as last_updated
         FROM pdpp_records WHERE deleted = 0 AND instance IN (${placeholders})
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
      if (binding.generation !== input.generation) {
        throw new PdppBindingError("binding_generation_mismatch");
      }
      if (binding.method !== input.method) {
        if (binding.method !== null) {
          throw new PdppBindingError("instance_bound_to_other_method");
        }
        if (instanceHasRecords(db, input.instance)) {
          throw new PdppBindingError("binding_required");
        }
      }
      const meta = storeBlobBytes(input.bytes, input.mimeType);
      db.prepare(
        `INSERT INTO pdpp_blob_claims (blob_id, instance, generation)
         VALUES (?, ?, ?)
         ON CONFLICT (blob_id, instance) DO UPDATE SET generation = excluded.generation`,
      ).run(meta.blobId, input.instance, input.generation);
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
    ingestBatch,
    getInstanceBinding,
    resetInstanceBinding,
    storeBlobBytesForInstance,
    replaceStream,
    getRecord,
    listRecords,
    deleteRecord,
    changesSince,
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
