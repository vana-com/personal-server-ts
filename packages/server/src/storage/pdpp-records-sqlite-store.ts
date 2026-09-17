import type { Database } from "better-sqlite3";
import {
  encodeRecordKey,
  keyMatchesData,
  RecordKeyError,
  decodeCursor,
  encodeCursor,
  InvalidCursorSyntaxError,
  CursorExpiredError,
  InvalidCursorError,
  type PdppRecordStore,
  type ChangesSinceOptions,
  type ChangesSincePage,
  type IngestResult,
  type ListRecordsOptions,
  type ListRecordsPage,
  type PdppBlobMeta,
  type PdppRecordEnvelopeInput,
  type PdppRecordRow,
  type PdppStoredRecord,
  type StreamListing,
  type StreamSemantics,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";

/**
 * Schema migrations for the desktop SQLite backend of the PDPP record
 * persistence index, applied in order and tracked in `pdpp_schema_version`
 * so re-opening an existing database never re-runs or reinterprets an
 * already-applied migration (C7: "no schema version, no ALTER path").
 *
 * `pdpp_records` holds current state (one row per instance+stream+record_key).
 * `pdpp_record_changes` holds full version history for mutable_state streams
 * (append_only streams only ever have one history row per key, at version 1,
 * since duplicates are no-ops). `pdpp_blobs` holds binary payload metadata
 * only; actual bytes storage is out of scope for this table.
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
export function createSqliteRecordStore(db: Database): PdppRecordStore {
  db.pragma("journal_mode = WAL");
  migrate(db);

  const nextWriteSeq = db.prepare(
    "UPDATE pdpp_write_clock SET value = value + 1 WHERE id = 1 RETURNING value",
  );

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
  const findBlobRefStmt = db.prepare(
    "SELECT instance, stream, record_key FROM pdpp_records WHERE blob_id = ? AND deleted = 0 LIMIT 1",
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
    streamSemantics: (stream: string) => StreamSemantics,
    primaryKeyFields: (stream: string) => string[],
  ): IngestResult {
    const rejected: IngestResult["rejected"] = [];
    let accepted = 0;

    // The whole batch is one SQLite transaction: a failure partway rolls
    // back every write from this call, never leaving partial version/
    // record_changes state (validation rejections below don't count as
    // "failure" — they're recorded and the transaction proceeds with the
    // remaining valid envelopes).
    const runBatch = db.transaction(() => {
      envelopes.forEach((envelope, index) => {
        try {
          const semantics = streamSemantics(envelope.stream);
          const pkFields = primaryKeyFields(envelope.stream);
          const recordKeyStr = encodeRecordKey(envelope.key);

          if (envelope.op === "delete") {
            if (semantics === "append_only") {
              rejected.push({
                index,
                reason: "append_only streams do not support delete directives",
              });
              return;
            }
            const version =
              latestVersion(envelope.instance, envelope.stream, recordKeyStr) +
              1;
            const writtenAt = nextWriteSeq.get() as { value: number };
            upsertCurrentStmt.run({
              instance: envelope.instance,
              stream: envelope.stream,
              record_key: recordKeyStr,
              data: null,
              version,
              emitted_at: envelope.emitted_at,
              deleted: 1,
              deleted_at: envelope.emitted_at,
              blob_id: null,
            });
            insertHistoryStmt.run({
              instance: envelope.instance,
              stream: envelope.stream,
              record_key: recordKeyStr,
              version,
              data: null,
              emitted_at: envelope.emitted_at,
              deleted: 1,
              deleted_at: envelope.emitted_at,
              written_at: writtenAt.value,
            });
            accepted += 1;
            return;
          }

          if (!envelope.data) {
            rejected.push({ index, reason: "data is required for upsert" });
            return;
          }

          if (!keyMatchesData(envelope.key, envelope.data, pkFields)) {
            rejected.push({
              index,
              reason:
                "envelope key does not match data's declared primary_key fields",
            });
            return;
          }

          const existing = getCurrentStmt.get(
            envelope.instance,
            envelope.stream,
            recordKeyStr,
          ) as RecordRowDb | undefined;

          if (semantics === "append_only" && existing) {
            // Duplicate key on append_only is a no-op, not an error.
            return;
          }

          const version =
            latestVersion(envelope.instance, envelope.stream, recordKeyStr) + 1;
          const writtenAt = nextWriteSeq.get() as { value: number };
          const dataJson = JSON.stringify(envelope.data);
          upsertCurrentStmt.run({
            instance: envelope.instance,
            stream: envelope.stream,
            record_key: recordKeyStr,
            data: dataJson,
            version,
            emitted_at: envelope.emitted_at,
            deleted: 0,
            deleted_at: null,
            blob_id: extractBlobId(envelope.data),
          });
          insertHistoryStmt.run({
            instance: envelope.instance,
            stream: envelope.stream,
            record_key: recordKeyStr,
            version,
            data: dataJson,
            emitted_at: envelope.emitted_at,
            deleted: 0,
            deleted_at: null,
            written_at: writtenAt.value,
          });
          accepted += 1;
        } catch (err) {
          rejected.push({
            index,
            reason: err instanceof RecordKeyError ? err.message : String(err),
          });
        }
      });
    });

    runBatch();
    return { accepted, rejected };
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

  function listRecords(
    stream: string,
    options: ListRecordsOptions,
  ): ListRecordsPage {
    let startAfter: { val: string; key: string } | null = null;
    if (options.cursor) {
      const payload = decodeCursor(options.cursor);
      if (payload.kind !== "list") throw new InvalidCursorError();
      if (payload.order !== options.order) throw new InvalidCursorError();
      startAfter = { val: payload.sortValue ?? "", key: payload.recordKey };
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
            })
          : undefined,
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
      horizon = Number(payload.horizon);
      sinceHorizon =
        payload.sinceHorizon !== null ? Number(payload.sinceHorizon) : null;
      offset = payload.offset;
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
      sinceHorizon = Number(payload.horizon);
      horizon = (nextWriteSeq.get() as { value: number }).value;
    } else {
      sinceHorizon = null;
      horizon = (nextWriteSeq.get() as { value: number }).value;
    }

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

  return {
    ingestBatch,
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
    getBlobMeta: (blobId: string) => {
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
    },
    findBlobReference: (blobId: string) => {
      const row = findBlobRefStmt.get(blobId) as
        { instance: string; stream: string; record_key: string } | undefined;
      if (!row) return undefined;
      return {
        instance: row.instance,
        stream: row.stream,
        recordKey: row.record_key,
      };
    },
    close: () => db.close(),
  };
}
