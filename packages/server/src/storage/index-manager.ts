import type Database from "better-sqlite3";
import { createHash, randomUUID } from "node:crypto";
import {
  closeSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import type {
  IndexEntry,
  IndexListOptions,
  NewIndexEntry,
  ScopeSummary,
} from "@opendatalabs/personal-server-ts-core/storage/index";

export interface IndexManager {
  insert(entry: NewIndexEntry): IndexEntry;
  insertIfCurrent(
    entry: NewIndexEntry,
    precondition?: { kind: "none" } | { kind: "match"; version: number },
  ):
    | { ok: true; entry: IndexEntry }
    | {
        ok: false;
        currentVersion: number | null;
        currentProducer: string | null;
      };
  closeScopeForWrites(scope: string): void;
  insertRecovered(entry: NewIndexEntry): IndexEntry;
  findByPath(path: string): IndexEntry | undefined;
  findByScope(options: IndexListOptions): IndexEntry[];
  findLatestByScope(scope: string): IndexEntry | undefined;
  countByScope(scope: string): number;
  deleteByPath(path: string): boolean;
  /**
   * Delete a row by path ONLY if it is still unsynced (`data_point_id IS NULL`).
   * Atomic guard against a TOCTOU: a row that became synced after the caller
   * selected it must keep its metadata (the gateway/on-chain state references
   * it). Returns true only when an unsynced row was actually removed.
   */
  deleteUnsyncedByPath(path: string): boolean;
  listDistinctScopes(options?: {
    scopePrefix?: string;
    limit?: number;
    offset?: number;
  }): { scopes: ScopeSummary[]; total: number };
  listIndexedScopes(): string[];
  findClosestByScope(scope: string, at: string): IndexEntry | undefined;
  findByFileId(fileId: string): IndexEntry | undefined;
  /** Find an index entry by its DPv2 data-point id (download dedup). */
  findByDataPointId(dataPointId: string): IndexEntry | undefined;
  /**
   * Find all index entries where dataPointId is null (not yet synced /
   * registered on-chain). Returns entries ordered by created_at ASC (oldest
   * first).
   */
  findUnsynced(options?: { limit?: number }): IndexEntry[];
  /**
   * Update the fileId for an index entry (after successful upload + on-chain registration).
   * @returns true if row was updated, false if path not found
   */
  updateFileId(path: string, fileId: string): boolean;
  /** Highest DPv2 sync version for a scope; 0 if none. */
  findLatestVersionByScope(scope: string): number;
  /**
   * Update the dataPointId for an index entry (after DPv2 registerDataPoint).
   * @returns true if row was updated, false if path not found
   */
  updateDataPointId(path: string, dataPointId: string): boolean;
  /**
   * Update the DPv2 `version` for an index entry (upload-worker rebase after
   * a stale-expectedVersion conflict).
   * @returns true if row was updated, false if path not found
   */
  updateVersion(path: string, version: number): boolean;
  /** Deletes all index entries for a scope. Returns count of deleted rows. */
  deleteByScope(scope: string): number;
  close(): void;
}

interface RawRow {
  id: number;
  file_id: string | null;
  schema_id: string | null;
  path: string;
  scope: string;
  collected_at: string;
  created_at: string;
  size_bytes: number;
  version: number;
  cas_revision: number;
  data_point_id: string | null;
  after_tombstone_version: number | null;
  producer: "pdpp-projector" | "pdpp-import-projection" | null;
  producer_provenance: string | null;
}

function rowToEntry(row: RawRow): IndexEntry {
  return {
    id: row.id,
    fileId: row.file_id,
    schemaId: row.schema_id,
    path: row.path,
    scope: row.scope,
    collectedAt: row.collected_at,
    createdAt: row.created_at,
    sizeBytes: row.size_bytes,
    version: row.version,
    casRevision: row.cas_revision,
    dataPointId: row.data_point_id,
    afterTombstoneVersion: row.after_tombstone_version ?? null,
    producer: row.producer,
    producerProvenance: row.producer_provenance,
  };
}

export function createIndexManager(
  db: Database.Database,
  options?: { revisionJournalDir?: string },
): IndexManager {
  const revisionJournalDir = options?.revisionJournalDir;
  if (revisionJournalDir) mkdirSync(revisionJournalDir, { recursive: true });

  const journalPath = (scope: string): string =>
    join(
      revisionJournalDir!,
      `${createHash("sha256").update(scope).digest("hex")}.revision`,
    );
  const closedMarkerPath = (scope: string): string =>
    `${journalPath(scope)}.closed`;
  const readJournal = (scope: string): number => {
    if (!revisionJournalDir) return 0;
    let value: string;
    try {
      value = readFileSync(journalPath(scope), "utf8");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return 0;
      throw error;
    }
    const revision = Number(value);
    if (!/^(0|[1-9]\d*)$/.test(value) || !Number.isSafeInteger(revision)) {
      throw new Error(`Invalid CAS revision journal for ${scope}`);
    }
    return revision;
  };
  const reserveJournal = (scope: string, revision: number): void => {
    if (!revisionJournalDir || revision <= readJournal(scope)) return;
    const path = journalPath(scope);
    const staged = `${path}.pending.${randomUUID()}`;
    const file = openSync(staged, "wx");
    try {
      writeFileSync(file, String(revision));
      fsyncSync(file);
    } finally {
      closeSync(file);
    }
    renameSync(staged, path);
    const dir = openSync(revisionJournalDir, "r");
    try {
      fsyncSync(dir);
    } finally {
      closeSync(dir);
    }
  };
  const reserveClosedMarker = (scope: string): void => {
    if (!revisionJournalDir) return;
    const path = closedMarkerPath(scope);
    try {
      readFileSync(path);
      return;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    const staged = `${path}.pending.${randomUUID()}`;
    const file = openSync(staged, "wx");
    try {
      writeFileSync(file, "closed\n");
      fsyncSync(file);
    } finally {
      closeSync(file);
    }
    renameSync(staged, path);
    const dir = openSync(revisionJournalDir, "r");
    try {
      fsyncSync(dir);
    } finally {
      closeSync(dir);
    }
  };

  // The index can be reconstructed from envelopes. Keep a separate durable
  // high-water mark so reconstruction cannot reuse a deleted CAS version.
  if (revisionJournalDir) {
    const existing = db
      .prepare("SELECT scope, cas_revision FROM scope_revisions")
      .all() as Array<{ scope: string; cas_revision: number }>;
    for (const row of existing) reserveJournal(row.scope, row.cas_revision);
  }
  const insertStmt = db.prepare<{
    file_id: string | null;
    schema_id: string | null;
    path: string;
    scope: string;
    collected_at: string;
    size_bytes: number;
    version: number;
    cas_revision: number;
    data_point_id: string | null;
    after_tombstone_version: number | null;
    producer: string | null;
    producer_provenance: string | null;
  }>(
    `INSERT INTO data_files (file_id, schema_id, path, scope, collected_at, size_bytes, version, cas_revision, data_point_id, after_tombstone_version, producer, producer_provenance)
     VALUES (@file_id, @schema_id, @path, @scope, @collected_at, @size_bytes, @version, @cas_revision, @data_point_id, @after_tombstone_version, @producer, @producer_provenance)`,
  );

  const maxVersionByScopeStmt = db.prepare<{ scope: string }>(
    "SELECT COALESCE(MAX(version), 0) AS max_version FROM data_files WHERE scope = @scope",
  );

  const findByPathStmt = db.prepare<{ path: string }>(
    "SELECT * FROM data_files WHERE path = @path",
  );

  const findLatestByScopeStmt = db.prepare<{ scope: string }>(
    "SELECT * FROM data_files WHERE scope = @scope ORDER BY julianday(collected_at) DESC, id DESC LIMIT 1",
  );
  const currentForWriteStmt = db.prepare<{ scope: string }>(
    `SELECT
       latest.cas_revision,
       latest.producer,
       revisions.closed_for_writes
     FROM scope_revisions revisions
     LEFT JOIN (
       SELECT cas_revision, producer
       FROM data_files
       WHERE scope = @scope
       ORDER BY julianday(collected_at) DESC, id DESC
       LIMIT 1
     ) latest ON 1 = 1
     WHERE revisions.scope = @scope`,
  );

  const countByScopeStmt = db.prepare<{ scope: string }>(
    "SELECT COUNT(*) AS cnt FROM data_files WHERE scope = @scope",
  );

  const deleteByPathStmt = db.prepare<{ path: string }>(
    "DELETE FROM data_files WHERE path = @path",
  );
  const deleteUnsyncedByPathStmt = db.prepare<{ path: string }>(
    "DELETE FROM data_files WHERE path = @path AND data_point_id IS NULL",
  );

  const findClosestByScopeStmt = db.prepare<{ scope: string; at: string }>(
    "SELECT * FROM data_files WHERE scope = @scope AND collected_at <= @at ORDER BY collected_at DESC LIMIT 1",
  );
  const listIndexedScopesStmt = db.prepare(
    "SELECT DISTINCT scope FROM data_files ORDER BY scope ASC",
  );

  const findByFileIdStmt = db.prepare<{ file_id: string }>(
    "SELECT * FROM data_files WHERE file_id = @file_id",
  );

  const findByDataPointIdStmt = db.prepare<{ data_point_id: string }>(
    "SELECT * FROM data_files WHERE data_point_id = @data_point_id",
  );

  const findUnsyncedStmt = db.prepare(
    "SELECT * FROM data_files WHERE data_point_id IS NULL ORDER BY created_at ASC",
  );

  const findUnsyncedLimitStmt = db.prepare<{ limit: number }>(
    "SELECT * FROM data_files WHERE data_point_id IS NULL ORDER BY created_at ASC LIMIT @limit",
  );

  const updateFileIdStmt = db.prepare<{ file_id: string; path: string }>(
    "UPDATE data_files SET file_id = @file_id WHERE path = @path",
  );

  const updateDataPointIdStmt = db.prepare<{
    data_point_id: string;
    path: string;
  }>("UPDATE data_files SET data_point_id = @data_point_id WHERE path = @path");

  const updateVersionStmt = db.prepare<{ version: number; path: string }>(
    "UPDATE data_files SET version = @version WHERE path = @path",
  );

  const ensureScopeRevisionStmt = db.prepare<{ scope: string }>(
    "INSERT OR IGNORE INTO scope_revisions (scope, cas_revision, closed_for_writes) VALUES (@scope, 0, 0)",
  );

  const readScopeRevisionStmt = db.prepare<{ scope: string }>(
    "SELECT cas_revision FROM scope_revisions WHERE scope = @scope",
  );

  const updateScopeRevisionStmt = db.prepare<{
    scope: string;
    cas_revision: number;
  }>(
    "UPDATE scope_revisions SET cas_revision = @cas_revision WHERE scope = @scope AND cas_revision < @cas_revision",
  );
  const closeScopeForWritesStmt = db.prepare<{ scope: string }>(
    "UPDATE scope_revisions SET closed_for_writes = 1 WHERE scope = @scope",
  );

  const deleteByScopeStmt = db.prepare<{ scope: string }>(
    "DELETE FROM data_files WHERE scope = @scope",
  );

  const insertRow = (entry: NewIndexEntry): IndexEntry => {
    ensureScopeRevisionStmt.run({ scope: entry.scope });
    const current = readScopeRevisionStmt.get({ scope: entry.scope }) as {
      cas_revision: number;
    };
    const casRevision =
      entry.casRevision ??
      Math.max(current.cas_revision, readJournal(entry.scope)) + 1;
    if (!Number.isSafeInteger(casRevision)) {
      throw new Error("CAS revision exhausted");
    }
    const version = entry.version ?? casRevision;
    // Reserve before the SQLite commit. A crash may leave a gap, but never
    // lets an old If-Match value name a different row after index recovery.
    reserveJournal(entry.scope, casRevision);
    updateScopeRevisionStmt.run({
      scope: entry.scope,
      cas_revision: casRevision,
    });
    const result = insertStmt.run({
      file_id: entry.fileId,
      schema_id: entry.schemaId ?? null,
      path: entry.path,
      scope: entry.scope,
      collected_at: entry.collectedAt,
      size_bytes: entry.sizeBytes,
      version,
      cas_revision: casRevision,
      data_point_id: entry.dataPointId ?? null,
      after_tombstone_version: entry.afterTombstoneVersion ?? null,
      producer: entry.producer ?? null,
      producer_provenance: entry.producerProvenance ?? null,
    });
    const row = db
      .prepare("SELECT * FROM data_files WHERE id = ?")
      .get(result.lastInsertRowid) as RawRow;
    return rowToEntry(row);
  };
  const insertIfCurrent = db.transaction(
    (
      entry: NewIndexEntry,
      precondition?: { kind: "none" } | { kind: "match"; version: number },
    ) => {
      const current = currentForWriteStmt.get({ scope: entry.scope }) as
        | {
            cas_revision: number | null;
            producer: string | null;
            closed_for_writes: number;
          }
        | undefined;
      const currentVersion =
        current === undefined ? null : (current.cas_revision ?? null);
      const scopeClosedForWrites = current?.closed_for_writes === 1;
      if (
        scopeClosedForWrites ||
        (precondition?.kind === "none" &&
          (current?.cas_revision ?? null) !== null) ||
        (precondition?.kind === "match" &&
          currentVersion !== precondition.version)
      ) {
        return {
          ok: false as const,
          currentVersion,
          currentProducer: current?.producer ?? null,
        };
      }
      return { ok: true as const, entry: insertRow(entry) };
    },
  );

  return {
    insert(entry) {
      const result = insertIfCurrent(entry);
      if (!result.ok) throw new Error("Unconditional insert was rejected");
      return result.entry;
    },
    insertIfCurrent,
    closeScopeForWrites(scope) {
      ensureScopeRevisionStmt.run({ scope });
      // Durable fail-closed marker. There is no HTTP reset path; clearing this
      // requires an explicit owner-confirmed offline repair/rebuild.
      reserveClosedMarker(scope);
      closeScopeForWritesStmt.run({ scope });
    },
    insertRecovered(entry) {
      return insertRow(entry);
    },

    findByPath(path) {
      const row = findByPathStmt.get({ path }) as RawRow | undefined;
      return row ? rowToEntry(row) : undefined;
    },

    findByScope(options) {
      let sql = "SELECT * FROM data_files";
      const params: Record<string, unknown> = {};

      if (options.scope) {
        sql += " WHERE scope = @scope";
        params.scope = options.scope;
      }

      // Preserve the legacy chronological head when sync backfills history.
      // julianday handles both older second-precision and newer millisecond
      // timestamps; id breaks exact ties.
      sql += " ORDER BY julianday(collected_at) DESC, id DESC";

      if (options.limit !== undefined) {
        sql += " LIMIT @limit";
        params.limit = options.limit;
      }

      if (options.offset !== undefined) {
        sql += " OFFSET @offset";
        params.offset = options.offset;
      }

      const rows = db.prepare(sql).all(params) as RawRow[];
      return rows.map(rowToEntry);
    },

    findLatestByScope(scope) {
      const row = findLatestByScopeStmt.get({ scope }) as RawRow | undefined;
      return row ? rowToEntry(row) : undefined;
    },

    countByScope(scope) {
      const row = countByScopeStmt.get({ scope }) as { cnt: number };
      return row.cnt;
    },

    deleteByPath(path) {
      const result = deleteByPathStmt.run({ path });
      return result.changes > 0;
    },

    deleteUnsyncedByPath(path) {
      const result = deleteUnsyncedByPathStmt.run({ path });
      return result.changes > 0;
    },

    listDistinctScopes(options) {
      const hasPrefix =
        options?.scopePrefix !== undefined && options.scopePrefix !== "";
      const prefix = hasPrefix ? options!.scopePrefix! + "%" : "%";

      const countRow = db
        .prepare(
          "SELECT COUNT(DISTINCT scope) AS cnt FROM data_files WHERE scope LIKE @prefix",
        )
        .get({ prefix }) as { cnt: number };
      const total = countRow.cnt;

      let sql = `SELECT latest.scope, latest.collected_at AS latest_collected_at,
                (SELECT COUNT(*) FROM data_files counted WHERE counted.scope = latest.scope) AS version_count
         FROM data_files latest
         WHERE latest.scope LIKE @prefix
           AND latest.id = (
             SELECT id FROM data_files candidate
             WHERE candidate.scope = latest.scope
             ORDER BY julianday(candidate.collected_at) DESC, candidate.id DESC
             LIMIT 1
           )
         ORDER BY latest.scope ASC`;
      const params: Record<string, unknown> = { prefix };

      if (options?.limit !== undefined) {
        sql += " LIMIT @limit";
        params.limit = options.limit;
      }
      if (options?.offset !== undefined) {
        sql += " OFFSET @offset";
        params.offset = options.offset;
      }

      const rows = db.prepare(sql).all(params) as Array<{
        scope: string;
        latest_collected_at: string;
        version_count: number;
      }>;

      return {
        scopes: rows.map((r) => ({
          scope: r.scope,
          latestCollectedAt: r.latest_collected_at,
          versionCount: r.version_count,
        })),
        total,
      };
    },

    listIndexedScopes() {
      const rows = listIndexedScopesStmt.all() as Array<{ scope: string }>;
      return rows.map((row) => row.scope);
    },

    findClosestByScope(scope, at) {
      const row = findClosestByScopeStmt.get({ scope, at }) as
        RawRow | undefined;
      return row ? rowToEntry(row) : undefined;
    },

    findByFileId(fileId) {
      const row = findByFileIdStmt.get({ file_id: fileId }) as
        RawRow | undefined;
      return row ? rowToEntry(row) : undefined;
    },

    findByDataPointId(dataPointId) {
      const row = findByDataPointIdStmt.get({ data_point_id: dataPointId }) as
        RawRow | undefined;
      return row ? rowToEntry(row) : undefined;
    },

    findUnsynced(options) {
      if (options?.limit !== undefined) {
        const rows = findUnsyncedLimitStmt.all({
          limit: options.limit,
        }) as RawRow[];
        return rows.map(rowToEntry);
      }
      const rows = findUnsyncedStmt.all() as RawRow[];
      return rows.map(rowToEntry);
    },

    updateFileId(path, fileId) {
      const result = updateFileIdStmt.run({ file_id: fileId, path });
      return result.changes > 0;
    },

    findLatestVersionByScope(scope) {
      const row = maxVersionByScopeStmt.get({ scope }) as
        | {
            max_version: number;
          }
        | undefined;
      return row?.max_version ?? 0;
    },

    updateDataPointId(path, dataPointId) {
      const result = updateDataPointIdStmt.run({
        data_point_id: dataPointId,
        path,
      });
      return result.changes > 0;
    },

    updateVersion(path, version) {
      const result = updateVersionStmt.run({ version, path });
      return result.changes > 0;
    },

    deleteByScope(scope) {
      const result = deleteByScopeStmt.run({ scope });
      return result.changes;
    },

    close() {
      db.close();
    },
  };
}
