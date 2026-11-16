import {
  controlScope,
  IDENTITYLESS_NS,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { syncBeforeBegin } from "./bootstrap.js";
import { TEMP_TABLES, mergeIncoming, withOrigin } from "./merge.js";
import {
  stageImportSnapshot,
  canonicalImportRow,
  clearImportSnapshot,
  type ImportRow,
} from "./import-snapshot.js";
import type { SqlStatement } from "./driver.js";
import { announceRecordsCommitted, type LocalSyncDeps } from "./deps.js";
import type { ImportLedger } from "./import-ledger.js";
import type { ImportReceipt, ImportSource } from "./legacy-import-types.js";

/**
 * A merge batch ends once it holds 2,048 rows or 4,194,304 body characters,
 * whichever comes first. Both are measured batching bounds, not derived
 * limits.
 *
 * Each batch pays a fixed cost: a transaction, the snapshot lookup and, after
 * the write, the SQLite worker's checkpoint pass (it runs once the WAL holds
 * 1,000 frames, about 4 MB at 4 KiB pages). What was measured, on filler rows
 * of 2,150 bytes (`seed-handoff.workload.ts`):
 * - 198,000 rows (405 MiB), the import after staging: 64 rows / 256 KiB, the
 *   earlier bounds, made 3,900 batches and took 112-117 s (n=2); with these
 *   bounds it takes 63-67 s (n=3). In an instrumented run of the earlier
 *   bounds 60 of 129 s went to 1,496 checkpoint passes; with 2,048 rows
 *   and 8 MiB there were 80.
 * - 20,000 rows: 64 rows / 256 KiB 10.5 s, 512 rows / 2 MiB 6.1 s, 2,048 rows /
 *   8 MiB 4.2 s.
 * Bigger batches kept winning up to the largest tried. 2,048 is that largest
 * row count, not an optimum, and nothing above it was tried. At this row size
 * the byte bound ends a batch at about 1,950 rows, so the two bounds act as
 * one here. The row bound keeps the statements of a batch of tiny rows
 * bounded.
 *
 * What the bytes count is limited: `body.length` is UTF-16 code units, not
 * UTF-8 bytes (a non-ASCII body takes up to three bytes per unit); keys, SQL
 * text, parameters and index overhead are not counted; and the bound is
 * checked only after the row that crosses it is appended, so a batch
 * overshoots by up to one row, and an oversized row may share the batch with
 * the rows before it. So this is not a memory bound. The import memory test holds that peak memory does not grow
 * with the row count of an import of rows this size; it does not bound the
 * worst batch.
 */
export const IMPORT_CHUNK_ROWS = 2048;
export const IMPORT_CHUNK_BYTES = 4 * 1024 * 1024;

/** Import refusals are diagnostics; copy removal has its own exact-byte fence. */
export type LegacyImportResult =
  | {
      readonly kind: "imported" | "already-imported";
      readonly receipt: ImportReceipt;
    }
  | {
      readonly kind: "refused";
      readonly reason:
        | "connection_deleted"
        | "generation_not_one"
        /** A real write already owns the stream; see `seedWindowClosed`. */
        | "seed_window_closed"
        | "unknown_control"
        | "owner_mismatch"
        | "source_changed"
        | "invalid_record";
    };

/**
 * F.2, C.0, F.5; r5.2 §1.2. Only refresh through syncBeforeBegin when the
 * target is its identityless controlScope; never use that helper to fabricate
 * an identity for another namespace. Unknown nonidentityless targets refuse
 * unknown_control; known generation-1 targets can proceed offline.
 * Bootstrap before staging, then hold the connection
 * queue (kind end). Recheck local deleted control and delete_intents BEFORE
 * registry refresh, and again inside every merge batch: refresh cannot undo
 * a local delete. Never reconnect. Require known generation 1. Merge with
 * origin import, stamp (0,'seed'), first_o NULL, one row per merge batch. Check
 * per-stream deletion history too. Stage sorted digests only, then replay source
 * rows and check each digest before merging. Missing/extra/changed rows cannot
 * earn a receipt. Replays/crash retries add no rows or changes.
 * A stream's seed window closes at its first real write (`seedWindowClosed`).
 * Receipt and last merge commit atomically; highestSeq includes earlier crash
 * batches (conservatively use the stream change high-water mark). Empty
 * snapshots receive a zero-row receipt; invalid, changed or excluded sources
 * never prove delivery. No frame codec.
 */
export async function importLegacySource(
  deps: LocalSyncDeps,
  ledger: ImportLedger,
  source: ImportSource,
): Promise<LegacyImportResult> {
  const result = await importSource(deps, ledger, source);
  // One wake per import, not per chunk: a wake per chunk would start a publish
  // cycle every debounce while the import is still merging.
  if (result.kind === "imported") announceRecordsCommitted(deps);
  return result;
}

async function importSource(
  deps: LocalSyncDeps,
  ledger: ImportLedger,
  source: ImportSource,
): Promise<LegacyImportResult> {
  const { connectionId, connector, stream } = source.target;
  const [meta] = await deps.db.query<{ owner: string; network: string }>(
    "SELECT owner, network FROM db_meta WHERE id = 1",
  );
  if (
    meta?.owner !== source.owner.toLowerCase() ||
    meta.owner !== deps.ownerAddress.toLowerCase() ||
    meta.network !== source.network
  )
    return { kind: "refused", reason: "owner_mismatch" };
  return deps.queue.run(connectionId, "end", async () => {
    // A closed seed window refuses a new import. A completed receipt for this
    // exact revision is reported as such, and nothing is merged again.
    const refuse = async (
      reason: Extract<LegacyImportResult, { kind: "refused" }>["reason"],
    ): Promise<LegacyImportResult> => {
      if (reason === "seed_window_closed") {
        const prior = await ledger.get(source.source, connectionId, stream);
        if (
          prior?.revision === source.revision &&
          ["imported", "verified", "retired"].includes(prior.state)
        )
          return { kind: "already-imported", receipt: prior };
      }
      return { kind: "refused", reason };
    };
    const refused = await importFence(deps, source);
    if (refused) return refuse(refused);
    if (connectionId === controlScope(connector, IDENTITYLESS_NS)) {
      await syncBeforeBegin(
        {
          ...deps,
          queue: {
            run: (id, kind, work) =>
              id === connectionId ? work() : deps.queue.run(id, kind, work),
          },
        },
        connector,
      );
    }
    const refreshed = await importFence(deps, source);
    if (refreshed) return refuse(refreshed);
    if (source.exclusions.length > 0)
      return { kind: "refused", reason: "invalid_record" };
    const op = deps.newOp();
    await deps.db.batch(TEMP_TABLES.map((sql) => ({ sql })));
    try {
      const fingerprint = await stageImportSnapshot(deps.db, source, op);
      const prior = await ledger.get(source.source, connectionId, stream);
      if (
        prior?.revision === source.revision &&
        (prior.rows !== fingerprint.rows ||
          prior.fingerprint !== fingerprint.fingerprint)
      )
        return { kind: "refused", reason: "source_changed" };
      const [before] = await deps.db.query<{ seq: number }>(
        "SELECT coalesce(max(seq),0) AS seq FROM record_changes WHERE connection_id = ? AND stream = ?",
        [connectionId, stream],
      );
      let lastRow: ImportRow | null = null;
      const guard = guardImport(source, op);
      const merge = mergeIncoming(op, connectionId);
      const incomingInsert = (row: ImportRow): SqlStatement => ({
        sql: `INSERT INTO incoming (op, stream, pk_hash, record_key, stamp_o, stamp_r, body, body_sha256, first_o) VALUES (?, ?, ?, ?, 0, 'seed', ?, ?, NULL)`,
        params: [
          op,
          stream,
          row.pk_hash,
          row.record_key,
          row.body,
          row.body_sha256,
        ],
      });
      const mergeBatch = (row: ImportRow): SqlStatement[] =>
        withOrigin("import", [
          ...guard,
          incomingInsert(row),
          ...merge,
          { sql: "UPDATE write_ctx SET origin = 'local' WHERE id = 1" },
        ]);
      // One round trip per chunk of rows, not per row: each driver call clones
      // its message across the SQLite worker's thread boundary, and a large
      // import grew the server's memory with the number of calls.
      let chunk: ImportRow[] = [];
      let chunkBytes = 0;
      const flush = async (): Promise<
        Extract<LegacyImportResult, { kind: "refused" }>["reason"] | null
      > => {
        if (chunk.length === 0) return null;
        const rows = chunk;
        chunk = [];
        chunkBytes = 0;
        const snapshot = await deps.db.query<{
          pk_hash: string;
          body_sha256: string;
          seen: number;
        }>(
          "SELECT pk_hash, body_sha256, seen FROM import_snapshot WHERE op = ? AND pk_hash IN (SELECT value FROM json_each(?))",
          [op, JSON.stringify(rows.map((r) => r.pk_hash))],
        );
        const expected = new Map(snapshot.map((r) => [r.pk_hash, r]));
        const todo: ImportRow[] = [];
        const taken = new Set<string>();
        for (const row of rows) {
          const known = expected.get(row.pk_hash);
          if (!known || known.body_sha256 !== row.body_sha256)
            return "source_changed";
          if (known.seen || taken.has(row.pk_hash)) continue;
          taken.add(row.pk_hash);
          todo.push(row);
        }
        if (todo.length === 0) return null;
        const fence = await importFence(deps, source);
        if (fence) return fence;
        await deps.db.batch(
          withOrigin("import", [
            ...guard,
            ...todo.map(incomingInsert),
            ...merge,
            { sql: "UPDATE write_ctx SET origin = 'local' WHERE id = 1" },
            ...todo.map((row) => ({
              sql: "UPDATE import_snapshot SET seen = 1 WHERE op = ? AND pk_hash = ?",
              params: [op, row.pk_hash],
            })),
          ]),
        );
        lastRow = todo[todo.length - 1]!;
        return null;
      };
      for await (const record of source.records()) {
        const row = await canonicalImportRow(record, source.target.primaryKey);
        chunk.push(row);
        chunkBytes += row.body.length;
        // Checked after the append: the batch ends with the row that crosses a
        // bound, so it can exceed the byte bound by up to one row.
        if (
          chunk.length >= IMPORT_CHUNK_ROWS ||
          chunkBytes >= IMPORT_CHUNK_BYTES
        ) {
          const refused = await flush();
          if (refused) return { kind: "refused", reason: refused };
        }
      }
      const refused = await flush();
      if (refused) return { kind: "refused", reason: refused };
      const [remaining] = await deps.db.query<{ n: number }>(
        "SELECT count(*) AS n FROM import_snapshot WHERE op = ? AND seen = 0",
        [op],
      );
      if (remaining!.n !== 0)
        return { kind: "refused", reason: "source_changed" };
      const fence = await importFence(deps, source);
      if (fence) return { kind: "refused", reason: fence };
      const [high] = await deps.db.query<{ seq: number }>(
        "SELECT coalesce(max(seq),0) AS seq FROM record_changes WHERE connection_id = ? AND stream = ?",
        [connectionId, stream],
      );
      const receipt: ImportReceipt = {
        ...fingerprint,
        source: source.source,
        revision: source.revision,
        connectionId,
        stream,
        generation: 1,
        highestSeq: high!.seq,
        state: "imported",
        reason: null,
        at: deps.now(),
      };
      // Final idempotent merge and receipt share this transaction. A crash
      // before it leaves only replayable batches, never a successful receipt.
      await deps.db.batch([
        ...(lastRow
          ? mergeBatch(lastRow)
          : withOrigin("import", [
              ...guard,
              { sql: "UPDATE write_ctx SET origin = 'local' WHERE id = 1" },
            ])),
        ...ledger.statements(receipt),
      ]);
      return {
        kind:
          prior?.revision === source.revision && high!.seq === before!.seq
            ? "already-imported"
            : "imported",
        receipt,
      };
    } catch (error) {
      const fence = await importFence(deps, source);
      if (fence) return { kind: "refused", reason: fence };
      if (
        error instanceof Error &&
        (error.message === "source_changed" ||
          error.message === "invalid_record")
      )
        return { kind: "refused", reason: error.message };
      if (error instanceof Error && error.message.includes("key_type_conflict"))
        return { kind: "refused", reason: "invalid_record" };
      throw error;
    } finally {
      await clearImportSnapshot(deps.db, op);
      await deps.db.batch([
        { sql: "DELETE FROM incoming WHERE op = ?", params: [op] },
      ]);
    }
  });
}

/** Reads the same conservative fence before refresh and every committed batch. */
async function importFence(
  deps: LocalSyncDeps,
  source: ImportSource,
): Promise<Extract<LegacyImportResult, { kind: "refused" }>["reason"] | null> {
  const [row] = await deps.db.query<{
    generation: number;
    control_state: string;
    deleted_at: number | null;
    deleting: number;
    connector: string;
  }>(
    `SELECT c.generation, c.control_state, c.deleted_at, c.connector, EXISTS(SELECT 1 FROM delete_intents d WHERE d.connector = c.connector) AS deleting FROM connections c WHERE connection_id = ?`,
    [source.target.connectionId],
  );
  if (!row) return "unknown_control";
  if (
    row.deleted_at !== null ||
    row.control_state === "deleted" ||
    row.deleting
  )
    return "connection_deleted";
  if (row.generation !== 1) return "generation_not_one";
  if (
    row.connector !== source.target.connector ||
    !["active", "absent"].includes(row.control_state)
  )
    return "unknown_control";
  const [state] = await deps.db.query<{
    primary_key: string;
    semantics: string;
    incremental: number;
    last_delete_version: number;
    floor_o: number | null;
    head_version: number;
  }>(
    "SELECT primary_key, semantics, incremental, last_delete_version, floor_o, head_version FROM stream_state WHERE connection_id = ? AND stream = ?",
    [source.target.connectionId, source.target.stream],
  );
  if (state && state.last_delete_version !== 0) return "connection_deleted";
  if (
    state &&
    (state.primary_key !== JSON.stringify(source.target.primaryKey) ||
      state.semantics !== source.target.semantics ||
      state.incremental !== (source.target.incremental ? 1 : 0))
  )
    return "invalid_record";
  if (state && seedWindowClosed(state)) return "seed_window_closed";
  return null;
}

/**
 * Old data is a one-time seed and any real write wins over it. A stream's
 * window closes at its first accepted real write (`floor_o`, set by run end) or
 * its first published or applied head (`head_version`). The merge cannot
 * enforce this: it inserts an absent key whatever its stamp, so a seed would
 * bring back a record that a real full refresh or delete already removed.
 * `guardImport` repeats this exact predicate in SQL.
 * The window also closes on purpose for a seed-only published head and for an
 * accepted run decision on a stream with no rows; a later seed must not reopen
 * either one. Do not treat them as bugs and reopen the window.
 */
function seedWindowClosed(state: {
  floor_o: number | null;
  head_version: number;
}): boolean {
  return state.floor_o !== null || state.head_version > 0;
}
/** Enforce the fence in the merge transaction too, closing the read/commit gap.
 * This TEMP assertion is operation-scoped and never authorizes deletion. */
function guardImport(source: ImportSource, op: string): SqlStatement[] {
  const {
    connectionId,
    connector,
    stream,
    primaryKey,
    semantics,
    incremental,
  } = source.target;
  return [
    {
      sql: "CREATE TEMP TABLE IF NOT EXISTS import_guard (op TEXT PRIMARY KEY, ok INTEGER NOT NULL CHECK(ok = 1))",
    },
    {
      sql: `INSERT INTO import_guard SELECT ?, CASE WHEN EXISTS(SELECT 1 FROM connections c WHERE c.connection_id = ? AND c.connector = ? AND c.generation = 1 AND c.control_state IN ('active','absent') AND c.deleted_at IS NULL AND NOT EXISTS(SELECT 1 FROM delete_intents d WHERE d.connector = c.connector)) AND NOT EXISTS(SELECT 1 FROM stream_state s WHERE s.connection_id = ? AND s.stream = ? AND (s.last_delete_version <> 0 OR s.floor_o IS NOT NULL OR s.head_version > 0 OR s.primary_key <> ? OR s.semantics <> ? OR s.incremental <> ?)) THEN 1 ELSE 0 END`,
      params: [
        op,
        connectionId,
        connector,
        connectionId,
        stream,
        JSON.stringify(primaryKey),
        semantics,
        incremental ? 1 : 0,
      ],
    },
    { sql: "DELETE FROM import_guard WHERE op = ?", params: [op] },
    {
      sql: "INSERT OR IGNORE INTO stream_state (connection_id, stream, primary_key, semantics, incremental) VALUES (?, ?, ?, ?, ?)",
      params: [
        connectionId,
        stream,
        JSON.stringify(primaryKey),
        semantics,
        incremental ? 1 : 0,
      ],
    },
  ];
}
