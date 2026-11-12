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
import type { LocalSyncDeps } from "./deps.js";
import type { ImportLedger } from "./import-ledger.js";
import type { ImportReceipt, ImportSource } from "./legacy-import-types.js";

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
      const mergeBatch = (row: ImportRow): SqlStatement[] =>
        withOrigin("import", [
          ...guard,
          {
            sql: `INSERT INTO incoming (op, stream, pk_hash, record_key, stamp_o, stamp_r, body, body_sha256, first_o) VALUES (?, ?, ?, ?, 0, 'seed', ?, ?, NULL)`,
            params: [
              op,
              stream,
              row.pk_hash,
              row.record_key,
              row.body,
              row.body_sha256,
            ],
          },
          ...merge,
          { sql: "UPDATE write_ctx SET origin = 'local' WHERE id = 1" },
        ]);
      for await (const record of source.records()) {
        const row = await canonicalImportRow(record, source.target.primaryKey);
        const [expected] = await deps.db.query<{
          body_sha256: string;
          seen: number;
        }>(
          "SELECT body_sha256, seen FROM import_snapshot WHERE op = ? AND pk_hash = ?",
          [op, row.pk_hash],
        );
        if (!expected || expected.body_sha256 !== row.body_sha256)
          return { kind: "refused", reason: "source_changed" };
        if (expected.seen) continue;
        const fence = await importFence(deps, source);
        if (fence) return { kind: "refused", reason: fence };
        await deps.db.batch([
          ...mergeBatch(row),
          {
            sql: "UPDATE import_snapshot SET seen = 1 WHERE op = ? AND pk_hash = ?",
            params: [op, row.pk_hash],
          },
        ]);
        lastRow = row;
      }
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
