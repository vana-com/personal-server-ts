import { planStreamStep } from "../stream-sync/publish-plan.js";
import type { LocalSyncDeps } from "./deps.js";
import type { SqlStatement } from "./driver.js";
import { planInputs, type StreamPlanRow } from "./plan-inputs.js";
import { mergeIncoming, SEEN_BEFORE, seenBeforeParams } from "./merge.js";

/**
 * Publish while collecting: batch admission and the tombstones it relies on.
 *
 * A run that began with `publishWhileCollecting` merges each batch's upserts
 * into `records` in the transaction that stages the batch, after the same
 * fence checks run end applies (intake's `FENCED` triggers). Run end then
 * keeps only what needs the whole run: omission deletes, explicit deletes and
 * the checkpoint. Admitted rows stay when the run is refused or fails; only a
 * reset or a connection delete removes them.
 *
 * Admission uses `mergeIncoming` with origin `local`, so a row admitted by an
 * older run never replaces a newer writer: merge.ts's stamp rule is not
 * touched. The one addition is the same-run rule below.
 */

/** One staged upsert of a batch. */
export interface AdmitRow {
  readonly stream: string;
  readonly pkHash: string;
  readonly recordKey: string;
  readonly body: string;
  readonly bodySha256: string;
}

/** The statements before the first per-row insert (the origin update). */
export const ADMIT_ROW_OFFSET = 1;

/**
 * Statements for one batch's admitted upserts. The per-row inserts come right
 * after the origin update, in row order: the caller reads `changes[offset + i]`
 * (0 = skipped because a newer delete is remembered for the key).
 *
 * `guard` is the staging guard of the batch's `run_rows` inserts: the rows
 * enter only while the run is collecting at the batch's expected position.
 */
export function admitUpserts(input: {
  readonly op: string;
  readonly connectionId: string;
  readonly runId: string;
  readonly o: number;
  readonly rows: readonly AdmitRow[];
  readonly guard: {
    readonly sql: string;
    readonly params: SqlStatement["params"];
  };
}): SqlStatement[] {
  const { op, connectionId, runId, o, rows, guard } = input;
  const guardParams = guard.params ?? [];
  const statements: SqlStatement[] = [
    // The logging triggers read the origin; run end writes under `local` too.
    {
      sql: "UPDATE write_ctx SET origin = 'local' WHERE id = 1",
      params: [],
    },
  ];
  for (const row of rows) {
    statements.push({
      // A later row for the same key in this batch replaces the earlier one.
      sql: `INSERT OR REPLACE INTO incoming (op, stream, pk_hash, record_key, stamp_o, stamp_r, body, body_sha256, first_o)
        SELECT ?, ?, ?, ?, ?, ?, ?, ?, ? WHERE ${guard.sql}
          AND NOT EXISTS (SELECT 1 FROM record_tombstones t
            WHERE t.connection_id = ? AND t.stream = ? AND t.pk_hash = ?
              AND (t.stamp_o, t.stamp_r) > (?, ?))`,
      params: [
        op,
        row.stream,
        row.pkHash,
        row.recordKey,
        o,
        runId,
        row.body,
        row.bodySha256,
        o,
        ...guardParams,
        connectionId,
        row.stream,
        row.pkHash,
        o,
        runId,
      ],
    });
  }
  statements.push(
    {
      // Within a run the later batch wins. A row this run already holds, as its
      // stamp or as its newest sighting, has the same stamp as the incoming
      // row, so mergeIncoming's strict stamp rule would keep the earlier batch.
      // Replace it here, and only for the run's own rows: another writer at the
      // same stamp is still never replaced.
      sql: `UPDATE records SET
          body = (SELECT i.body FROM incoming i WHERE i.op = ? AND i.stream = records.stream AND i.pk_hash = records.pk_hash),
          body_sha256 = (SELECT i.body_sha256 FROM incoming i WHERE i.op = ? AND i.stream = records.stream AND i.pk_hash = records.pk_hash),
          body_bytes = (SELECT LENGTH(CAST(i.body AS BLOB)) FROM incoming i WHERE i.op = ? AND i.stream = records.stream AND i.pk_hash = records.pk_hash),
          stamp_o = ?, stamp_r = ?, seen_o = NULL, seen_r = NULL
        WHERE (connection_id, stream, pk_hash) IN (SELECT ?, stream, pk_hash FROM incoming WHERE op = ?)
          AND COALESCE(seen_o, stamp_o) = ? AND COALESCE(seen_r, stamp_r) = ?
          AND EXISTS (SELECT 1 FROM incoming i WHERE i.op = ? AND i.stream = records.stream AND i.pk_hash = records.pk_hash
                      AND NOT (i.body_sha256 = records.body_sha256 AND i.body = records.body))`,
      params: [op, op, op, o, runId, connectionId, op, o, runId, op],
    },
    ...mergeIncoming(op, connectionId),
  );
  return statements;
}

/** Remember a run's explicit deletes by the deleting run's stamp. */
export function tombstoneRunDeletes(
  connectionId: string,
  stream: string,
  runId: string,
  observedAt: number,
): SqlStatement[] {
  return [
    {
      // Keep the newer stamp when a key already has a tombstone.
      sql: `DELETE FROM record_tombstones WHERE connection_id = ? AND stream = ?
        AND pk_hash IN (SELECT pk_hash FROM run_rows WHERE run_id = ? AND stream = ? AND op = 'delete')
        AND (stamp_o, stamp_r) < (?, ?)`,
      params: [connectionId, stream, runId, stream, observedAt, runId],
    },
    {
      sql: `INSERT OR IGNORE INTO record_tombstones (connection_id, stream, pk_hash, stamp_o, stamp_r)
        SELECT ?, stream, pk_hash, ?, ? FROM run_rows WHERE run_id = ? AND stream = ? AND op = 'delete'`,
      params: [connectionId, observedAt, runId, runId, stream],
    },
  ];
}

/**
 * Remember the rows a full refresh is about to drop (`replaceDelete`) by the
 * replacing run's stamp. Runs before that delete, in the same batch.
 */
export function tombstoneOmissions(
  connectionId: string,
  stream: string,
  stampO: number,
  stampR: string,
): SqlStatement {
  return {
    sql: `INSERT OR REPLACE INTO record_tombstones (connection_id, stream, pk_hash, stamp_o, stamp_r)
      SELECT connection_id, stream, pk_hash, ?, ? FROM records
       WHERE connection_id = ? AND stream = ? AND ${SEEN_BEFORE}
         AND NOT EXISTS (SELECT 1 FROM record_tombstones t
           WHERE t.connection_id = records.connection_id AND t.stream = records.stream
             AND t.pk_hash = records.pk_hash AND (t.stamp_o, t.stamp_r) > (?, ?))`,
    params: [
      stampO,
      stampR,
      connectionId,
      stream,
      ...seenBeforeParams(stampO, stampR),
      stampO,
      stampR,
    ],
  };
}

/**
 * Drop the tombstones no collecting run can still need. A tombstone matters to
 * a run only if the run started before it. With no collecting run older than a
 * tombstone, every later run starts later and carries a newer stamp, so the
 * row can go. Call after a run ends and after a run begins (its row counts).
 */
export function compactTombstones(connectionId: string): SqlStatement {
  return {
    sql: `DELETE FROM record_tombstones WHERE connection_id = ?
      AND NOT EXISTS (SELECT 1 FROM runs r WHERE r.connection_id = ? AND r.state = 'collecting'
        AND (r.o, r.run_id) < (record_tombstones.stamp_o, record_tombstones.stamp_r))`,
    params: [connectionId, connectionId],
  };
}

/**
 * The streams of a run whose connector run end would refuse with
 * `connector_update_required` today: below the version floor or the head's
 * version, or a primary key the head does not accept from this version.
 * It asks `planStreamStep` with the facts run end gives it and no commit
 * order, so `out_of_order` never refuses an upsert here.
 */
export async function connectorBlockedStreams(
  deps: LocalSyncDeps,
  runId: string,
  run: {
    readonly connection_id: string;
    readonly o: number;
    readonly generation: number | null;
    readonly artifact_version: string;
  },
): Promise<Set<string>> {
  const [connection] = await deps.db.query<{ connector: string }>(
    "SELECT connector FROM connections WHERE connection_id = ?",
    [run.connection_id],
  );
  if (!connection) return new Set();
  const rows = await deps.db.query<StreamPlanRow & { stream: string }>(
    `SELECT rs.stream, rs.primary_key, rs.profile_key, rs.profile_version,
            s.primary_key AS local_primary_key, s.profile_key AS local_profile_key,
            s.profile_version AS local_profile_version, s.complete,
            s.head_version, s.head_generation, s.floor_version, s.floor_o
       FROM run_streams rs JOIN stream_state s
         ON s.connection_id = ? AND s.stream = rs.stream
      WHERE rs.run_id = ?`,
    [run.connection_id, runId],
  );
  const blocked = new Set<string>();
  for (const row of rows) {
    const { primaryKey, profile, head } = planInputs(
      row,
      run,
      connection.connector,
    );
    const decision = planStreamStep(
      {
        head,
        floor: { version: row.floor_version, committed: null },
      },
      {
        runId,
        observedAt: run.o,
        generation: run.generation,
        primaryKey,
        profile,
        full: false,
        foreignCheckpoint: false,
        empty: false,
        seed: "none",
      },
    );
    if (
      decision.kind === "refused" &&
      decision.reason === "connector_update_required"
    )
      blocked.add(row.stream);
  }
  return blocked;
}
