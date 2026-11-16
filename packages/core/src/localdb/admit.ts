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
 * What the connector check read of a stream's local state. The batch's
 * transaction admits the stream's rows only while the state still shows these
 * values, so a commit that lands between the read and the write (a newer
 * connector raising the floor, a head with another key) cannot slip past.
 */
export interface StreamFacts {
  readonly head_version: number;
  readonly head_generation: number | null;
  readonly floor_version: string | null;
  readonly floor_o: number | null;
  readonly local_primary_key: string;
}

function factsGuard(
  connectionId: string,
  stream: string,
  facts: StreamFacts,
): { sql: string; params: SqlStatement["params"] } {
  return {
    sql: `EXISTS (SELECT 1 FROM stream_state s WHERE s.connection_id = ? AND s.stream = ?
        AND s.head_version = ? AND s.head_generation IS ? AND s.floor_version IS ?
        AND s.floor_o IS ? AND s.primary_key = ?)`,
    params: [
      connectionId,
      stream,
      facts.head_version,
      facts.head_generation,
      facts.floor_version,
      facts.floor_o,
      facts.local_primary_key,
    ],
  };
}

/**
 * One statement per stream, after the admission statements: marks the stream
 * `unadmitted` when its facts no longer hold. `changes` is 1 for a stream whose
 * rows were not admitted for that reason.
 */
export function guardFailureMarks(
  connectionId: string,
  runId: string,
  facts: ReadonlyMap<string, StreamFacts>,
  streams: readonly string[],
): SqlStatement[] {
  return streams.map((stream) => {
    const known = facts.get(stream);
    const guard = known ? factsGuard(connectionId, stream, known) : null;
    return {
      sql: `UPDATE run_streams SET unadmitted = 1 WHERE run_id = ? AND stream = ?${
        guard ? ` AND NOT ${guard.sql}` : ""
      }`,
      params: [runId, stream, ...(guard?.params ?? [])],
    };
  });
}

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
  /** The run's intake batch index: the order between two bodies of a key at the run's stamp. */
  readonly batch: number;
  readonly rows: readonly AdmitRow[];
  readonly facts: ReadonlyMap<string, StreamFacts>;
  readonly guard: {
    readonly sql: string;
    readonly params: SqlStatement["params"];
  };
}): SqlStatement[] {
  const { op, connectionId, runId, o, batch, rows, facts, guard } = input;
  const guardParams = guard.params ?? [];
  const statements: SqlStatement[] = [
    // The logging triggers read the origin; run end writes under `local` too.
    {
      sql: "UPDATE write_ctx SET origin = 'local' WHERE id = 1",
      params: [],
    },
  ];
  for (const row of rows) {
    const known = facts.get(row.stream);
    // No facts for the stream: nothing to check the row against, so it stays staged.
    const stream = known
      ? factsGuard(connectionId, row.stream, known)
      : { sql: "0", params: [] };
    statements.push({
      // A later row for the same key in this batch replaces the earlier one.
      sql: `INSERT OR REPLACE INTO incoming (op, stream, pk_hash, record_key, stamp_o, stamp_r, body, body_sha256, first_o, stamp_n)
        SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ? WHERE ${guard.sql} AND ${stream.sql}
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
        batch,
        ...guardParams,
        ...(stream.params ?? []),
        connectionId,
        row.stream,
        row.pkHash,
        o,
        runId,
      ],
    });
  }
  statements.push(
    replaceOwnRunRows(op, connectionId, runId, o),
    ...mergeIncoming(op, connectionId),
  );
  return statements;
}

/**
 * Within a run the later batch wins. A row this run already holds, as its
 * stamp or as its newest sighting, has the same stamp as the incoming row, or
 * the sighting's older stamp, so mergeIncoming's stamp rule alone would keep
 * the earlier batch. Replace it here, and only for the run's own rows: another
 * writer at the same stamp is still never replaced here. The row takes the
 * batch's ordinal (`stamp_n`), which is what orders it against the body a
 * reader already holds from an earlier publication of this run
 * (`mergeIncoming` applies the same ordinal at a reader). Runs on `incoming`
 * rows of `op`, before the merge.
 */
export function replaceOwnRunRows(
  op: string,
  connectionId: string,
  runId: string,
  o: number,
): SqlStatement {
  return {
    sql: `UPDATE records SET
        body = (SELECT i.body FROM incoming i WHERE i.op = ? AND i.stream = records.stream AND i.pk_hash = records.pk_hash),
        body_sha256 = (SELECT i.body_sha256 FROM incoming i WHERE i.op = ? AND i.stream = records.stream AND i.pk_hash = records.pk_hash),
        body_bytes = (SELECT LENGTH(CAST(i.body AS BLOB)) FROM incoming i WHERE i.op = ? AND i.stream = records.stream AND i.pk_hash = records.pk_hash),
        stamp_o = ?, stamp_r = ?, stamp_n = (SELECT i.stamp_n FROM incoming i WHERE i.op = ? AND i.stream = records.stream AND i.pk_hash = records.pk_hash),
        seen_o = NULL, seen_r = NULL
      WHERE (connection_id, stream, pk_hash) IN (SELECT ?, stream, pk_hash FROM incoming WHERE op = ?)
        AND COALESCE(seen_o, stamp_o) = ? AND COALESCE(seen_r, stamp_r) = ?
        AND EXISTS (SELECT 1 FROM incoming i WHERE i.op = ? AND i.stream = records.stream AND i.pk_hash = records.pk_hash
                    AND NOT (i.body_sha256 = records.body_sha256 AND i.body = records.body))`,
    params: [op, op, op, o, runId, op, connectionId, op, o, runId, op],
  };
}

// An older admitting run that still collects can admit the key later. Whether a
// delete needs a tombstone is a fact about those persisted runs, not about the
// flag now: the flag may have gone off since the run began.
const OLDER_ADMITTING_RUN = `EXISTS (SELECT 1 FROM runs r
    WHERE r.connection_id = ? AND r.state = 'collecting' AND r.admitting = 1
      AND (r.o, r.run_id) < (?, ?))`;

/**
 * Remember a run's explicit deletes by the deleting run's stamp. Written when
 * the flag is on, and when an older admitting run still collects (it began with
 * the flag on and keeps that mode), so turning the flag off cannot let that
 * run bring a delete back.
 */
export function tombstoneRunDeletes(
  connectionId: string,
  stream: string,
  runId: string,
  observedAt: number,
  flagOn: boolean,
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
        SELECT ?, stream, pk_hash, ?, ? FROM run_rows WHERE run_id = ? AND stream = ? AND op = 'delete'
          AND (? = 1 OR ${OLDER_ADMITTING_RUN})`,
      params: [
        connectionId,
        observedAt,
        runId,
        runId,
        stream,
        flagOn ? 1 : 0,
        connectionId,
        observedAt,
        runId,
      ],
    },
  ];
}

/**
 * Remember the rows a full refresh is about to drop (`replaceDelete`) by the
 * replacing run's stamp. Runs before that delete, in the same batch. Written
 * under the same rule as `tombstoneRunDeletes`.
 */
export function tombstoneOmissions(
  connectionId: string,
  stream: string,
  stampO: number,
  stampR: string,
  flagOn: boolean,
): SqlStatement {
  return {
    sql: `INSERT OR REPLACE INTO record_tombstones (connection_id, stream, pk_hash, stamp_o, stamp_r)
      SELECT connection_id, stream, pk_hash, ?, ? FROM records
       WHERE connection_id = ? AND stream = ? AND ${SEEN_BEFORE}
         AND (? = 1 OR ${OLDER_ADMITTING_RUN})
         AND NOT EXISTS (SELECT 1 FROM record_tombstones t
           WHERE t.connection_id = records.connection_id AND t.stream = records.stream
             AND t.pk_hash = records.pk_hash AND (t.stamp_o, t.stamp_r) > (?, ?))`,
    params: [
      stampO,
      stampR,
      connectionId,
      stream,
      ...seenBeforeParams(stampO, stampR),
      flagOn ? 1 : 0,
      connectionId,
      stampO,
      stampR,
      stampO,
      stampR,
    ],
  };
}

// A tombstone no collecting run can still need: no collecting run of the
// connection started before it (by stamp). With none, every later run starts
// later and carries a newer stamp.
const DROPPABLE = (t: string) => `NOT EXISTS (SELECT 1 FROM runs r
    WHERE r.connection_id = ? AND r.state = 'collecting'
      AND (r.o, r.run_id) < (${t}.stamp_o, ${t}.stamp_r))`;

/**
 * Drop the tombstones no collecting run can still need, and keep the highest
 * stamp dropped as the connection's watermark. Call after a run ends and after
 * a run begins (its row counts).
 */
export function compactTombstones(connectionId: string): SqlStatement[] {
  return [
    {
      // The watermark moves first, from the rows the delete below removes.
      sql: `UPDATE connections SET
          tombstone_wm_o = (SELECT t.stamp_o FROM record_tombstones t
            WHERE t.connection_id = connections.connection_id AND ${DROPPABLE("t")}
            ORDER BY t.stamp_o DESC, t.stamp_r DESC LIMIT 1),
          tombstone_wm_r = (SELECT t.stamp_r FROM record_tombstones t
            WHERE t.connection_id = connections.connection_id AND ${DROPPABLE("t")}
            ORDER BY t.stamp_o DESC, t.stamp_r DESC LIMIT 1)
        WHERE connection_id = ?
          AND EXISTS (SELECT 1 FROM record_tombstones t
            WHERE t.connection_id = connections.connection_id AND ${DROPPABLE("t")}
              AND (connections.tombstone_wm_o IS NULL
                   OR (t.stamp_o, t.stamp_r) > (connections.tombstone_wm_o, connections.tombstone_wm_r)))`,
      params: [connectionId, connectionId, connectionId, connectionId],
    },
    {
      sql: `DELETE FROM record_tombstones WHERE connection_id = ?
        AND ${DROPPABLE("record_tombstones")}`,
      params: [connectionId, connectionId],
    },
  ];
}

/**
 * Raise a new run's `o` until its stamp `(o, run_id)` is above the connection's
 * watermark. A tombstone below the watermark is gone, so a run that stamped
 * below it (a caller-supplied old `observedAt`) could admit a row back that a
 * newer run deleted. Runs in the begin batch, after the run row is inserted
 * and before compaction counts it.
 */
export function clampRunStart(runId: string): SqlStatement {
  return {
    sql: `UPDATE runs SET o = (SELECT CASE
          WHEN c.tombstone_wm_o IS NULL THEN runs.o
          WHEN (runs.o, runs.run_id) > (c.tombstone_wm_o, c.tombstone_wm_r) THEN runs.o
          WHEN runs.run_id > c.tombstone_wm_r THEN c.tombstone_wm_o
          ELSE c.tombstone_wm_o + 1 END
        FROM connections c WHERE c.connection_id = runs.connection_id)
      WHERE run_id = ?`,
    params: [runId],
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
): Promise<{
  readonly blocked: Set<string>;
  readonly facts: Map<string, StreamFacts>;
}> {
  const [connection] = await deps.db.query<{ connector: string }>(
    "SELECT connector FROM connections WHERE connection_id = ?",
    [run.connection_id],
  );
  if (!connection) return { blocked: new Set(), facts: new Map() };
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
  const facts = new Map<string, StreamFacts>();
  for (const row of rows) {
    facts.set(row.stream, {
      head_version: row.head_version,
      head_generation: row.head_generation,
      floor_version: row.floor_version,
      floor_o: row.floor_o,
      local_primary_key: row.local_primary_key,
    });
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
  return { blocked, facts };
}
