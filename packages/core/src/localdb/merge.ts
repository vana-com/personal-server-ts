import type { SqlStatement, SqlValue } from "./driver.js";

/** Why a batch writes. The triggers copy it into `record_changes.origin`. */
export type WriteOrigin = "local" | "import" | "remote" | "refresh" | "purge";

/** Every write batch begins with the origin, which the triggers read. */
export function withOrigin(
  origin: WriteOrigin,
  statements: readonly SqlStatement[],
): SqlStatement[] {
  return [
    { sql: "UPDATE write_ctx SET origin = ? WHERE id = 1", params: [origin] },
    ...statements,
  ];
}

/**
 * TEMP tables for multi-batch operations. Every row carries the id of its
 * operation (`op`); an operation reads and clears only its own rows. A crash
 * or close drops them, and the operation re-runs from its durable inputs.
 */
export const TEMP_TABLES: readonly string[] = [
  `CREATE TEMP TABLE IF NOT EXISTS incoming (op TEXT NOT NULL, stream TEXT NOT NULL, pk_hash TEXT NOT NULL,
    record_key TEXT NOT NULL, stamp_o INTEGER NOT NULL, stamp_r TEXT NOT NULL, body TEXT NOT NULL, body_sha256 TEXT NOT NULL, first_o INTEGER,
    PRIMARY KEY (op, stream, pk_hash)) WITHOUT ROWID`,
  `CREATE TEMP TABLE IF NOT EXISTS apply_keys (op TEXT NOT NULL, pk_hash TEXT NOT NULL,
    PRIMARY KEY (op, pk_hash)) WITHOUT ROWID`,
  `CREATE TEMP TABLE IF NOT EXISTS keep_ranges (op TEXT NOT NULL, lo TEXT NOT NULL, hi TEXT NOT NULL)`,
];

const FIELDS = ["record_key", "stamp_o", "stamp_r", "body", "body_sha256"];

/**
 * The only way rows enter `records`: rows staged in `incoming` under `op`.
 * A strictly newer stamp (o, then r) wins; an equal or older one changes
 * no stamped fields and logs nothing. Independently, first_o is the minimum
 * checkpoint with NULL as the bottom; imported rows have an unknown checkpoint.
 * Clears the operation's `incoming` rows.
 */
export function mergeIncoming(
  op: string,
  connectionId: string,
): SqlStatement[] {
  const pick = (f: string) =>
    `(SELECT i.${f} FROM incoming i WHERE i.op = ? AND i.stream = records.stream AND i.pk_hash = records.pk_hash)`;
  return [
    {
      // Until publication acknowledges an explicit delete, an older downloaded
      // row must not recreate it. Newer writes still win by the normal stamp.
      sql: `DELETE FROM temp.incoming WHERE op=? AND EXISTS (
        SELECT 1 FROM record_changes ch WHERE ch.connection_id=?
          AND ch.stream=incoming.stream AND ch.pk_hash=incoming.pk_hash
          AND ch.explicit_delete=1
          AND ch.seq>COALESCE((SELECT publish_watermark FROM stream_state
            WHERE connection_id=? AND stream=incoming.stream),0)
          AND (ch.stamp_o>incoming.stamp_o OR
            (ch.stamp_o=incoming.stamp_o AND ch.stamp_r>=incoming.stamp_r)))`,
      params: [op, connectionId, connectionId],
    },
    {
      // This statement must not assign a column watched by records_au.
      sql: `UPDATE records SET first_o = CASE
   WHEN (SELECT origin FROM write_ctx WHERE id = 1) = 'import'
     OR first_o IS NULL OR ${pick("first_o")} IS NULL THEN NULL
   WHEN ${pick("first_o")} < first_o THEN ${pick("first_o")}
   ELSE first_o END
 WHERE (connection_id, stream, pk_hash) IN
   (SELECT ?, stream, pk_hash FROM incoming WHERE op = ?)`,
      params: [op, op, op, connectionId, op],
    },
    {
      sql: `UPDATE records SET ${FIELDS.map((f) => `${f} = ${pick(f)}`).join(", ")}
 WHERE (connection_id, stream, pk_hash) IN
   (SELECT ?, stream, pk_hash FROM incoming WHERE op = ?)
   AND EXISTS (SELECT 1 FROM incoming i WHERE i.op = ? AND i.stream = records.stream AND i.pk_hash = records.pk_hash
               AND (i.stamp_o > records.stamp_o OR (i.stamp_o = records.stamp_o AND i.stamp_r > records.stamp_r)))`,
      params: [...FIELDS.map(() => op), connectionId, op, op],
    },
    {
      sql: `INSERT INTO records (connection_id, stream, pk_hash, ${FIELDS.join(", ")}, first_o)
SELECT ?, i.stream, i.pk_hash, ${FIELDS.map((f) => `i.${f}`).join(", ")},
       CASE WHEN (SELECT origin FROM write_ctx WHERE id = 1) = 'import' THEN NULL ELSE i.first_o END
 FROM incoming i
 WHERE i.op = ? AND NOT EXISTS (SELECT 1 FROM records r WHERE r.connection_id = ? AND r.stream = i.stream AND r.pk_hash = i.pk_hash)`,
      params: [connectionId, op, connectionId],
    },
    { sql: "DELETE FROM incoming WHERE op = ?", params: [op] },
  ];
}

/**
 * Apply's one delete per stream (origin `remote`): drops rows the applied head
 * does not hold, except rows in an unchanged part (`keep_ranges`) and rows a
 * local write changed after the publish watermark. Clears the operation's TEMP rows.
 */
export function applyDelete(
  op: string,
  connectionId: string,
  stream: string,
): SqlStatement[] {
  const keys: SqlValue[] = [connectionId, stream];
  return [
    {
      sql: `DELETE FROM records
 WHERE connection_id = ? AND stream = ?
   AND pk_hash NOT IN (SELECT pk_hash FROM temp.apply_keys WHERE op = ?)
   AND NOT EXISTS (SELECT 1 FROM temp.keep_ranges k WHERE k.op = ? AND records.pk_hash >= k.lo AND records.pk_hash < k.hi)
   AND NOT EXISTS (SELECT 1 FROM record_changes ch
                    WHERE ch.connection_id = records.connection_id AND ch.stream = records.stream
                      AND ch.pk_hash = records.pk_hash AND ch.origin IN ('local','import','refresh')
                      AND ch.seq > (SELECT publish_watermark FROM stream_state WHERE connection_id = ? AND stream = ?))`,
      params: [...keys, op, op, ...keys],
    },
    { sql: "DELETE FROM temp.apply_keys WHERE op = ?", params: [op] },
    { sql: "DELETE FROM temp.keep_ranges WHERE op = ?", params: [op] },
  ];
}

/**
 * After a full-refresh replace passed the registry CAS (origin `refresh`):
 * drops the stream's rows stamped below the run's stamp (o, then run id).
 */
export function replaceDelete(
  connectionId: string,
  stream: string,
  stampO: number,
  stampR: string,
): SqlStatement {
  return {
    sql: `DELETE FROM records WHERE connection_id = ? AND stream = ?
   AND (stamp_o < ? OR (stamp_o = ? AND stamp_r < ?))`,
    params: [connectionId, stream, stampO, stampO, stampR],
  };
}

/** Explicit PDPP deletes commit with their run, including a tombstone for a missing key. */
export function deleteRunRecords(
  connectionId: string,
  stream: string,
  runId: string,
  observedAt: number,
  afterSeq: number,
): SqlStatement[] {
  return [
    {
      sql: `INSERT INTO record_changes(connection_id,stream,pk_hash,record_key,op,stamp_o,stamp_r,origin,explicit_delete)
        SELECT ?,r.stream,r.pk_hash,r.record_key,'remove',?,?,'local',1 FROM run_rows r
        WHERE r.run_id=? AND r.stream=? AND r.op='delete'
          AND NOT EXISTS (SELECT 1 FROM records x WHERE x.connection_id=? AND x.stream=r.stream AND x.pk_hash=r.pk_hash)`,
      params: [connectionId, observedAt, runId, runId, stream, connectionId],
    },
    {
      sql: `DELETE FROM records WHERE connection_id=? AND stream=?
        AND pk_hash IN (SELECT pk_hash FROM run_rows WHERE run_id=? AND stream=? AND op='delete')
        AND (stamp_o < ? OR (stamp_o=? AND stamp_r<=?))`,
      params: [
        connectionId,
        stream,
        runId,
        stream,
        observedAt,
        observedAt,
        runId,
      ],
    },
    {
      // The DELETE trigger logs the prior row stamp. Publish/apply need the
      // deletion's stamp; readers see only this transaction's final event.
      sql: `UPDATE record_changes SET stamp_o=?,stamp_r=?,explicit_delete=1
        WHERE connection_id=? AND stream=? AND seq>? AND op='remove'`,
      params: [observedAt, runId, connectionId, stream, afterSeq],
    },
  ];
}
