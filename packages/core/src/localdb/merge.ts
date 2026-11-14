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
 * A record has two stamps. `stamp_o`/`stamp_r` travel in the published bytes
 * and change only when the body changes (git and restic do the same: equal
 * content, equal identity, nothing new written). The SEEN stamp is the newest
 * run that observed the body, local only; it orders conflicts and decides what
 * a full refresh keeps. `seen_o`/`seen_r` are NULL, or older than the stamp,
 * until a run sees an unchanged body, so always read them through these.
 * The pair is NULL, or at least the stamp: whatever moves the stamp keeps or
 * clears it. That makes the effective stamp a plain COALESCE, which the index
 * `records_by_observation` holds, so "rows last seen before run R" is a seek.
 */
export function seenStamp(alias = ""): { o: string; r: string } {
  const c = (name: string) => `${alias}${name}`;
  return {
    o: `COALESCE(${c("seen_o")}, ${c("stamp_o")})`,
    r: `COALESCE(${c("seen_r")}, ${c("stamp_r")})`,
  };
}

/** The SEEN stamp as a row value, for comparisons: `${seenPair("r.")} < (?, ?)`. */
export function seenPair(alias = ""): string {
  const seen = seenStamp(alias);
  return `(${seen.o}, ${seen.r})`;
}

const SEEN = seenStamp();
export const SEEN_PAIR = seenPair();
/**
 * "Last observed before run (o, r)", written so the index seeks. SQLite
 * ranges an index on a lone leading term, not on a row value, so the first term
 * is the seek and the row value is the exact test. Bind `seenBeforeParams`.
 */
export const SEEN_BEFORE = `${SEEN.o} <= ? AND ${SEEN_PAIR} < (?, ?)`;
export const seenBeforeParams = (
  o: number,
  r: string,
): [number, number, string] => [o, o, r];
/** `SEEN.o` as a column name for reads that show when a record was last collected. */
export const SEEN_O = SEEN.o;

const SAME_BODY =
  "i.body_sha256 = records.body_sha256 AND i.body = records.body";

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
 *
 * Equal bodies are one fact. A run (origin `local`) that sees the body a row
 * already holds moves only the row's SEEN stamp: the stamp in the published
 * bytes stays, no change is logged, and the next publish has nothing to send.
 * Any other origin that brings an equal body under a newer stamp adopts the
 * newer stamp, as before, so every device ends on the same bytes.
 *
 * A different body wins when its stamp (o, then r) is strictly newer than the
 * row's SEEN stamp: the newest observation wins, whether or not this device
 * had pulled the other write first. An equal or older one changes nothing.
 * Independently, first_o is the minimum checkpoint with NULL as the bottom;
 * imported rows have an unknown checkpoint.
 *
 * With `promoteSeen` (apply only, origin `remote`): a different body that is
 * newer than the row's stamp but not than its SEEN stamp loses to the local
 * observation, and the registry holds the loser. The observation then takes
 * the stamp it was seen at and is logged as a local change, so the next
 * publish tells the registry. Without it the other device's write would win by
 * accident of pull timing.
 *
 * Clears the operation's `incoming` rows.
 */
export function mergeIncoming(
  op: string,
  connectionId: string,
  options: { readonly promoteSeen?: boolean } = {},
): SqlStatement[] {
  const pick = (f: string) =>
    `(SELECT i.${f} FROM incoming i WHERE i.op = ? AND i.stream = records.stream AND i.pk_hash = records.pk_hash)`;
  const incomingKeys = `(connection_id, stream, pk_hash) IN
   (SELECT ?, stream, pk_hash FROM incoming WHERE op = ?)`;
  const statements: SqlStatement[] = [
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
      // A run saw a body the row already holds. Neither assigned column is
      // watched by records_au, so nothing is logged.
      sql: `UPDATE records SET seen_o = ${pick("stamp_o")}, seen_r = ${pick("stamp_r")}
 WHERE ${incomingKeys}
   AND (SELECT origin FROM write_ctx WHERE id = 1) = 'local'
   AND EXISTS (SELECT 1 FROM incoming i WHERE i.op = ? AND i.stream = records.stream AND i.pk_hash = records.pk_hash
               AND ${SAME_BODY}
               AND (i.stamp_o, i.stamp_r) > ${seenPair("records.")})`,
      params: [op, op, connectionId, op, op],
    },
    {
      // A seen stamp newer than the incoming one survives; an older one is
      // the incoming row's own observation.
      sql: `UPDATE records SET ${FIELDS.map((f) => `${f} = ${pick(f)}`).join(", ")},
   seen_o = CASE WHEN (seen_o, seen_r) > (${pick("stamp_o")}, ${pick("stamp_r")}) THEN seen_o END,
   seen_r = CASE WHEN (seen_o, seen_r) > (${pick("stamp_o")}, ${pick("stamp_r")}) THEN seen_r END
 WHERE ${incomingKeys}
   AND EXISTS (SELECT 1 FROM incoming i WHERE i.op = ? AND i.stream = records.stream AND i.pk_hash = records.pk_hash
               AND CASE WHEN ${SAME_BODY}
                        THEN (SELECT origin FROM write_ctx WHERE id = 1) <> 'local'
                             AND (i.stamp_o, i.stamp_r) > (records.stamp_o, records.stamp_r)
                        ELSE (i.stamp_o, i.stamp_r) > ${seenPair("records.")} END)`,
      params: [...FIELDS.map(() => op), op, op, op, op, connectionId, op, op],
    },
  ];
  if (options.promoteSeen) {
    statements.push(
      // The logging trigger reads the origin: log the promotion as a local
      // change, which publish sends, then go back to the apply's origin.
      {
        sql: "UPDATE write_ctx SET origin = 'local' WHERE id = 1 AND origin = 'remote'",
        params: [],
      },
      {
        sql: `UPDATE records SET stamp_o = ${SEEN.o}, stamp_r = ${SEEN.r}
 WHERE ${incomingKeys}
   AND (seen_o, seen_r) > (stamp_o, stamp_r)
   AND EXISTS (SELECT 1 FROM incoming i WHERE i.op = ? AND i.stream = records.stream AND i.pk_hash = records.pk_hash
               AND NOT (${SAME_BODY})
               AND (i.stamp_o, i.stamp_r) > (records.stamp_o, records.stamp_r))`,
        params: [connectionId, op, op],
      },
      {
        sql: "UPDATE write_ctx SET origin = 'remote' WHERE id = 1 AND origin = 'local'",
        params: [],
      },
    );
  }
  statements.push(
    {
      sql: `INSERT INTO records (connection_id, stream, pk_hash, ${FIELDS.join(", ")}, first_o)
SELECT ?, i.stream, i.pk_hash, ${FIELDS.map((f) => `i.${f}`).join(", ")},
       CASE WHEN (SELECT origin FROM write_ctx WHERE id = 1) = 'import' THEN NULL ELSE i.first_o END
 FROM incoming i
 WHERE i.op = ? AND NOT EXISTS (SELECT 1 FROM records r WHERE r.connection_id = ? AND r.stream = i.stream AND r.pk_hash = i.pk_hash)`,
      params: [connectionId, op, connectionId],
    },
    { sql: "DELETE FROM incoming WHERE op = ?", params: [op] },
  );
  return statements;
}

/**
 * Apply's one delete per stream (origin `remote`): drops rows the applied head
 * does not hold, except rows in an unchanged part (`keep_ranges`) and rows a
 * local write changed after the publish watermark. Clears the operation's TEMP rows.
 *
 * A head that omits a row says the source did not list it when the head was
 * observed (`observedAt`). A run on this device that saw the row's body later
 * than that, and only moved `seen`, logged no change. Before the delete, that
 * sighting becomes the row's published stamp, as a local change, so the delete
 * spares it and publish sends the row back.
 */
export function applyDelete(
  op: string,
  connectionId: string,
  stream: string,
  observedAt: number = Number.MAX_SAFE_INTEGER,
): SqlStatement[] {
  const keys: SqlValue[] = [connectionId, stream];
  const omitted = `connection_id = ? AND stream = ?
   AND pk_hash NOT IN (SELECT pk_hash FROM temp.apply_keys WHERE op = ?)
   AND NOT EXISTS (SELECT 1 FROM temp.keep_ranges k WHERE k.op = ? AND records.pk_hash >= k.lo AND records.pk_hash < k.hi)`;
  return [
    {
      sql: "UPDATE write_ctx SET origin = 'local' WHERE id = 1 AND origin = 'remote'",
      params: [],
    },
    {
      sql: `UPDATE records SET stamp_o = seen_o, stamp_r = seen_r
 WHERE ${omitted}
   AND seen_o > ?`,
      params: [...keys, op, op, observedAt],
    },
    {
      sql: "UPDATE write_ctx SET origin = 'remote' WHERE id = 1 AND origin = 'local'",
      params: [],
    },
    {
      sql: `DELETE FROM records
 WHERE ${omitted}
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
 * drops the stream's rows no run at or above the run's stamp (o, then run id)
 * has observed.
 */
export function replaceDelete(
  connectionId: string,
  stream: string,
  stampO: number,
  stampR: string,
): SqlStatement {
  return {
    sql: `DELETE FROM records WHERE connection_id = ? AND stream = ?
   AND ${SEEN_BEFORE}`,
    params: [connectionId, stream, ...seenBeforeParams(stampO, stampR)],
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
        AND ${SEEN_PAIR} <= (?, ?)`,
      params: [connectionId, stream, runId, stream, observedAt, runId],
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

/**
 * A run that was refused or discarded is un-written: delete the rows it
 * changed (they carry its stamp), and forget that it observed the rest. The
 * rows it only observed were there before it, so they stay.
 */
export function dropRunRows(
  connectionId: string,
  stream: string,
  o: number,
  runId: string,
): SqlStatement[] {
  return [
    {
      sql: `DELETE FROM records WHERE connection_id = ? AND stream = ?
   AND stamp_o = ? AND stamp_r = ?`,
      params: [connectionId, stream, o, runId],
    },
    {
      sql: `UPDATE records SET seen_o = NULL, seen_r = NULL
 WHERE connection_id = ? AND stream = ? AND seen_o = ? AND seen_r = ?`,
      params: [connectionId, stream, o, runId],
    },
  ];
}
