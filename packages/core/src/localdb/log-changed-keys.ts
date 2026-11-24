// The keys changed in a window of a stream's change log, oldest change first,
// a page at a time. A publish round takes a segment's worth of them and stops;
// reading them all (a key per row of the source) made each round, and so the
// whole publish, cost memory and time in the size of what was left.
//
// A key's place is its last eligible change in the window: the order of
// `SELECT pk_hash, MAX(seq) ... GROUP BY pk_hash ORDER BY MAX(seq)`. The change
// rows are read in `seq` order, and a row is kept only if no later eligible
// change of its key is in the window (the key's `MAX(seq)`, one lookup on the
// `(connection_id, stream, pk_hash, seq)` index per page).

import type { SqlDriver } from "./driver.js";
import { rowsPerStatement } from "./log-batch.js";
import { ELIGIBLE_CHANGE } from "./publication-work.js";

/** Rows a page reads; also the keys its last-change lookup binds. */
export const CHANGE_PAGE = rowsPerStatement(1, 4);

export interface ChangedKey {
  readonly pk: string;
  readonly seq: number;
}

type Db = Pick<SqlDriver, "query">;

/** Whether the window holds a change that counts. */
export async function hasChangedKeys(
  db: Db,
  connectionId: string,
  stream: string,
  from: number,
  to: number,
): Promise<boolean> {
  const rows = await db.query<{ seq: number }>(
    `SELECT seq FROM record_changes
      WHERE connection_id = ? AND stream = ? AND seq > ? AND seq <= ?
        AND ${ELIGIBLE_CHANGE} LIMIT 1`,
    [connectionId, stream, from, to],
  );
  return rows.length > 0;
}

/** The changed keys of the window in pages of at most `CHANGE_PAGE`. */
export async function* changedKeyPages(
  db: Db,
  connectionId: string,
  stream: string,
  from: number,
  to: number,
): AsyncGenerator<ChangedKey[], void, void> {
  let after = from;
  for (;;) {
    const rows = await db.query<{ pk_hash: string; seq: number }>(
      `SELECT pk_hash, seq FROM record_changes NOT INDEXED
        WHERE connection_id = ? AND stream = ? AND seq > ? AND seq <= ?
          AND ${ELIGIBLE_CHANGE}
        ORDER BY seq LIMIT ${CHANGE_PAGE}`,
      [connectionId, stream, after, to],
    );
    if (rows.length === 0) return;
    const pks = [...new Set(rows.map((row) => row.pk_hash))];
    const last = await db.query<{ pk_hash: string; seq: number }>(
      `SELECT pk_hash, MAX(seq) AS seq FROM record_changes
        WHERE connection_id = ? AND stream = ? AND seq > ? AND seq <= ?
          AND ${ELIGIBLE_CHANGE}
          AND pk_hash IN (${pks.map(() => "?").join(",")})
        GROUP BY pk_hash`,
      [connectionId, stream, from, to, ...pks],
    );
    const latest = new Map(last.map((row) => [row.pk_hash, row.seq]));
    const keys = rows
      .filter((row) => latest.get(row.pk_hash) === row.seq)
      .map((row) => ({ pk: row.pk_hash, seq: row.seq }));
    if (keys.length > 0) yield keys;
    if (rows.length < CHANGE_PAGE) return;
    after = rows[rows.length - 1]!.seq;
  }
}

/** A deletion in the window that has no typed key of its own. */
export interface UntypedDelete {
  readonly pk: string;
  /** The lossy string key of the deletion, which a declared type may give back. */
  readonly recordKey: string;
  readonly seq: number;
}

/**
 * The keys whose last say in the window is an explicit delete made before
 * typed keys were kept (`pk_values` null), for keys that no row holds and that
 * have a change that counts. These are the deletes the log cannot name unless
 * the stream's declared key types give the key back.
 *
 * They are read from the rows of such deletes alone, by the partial index
 * `record_changes_untyped_deletes`: a stream with none visits no row,
 * whatever the window holds, so asking again each round does not grow with the
 * changes still to publish.
 */
export async function* untypedDeletePages(
  db: Db,
  connectionId: string,
  stream: string,
  from: number,
  to: number,
): AsyncGenerator<UntypedDelete[], void, void> {
  let after = from;
  for (;;) {
    const rows = await db.query<{
      pk_hash: string;
      record_key: string;
      seq: number;
    }>(
      `SELECT d.pk_hash, d.record_key, d.seq FROM record_changes d
        WHERE d.connection_id = ? AND d.stream = ? AND d.seq > ? AND d.seq <= ?
          AND d.op = 'remove' AND d.explicit_delete = 1 AND d.pk_values IS NULL
          AND NOT EXISTS (SELECT 1 FROM records h
                           WHERE h.connection_id = d.connection_id
                             AND h.stream = d.stream AND h.pk_hash = d.pk_hash)
          AND d.seq = (SELECT MAX(m.seq) FROM record_changes m
                        WHERE m.connection_id = d.connection_id
                          AND m.stream = d.stream AND m.pk_hash = d.pk_hash
                          AND m.seq > ? AND m.seq <= ?
                          AND m.op = 'remove'
                          AND (m.explicit_delete = 1 OR m.pk_values IS NOT NULL))
          AND EXISTS (SELECT 1 FROM record_changes
                       WHERE connection_id = d.connection_id
                         AND stream = d.stream AND pk_hash = d.pk_hash
                         AND seq > ? AND seq <= ? AND ${ELIGIBLE_CHANGE})
        ORDER BY d.seq LIMIT ${CHANGE_PAGE}`,
      [connectionId, stream, after, to, from, to, from, to],
    );
    if (rows.length === 0) return;
    yield rows.map((row) => ({
      pk: row.pk_hash,
      recordKey: row.record_key,
      seq: row.seq,
    }));
    if (rows.length < CHANGE_PAGE) return;
    after = rows[rows.length - 1]!.seq;
  }
}
