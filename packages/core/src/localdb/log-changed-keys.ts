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
