import { readerOf, type SqlDriver, type SqlReader } from "./driver.js";
import { PartialViewMoved, type PartialHead } from "./partial-read.js";

/**
 * Rows per page. A page is one statement on the reader, so the size trades
 * statement overhead against how long one statement keeps the reader. 500
 * rows read a 198k-row stream in the browser faster than the unpaged body did
 * (3.7 s against 4.1 to 4.9 s); 100 rows were 13% slower.
 */
export const COMPLETE_PAGE_SIZE = 500;
const PAGE_SIZE = COMPLETE_PAGE_SIZE;

/**
 * Pins a stream for a body that is read a page at a time: the epoch of its
 * change mark, taken so that any change after this returns moves the epoch.
 *
 * The mark (`stream_change_marks`) is written by the first change after its
 * `dirty` flag was cleared, and that write counts a new epoch. Reading the
 * epoch and then clearing the flag gives the guarantee: a change after the
 * clear finds the flag clear and moves the epoch; a change between the read
 * and the clear leaves the flag set but is already in the rows every page
 * reads afterwards, and a pin that reads an epoch such a change moved only
 * fails its first check, which is safe. Another reader clearing the flag
 * later cannot hide a change from this pin: the change that set the flag
 * moved the epoch first. A stream with no mark has epoch 0, and its first
 * change creates the mark at epoch 1. Call it before the head is read.
 */
export async function pinStream(
  db: SqlDriver,
  connectionId: string,
  stream: string,
): Promise<number> {
  return clearMark(
    db,
    connectionId,
    stream,
    await readMark(db, connectionId, stream),
  );
}

/** What a stream's change mark says now (`pinStream`'s first step). */
export async function readMark(
  db: SqlDriver,
  connectionId: string,
  stream: string,
): Promise<{ epoch: number; dirty: number }> {
  const [mark] = await readerOf(db).query<{ epoch: number; dirty: number }>(
    "SELECT epoch, dirty FROM stream_change_marks WHERE connection_id = ? AND stream = ?",
    [connectionId, stream],
  );
  return mark ?? { epoch: 0, dirty: 0 };
}

/** Clears the flag a mark was read with set, and returns its epoch (`pinStream`'s second step). */
export async function clearMark(
  db: SqlDriver,
  connectionId: string,
  stream: string,
  read: { epoch: number; dirty: number },
): Promise<number> {
  if (read.dirty === 1) {
    await db.batch([
      {
        sql: "UPDATE stream_change_marks SET dirty = 0 WHERE connection_id = ? AND stream = ?",
        params: [connectionId, stream],
      },
    ]);
  }
  return read.epoch;
}

/**
 * The statement and parameters of one page of a complete body: the check, then
 * the rows after `after` (the key hash the last page ended at; none for the
 * first page).
 *
 * The rows come from their own subquery. Joined straight to the check's one
 * row, the planner may pick an index in another order and sort the whole
 * stream, which costs a page read per row in a browser. A subquery with a
 * `LIMIT` is not merged into the join, so it reads the key index in order and
 * stops after the page. SQL does not promise that the join keeps that order,
 * and the reader takes the last row of a page as the next cursor, so the outer
 * query sorts the page again: at most `PAGE_SIZE` rows, never the stream.
 *
 * The check is the rule `partialBody` applies to a head that completed: the
 * stream's installed head (its version and data hash) is the one the read was
 * decided on, and its connection is still active, of the same generation,
 * with no delete intent. Both answer in the statement that reads the rows. A
 * head that stopped being complete, or moved to another generation, has a
 * version of its own, so the version names those too.
 *
 * One more clause, because of how a head replaces another. An apply writes the
 * rows of a new head into the table in commits of its own, and moves the
 * stream's head in its last one. For all of that time the head still names the
 * old one, while the rows are a mix. So a complete body also needs the stream
 * to have had no row written, changed or removed since it was pinned
 * (`pinStream`): the epoch of the stream's change mark is still the pinned
 * one. The mark is one primary-key row, so the check does not read what other
 * streams and connections write meanwhile.
 */
export function completePage(
  head: PartialHead,
  pin: number,
  after: string | undefined,
): { sql: string; params: (string | number)[] } {
  return {
    sql: `WITH g AS (SELECT (
         EXISTS (SELECT 1 FROM stream_state s WHERE s.connection_id = ? AND s.stream = ?
                   AND s.head_version = ? AND s.head_data_hash = ?)
         AND EXISTS (SELECT 1 FROM connections c WHERE c.connection_id = ? AND c.generation = ?
                   AND c.control_state = 'active' AND c.deleted_at IS NULL
                   AND NOT EXISTS (SELECT 1 FROM delete_intents d WHERE d.connector = c.connector))
         AND COALESCE((SELECT m.epoch FROM stream_change_marks m
                        WHERE m.connection_id = ? AND m.stream = ?), 0) = ?) AS ok)
       SELECT g.ok AS ok, r.pk_hash AS pk_hash, r.body AS body
       FROM g LEFT JOIN (
         SELECT pk_hash, body FROM records r
         WHERE (SELECT ok FROM g) = 1 AND r.connection_id = ? AND r.stream = ?
           ${after === undefined ? "" : "AND r.pk_hash > ?"}
         ORDER BY r.pk_hash LIMIT ?) r
       ORDER BY r.pk_hash`,
    params: [
      head.connectionId,
      head.stream,
      head.version,
      head.dataHash,
      head.connectionId,
      head.generation,
      head.connectionId,
      head.stream,
      pin,
      head.connectionId,
      head.stream,
      ...(after === undefined ? [] : [after]),
      PAGE_SIZE,
    ],
  };
}

/**
 * The records of one stream's complete head, as the JSON body of a read, in
 * primary-key hash order a page at a time. The body is the stream as it was
 * when `pin` was taken or it ends in `PartialViewMoved`, which a reader
 * answers by asking again: never a body of two states. Nothing is held between
 * pages, so a body that is not read to its end costs nothing.
 */
export async function* completeBody(
  db: SqlReader,
  head: PartialHead,
  pin: number,
): AsyncGenerator<string> {
  yield '{"records":[';
  let first = true;
  let after: string | undefined;
  for (;;) {
    const { sql, params } = completePage(head, pin, after);
    const page = await db.query<{
      ok: number;
      pk_hash: string | null;
      body: string | null;
    }>(sql, params);
    if (page[0]?.ok !== 1) throw new PartialViewMoved();
    const rows = page.filter((row) => row.pk_hash !== null);
    for (const row of rows) {
      yield (first ? "" : ",") + row.body!;
      first = false;
    }
    if (rows.length < PAGE_SIZE) break;
    after = rows[rows.length - 1]!.pk_hash!;
  }
  yield "]}";
}
