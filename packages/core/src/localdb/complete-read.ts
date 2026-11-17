import type { SqlReader } from "./driver.js";
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
 * The newest change `record_changes` holds. Read before the head is read, so
 * a row that changes in between is a change after the pin, never one the body
 * could miss.
 */
export async function changePin(db: SqlReader): Promise<number> {
  const [row] = await db.query<{ seq: number }>(
    "SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name = 'record_changes'), 0) AS seq",
  );
  return row!.seq;
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
 * stream's installed head is the one the read was decided on, and its
 * connection is still active, of the same generation, with no delete intent.
 * Both answer in the statement that reads the rows.
 *
 * One more clause, because of how a head replaces another. An apply writes the
 * rows of a new head into the table in commits of its own, and moves the
 * stream's head in its last one. For all of that time the head still names the
 * old one, while the rows are a mix. So a complete body also needs the stream
 * to have had no row written, changed or removed since `since`, which is what
 * every write of a row leaves in `record_changes`. A compaction that erased
 * such an entry moves `change_floor` past `since`: the check then fails
 * instead of trusting an absence it can no longer see. The check seeks
 * `record_changes_by_stream` to the stream's entries after `since`, so what
 * other streams and connections wrote meanwhile is not read.
 */
export function completePage(
  head: PartialHead,
  since: number,
  after: string | undefined,
): { sql: string; params: (string | number)[] } {
  return {
    sql: `WITH g AS (SELECT (
         EXISTS (SELECT 1 FROM stream_state s WHERE s.connection_id = ? AND s.stream = ?
                   AND s.complete = 1 AND s.head_version = ? AND s.head_generation = ? AND s.head_data_hash = ?)
         AND EXISTS (SELECT 1 FROM connections c WHERE c.connection_id = ? AND c.generation = ?
                   AND c.control_state = 'active' AND c.deleted_at IS NULL
                   AND NOT EXISTS (SELECT 1 FROM delete_intents d WHERE d.connector = c.connector))
         AND (SELECT change_floor FROM db_meta WHERE id = 1) <= ?
         AND NOT EXISTS (SELECT 1 FROM record_changes x
                           WHERE x.seq > ? AND x.connection_id = ? AND x.stream = ?)) AS ok)
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
      head.generation,
      head.dataHash,
      head.connectionId,
      head.generation,
      since,
      since,
      head.connectionId,
      head.stream,
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
 * when `since` was pinned or it ends in `PartialViewMoved`, which a reader
 * answers by asking again: never a body of two states. Nothing is held between
 * pages, so a body that is not read to its end costs nothing.
 */
export async function* completeBody(
  db: SqlReader,
  head: PartialHead,
  since: number,
): AsyncGenerator<string> {
  yield '{"records":[';
  let first = true;
  let after: string | undefined;
  for (;;) {
    const { sql, params } = completePage(head, since, after);
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
