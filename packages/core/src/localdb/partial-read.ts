import type { SqlReader } from "./driver.js";

/**
 * The head a partial view was built for. A body of rows is served only while
 * this head still owns them.
 */
export interface PartialHead {
  readonly connectionId: string;
  readonly generation: number;
  readonly stream: string;
  readonly version: number;
  readonly dataHash: string;
}

/**
 * The head a body was reading is no longer the stream's head: another head
 * began loading (and dropped these rows), the connection's generation moved,
 * or the connection was deleted or has a delete intent saved (the purge that
 * follows removes these rows, and waits behind the apply that serves them). The body stops there, so a reader sees an
 * aborted read and asks again, never a body of two heads.
 */
export class PartialViewMoved extends Error {
  constructor() {
    super("partial view: the head it was reading moved");
    this.name = "PartialViewMoved";
  }
}

const PAGE_SIZE = 100;

/**
 * The records of one stream's first load, as the JSON body of a read: the rows
 * of the parts applied so far, in primary-key hash order, a page at a time.
 * A row the stream held before the load began stays out of it (`partial_hidden`)
 * until a part holds its key: the complete state, not this read, decides
 * whether it stays, so a view never shows a row the finished result lacks.
 *
 * A body streams while apply goes on committing parts, so each page checks,
 * in the same statement that reads the rows, that the head is still the one
 * the view was built for: its load is still running, or it completed (the same
 * head, then complete). A part of the same head landing between pages only
 * adds rows. A different head replaces the rows in one commit, and this check
 * is what keeps a body from holding rows from before it and after it.
 */
export async function* partialBody(
  db: SqlReader,
  head: PartialHead,
): AsyncGenerator<string> {
  yield '{"records":[';
  let first = true;
  let after: string | undefined;
  for (;;) {
    const page = await db.query<{
      ok: number;
      pk_hash: string | null;
      body: string | null;
    }>(
      `WITH g AS (SELECT (
         (EXISTS (SELECT 1 FROM stream_partial p WHERE p.connection_id = ? AND p.stream = ?
                    AND p.version = ? AND p.generation = ? AND p.data_hash = ?)
          OR EXISTS (SELECT 1 FROM stream_state s WHERE s.connection_id = ? AND s.stream = ?
                    AND s.complete = 1 AND s.head_version = ? AND s.head_generation = ? AND s.head_data_hash = ?))
         AND EXISTS (SELECT 1 FROM connections c WHERE c.connection_id = ? AND c.generation = ?
                    AND c.control_state = 'active' AND c.deleted_at IS NULL
                    AND NOT EXISTS (SELECT 1 FROM delete_intents d WHERE d.connector = c.connector))) AS ok)
       SELECT g.ok AS ok, r.pk_hash AS pk_hash, r.body AS body
       FROM g LEFT JOIN records r ON g.ok = 1 AND r.connection_id = ? AND r.stream = ?
         AND NOT EXISTS (SELECT 1 FROM partial_hidden h WHERE h.connection_id = r.connection_id
                           AND h.stream = r.stream AND h.pk_hash = r.pk_hash)
         ${after === undefined ? "" : "AND r.pk_hash > ?"}
       ORDER BY r.pk_hash LIMIT ?`,
      [
        head.connectionId,
        head.stream,
        head.version,
        head.generation,
        head.dataHash,
        head.connectionId,
        head.stream,
        head.version,
        head.generation,
        head.dataHash,
        head.connectionId,
        head.generation,
        head.connectionId,
        head.stream,
        ...(after === undefined ? [] : [after]),
        PAGE_SIZE,
      ],
    );
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
