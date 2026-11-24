// Reads that hold row bodies are cut by the bytes the reply will hold, never
// by a row count or an estimate from rows already read.
//
// A phone's SQL bridge refuses a reply over 4 MiB of JSON. A text value in a
// reply is escaped a second time (a quote or a backslash is two bytes), so
// its worst case is twice its stored size; a blob travels as base64, a third
// larger and never more. A body is therefore read as a blob
// (`CAST(body AS BLOB)`) and decoded here, and a page costs `replyBytes` of its
// stored bytes, whatever the characters are.
//
// A caller first reads the sizes of the next rows alone (small rows: a key and
// a number), then fetches the longest run of them that fits the budget. A row
// that alone costs more than the budget is read by itself, in chunks
// (`readChunked`), each a blob of at most `CHUNK_BYTES`: a value larger than
// the frame still crosses it.

import type { SqlDriver, SqlValue } from "./driver.js";

/**
 * What one request or one reply holds, at most, when two or more rows fit: a
 * quarter of the bridge's 4 MiB frame, as the other byte-cut batches take
 * (`BATCH_BYTES` of the seed staging, `WHOLE_STREAM_BATCH_BYTES` of the alias
 * reads). The rest of the frame is the headroom for what the count leaves out:
 * column names, keys and the shape of a result.
 */
export const PAGE_BYTES = 1024 * 1024;
/** Stored bytes of one chunk of a value read in pieces: a reply of a third more. */
export const CHUNK_BYTES = 1024 * 1024;
/** Rows whose sizes are read at a time: a bound on a size query, not on a page. */
export const SIZE_ROWS = 2048;
/** What a row costs beyond its values: column names and the shape of a result. */
const ROW_OVERHEAD = 256;

/** The most stored bytes of one body that a reply holds beside other rows (`fitsPage` of its `replyBytes`). */
export const INLINE_BYTES = 3 * Math.floor((PAGE_BYTES - ROW_OVERHEAD) / 4);

/**
 * A text column as a blob in a select list, or NULL when its `bytes` (an SQL
 * expression for its stored size) are over `INLINE_BYTES`: the caller then
 * reads that one value in chunks. A body that fits is a blob in the reply, so
 * what escapes in JSON (quotes, backslashes, control characters) costs
 * nothing more.
 */
export const blobIfFits = (column: string, bytes: string): string =>
  `CASE WHEN ${bytes} <= ${INLINE_BYTES} THEN CAST(${column} AS BLOB) END`;

/** The bytes of a reply that holds `stored` bytes of a blob: base64. */
export const replyBytes = (stored: number): number => 4 * Math.ceil(stored / 3);

/** Whether a row that costs `cost` fits a page with other rows. */
export const fitsPage = (cost: number): boolean =>
  cost + ROW_OVERHEAD <= PAGE_BYTES;

/**
 * How many leading rows of `costs` (what each row's reply holds) fit
 * `budget`: at least one, so a row over the budget is a page of its own, and
 * none for no rows.
 */
export function rowsWithin(
  costs: readonly number[],
  budget: number = PAGE_BYTES,
): number {
  let take = 0;
  let bytes = 0;
  while (take < costs.length) {
    const next = costs[take]! + ROW_OVERHEAD;
    if (take > 0 && bytes + next > budget) break;
    bytes += next;
    take += 1;
  }
  return take;
}

/**
 * A value of `bytes` stored bytes, read in blobs of at most `CHUNK_BYTES`.
 * `chunk(offset, length)` is the statement for the bytes `[offset, offset +
 * length)` counted from 1, as `substr` counts: it must return one row with the
 * blob in its first column (`substr(CAST(column AS BLOB), ?, ?)`).
 */
export async function readChunked(
  db: Pick<SqlDriver, "query">,
  bytes: number,
  chunk: (
    offset: number,
    length: number,
  ) => { sql: string; params: readonly SqlValue[] },
): Promise<Uint8Array> {
  const whole = new Uint8Array(bytes);
  let at = 0;
  while (at < bytes) {
    const { sql, params } = chunk(at + 1, Math.min(CHUNK_BYTES, bytes - at));
    const [row] = await db.query<Record<string, Uint8Array | null>>(
      sql,
      params,
    );
    const part = row ? Object.values(row)[0] : null;
    if (!part || part.length === 0)
      throw new Error("a stored value is gone or cut short");
    whole.set(part, at);
    at += part.length;
  }
  return whole;
}

const decoder = new TextDecoder();
/** A body read as a blob, as the text it was stored as. */
export const textOf = (bytes: Uint8Array): string => decoder.decode(bytes);
