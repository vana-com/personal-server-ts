// Writes that carry bodies are cut by the bytes they carry, never by a count.
//
// A phone's SQL bridge refuses a request over 4 MiB of JSON, sends a value
// over 1 MiB ahead of its statement in pieces (a staged value: at most 8 per
// request), and sends a blob as base64, a third larger. A batch of 200
// statements with bodies of 100 KB is 20 MB and is refused. A write path cuts
// its statements into batches of at most `WRITE_BATCH_BYTES` as they will be
// serialized; a group over the budget goes alone, so a batch holds at most one
// value the bridge stages.
//
// The budget is the 1 MiB that the other byte-cut batches use (`BATCH_BYTES`
// of the seed staging, `WHOLE_STREAM_BATCH_BYTES` of the alias reads): a
// quarter of the frame, which leaves room for the sql text, the keys and the
// escaping of quotes in a body (a quote costs two bytes in the stored body and
// four in the request).

import { PAGE_BYTES } from "./byte-pages.js";
import type { SqlDriver, SqlStatement, SqlValue } from "./driver.js";

/** What one write batch carries, at most, when two or more groups fit. */
export const WRITE_BATCH_BYTES = PAGE_BYTES;

/** The bytes `value` takes as UTF-8, the unit SQLite's `LENGTH(CAST(x AS BLOB))` counts. */
export function utf8Length(value: string): number {
  let bytes = 0;
  for (let i = 0; i < value.length; i++) {
    const unit = value.charCodeAt(i);
    if (unit < 0x80) bytes += 1;
    else if (unit < 0x800) bytes += 2;
    else if (
      unit >= 0xd800 &&
      unit <= 0xdbff &&
      i + 1 < value.length &&
      (value.charCodeAt(i + 1) & 0xfc00) === 0xdc00
    ) {
      bytes += 4;
      i += 1;
    } else bytes += 3;
  }
  return bytes;
}

/** The UTF-8 bytes of `JSON.stringify(value)`: the quotes, the escapes, the text. */
export function jsonStringBytes(value: string): number {
  let bytes = 2;
  for (let i = 0; i < value.length; i++) {
    const unit = value.charCodeAt(i);
    if (unit === 0x22 || unit === 0x5c) bytes += 2;
    else if (unit < 0x20)
      bytes +=
        unit === 8 || unit === 9 || unit === 10 || unit === 12 || unit === 13
          ? 2
          : 6;
    else if (unit < 0x80) bytes += 1;
    else if (unit < 0x800) bytes += 2;
    else if (
      unit >= 0xd800 &&
      unit <= 0xdbff &&
      i + 1 < value.length &&
      (value.charCodeAt(i + 1) & 0xfc00) === 0xdc00
    ) {
      bytes += 4;
      i += 1;
    } else if (unit >= 0xd800 && unit <= 0xdfff) bytes += 6;
    else bytes += 3;
  }
  return bytes;
}

function valueBytes(value: SqlValue): number {
  if (typeof value === "string") return jsonStringBytes(value);
  // `{"$":"b","v":"…"}`: base64 is four characters for three bytes.
  if (value instanceof Uint8Array) return 16 + 4 * Math.ceil(value.length / 3);
  // null, a number or an integer past 2^53 (`{"$":"i","v":"…"}`).
  return 32;
}

/** The bytes `statement` takes in a request, as the phone bridge serializes it. */
export function statementBytes(statement: SqlStatement): number {
  let bytes = jsonStringBytes(statement.sql) + 32;
  for (const value of statement.params ?? []) bytes += valueBytes(value) + 1;
  return bytes;
}

/**
 * Write `groups` in order, in batches of whole groups: a batch is closed when
 * the next group would take it past `budget`. A group over the budget is a
 * batch of its own. The groups are read one at a time.
 */
export async function writeInBatches(
  db: Pick<SqlDriver, "batch">,
  groups: Iterable<readonly SqlStatement[]>,
  budget: number = WRITE_BATCH_BYTES,
): Promise<void> {
  let batch: SqlStatement[] = [];
  let bytes = 0;
  for (const group of groups) {
    let size = 0;
    for (const statement of group) size += statementBytes(statement);
    if (batch.length > 0 && bytes + size > budget) {
      await db.batch(batch);
      batch = [];
      bytes = 0;
    }
    batch.push(...group);
    bytes += size;
    if (bytes >= budget) {
      await db.batch(batch);
      batch = [];
      bytes = 0;
    }
  }
  if (batch.length > 0) await db.batch(batch);
}
