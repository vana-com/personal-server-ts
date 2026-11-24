// The writes that keep a stream's first load readable while it applies: the
// row of `stream_partial`, and the list of keys `partial_hidden` keeps out of
// the view. The log's apply (`log-apply.ts`, a log's segments and snapshot parts)
// writes them here, and `partial-read.ts` is the one reader: a row is visible
// during a load when it is stored and not in `partial_hidden`. No path has a
// predicate of its own.

import type { SqlStatement } from "./driver.js";

/** The head a load builds: what a reader pins and what completion becomes. */
export interface PartialIdentity {
  readonly connectionId: string;
  readonly stream: string;
  readonly version: number;
  readonly generation: number;
  readonly dataHash: string;
  readonly headBlob: string;
  readonly observedAt: number;
}

/**
 * The stream's row, with `applied` of `total` parts shown. Never fewer parts
 * than a load of this same head already showed. `recordsTotal` 0 means the
 * total is not known: a log has no count of the rows its fold will hold.
 */
export function partialRowStatement(
  head: PartialIdentity,
  applied: number,
  total: number,
  recordsTotal: number,
): SqlStatement {
  return {
    sql: `INSERT OR REPLACE INTO stream_partial (connection_id,stream,version,generation,data_hash,head_blob,observed_at,parts_applied,parts_total,records_total)
 VALUES (?,?,?,?,?,?,?,MAX(?,COALESCE((SELECT parts_applied FROM stream_partial WHERE connection_id=? AND stream=? AND version=? AND generation=? AND data_hash=?),0)),?,?)`,
    params: [
      head.connectionId,
      head.stream,
      head.version,
      head.generation,
      head.dataHash,
      head.headBlob,
      head.observedAt,
      applied,
      head.connectionId,
      head.stream,
      head.version,
      head.generation,
      head.dataHash,
      total,
      recordsTotal,
    ],
  };
}

/**
 * A load that begins hides every row the stream holds, outside the ranges the
 * load keeps as they are (`keepOp`: its rows of `temp.keep_ranges`). Nothing
 * is deleted: only the complete state decides which of them go (a row seen
 * again since the head's cutoff, a local change not yet published, a key a
 * later part holds). A part shows its keys by taking them off the list.
 */
export function hideStoredRows(
  connectionId: string,
  stream: string,
  keepOp?: string,
): SqlStatement[] {
  return [
    {
      sql: "DELETE FROM partial_hidden WHERE connection_id=? AND stream=?",
      params: [connectionId, stream],
    },
    {
      sql: `INSERT INTO partial_hidden (connection_id,stream,pk_hash)
 SELECT connection_id, stream, pk_hash FROM records
  WHERE connection_id = ? AND stream = ?${
    keepOp === undefined
      ? ""
      : `
    AND NOT EXISTS (SELECT 1 FROM temp.keep_ranges k WHERE k.op = ? AND records.pk_hash >= k.lo AND records.pk_hash < k.hi)`
  }`,
      params: [connectionId, stream, ...(keepOp === undefined ? [] : [keepOp])],
    },
  ];
}

/** The keys of this part (its rows of `temp.incoming` of the stream), which the merge then clears. */
export function showIncomingKeys(
  connectionId: string,
  stream: string,
  op: string,
): SqlStatement {
  return {
    sql: `DELETE FROM partial_hidden WHERE connection_id = ? AND stream = ?
   AND pk_hash IN (SELECT pk_hash FROM temp.incoming WHERE op = ? AND stream = ?)`,
    params: [connectionId, stream, op, stream],
  };
}

/** The load stopped before its last part, for `code` (see `failureCode`). */
export function failedRowStatement(
  head: PartialIdentity,
  code: string,
): SqlStatement {
  return {
    sql: "UPDATE stream_partial SET failed = 1, last_error = ? WHERE connection_id = ? AND stream = ? AND version = ? AND generation = ? AND data_hash = ?",
    params: [
      code,
      head.connectionId,
      head.stream,
      head.version,
      head.generation,
      head.dataHash,
    ],
  };
}

/**
 * The streams one apply attempt marked failed, with the reason of each. The
 * attempt owns it (`LocalSyncDeps.attemptFailures`); nothing outlives it.
 */
export type AttemptFailures = Map<string, string>;

/** Say that this attempt marked `streams` failed for `code`. */
export function noteMarkedFailed(
  into: AttemptFailures | undefined,
  streams: Iterable<string>,
  code: string,
): void {
  if (!into) return;
  for (const stream of streams) into.set(stream, code);
}

/** Rows a statement binds at most; SQLite 3.22 allows 999 variables. */
const HELD_PER_STATEMENT = 200;

/**
 * Keys the view keeps out although a part holds them: the log's later segment
 * (already fetched) deletes or omits them, so the finished result may lack
 * them. They stay hidden until a later part writes them again.
 */
export function holdKeys(
  connectionId: string,
  stream: string,
  keys: readonly string[],
): SqlStatement[] {
  const out: SqlStatement[] = [];
  for (let i = 0; i < keys.length; i += HELD_PER_STATEMENT) {
    const group = keys.slice(i, i + HELD_PER_STATEMENT);
    out.push({
      sql: `INSERT OR IGNORE INTO partial_hidden (connection_id,stream,pk_hash) VALUES ${group
        .map(() => "(?,?,?)")
        .join(",")}`,
      params: group.flatMap((pk) => [connectionId, stream, pk]),
    });
  }
  return out;
}

/**
 * A short, stable name for why an apply stopped, for a reader to show or
 * log: the error's own `code` if it has one, else its message as a slug
 * (`apply: missing part blob` is `missing_part_blob`).
 */
export function failureCode(error: unknown): string {
  const code = (error as { code?: unknown } | null)?.code;
  const text =
    typeof code === "string" && code !== ""
      ? code
      : error instanceof Error
        ? error.message
        : String(error);
  return (
    text
      .replace(/^apply:\s*/i, "")
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "_")
      .replace(/^_+|_+$/g, "")
      .slice(0, 64) || "unknown"
  );
}
