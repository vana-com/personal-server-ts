/**
 * A stream's connector cursor on its way into and out of the log (see the
 * `stream_state.cursor_*` migration in schema.ts). A run end saves it as
 * unpublished; the publisher carries it in the segment that closes the rows
 * it covers; a path that drops the run's rows drops it. A device that applies
 * the segment takes the cursor with its rows.
 */
import {
  isPlainObject,
  type JsonValue,
  type LogCursor,
} from "@opendatalabs/personal-server-ts-stream-sync";
import type { SqlDriver, SqlStatement } from "./driver.js";

/**
 * A checkpoint entry a run end wrote waits to travel in the log. It runs
 * after the merge in the same batch, so `cursor_seq` is the stream's last
 * change seq, which includes this run's rows.
 */
export function cursorSaved(
  connectionId: string,
  stream: string,
  state: unknown,
  connectorVersion: string,
  children: readonly string[],
): SqlStatement {
  return {
    sql: `UPDATE stream_state SET
      cursor_unpublished = ?,
      cursor_write = cursor_write + 1,
      cursor_seq = (SELECT COALESCE(MAX(seq), 0) FROM record_changes WHERE connection_id = ? AND stream = ?),
      cursor_children = ?,
      cursor_version = ?
    WHERE connection_id = ? AND stream = ?`,
    params: [
      JSON.stringify({ state, connectorVersion }),
      connectionId,
      stream,
      JSON.stringify(children),
      connectorVersion,
      connectionId,
      stream,
    ],
  };
}

/**
 * Each stream's state descendants: the streams that name it as a state
 * parent, and theirs, and so on. A parent's cursor claims their rows too
 * (they are read through it), so it travels only once they are published.
 */
export function stateDescendants(
  parentsOf: Readonly<Record<string, readonly string[]>>,
): Record<string, string[]> {
  const children = new Map<string, string[]>();
  for (const [child, parents] of Object.entries(parentsOf))
    for (const parent of parents)
      children.set(parent, [...(children.get(parent) ?? []), child]);
  const out: Record<string, string[]> = Object.create(null);
  for (const stream of Object.keys(parentsOf)) {
    const seen = new Set<string>();
    const queue = [...(children.get(stream) ?? [])];
    while (queue.length > 0) {
      const next = queue.shift()!;
      if (next === stream || seen.has(next)) continue;
      seen.add(next);
      queue.push(...(children.get(next) ?? []));
    }
    out[stream] = [...seen].sort();
  }
  return out;
}

/**
 * A run whose rows are dropped after its end (refused, fenced) must not
 * publish a cursor: the cursor may cover the dropped rows. The pending cursors
 * of the whole connection go, since a parent's cursor may cover the child's
 * rows. The local checkpoint stays as it was; another device that lacks the
 * cursor reads the stream in full.
 */
export function dropUnpublishedCursors(connectionId: string): SqlStatement {
  return {
    sql: "UPDATE stream_state SET cursor_unpublished = NULL, cursor_seq = NULL, cursor_children = NULL WHERE connection_id = ?",
    params: [connectionId],
  };
}

/**
 * A segment that carried `cursor` for `stream` is applied (or was published by
 * this device): written in the batch of the rows the cursor covers. The
 * stream's checkpoint entry takes it at the next fold.
 */
export function cursorApplied(
  connectionId: string,
  stream: string,
  cursor: LogCursor,
): SqlStatement {
  return {
    sql: "UPDATE stream_state SET cursor_applied = ? WHERE connection_id = ? AND stream = ?",
    params: [JSON.stringify(cursor), connectionId, stream],
  };
}

/**
 * Move the applied cursors into `connections.checkpoint`, each as its stream's
 * entry: the device holds the rows the log's cursor covers. Run before every
 * read of the checkpoint.
 *
 * The cursor later in log order wins. A stream whose own cursor waits to
 * publish (`cursor_unpublished`) keeps its entry and `cursor_version`: every
 * segment this device applies was published before that cursor, which goes
 * to the log after it. Its applied cursor stays staged. The acknowledgement
 * of the device's own cursor replaces it; a drop of the pending cursor lets
 * the next fold take it.
 *
 * The write is conditional on the checkpoint it read; a fold that loses that
 * race leaves the cursors staged for the next one, and the reader resumes
 * from what the checkpoint held, which reads more, never less.
 */
export async function foldAppliedCursors(
  db: SqlDriver,
  connectionId: string,
): Promise<void> {
  const applied = await db.query<{ stream: string; cursor_applied: string }>(
    "SELECT stream, cursor_applied FROM stream_state WHERE connection_id = ? AND cursor_applied IS NOT NULL AND cursor_unpublished IS NULL",
    [connectionId],
  );
  if (applied.length === 0) return;
  const [connection] = await db.query<{ checkpoint: string | null }>(
    "SELECT checkpoint FROM connections WHERE connection_id = ?",
    [connectionId],
  );
  if (!connection) return;
  const stored: unknown =
    connection.checkpoint === null ? null : JSON.parse(connection.checkpoint);
  const next: Record<string, JsonValue> = isPlainObject(stored)
    ? { ...(stored as Record<string, JsonValue>) }
    : {};
  const cursors = applied.map((row) => ({
    ...row,
    cursor: JSON.parse(row.cursor_applied) as LogCursor,
  }));
  for (const { stream, cursor } of cursors) next[stream] = cursor.state;
  const checkpoint = JSON.stringify(next);
  await db.batch([
    {
      sql: "UPDATE connections SET checkpoint = ? WHERE connection_id = ? AND checkpoint IS ?",
      params: [checkpoint, connectionId, connection.checkpoint],
    },
    ...cursors.map(({ stream, cursor_applied, cursor }) => ({
      sql: `UPDATE stream_state SET cursor_version = ?, cursor_applied = NULL
             WHERE connection_id = ? AND stream = ? AND cursor_applied = ?
               AND cursor_unpublished IS NULL
               AND (SELECT checkpoint FROM connections WHERE connection_id = ?) = ?`,
      params: [
        cursor.connectorVersion,
        connectionId,
        stream,
        cursor_applied,
        connectionId,
        checkpoint,
      ],
    })),
  ]);
}

/**
 * After a rebase queues again the rows that only the lost segments held: each
 * stream whose lost segments carried a cursor queues its checkpoint entry
 * again, and every cursor waiting to publish waits for the queued rows. The
 * device does not know which streams a re-queued cursor reads through, so it
 * waits for every other stream of the connection to close.
 */
export async function cursorsRequeued(
  db: SqlDriver,
  connectionId: string,
  carried: readonly string[],
): Promise<SqlStatement[]> {
  const statements: SqlStatement[] = [];
  const [connection] = await db.query<{ checkpoint: string | null }>(
    "SELECT checkpoint FROM connections WHERE connection_id = ?",
    [connectionId],
  );
  const stored: unknown =
    connection?.checkpoint == null ? null : JSON.parse(connection.checkpoint);
  if (carried.length > 0 && isPlainObject(stored)) {
    const rows = await db.query<{
      stream: string;
      cursor_version: string | null;
    }>(
      "SELECT stream, cursor_version FROM stream_state WHERE connection_id = ?",
      [connectionId],
    );
    for (const stream of carried) {
      const state = (stored as Record<string, JsonValue>)[stream];
      const version = rows.find((r) => r.stream === stream)?.cursor_version;
      if (state === undefined || version == null) continue;
      statements.push({
        sql: `UPDATE stream_state SET cursor_unpublished = ?, cursor_children = ?,
                 cursor_write = cursor_write + 1
               WHERE connection_id = ? AND stream = ? AND cursor_unpublished IS NULL`,
        params: [
          JSON.stringify({ state, connectorVersion: version }),
          JSON.stringify(
            rows.map((r) => r.stream).filter((other) => other !== stream),
          ),
          connectionId,
          stream,
        ],
      });
    }
  }
  statements.push({
    sql: `UPDATE stream_state SET cursor_seq = (
            SELECT COALESCE(MAX(seq), 0) FROM record_changes c
             WHERE c.connection_id = stream_state.connection_id AND c.stream = stream_state.stream)
           WHERE connection_id = ? AND cursor_unpublished IS NOT NULL`,
    params: [connectionId],
  });
  return statements;
}
