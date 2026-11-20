/**
 * A stream's connector cursor on its way into the log (see the
 * `stream_state.cursor_*` migration in schema.ts). A run end saves it as
 * unpublished; the publisher carries it in the segment that closes the rows
 * it covers; a path that drops the run's rows drops it.
 */
import type { SqlStatement } from "./driver.js";

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
