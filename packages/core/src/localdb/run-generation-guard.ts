/**
 * SQL condition (one `?` parameter: the run id) that is true while the run
 * still owns its connection's state: the run has no admitted generation yet,
 * or the connection has not moved past it. A fenced collector from an older
 * generation must not reset the checkpoint or stream completeness that a
 * newer generation committed. `table` is the table being updated; it must
 * have a `connection_id` column.
 */
export function runOwnsConnectionState(
  table: "connections" | "stream_state",
): string {
  return `EXISTS (
    SELECT 1 FROM runs r JOIN connections c ON c.connection_id = r.connection_id
    WHERE r.run_id = ? AND r.connection_id = ${table}.connection_id
      AND (r.generation IS NULL OR c.generation <= r.generation))`;
}
