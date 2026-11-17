import type { SqlReader } from "./driver.js";
import { connectionLifetime } from "./purge.js";

/** The same eligibility predicate for planning and completion, including imports and deletes. */
export const ELIGIBLE_CHANGE = `origin IN ('local', 'import', 'refresh')
  AND NOT EXISTS (SELECT 1 FROM runs r JOIN run_streams rs ON rs.run_id=r.run_id
    WHERE r.connection_id=record_changes.connection_id AND rs.stream=record_changes.stream
      AND r.run_id=record_changes.stamp_r AND r.o=record_changes.stamp_o
      AND r.admitting = 0 AND rs.decision IN ('refused','discarded'))`;

export const PENDING_RUN = `r.state = 'ended'
  AND rs.decision IN ('publish', 'noop', 'deferred')
  AND rs.publication_state = 'pending'`;

export interface PublicationWork {
  stream: string;
  generation: number;
  lifetime: object;
  /** Change identities are the monotonic seq interval (start, watermark], including collecting runs. */
  start: number;
  watermark: number;
  hadChanges: boolean;
  runIds: string[];
  runReasons: Map<string, string | null>;
}

/** Capture the work a caller awaits; a later collector cannot extend its obligation. */
export async function readPublicationWork(
  db: SqlReader,
  connectionId: string,
): Promise<PublicationWork[]> {
  // One statement captures changes and ended runs from the same database snapshot.
  const rows = await db.query<{
    stream: string;
    generation: number;
    watermark: number;
    start: number;
    run_id: string | null;
    blocked_reason: string | null;
  }>(
    `SELECT s.stream, c.generation, s.publish_watermark AS start, p.run_id, p.blocked_reason,
      COALESCE((SELECT MAX(seq) FROM record_changes
        WHERE connection_id=s.connection_id AND stream=s.stream
          AND seq > s.publish_watermark AND ${ELIGIBLE_CHANGE}), s.publish_watermark) AS watermark
      FROM stream_state s JOIN connections c ON c.connection_id=s.connection_id
      LEFT JOIN (SELECT r.connection_id, rs.stream, r.run_id, r.o, rs.publish_blocked_reason AS blocked_reason
        FROM runs r JOIN run_streams rs ON rs.run_id=r.run_id WHERE ${PENDING_RUN} AND r.connection_id=?) p
        ON p.connection_id=s.connection_id AND p.stream=s.stream
      WHERE s.connection_id=? ORDER BY s.stream, p.o, p.run_id`,
    [connectionId, connectionId],
  );
  const work = new Map<string, PublicationWork>();
  for (const row of rows) {
    let item = work.get(row.stream);
    if (!item) {
      item = {
        stream: row.stream,
        generation: row.generation,
        lifetime: connectionLifetime(db, connectionId),
        start: row.start,
        watermark: row.watermark,
        hadChanges: row.watermark > row.start,
        runIds: [],
        runReasons: new Map(),
      };
      work.set(row.stream, item);
    }
    if (row.run_id !== null) {
      item.runIds.push(row.run_id);
      item.runReasons.set(row.run_id, row.blocked_reason);
    }
  }
  return [...work.values()];
}

/** Reasons on unacknowledged changes in the original window; null means no blocker was recorded. */
export async function pendingChangeReasons(
  db: SqlReader,
  connectionId: string,
  work: PublicationWork,
): Promise<(string | null)[]> {
  const rows = await db.query<{ publish_blocked_reason: string | null }>(
    `SELECT DISTINCT publish_blocked_reason FROM record_changes WHERE connection_id=? AND stream=?
      AND seq > (SELECT publish_watermark FROM stream_state WHERE connection_id=? AND stream=?)
      AND seq > ? AND seq <= ? AND ${ELIGIBLE_CHANGE}`,
    [
      connectionId,
      work.stream,
      connectionId,
      work.stream,
      work.start,
      work.watermark,
    ],
  );
  return rows.map((row) => row.publish_blocked_reason);
}
