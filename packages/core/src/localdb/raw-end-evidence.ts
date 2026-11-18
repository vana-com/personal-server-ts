import type { DurableRecordEvidence } from "../stream-sync/normalize-raw-end.js";
import type { SqlReader } from "./driver.js";

/**
 * Raw intake writes typed run_rows and its event ledger in the same transaction.
 * Reuse run end's final fold counts; orphan ledger entries still contribute event
 * totals and history, but never final rows. Group presence is kept for selection
 * validation. Unlike the old materialization this does not parse stored keys:
 * those keys are written by our own trigger after intake's key validation, and
 * normalization needs no key values to authorize its count-based proof.
 */
export async function readRawRecordEvidence(
  db: SqlReader,
  runId: string,
  finalCounts: readonly { stream: string; upserts: number; deletes: number }[],
): Promise<Record<string, DurableRecordEvidence>> {
  const rows = await db.query<{
    stream: string;
    ever_deleted: number;
    upsert_events: number;
    delete_events: number;
  }>(
    `SELECT stream,MAX(CASE WHEN ever_deleted=1 THEN 1 ELSE 0 END) AS ever_deleted,
       SUM(upsert_events) AS upsert_events,SUM(delete_events) AS delete_events
     FROM run_record_evidence WHERE run_id=? GROUP BY stream`,
    [runId],
  );
  const counts = new Map(finalCounts.map((row) => [row.stream, row]));
  const evidence: Record<string, DurableRecordEvidence> = Object.create(null);
  for (const row of rows) {
    const final = counts.get(row.stream);
    evidence[row.stream] = {
      liveCount: final?.upserts ?? 0,
      deletedCount: final?.deletes ?? 0,
      everDeleted: row.ever_deleted === 1,
      upsertEvents: row.upsert_events,
      deleteEvents: row.delete_events,
    };
  }
  return evidence;
}
