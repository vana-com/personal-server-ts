import type { JsonValue } from "@opendatalabs/personal-server-ts-stream-sync";
import type { RawRecordEvidence } from "../stream-sync/raw-end.js";
import type { SqlReader } from "./driver.js";

/** Intake's atomic event ledger plus its ordered, final key fold. */
export async function readRawRecordEvidence(
  db: SqlReader,
  runId: string,
): Promise<Record<string, RawRecordEvidence>> {
  const rows = await db.query<{
    stream: string;
    pk_values: string;
    ever_deleted: number;
    upsert_events: number;
    delete_events: number;
    op: string | null;
  }>(
    `SELECT e.stream,e.pk_values,e.ever_deleted,e.upsert_events,e.delete_events,r.op
     FROM run_record_evidence e LEFT JOIN run_rows r
       ON r.run_id=e.run_id AND r.stream=e.stream AND r.pk_hash=e.pk_hash
     WHERE e.run_id=?`,
    [runId],
  );
  const evidence: Record<
    string,
    {
      liveKeys: JsonValue[];
      deletedKeys: JsonValue[];
      everDeletedKeys: JsonValue[];
      upsertEvents: number;
      deleteEvents: number;
    }
  > = Object.create(null);
  for (const row of rows) {
    const stream = (evidence[row.stream] ??= {
      liveKeys: [],
      deletedKeys: [],
      everDeletedKeys: [],
      upsertEvents: 0,
      deleteEvents: 0,
    });
    const key = JSON.parse(row.pk_values) as JsonValue;
    if (row.op === "upsert") stream.liveKeys.push(key);
    if (row.op === "delete") stream.deletedKeys.push(key);
    if (row.ever_deleted === 1) stream.everDeletedKeys.push(key);
    stream.upsertEvents += row.upsert_events;
    stream.deleteEvents += row.delete_events;
  }
  return evidence;
}
