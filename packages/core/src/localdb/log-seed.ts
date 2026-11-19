// The records a device holds from before it took part in the connection's
// log. Nothing below the log's first segment is read from anywhere else, so a
// record that is not in the log is not there for a reader that has only the
// log. Such records are queued for publish once, when this device's log
// position first leaves 0: by its own first write (`log-publish.ts`), or by
// the first apply that installs another device's log (`log-apply.ts`).

import type { LocalSyncDeps } from "./deps.js";
/**
 * Give every record of the connection with no change pending one (`import`,
 * at the stamp it already holds), so the usual rounds publish it: bounded by
 * the part target, in order, acknowledged one round at a time. A key that
 * already has a pending change is left alone, so seeding again (a round that
 * lost its commit, an apply that failed before it moved the position) queues
 * nothing twice. Returns the streams seeded.
 */
export async function seedFromRecords(
  deps: Pick<LocalSyncDeps, "db">,
  connectionId: string,
): Promise<Set<string>> {
  const [mark] = await deps.db.query<{ seq: number | null }>(
    "SELECT MAX(seq) AS seq FROM record_changes",
  );
  const from = mark?.seq ?? 0;
  await deps.db.batch([
    {
      sql: `INSERT INTO record_changes(connection_id,stream,pk_hash,record_key,op,stamp_o,stamp_r,origin)
        SELECT r.connection_id,r.stream,r.pk_hash,r.record_key,'upsert',r.stamp_o,r.stamp_r,'import'
          FROM records r
          JOIN stream_state s ON s.connection_id=r.connection_id AND s.stream=r.stream
         WHERE r.connection_id=?
           AND NOT EXISTS (SELECT 1 FROM record_changes c
                            WHERE c.connection_id=r.connection_id AND c.stream=r.stream
                              AND c.pk_hash=r.pk_hash AND c.seq > s.publish_watermark)`,
      params: [connectionId],
    },
  ]);
  const rows = await deps.db.query<{ stream: string }>(
    "SELECT DISTINCT stream FROM record_changes WHERE connection_id=? AND seq > ?",
    [connectionId, from],
  );
  return new Set(rows.map((r) => r.stream));
}
