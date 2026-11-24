// The records a device holds from before it took part in the connection's
// log. Nothing below the log's first segment is read from anywhere else, so a
// record that is not in the log is not there for a reader that has only the
// log. Such records are queued for publish once, when this device's log
// position first leaves 0: by its own first write (`log-publish.ts`), or by
// the first apply that installs another device's log (`log-apply.ts`).

import type { WireEntry } from "@opendatalabs/personal-server-ts-stream-sync";
import type { LocalSyncDeps } from "./deps.js";
import type { SqlStatement, SqlValue } from "./driver.js";
import {
  EXPLICIT_DELETE_RANK,
  OMISSION_RANK,
  recordKeyOfKey,
} from "./log-batch.js";

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

/**
 * Queue every key a history this device applied touched (`entries`, the fold
 * of its segments: `foldLog`, or a page of it from the disk fold) at what this device holds of the key now. A key
 * it holds a record of goes as that record. A key it holds none of goes as the
 * deletion the history made, of the same kind (a delete, or the omission of a
 * pass that proved it absent at its cutoff, which ranks below an observation
 * at that stamp), and leaves its tombstone here, so an older upsert from
 * another history cannot bring it back. A key with a change pending is left
 * alone, as in `seedFromRecords`, so the entries can go in as many calls as
 * the caller likes (`log-rebase.ts`).
 */
export function seedFromHistory(
  connectionId: string,
  entries: readonly WireEntry[],
  primaryKeyOf: ReadonlyMap<string, readonly string[]>,
): SqlStatement[] {
  const pending = (stream: string, pk: string): [string, SqlValue[]] => [
    `NOT EXISTS (SELECT 1 FROM record_changes c
                  WHERE c.connection_id = ? AND c.stream = ? AND c.pk_hash = ?
                    AND c.seq > COALESCE((SELECT publish_watermark FROM stream_state
                                           WHERE connection_id = ? AND stream = ?), 0))`,
    [connectionId, stream, pk, connectionId, stream],
  ];
  const statements: SqlStatement[] = [];
  for (const entry of entries) {
    const [notPending, pendingParams] = pending(entry.stream, entry.pkHash);
    if (entry.kind === "upsert" || entry.kind === "upsert-ref") {
      statements.push({
        sql: `INSERT INTO record_changes(connection_id,stream,pk_hash,record_key,op,stamp_o,stamp_r,origin)
              SELECT r.connection_id,r.stream,r.pk_hash,r.record_key,'upsert',r.stamp_o,r.stamp_r,'import'
                FROM records r
               WHERE r.connection_id = ? AND r.stream = ? AND r.pk_hash = ? AND ${notPending}`,
        params: [connectionId, entry.stream, entry.pkHash, ...pendingParams],
      });
      continue;
    }
    const primaryKey = primaryKeyOf.get(entry.stream);
    if (primaryKey === undefined)
      throw new Error(
        `seed: no primary key for stream "${entry.stream}" of a deletion`,
      );
    const recordKey = recordKeyOfKey(primaryKey, entry.key);
    const explicit = entry.kind === "delete";
    const rank = explicit ? EXPLICIT_DELETE_RANK : OMISSION_RANK;
    const { o, r } = entry.stamp;
    statements.push(
      {
        sql: `INSERT OR IGNORE INTO log_tombstones (connection_id, stream, pk_hash, record_key, stamp_o, stamp_r, rank)
              VALUES (?, ?, ?, ?, ?, ?, ?)`,
        params: [
          connectionId,
          entry.stream,
          entry.pkHash,
          recordKey,
          o,
          r,
          rank,
        ],
      },
      {
        sql: `UPDATE log_tombstones SET record_key = ?, stamp_o = ?, stamp_r = ?, rank = ?
               WHERE connection_id = ? AND stream = ? AND pk_hash = ?
                 AND (stamp_o, stamp_r, rank) < (?, ?, ?)`,
        params: [
          recordKey,
          o,
          r,
          rank,
          connectionId,
          entry.stream,
          entry.pkHash,
          o,
          r,
          rank,
        ],
      },
      {
        // `pk_values` is set on a remove change only by an explicit delete
        // and here, so a remove with it and without `explicit_delete` is an
        // omission to publish (`operationsFor` in log-publish.ts).
        sql: `INSERT INTO record_changes(connection_id,stream,pk_hash,record_key,op,stamp_o,stamp_r,origin,explicit_delete,pk_values)
              SELECT ?, ?, ?, ?, 'remove', ?, ?, 'import', ?, ?
               WHERE NOT EXISTS (SELECT 1 FROM records
                                  WHERE connection_id = ? AND stream = ? AND pk_hash = ?)
                 AND ${notPending}`,
        params: [
          connectionId,
          entry.stream,
          entry.pkHash,
          recordKey,
          o,
          r,
          explicit ? 1 : 0,
          JSON.stringify(entry.key),
          connectionId,
          entry.stream,
          entry.pkHash,
          ...pendingParams,
        ],
      },
    );
  }
  return statements;
}
