// Frozen pre-workspace seed behavior, retained only as an independent SQL oracle.
import type { LogEntry } from "@opendatalabs/personal-server-ts-stream-sync";
import type {
  SqlStatement,
  SqlValue,
} from "../../../core/src/localdb/driver.js";
import {
  EXPLICIT_DELETE_RANK,
  OMISSION_RANK,
  recordKeyOfKey,
} from "../../../core/src/localdb/log-batch.js";

/**
 * Queue every key a history this device applied touched (`entries`, the fold
 * of its segments: `foldLog`) at what this device holds of the key now. A key
 * it holds a record of goes as that record. A key it holds none of goes as the
 * deletion the history made, of the same kind (a delete, or the omission of a
 * pass that proved it absent at its cutoff, which ranks below an observation
 * at that stamp), and leaves its tombstone here, so an older upsert from
 * another history cannot bring it back. A key with a change pending is left
 * alone, as in `seedFromRecords`. The statements go in one transaction with
 * whatever moves the position (`log-rebase.ts`).
 */
export function seedFromHistory(
  connectionId: string,
  entries: readonly LogEntry[],
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
    if (entry.kind === "upsert") {
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
