// One-record staging; canonical visibility changes only in commitPart.
import type { SqlDriver, SqlStatement } from "./driver.js";
import type { WorkspaceBinding } from "./workspace-capability.js";
import { workspaceGuard } from "./workspace.js";
import { mergeIncoming, seenPair } from "./merge.js";
import type { PreparedOperation } from "./log-batch.js";

export const partialOp = (b: WorkspaceBinding, index: number) =>
  `${b.operation}:${index}`;
export async function stagePartialOperation(
  db: SqlDriver,
  b: WorkspaceBinding,
  index: number,
  operation: PreparedOperation,
) {
  const op = partialOp(b, index);
  const statements: SqlStatement[] = [];
  if (operation.kind === "upsert")
    statements.push({
      sql: "INSERT OR REPLACE INTO workspace_partial_incoming(operation,op,stream,pk_hash,record_key,stamp_o,stamp_r,body,body_sha256,first_o,stamp_n) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
      params: [
        b.operation,
        op,
        operation.stream,
        operation.pkHash,
        operation.recordKey,
        operation.stampO,
        operation.stampR,
        operation.body,
        operation.bodySha256,
        operation.firstO,
        operation.ordinal,
      ],
    });
  else {
    const keys =
      operation.kind === "complete" ? operation.omitted : [operation];
    const rank = operation.kind === "delete" ? 2 : 0;
    for (const key of keys) {
      statements.push(
        {
          sql: "INSERT OR IGNORE INTO workspace_partial_deletions VALUES(?,?,?,?,?,?,?,?,?)",
          params: [
            b.operation,
            op,
            operation.stream,
            key.pkHash,
            key.recordKey,
            operation.stampO,
            operation.stampR,
            rank,
            index,
          ],
        },
        {
          sql: "UPDATE workspace_partial_deletions SET record_key=?,stamp_o=?,stamp_r=?,rank=? WHERE op=? AND stream=? AND pk_hash=? AND (stamp_o,stamp_r,rank)<(?,?,?)",
          params: [
            key.recordKey,
            operation.stampO,
            operation.stampR,
            rank,
            op,
            operation.stream,
            key.pkHash,
            operation.stampO,
            operation.stampR,
            rank,
          ],
        },
      );
      await db.batch([...workspaceGuard(b), ...statements]);
      statements.length = 0;
    }
    return;
  }
  await db.batch([...workspaceGuard(b), ...statements]);
}
export function promotePartialOperations(
  b: WorkspaceBinding,
  index: number,
): SqlStatement[] {
  const op = partialOp(b, index);
  const deletion =
    "d.op=? AND d.stream=records.stream AND d.pk_hash=records.pk_hash";
  const cutoff = `(${seenPair("records.")} < (d.stamp_o,d.stamp_r) OR (${seenPair("records.")} = (d.stamp_o,d.stamp_r) AND d.rank=2))`;
  const incoming = "workspace_partial_incoming";
  return [
    {
      sql: "INSERT OR IGNORE INTO log_tombstones(connection_id,stream,pk_hash,record_key,stamp_o,stamp_r,rank) SELECT ?,stream,pk_hash,record_key,stamp_o,stamp_r,rank FROM workspace_partial_deletions WHERE op=?",
      params: [b.connection, op],
    },
    {
      sql: `UPDATE log_tombstones SET record_key=(SELECT d.record_key FROM workspace_partial_deletions d WHERE d.op=? AND d.stream=log_tombstones.stream AND d.pk_hash=log_tombstones.pk_hash),stamp_o=(SELECT d.stamp_o FROM workspace_partial_deletions d WHERE d.op=? AND d.stream=log_tombstones.stream AND d.pk_hash=log_tombstones.pk_hash),stamp_r=(SELECT d.stamp_r FROM workspace_partial_deletions d WHERE d.op=? AND d.stream=log_tombstones.stream AND d.pk_hash=log_tombstones.pk_hash),rank=(SELECT d.rank FROM workspace_partial_deletions d WHERE d.op=? AND d.stream=log_tombstones.stream AND d.pk_hash=log_tombstones.pk_hash)
      WHERE connection_id=? AND (stream,pk_hash) IN (SELECT stream,pk_hash FROM workspace_partial_deletions WHERE op=?) AND EXISTS(SELECT 1 FROM workspace_partial_deletions d WHERE d.op=? AND d.stream=log_tombstones.stream AND d.pk_hash=log_tombstones.pk_hash AND (log_tombstones.stamp_o,log_tombstones.stamp_r,log_tombstones.rank)<(d.stamp_o,d.stamp_r,d.rank))`,
      params: [op, op, op, op, b.connection, op, op],
    },
    {
      sql: "UPDATE write_ctx SET origin='local' WHERE id=1 AND origin='remote'",
    },
    {
      sql: `UPDATE records SET stamp_o=seen_o,stamp_r=seen_r,stamp_n=0 WHERE connection_id=? AND (stream,pk_hash) IN (SELECT stream,pk_hash FROM workspace_partial_deletions WHERE op=?) AND seen_o IS NOT NULL AND EXISTS(SELECT 1 FROM workspace_partial_deletions d WHERE ${deletion} AND NOT ${cutoff})`,
      params: [b.connection, op, op],
    },
    {
      sql: "UPDATE write_ctx SET origin='remote' WHERE id=1 AND origin='local'",
    },
    {
      sql: `DELETE FROM records WHERE connection_id=? AND (stream,pk_hash) IN (SELECT stream,pk_hash FROM workspace_partial_deletions WHERE op=?) AND EXISTS(SELECT 1 FROM workspace_partial_deletions d WHERE ${deletion} AND ${cutoff})`,
      params: [b.connection, op, op],
    },
    {
      sql: `DELETE FROM ${incoming} WHERE op=? AND EXISTS(SELECT 1 FROM log_tombstones t WHERE t.connection_id=? AND t.stream=${incoming}.stream AND t.pk_hash=${incoming}.pk_hash AND (t.stamp_o,t.stamp_r,t.rank)>(${incoming}.stamp_o,${incoming}.stamp_r,1))`,
      params: [op, b.connection],
    },
    {
      sql: `DELETE FROM partial_hidden WHERE connection_id=? AND (stream,pk_hash) IN (SELECT stream,pk_hash FROM ${incoming} WHERE op=?)`,
      params: [b.connection, op],
    },
    {
      sql: `INSERT OR IGNORE INTO partial_hidden(connection_id,stream,pk_hash) SELECT ?,i.stream,i.pk_hash FROM ${incoming} i JOIN workspace_partial_keys k ON k.operation=? AND k.stream=i.stream AND k.pk_hash=i.pk_hash JOIN workspace_partial_streams s ON s.operation=k.operation AND s.stream=i.stream AND s.skip=0 WHERE i.op=? AND k.last_removal>?`,
      params: [b.connection, b.operation, op, index],
    },
    ...mergeIncoming(op, b.connection, {
      promoteSeen: true,
      firstSeenOfWinner: true,
      source: "workspace_partial_incoming",
    }),
    { sql: "DELETE FROM workspace_partial_deletions WHERE op=?", params: [op] },
  ];
}
