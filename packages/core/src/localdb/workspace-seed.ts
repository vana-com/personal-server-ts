import type { LogEntry } from "@opendatalabs/personal-server-ts-stream-sync";
import type { SqlDriver } from "./driver.js";
import type { WorkspaceBinding } from "./workspace-capability.js";
import { workspaceAssert, workspaceGuard } from "./workspace.js";
import { recordKeyOfKey } from "./log-batch.js";
import { writeLogState, type LogState } from "./log-state.js";

/** Scalar seed relation: final promotion never parses bodies or builds N statements. */
export const WORKSPACE_SEED_SCHEMA = `CREATE TABLE workspace_seed(operation TEXT NOT NULL,stream TEXT NOT NULL,pk_hash TEXT NOT NULL,record_key TEXT NOT NULL,has_upsert INTEGER NOT NULL DEFAULT 0,stamp_o INTEGER,stamp_r TEXT,rank INTEGER,pk_values TEXT,PRIMARY KEY(operation,stream,pk_hash)) WITHOUT ROWID`;

export async function stageWorkspaceSeed(
  db: SqlDriver,
  b: WorkspaceBinding,
  entry: LogEntry,
  primaryKey: readonly string[],
) {
  const key =
    entry.kind === "upsert" ? null : recordKeyOfKey(primaryKey, entry.key);
  await db.batch([
    ...workspaceGuard(b),
    {
      sql: "INSERT OR IGNORE INTO workspace_seed(operation,stream,pk_hash,record_key) VALUES(?,?,?,?)",
      params: [b.operation, entry.stream, entry.pkHash, key ?? ""],
    },
    entry.kind === "upsert"
      ? {
          sql: "UPDATE workspace_seed SET has_upsert=1 WHERE operation=? AND stream=? AND pk_hash=?",
          params: [b.operation, entry.stream, entry.pkHash],
        }
      : {
          sql: "UPDATE workspace_seed SET record_key=?,stamp_o=?,stamp_r=?,rank=?,pk_values=? WHERE operation=? AND stream=? AND pk_hash=?",
          params: [
            key,
            entry.stamp.o,
            entry.stamp.r,
            entry.kind === "delete" ? 2 : 0,
            JSON.stringify(entry.key),
            b.operation,
            entry.stream,
            entry.pkHash,
          ],
        },
  ]);
}

export async function promoteWorkspaceSeed(
  db: SqlDriver,
  b: WorkspaceBinding,
  expected: LogState,
  target: LogState,
  controlVersion: number,
) {
  const pending = `NOT EXISTS(SELECT 1 FROM record_changes c WHERE c.connection_id=? AND c.stream=s.stream AND c.pk_hash=s.pk_hash AND c.seq>COALESCE((SELECT publish_watermark FROM stream_state WHERE connection_id=? AND stream=s.stream),0))`;
  await db.batch([
    ...workspaceGuard(b),
    workspaceAssert(
      "EXISTS(SELECT 1 FROM connections WHERE connection_id=? AND control_version=?)",
      [b.connection, controlVersion],
    ),
    workspaceAssert(
      "EXISTS(SELECT 1 FROM log_state WHERE connection_id=? AND position=? AND base=? AND refs=? AND snapshot IS ?)",
      [
        b.connection,
        expected.position,
        expected.base,
        JSON.stringify(expected.refs),
        expected.snapshot ? JSON.stringify(expected.snapshot) : null,
      ],
    ),
    workspaceAssert(
      "(SELECT phase FROM workspaces WHERE operation=?)='folded'",
      [b.operation],
    ),
    {
      sql: `INSERT OR IGNORE INTO log_tombstones(connection_id,stream,pk_hash,record_key,stamp_o,stamp_r,rank)
      SELECT ?,stream,pk_hash,record_key,stamp_o,stamp_r,rank FROM workspace_seed WHERE operation=? AND rank IS NOT NULL`,
      params: [b.connection, b.operation],
    },
    {
      sql: `UPDATE log_tombstones SET (record_key,stamp_o,stamp_r,rank)=(SELECT s.record_key,s.stamp_o,s.stamp_r,s.rank FROM workspace_seed s WHERE s.operation=? AND s.stream=log_tombstones.stream AND s.pk_hash=log_tombstones.pk_hash)
      WHERE connection_id=? AND EXISTS(SELECT 1 FROM workspace_seed s WHERE s.operation=? AND s.stream=log_tombstones.stream AND s.pk_hash=log_tombstones.pk_hash AND (s.stamp_o,s.stamp_r,s.rank)>(log_tombstones.stamp_o,log_tombstones.stamp_r,log_tombstones.rank))`,
      params: [b.operation, b.connection, b.operation],
    },
    {
      sql: `INSERT INTO record_changes(connection_id,stream,pk_hash,record_key,op,stamp_o,stamp_r,origin)
      SELECT r.connection_id,r.stream,r.pk_hash,r.record_key,'upsert',r.stamp_o,r.stamp_r,'import' FROM workspace_seed s JOIN records r ON r.connection_id=? AND r.stream=s.stream AND r.pk_hash=s.pk_hash
      WHERE s.operation=? AND s.has_upsert=1 AND ${pending}`,
      params: [b.connection, b.operation, b.connection, b.connection],
    },
    {
      sql: `INSERT INTO record_changes(connection_id,stream,pk_hash,record_key,op,stamp_o,stamp_r,origin,explicit_delete,pk_values)
      SELECT ?,s.stream,s.pk_hash,s.record_key,'remove',s.stamp_o,s.stamp_r,'import',CASE WHEN s.rank=2 THEN 1 ELSE 0 END,s.pk_values FROM workspace_seed s
      WHERE s.operation=? AND s.rank IS NOT NULL AND NOT EXISTS(SELECT 1 FROM records r WHERE r.connection_id=? AND r.stream=s.stream AND r.pk_hash=s.pk_hash) AND ${pending}`,
      params: [
        b.connection,
        b.operation,
        b.connection,
        b.connection,
        b.connection,
      ],
    },
    writeLogState(b.connection, target),
    {
      sql: "UPDATE workspaces SET phase='finished' WHERE operation=?",
      params: [b.operation],
    },
  ]);
}
