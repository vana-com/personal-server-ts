import type { PreparedOperation } from "./log-batch.js";
import { rowsPerStatement } from "./log-batch.js";
import type { SqlStatement, SqlValue } from "./driver.js";

// One database-wide bootstrap owns this heap. Its bodies are appended in
// segment order; the temporary winning-key relation holds row pointers only.
export const BOOTSTRAP_HEAP = `CREATE TABLE IF NOT EXISTS bootstrap_rows (
  seq INTEGER PRIMARY KEY, connection_id TEXT NOT NULL, stream TEXT NOT NULL,
  pk_hash TEXT NOT NULL, kind TEXT NOT NULL, rank INTEGER NOT NULL,
  record_key TEXT NOT NULL, stamp_o INTEGER NOT NULL, stamp_r TEXT NOT NULL,
  stamp_n INTEGER NOT NULL, body TEXT, body_sha256 TEXT, first_o INTEGER, body_bytes INTEGER)`;

export function appendBootstrapRows(
  connectionId: string,
  operations: readonly PreparedOperation[],
): SqlStatement[] {
  const rows: SqlValue[][] = [];
  const deletion = (
    stream: string,
    hash: string,
    key: string,
    o: number,
    r: string,
    rank: number,
  ) =>
    rows.push([
      connectionId,
      stream,
      hash,
      "d",
      rank,
      key,
      o,
      r,
      0,
      null,
      null,
      null,
      null,
    ]);
  for (const op of operations) {
    if (op.kind === "upsert")
      rows.push([
        connectionId,
        op.stream,
        op.pkHash,
        "u",
        1,
        op.recordKey,
        op.stampO,
        op.stampR,
        op.ordinal,
        op.body,
        op.bodySha256,
        op.firstO,
        new TextEncoder().encode(op.body).length,
      ]);
    else if (op.kind === "complete")
      for (const key of op.omitted)
        deletion(op.stream, key.pkHash, key.recordKey, op.stampO, op.stampR, 0);
    else
      deletion(
        op.stream,
        op.pkHash,
        op.recordKey,
        op.stampO,
        op.stampR,
        op.kind === "delete" ? 2 : 0,
      );
  }
  const statements: SqlStatement[] = [];
  const size = rowsPerStatement(13);
  for (let i = 0; i < rows.length; i += size) {
    const group = rows.slice(i, i + size);
    statements.push({
      sql: `INSERT INTO bootstrap_rows(connection_id,stream,pk_hash,kind,rank,record_key,stamp_o,stamp_r,stamp_n,body,body_sha256,first_o,body_bytes) VALUES ${group.map(() => "(" + Array(13).fill("?").join(",") + ")").join(",")}`,
      params: group.flat(),
    });
  }
  return statements;
}
