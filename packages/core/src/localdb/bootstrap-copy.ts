import type { SqlReader, SqlStatement } from "./driver.js";
import type { WinnerGroup } from "./bootstrap-keys.js";
import type { BootstrapSchema } from "./bootstrap-swap.js";
import { rowsPerStatement } from "./log-batch.js";

const columns = [
  "connection_id",
  "stream",
  "pk_hash",
  "record_key",
  "stamp_o",
  "stamp_r",
  "body",
  "body_sha256",
  "first_o",
  "seen_o",
  "seen_r",
  "body_bytes",
  "stamp_n",
];
const changed = ["body_sha256", "stamp_o", "stamp_r", "stamp_n", "first_o"];

/** A populated replica keeps its shared table. The port carries rowids only. */
export async function copyBootstrapRecords(
  db: SqlReader,
  schema: BootstrapSchema,
  groups: readonly WinnerGroup[],
): Promise<SqlStatement[]> {
  const preview = new Set(
    (
      await db.query<{
        connection_id: string;
        stream: string;
        pk_hash: string;
      }>("SELECT * FROM bootstrap_preview")
    ).map((row) =>
      JSON.stringify([row.connection_id, row.stream, row.pk_hash]),
    ),
  );
  const secondary = schema.indexes.filter(
    (index) => index.name !== "records_key",
  );
  const statements: SqlStatement[] = secondary.map((index) => ({
    sql: `DROP INDEX "${index.name.replaceAll('"', '""')}"`,
  }));
  statements.push({
    sql: `CREATE TEMP TABLE bootstrap_winners(connection_id TEXT NOT NULL,stream TEXT NOT NULL,pk_hash TEXT NOT NULL,row_id INTEGER NOT NULL,
      PRIMARY KEY(connection_id,stream,pk_hash)) WITHOUT ROWID`,
  });
  const size = rowsPerStatement(4);
  let rows: (string | number)[][] = [];
  const flush = () => {
    if (!rows.length) return;
    statements.push({
      sql: `INSERT INTO temp.bootstrap_winners VALUES ${rows.map(() => "(?,?,?,?)").join(",")}`,
      params: rows.flat(),
    });
    rows = [];
  };
  const fields = columns.slice(3);
  const update = `UPDATE records SET ${fields.map((field) => `${field}=(SELECT ${field} FROM bootstrap_records WHERE rowid=?)`).join(",")}
    WHERE connection_id=? AND stream=? AND pk_hash=?
      AND EXISTS(SELECT 1 FROM bootstrap_records s WHERE s.rowid=? AND (${changed.map((field) => `records.${field} IS NOT s.${field}`).join(" OR ")}))`;
  for (const group of groups)
    for (const [hash, upsert] of group.keys) {
      const identity = [group.connectionId, group.stream, hash];
      if (!upsert) {
        if (preview.has(JSON.stringify(identity)))
          statements.push({
            sql: "DELETE FROM records WHERE connection_id=? AND stream=? AND pk_hash=?",
            params: identity,
          });
      } else if (preview.has(JSON.stringify(identity))) {
        statements.push({
          sql: update,
          params: [...fields.map(() => upsert), ...identity, upsert],
        });
      } else {
        rows.push([...identity, upsert]);
        if (rows.length === size) flush();
      }
    }
  flush();
  // CROSS JOIN fixes the key table as the outer loop. Its PRIMARY KEY supplies
  // ORDER BY; each inner lookup reads one body by rowid. No body enters a sorter.
  statements.push(
    {
      sql: `INSERT INTO records(${columns.join(",")}) SELECT ${columns.map((column) => `b.${column}`).join(",")}
      FROM temp.bootstrap_winners w CROSS JOIN bootstrap_records b ON b.rowid=w.row_id
      ORDER BY w.connection_id,w.stream,w.pk_hash`,
    },
    { sql: "DROP TABLE temp.bootstrap_winners" },
  );
  statements.push(...secondary.map((index) => ({ sql: index.sql })), {
    sql: "DROP TABLE bootstrap_records",
  });
  return statements;
}
