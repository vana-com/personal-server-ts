import type { SqlReader, SqlStatement } from "./driver.js";
import type { WinnerGroup } from "./bootstrap-keys.js";
import type { BootstrapSchema } from "./bootstrap-swap.js";

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
        const fields = columns.slice(3);
        statements.push({
          sql: `UPDATE records SET ${fields.map((field) => `${field}=(SELECT ${field} FROM bootstrap_records WHERE rowid=?)`).join(",")}
        WHERE connection_id=? AND stream=? AND pk_hash=?
          AND EXISTS(SELECT 1 FROM bootstrap_records s WHERE s.rowid=? AND (${changed.map((field) => `records.${field} IS NOT s.${field}`).join(" OR ")}))`,
          params: [...fields.map(() => upsert), ...identity, upsert],
        });
      } else {
        // Each statement performs one rowid lookup. There is no body sorter and
        // no body/structured clone in this statement's sole parameter.
        statements.push({
          sql: `INSERT INTO records(${columns.join(",")}) SELECT ${columns.join(",")} FROM bootstrap_records WHERE rowid=?`,
          params: [upsert],
        });
      }
    }
  statements.push(...secondary.map((index) => ({ sql: index.sql })), {
    sql: "DROP TABLE bootstrap_records",
  });
  return statements;
}
