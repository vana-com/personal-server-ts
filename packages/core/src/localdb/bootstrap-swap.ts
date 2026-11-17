import type { SqlReader, SqlStatement } from "./driver.js";

export interface BootstrapSchema {
  table: string;
  indexes: readonly { name: string; sql: string }[];
  triggers: readonly { name: string; sql: string }[];
}
const quote = (name: string) => `"${name.replaceAll('"', '""')}"`;

/** Refuse a swap if another schema object could be redirected or broken. */
export async function bootstrapSchema(
  db: SqlReader,
  checkReferences = true,
): Promise<BootstrapSchema> {
  const tables = await db.query<{ name: string; sql: string }>(
    "SELECT name,sql FROM sqlite_master WHERE type='table'",
  );
  const records = tables.find((t) => t.name === "records");
  if (!records) throw new Error("bootstrap: records table missing");
  if (checkReferences)
    for (const table of tables) {
      const refs = await db.query<{ table: string }>(
        `PRAGMA foreign_key_list(${quote(table.name)})`,
      );
      if (refs.some((ref) => ref.table === "records"))
        throw new Error("bootstrap: external records foreign key");
    }
  if (checkReferences)
    for (const schema of ["sqlite_master", "sqlite_temp_master"]) {
      const objects = await db.query<{
        name: string;
        tbl_name: string;
        sql: string;
      }>(
        `SELECT name,tbl_name,sql FROM ${schema} WHERE type IN ('trigger','view')`,
      );
      if (
        objects.some(
          (o) => o.tbl_name !== "records" && /\brecords\b/i.test(o.sql),
        )
      )
        throw new Error("bootstrap: external records view or trigger");
    }
  return {
    table: `CREATE TABLE bootstrap_records ${records.sql.slice(records.sql.indexOf("("))}`,
    indexes: await db.query(
      "SELECT name,sql FROM sqlite_master WHERE type='index' AND tbl_name='records' AND sql IS NOT NULL",
    ),
    triggers: await db.query(
      "SELECT name,sql FROM sqlite_master WHERE type='trigger' AND tbl_name='records'",
    ),
  };
}

/** No body copy: replace the preview, then build indexes from their exact SQL. */
export function swapBootstrapRecords(
  schema: BootstrapSchema,
  connectionId: string,
): SqlStatement[] {
  return [
    {
      sql: `INSERT INTO record_changes(connection_id,stream,pk_hash,record_key,op,stamp_o,stamp_r,origin)
      SELECT r.connection_id,r.stream,r.pk_hash,r.record_key,'remove',r.stamp_o,r.stamp_r,'remote'
      FROM records r WHERE r.connection_id=? AND NOT EXISTS(SELECT 1 FROM bootstrap_records b
        WHERE b.connection_id=r.connection_id AND b.stream=r.stream AND b.pk_hash=r.pk_hash)`,
      params: [connectionId],
    },
    {
      sql: `DELETE FROM blob_refs WHERE connection_id=? AND NOT EXISTS(SELECT 1 FROM bootstrap_records b
      WHERE b.connection_id=blob_refs.connection_id AND b.stream=blob_refs.stream AND b.pk_hash=blob_refs.pk_hash)`,
      params: [connectionId],
    },
    // A fresh replica still owes record-level readers the newly installed keys.
    // This sorts metadata only; neither SELECT nor ORDER BY includes the body.
    {
      sql: `INSERT INTO record_changes(connection_id,stream,pk_hash,record_key,op,stamp_o,stamp_r,origin)
      SELECT b.connection_id,b.stream,b.pk_hash,b.record_key,'upsert',b.stamp_o,b.stamp_r,'remote'
      FROM bootstrap_records b WHERE NOT EXISTS(SELECT 1 FROM records r
        WHERE r.connection_id=b.connection_id AND r.stream=b.stream AND r.pk_hash=b.pk_hash
          AND r.body_sha256=b.body_sha256 AND r.stamp_o=b.stamp_o AND r.stamp_r=b.stamp_r AND r.stamp_n=b.stamp_n)
      ORDER BY b.connection_id,b.stream,b.pk_hash`,
    },
    // DROP removes only the preview table's own triggers. Never rename it:
    // modern SQLite would rewrite external references to the retired name.
    { sql: "DROP TABLE records" },
    { sql: "ALTER TABLE bootstrap_records RENAME TO records" },
    // Recreate from the exact captured SQL after the rename. Creating on the
    // temporary name first would make ALTER rewrite the index SQL text.
    ...schema.indexes.map((index) => ({ sql: index.sql })),
    ...schema.triggers.map((t) => ({ sql: t.sql })),
  ];
}
