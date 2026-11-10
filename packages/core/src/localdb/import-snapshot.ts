import {
  canonicalJson,
  pkHash,
  type JsonObject,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils";
import { computeRecordKeyFromData } from "../storage/pdpp-records/record-key.js";
import type { SqlDriver, SqlStatement } from "./driver.js";
import type { ImportSource } from "./legacy-import-types.js";
import { importFingerprint } from "./import-fingerprint.js";

export const IMPORT_BATCH_BYTES = 4 * 1024 * 1024;
export type ImportRow = {
  pk_hash: string;
  record_key: string;
  body: string;
  body_sha256: string;
};

/** One operation's disk-sortable source view. Owns canonical row composition,
 * not key/hash algorithms: those stay at their existing PDPP/stream-sync owners.
 * Conflicting duplicates hold instead of choosing a record by device/order. */
export async function stageImportSnapshot(
  db: SqlDriver,
  source: ImportSource,
  op: string,
) {
  await db.batch([
    {
      sql: `CREATE TEMP TABLE IF NOT EXISTS import_snapshot (
    op TEXT NOT NULL, pk_hash TEXT NOT NULL, record_key TEXT NOT NULL,
    body TEXT NOT NULL, body_sha256 TEXT NOT NULL,
    PRIMARY KEY (op, pk_hash)) WITHOUT ROWID`,
    },
  ]);
  for await (const record of source.records()) {
    let row: ImportRow;
    try {
      const body = canonicalJson(record);
      row = {
        record_key: computeRecordKeyFromData(record, [
          ...source.target.primaryKey,
        ]),
        pk_hash: await pkHash(
          async (bytes) => sha256(bytes),
          record as JsonObject,
          source.target.primaryKey,
        ),
        body,
        body_sha256: bytesToHex(sha256(utf8ToBytes(body))),
      };
      // Include the staged row metadata and parameter envelope, not just body.
      if (utf8ToBytes(JSON.stringify(row)).length > IMPORT_BATCH_BYTES)
        throw new Error();
    } catch {
      throw new Error("invalid_record");
    }
    const [prior] = await db.query<{ body_sha256: string }>(
      "SELECT body_sha256 FROM import_snapshot WHERE op = ? AND pk_hash = ?",
      [op, row.pk_hash],
    );
    if (prior && prior.body_sha256 !== row.body_sha256)
      throw new Error("invalid_record");
    await db.batch(
      boundedImportBatch([
        {
          sql: "INSERT OR IGNORE INTO import_snapshot VALUES (?, ?, ?, ?, ?)",
          params: [op, row.pk_hash, row.record_key, row.body, row.body_sha256],
        },
      ]),
    );
  }
  return importFingerprint(snapshotDigests(db, op));
}

/** Keyset iteration keeps at most one bounded body live, even for large rows. */
export async function* snapshotRows(
  db: SqlDriver,
  op: string,
): AsyncIterable<ImportRow> {
  let after = "";
  for (;;) {
    const [row] = await db.query<ImportRow>(
      "SELECT pk_hash, record_key, body, body_sha256 FROM import_snapshot WHERE op = ? AND pk_hash > ? ORDER BY pk_hash LIMIT 1",
      [op, after],
    );
    if (!row) return;
    yield row;
    after = row.pk_hash;
  }
}
async function* snapshotDigests(db: SqlDriver, op: string) {
  let after = "";
  for (;;) {
    const rows = await db.query<{ pk_hash: string; body_sha256: string }>(
      "SELECT pk_hash, body_sha256 FROM import_snapshot WHERE op = ? AND pk_hash > ? ORDER BY pk_hash LIMIT 128",
      [op, after],
    );
    if (rows.length === 0) return;
    yield* rows;
    after = rows[rows.length - 1]!.pk_hash;
  }
}
export async function clearImportSnapshot(db: SqlDriver, op: string) {
  await db.batch([
    { sql: "DELETE FROM import_snapshot WHERE op = ?", params: [op] },
  ]);
}

/** Parameter-envelope-inclusive bound, shared by staging and merge commits. */
export function boundedImportBatch(
  statements: readonly SqlStatement[],
): readonly SqlStatement[] {
  if (utf8ToBytes(JSON.stringify(statements)).length > IMPORT_BATCH_BYTES)
    throw new Error("invalid_record");
  return statements;
}
