import {
  canonicalJson,
  pkHash,
  type JsonObject,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex } from "@noble/hashes/utils";
import { computeRecordKeyFromData } from "../storage/pdpp-records/record-key.js";
import type { SqlDriver } from "./driver.js";
import type { ImportSource } from "./legacy-import-types.js";
import { importFingerprint } from "./import-fingerprint.js";

/** Rows of digests per staging round trip; a digest row is about 100 bytes. */
const SNAPSHOT_CHUNK_ROWS = 256;

const encoder = new TextEncoder();
const hashBytes = new Uint8Array(64 * 1024);

/** Synchronous hashing owns the scratch buffer until update returns; no await
 * or retained view may cross this scope. Avoid one external allocation per row. */
function bodyHash(body: string): string {
  const hash = sha256.create();
  let offset = 0;
  while (offset < body.length) {
    const { read, written } = encoder.encodeInto(body.slice(offset), hashBytes);
    hash.update(hashBytes.subarray(0, written));
    offset += read;
  }
  return bytesToHex(hash.digest());
}

export type ImportRow = {
  pk_hash: string;
  record_key: string;
  body: string;
  body_sha256: string;
};

/** One operation's disk-sortable digest view; never retain source bodies.
 * The replayable source supplies each body again for a checked merge. Owns canonical row composition,
 * not key/hash algorithms: those stay at their existing PDPP/stream-sync owners.
 * Conflicting duplicates refuse the import instead of choosing by device/order. */
export async function stageImportSnapshot(
  db: SqlDriver,
  source: ImportSource,
  op: string,
) {
  await db.batch([
    {
      sql: `CREATE TEMP TABLE IF NOT EXISTS import_snapshot (
    op TEXT NOT NULL, pk_hash TEXT NOT NULL, body_sha256 TEXT NOT NULL,
    seen INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (op, pk_hash)) WITHOUT ROWID`,
    },
  ]);
  // One worker round trip per chunk, not per row: each driver call clones its
  // message across the SQLite worker's thread boundary.
  let chunk = new Map<string, string>();
  const flush = async () => {
    if (chunk.size === 0) return;
    const prior = await db.query<{ pk_hash: string; body_sha256: string }>(
      "SELECT pk_hash, body_sha256 FROM import_snapshot WHERE op = ? AND pk_hash IN (SELECT value FROM json_each(?))",
      [op, JSON.stringify([...chunk.keys()])],
    );
    for (const row of prior)
      if (row.body_sha256 !== chunk.get(row.pk_hash))
        throw new Error("invalid_record");
    await db.batch(
      [...chunk].map(([pkHash, sha]) => ({
        sql: "INSERT OR IGNORE INTO import_snapshot (op, pk_hash, body_sha256) VALUES (?, ?, ?)",
        params: [op, pkHash, sha],
      })),
    );
    chunk = new Map();
  };
  for await (const record of source.records()) {
    const row = await canonicalImportRow(record, source.target.primaryKey);
    const inChunk = chunk.get(row.pk_hash);
    if (inChunk !== undefined && inChunk !== row.body_sha256)
      throw new Error("invalid_record");
    chunk.set(row.pk_hash, row.body_sha256);
    if (chunk.size >= SNAPSHOT_CHUNK_ROWS) await flush();
  }
  await flush();
  return importFingerprint(snapshotDigests(db, op));
}

export async function* snapshotDigests(db: SqlDriver, op: string) {
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

/** The shared composition used by import staging and committed-row validation. */
export async function canonicalImportRow(
  record: Record<string, unknown>,
  primaryKey: readonly string[],
): Promise<ImportRow> {
  try {
    const body = canonicalJson(record);
    const row = {
      record_key: computeRecordKeyFromData(record, [...primaryKey]),
      pk_hash: await pkHash(
        async (bytes) => sha256(bytes),
        record as JsonObject,
        primaryKey,
      ),
      body,
      body_sha256: bodyHash(body),
    };
    return row;
  } catch {
    throw new Error("invalid_record");
  }
}
