import {
  canonicalJson,
  pkHash,
  type JsonObject,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex } from "@noble/hashes/utils";
import { computeRecordKeyFromData } from "../storage/pdpp-records/record-key.js";
import type { SqlDriver, SqlStatement } from "./driver.js";
import type { ImportFingerprint, ImportSource } from "./legacy-import-types.js";
import {
  quarantineTally,
  isQuarantinedRow,
  type QuarantineCounts,
} from "./legacy-quarantine.js";
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

export type ClassifiedRow =
  { readonly row: ImportRow } | { readonly quarantine: string };

export type ClassifiedKey =
  | { readonly key: { pk_hash: string; record_key: string } }
  | { readonly quarantine: string };

const isKeyValue = (value: unknown): boolean =>
  typeof value === "string" ||
  typeof value === "boolean" ||
  (typeof value === "number" && Number.isFinite(value));

/** Why `record` cannot hold a full identity over `primaryKey`, or null. */
function identityFault(
  record: unknown,
  primaryKey: readonly string[],
): string | null {
  if (isQuarantinedRow(record)) return record.reason;
  if (!record || typeof record !== "object" || Array.isArray(record))
    return "not_an_object";
  const fields = record as Record<string, unknown>;
  for (const field of primaryKey) {
    if (!Object.hasOwn(fields, field)) return "missing_key_field";
    if (!isKeyValue(fields[field])) return "bad_key_value";
  }
  return null;
}

/** The row as an import row, or the reason it has no full identity. A source
 * fault (a changed or unreadable source) is not a row fault and still throws. */
export async function classifyImportRow(
  record: unknown,
  primaryKey: readonly string[],
): Promise<ClassifiedRow> {
  const fault = identityFault(record, primaryKey);
  if (fault) return { quarantine: fault };
  try {
    return {
      row: await canonicalImportRow(
        record as Record<string, unknown>,
        primaryKey,
      ),
    };
  } catch {
    return { quarantine: "unserializable_body" };
  }
}

/** The key of a row (or of a deletion that names only its key fields), by the
 * same rules and hashes as `classifyImportRow`. The body is not read. */
export async function classifyImportKey(
  record: unknown,
  primaryKey: readonly string[],
): Promise<ClassifiedKey> {
  const fault = identityFault(record, primaryKey);
  if (fault) return { quarantine: fault };
  const fields = record as Record<string, unknown>;
  try {
    return {
      key: {
        record_key: computeRecordKeyFromData(fields, [...primaryKey]),
        pk_hash: await pkHash(
          async (bytes) => sha256(bytes),
          fields as JsonObject,
          primaryKey,
        ),
      },
    };
  } catch {
    return { quarantine: "bad_key_value" };
  }
}

/** One operation's disk-sortable digest view; never retain source bodies.
 * The replayable source supplies each body again for a checked merge. Owns canonical row composition,
 * not key/hash algorithms: those stay at their existing PDPP/stream-sync owners.
 * A row is identified by its legacy record key, the key the database keeps it
 * under; its typed `pk_hash` is the storage form of that row (and the
 * fingerprint's order), never a second identity. Two rows of one record key
 * that differ in body or in typed key conflict, and the import refuses.
 * A row with no full identity is left out and counted (`classifyImportRow`):
 * the digest view holds only importable rows, so the receipt proves exactly
 * what the import may bring. */
export async function stageImportSnapshot(
  db: SqlDriver,
  source: ImportSource,
  op: string,
): Promise<{
  readonly fingerprint: ImportFingerprint;
  readonly quarantine: QuarantineCounts;
}> {
  const quarantine = quarantineTally();
  await db.batch([
    {
      sql: `CREATE TEMP TABLE IF NOT EXISTS import_snapshot (
    op TEXT NOT NULL, pk_hash TEXT NOT NULL, record_key TEXT NOT NULL,
    body_sha256 TEXT NOT NULL, seen INTEGER NOT NULL DEFAULT 0,
    blocked INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (op, pk_hash), UNIQUE (op, record_key)) WITHOUT ROWID`,
    },
    {
      sql: `CREATE TEMP TABLE IF NOT EXISTS import_deletions (
    op TEXT NOT NULL, pk_hash TEXT NOT NULL, record_key TEXT NOT NULL,
    PRIMARY KEY (op, pk_hash)) WITHOUT ROWID`,
    },
  ]);
  // One worker round trip per chunk, not per row: each driver call clones its
  // message across the SQLite worker's thread boundary.
  let chunk = new Map<string, { pk_hash: string; body_sha256: string }>();
  const flush = async () => {
    if (chunk.size === 0) return;
    const prior = await db.query<{
      record_key: string;
      pk_hash: string;
      body_sha256: string;
    }>(
      "SELECT record_key, pk_hash, body_sha256 FROM import_snapshot WHERE op = ? AND record_key IN (SELECT value FROM json_each(?))",
      [op, JSON.stringify([...chunk.keys()])],
    );
    for (const row of prior) {
      const held = chunk.get(row.record_key)!;
      if (row.pk_hash !== held.pk_hash || row.body_sha256 !== held.body_sha256)
        throw new Error("invalid_record");
      // The same row again, from an earlier chunk: counted, as the fold does.
      quarantine.add("duplicate_key");
    }
    await db.batch(
      [...chunk].map(([recordKey, held]) => ({
        sql: "INSERT OR IGNORE INTO import_snapshot (op, pk_hash, record_key, body_sha256) VALUES (?, ?, ?, ?)",
        params: [op, held.pk_hash, recordKey, held.body_sha256],
      })),
    );
    chunk = new Map();
  };
  for await (const record of source.records()) {
    const classified = await classifyImportRow(
      record,
      source.target.primaryKey,
    );
    if ("quarantine" in classified) {
      quarantine.add(classified.quarantine);
      continue;
    }
    const row = classified.row;
    const inChunk = chunk.get(row.record_key);
    if (inChunk !== undefined) {
      if (
        inChunk.pk_hash !== row.pk_hash ||
        inChunk.body_sha256 !== row.body_sha256
      )
        throw new Error("invalid_record");
      quarantine.add("duplicate_key");
      continue;
    }
    chunk.set(row.record_key, {
      pk_hash: row.pk_hash,
      body_sha256: row.body_sha256,
    });
    if (chunk.size >= SNAPSHOT_CHUNK_ROWS) await flush();
  }
  await flush();
  return {
    fingerprint: await importFingerprint(snapshotDigests(db, op)),
    quarantine: quarantine.counts(),
  };
}

export async function* snapshotDigests(db: SqlDriver, op: string) {
  let after = "";
  for (;;) {
    const rows = await db.query<{
      pk_hash: string;
      record_key: string;
      body_sha256: string;
    }>(
      "SELECT pk_hash, record_key, body_sha256 FROM import_snapshot WHERE op = ? AND pk_hash > ? ORDER BY pk_hash LIMIT 128",
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
    { sql: "DELETE FROM import_deletions WHERE op = ?", params: [op] },
  ]);
}

/** Holds deleted keys outside `log_tombstones` until the source's last check
 * passes: a refused import then leaves no tombstone behind. The temp table
 * exists once `stageImportSnapshot` has run for this connection. */
export async function stageImportDeletions(
  db: SqlDriver,
  op: string,
  keys: readonly { pk_hash: string; record_key: string }[],
) {
  if (keys.length === 0) return;
  await db.batch(
    keys.map((key) => ({
      sql: "INSERT OR IGNORE INTO import_deletions (op, pk_hash, record_key) VALUES (?, ?, ?)",
      params: [op, key.pk_hash, key.record_key],
    })),
  );
}

/** One statement that turns the staged keys into seed tombstones. A live row
 * or an earlier tombstone for the key keeps the key out. A tombstone with no
 * record key (written before the column) has the same hash, so the primary
 * key's `INSERT OR IGNORE` keeps it. */
export function commitImportDeletions(
  op: string,
  target: { connectionId: string; stream: string },
  rank: number,
): SqlStatement {
  return {
    sql: `INSERT OR IGNORE INTO log_tombstones (connection_id, stream, pk_hash, record_key, stamp_o, stamp_r, rank)
      SELECT ?, ?, d.pk_hash, d.record_key, 0, 'seed', ? FROM import_deletions d
      WHERE d.op = ?
        AND NOT EXISTS (SELECT 1 FROM records r
          WHERE r.connection_id = ? AND r.stream = ? AND r.record_key = d.record_key)
        AND NOT EXISTS (SELECT 1 FROM log_tombstones t
          WHERE t.connection_id = ? AND t.stream = ? AND t.record_key = d.record_key)`,
    params: [
      target.connectionId,
      target.stream,
      rank,
      op,
      target.connectionId,
      target.stream,
      target.connectionId,
      target.stream,
    ],
  };
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
