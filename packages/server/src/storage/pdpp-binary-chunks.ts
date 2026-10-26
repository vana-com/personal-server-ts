import type { Database } from "better-sqlite3";
import { createHash } from "node:crypto";

export const BINARY_CHUNK_BYTES = 64 * 1024;
export const CANONICAL_INLINE_BYTES = 1024 * 1024;
export const BINARY_CHUNKS_MIGRATION = `
CREATE TABLE IF NOT EXISTS pdpp_binary_manifests (
 namespace TEXT NOT NULL, blob_id TEXT NOT NULL, size_bytes INTEGER NOT NULL,
 PRIMARY KEY(namespace,blob_id));
CREATE TABLE IF NOT EXISTS pdpp_binary_chunks (
 namespace TEXT NOT NULL, blob_id TEXT NOT NULL, position INTEGER NOT NULL, bytes BLOB NOT NULL,
 PRIMARY KEY(namespace,blob_id,position));
`;
export type BinaryNamespace =
  "canonical" | "pinned" | "received" | "staging" | "payload" | "pending";
/**
 * What each namespace's bytes are for. A "reader" namespace holds bytes a
 * reader can be served. Each one MUST have manifest insert and delete
 * triggers in the visibility view (pdpp-replica-visibility-view.ts), or
 * records stay stale when its chunked bytes arrive or leave. Add a new
 * namespace here first; pdpp-replica-invariants.test.ts guards the triggers.
 */
export const BINARY_NAMESPACE_ROLE = {
  canonical: "reader",
  received: "reader",
  pending: "reader",
  pinned: "export",
  staging: "scratch",
  payload: "scratch",
} as const satisfies Record<BinaryNamespace, "reader" | "export" | "scratch">;
const legacy = {
  canonical: "pdpp_blob_bytes",
  pinned: "pdpp_replica_blob_bytes",
  received: "pdpp_replica_received_bytes",
  staging: null,
  payload: null,
  pending: null,
} as const;

/** Read chunk copies when present; fall back to main's whole-value blob row. */
export function binaryLength(
  db: Database,
  namespace: BinaryNamespace,
  id: string,
): number | undefined {
  const manifest = db
    .prepare(
      "SELECT size_bytes AS size FROM pdpp_binary_manifests WHERE namespace=? AND blob_id=?",
    )
    .get(namespace, id) as { size: number } | undefined;
  if (manifest)
    return Number.isSafeInteger(manifest.size) && manifest.size >= 0
      ? manifest.size
      : undefined;

  const table = legacy[namespace];
  if (table) {
    const row = db
      .prepare(`SELECT length(bytes) AS size FROM ${table} WHERE blob_id=?`)
      .get(id) as { size: number } | undefined;
    if (row) return row.size;
  }
  return undefined;
}

export function* readBinaryChunks(
  db: Database,
  namespace: BinaryNamespace,
  id: string,
): Generator<Uint8Array> {
  const table = legacy[namespace];
  const hasManifest =
    db
      .prepare(
        "SELECT 1 FROM pdpp_binary_manifests WHERE namespace=? AND blob_id=?",
      )
      .get(namespace, id) !== undefined;
  if (table && !hasManifest) {
    const row = db
      .prepare(`SELECT length(bytes) AS size FROM ${table} WHERE blob_id=?`)
      .get(id) as { size: number } | undefined;
    if (row) {
      const readPart = db.prepare(
        `SELECT substr(bytes, ?, ?) AS bytes FROM ${table} WHERE blob_id=?`,
      );
      for (let offset = 0; offset < row.size; offset += BINARY_CHUNK_BYTES) {
        const part = readPart.get(offset + 1, BINARY_CHUNK_BYTES, id) as
          { bytes: Buffer } | undefined;
        if (!part?.bytes.length) throw new Error("corrupt binary chunks");
        yield part.bytes;
      }
      return;
    }
  }
  const size = binaryLength(db, namespace, id);
  if (size === undefined) throw new Error("missing binary bytes");
  let offset = 0,
    position = 0;
  while (offset < size) {
    const row = db
      .prepare(
        "SELECT bytes FROM pdpp_binary_chunks WHERE namespace=? AND blob_id=? AND position=?",
      )
      .get(namespace, id, position++) as { bytes: Buffer } | undefined;
    if (
      !row ||
      !row.bytes.length ||
      row.bytes.length > BINARY_CHUNK_BYTES ||
      offset + row.bytes.length > size
    )
      throw new Error("corrupt binary chunks");
    offset += row.bytes.length;
    yield row.bytes;
  }
  if (
    db
      .prepare(
        "SELECT 1 FROM pdpp_binary_chunks WHERE namespace=? AND blob_id=? AND position>=? LIMIT 1",
      )
      .get(namespace, id, position)
  )
    throw new Error("excess binary chunks");
}

export function verifyBinary(
  db: Database,
  namespace: BinaryNamespace,
  id: string,
  digest: string,
  size: number,
): boolean {
  if (binaryLength(db, namespace, id) !== size) return false;
  const hash = createHash("sha256");
  try {
    for (const bytes of readBinaryChunks(db, namespace, id)) hash.update(bytes);
  } catch {
    return false;
  }
  return `sha256:${hash.digest("hex")}` === digest;
}

export function deleteBinary(
  db: Database,
  namespace: BinaryNamespace,
  id: string,
): void {
  db.prepare(
    "DELETE FROM pdpp_binary_chunks WHERE namespace=? AND blob_id=?",
  ).run(namespace, id);
  db.prepare(
    "DELETE FROM pdpp_binary_manifests WHERE namespace=? AND blob_id=?",
  ).run(namespace, id);
}

/**
 * A repair write is about to give `id` a verified copy in `namespace`.
 * Remove a published manifest whose size is not a safe non-negative
 * integer, with its chunks, in the caller's transaction. Readers veto a
 * namespace on such a manifest even beside a legacy row, so without this a
 * repair would never take effect.
 */
export function clearMalformedManifest(
  db: Database,
  namespace: BinaryNamespace,
  id: string,
): void {
  const row = db
    .prepare(
      "SELECT size_bytes AS size FROM pdpp_binary_manifests WHERE namespace=? AND blob_id=?",
    )
    .get(namespace, id) as { size: unknown } | undefined;
  if (
    row &&
    !(
      typeof row.size === "number" &&
      Number.isSafeInteger(row.size) &&
      row.size >= 0
    )
  )
    deleteBinary(db, namespace, id);
}

/** Publish the manifest only after EOF. Callers own transaction/visibility and cleanup. */
export function binaryWriter(
  db: Database,
  namespace: BinaryNamespace,
  id: string,
) {
  deleteBinary(db, namespace, id);
  let size = 0,
    position = 0;
  return {
    write(bytes: Uint8Array) {
      for (
        let offset = 0;
        offset < bytes.length;
        offset += BINARY_CHUNK_BYTES
      ) {
        const part = bytes.subarray(offset, offset + BINARY_CHUNK_BYTES);
        db.prepare("INSERT INTO pdpp_binary_chunks VALUES (?,?,?,?)").run(
          namespace,
          id,
          position++,
          part,
        );
        size += part.length;
      }
    },
    finish() {
      db.prepare("INSERT INTO pdpp_binary_manifests VALUES (?,?,?)").run(
        namespace,
        id,
        size,
      );
      return size;
    },
  };
}

export function copyBinary(
  db: Database,
  from: BinaryNamespace,
  sourceId: string,
  to: BinaryNamespace,
  targetId = sourceId,
): void {
  const writer = binaryWriter(db, to, targetId);
  for (const chunk of readBinaryChunks(db, from, sourceId)) writer.write(chunk);
  writer.finish();
}

/**
 * Main's whole-value row owns canonical bytes. The caller keeps the optional
 * transport copy separate so promotion can release its assembly buffer first.
 */
export function writeCanonicalBinary(
  db: Database,
  id: string,
  bytes: Uint8Array,
): void {
  deleteBinary(db, "canonical", id);
  const view = Buffer.from(
    bytes.buffer as ArrayBuffer,
    bytes.byteOffset,
    bytes.byteLength,
  );
  db.prepare(
    `INSERT INTO ${legacy.canonical} (blob_id, bytes) VALUES (?, ?)
     ON CONFLICT(blob_id) DO UPDATE SET bytes = excluded.bytes`,
  ).run(id, view);
  if (bytes.length <= CANONICAL_INLINE_BYTES) return;
  const writer = binaryWriter(db, "canonical", id);
  for (let offset = 0; offset < bytes.length; offset += BINARY_CHUNK_BYTES)
    writer.write(bytes.subarray(offset, offset + BINARY_CHUNK_BYTES));
  writer.finish();
}

/** Promote verified bytes through the canonical writer and its transport copy. */
export function copyBinaryToCanonical(
  db: Database,
  from: BinaryNamespace,
  sourceId: string,
  targetId = sourceId,
): void {
  const bytes = readBinary(db, from, sourceId);
  if (!bytes) throw new Error("missing binary bytes");
  writeCanonicalBinary(db, targetId, bytes);
}

/** Explicit whole-value API for existing HTTP consumers, never used by replication. */
export function readBinary(
  db: Database,
  namespace: BinaryNamespace,
  id: string,
): Uint8Array<ArrayBuffer> | undefined {
  const length = binaryLength(db, namespace, id);
  if (length === undefined) return undefined;
  const result = new Uint8Array(length);
  let offset = 0;
  try {
    for (const bytes of readBinaryChunks(db, namespace, id)) {
      result.set(bytes, offset);
      offset += bytes.length;
    }
  } catch {
    return undefined;
  }
  return result;
}
