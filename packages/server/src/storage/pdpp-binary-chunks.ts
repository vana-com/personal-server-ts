import type { Database } from "better-sqlite3";
import { createHash } from "node:crypto";

export const BINARY_CHUNK_BYTES = 64 * 1024;
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

/** Legacy rows remain readable; new large values never cross SQLite as one BLOB. */
export function binaryLength(
  db: Database,
  namespace: BinaryNamespace,
  id: string,
): number | undefined {
  const table = legacy[namespace];
  if (table) {
    const row = db
      .prepare(`SELECT length(bytes) AS size FROM ${table} WHERE blob_id=?`)
      .get(id) as { size: number } | undefined;
    if (row) return row.size;
  }
  const size = (
    db
      .prepare(
        "SELECT size_bytes AS size FROM pdpp_binary_manifests WHERE namespace=? AND blob_id=?",
      )
      .get(namespace, id) as { size: number } | undefined
  )?.size;
  return size !== undefined && Number.isSafeInteger(size) && size >= 0
    ? size
    : undefined;
}

export function* readBinaryChunks(
  db: Database,
  namespace: BinaryNamespace,
  id: string,
): Generator<Uint8Array> {
  const table = legacy[namespace];
  if (table) {
    const row = db
      .prepare(`SELECT length(bytes) AS size FROM ${table} WHERE blob_id=?`)
      .get(id) as { size: number } | undefined;
    if (row) {
      // One whole legacy read avoids SQLite reloading the value per substring.
      const value = db
        .prepare(`SELECT bytes FROM ${table} WHERE blob_id=?`)
        .get(id) as { bytes: Buffer };
      for (
        let offset = 0;
        offset < value.bytes.length;
        offset += BINARY_CHUNK_BYTES
      )
        yield value.bytes.subarray(offset, offset + BINARY_CHUNK_BYTES);
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
