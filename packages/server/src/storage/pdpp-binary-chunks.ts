import type { Database } from "better-sqlite3";
import { createHash } from "node:crypto";

export const BINARY_CHUNK_BYTES = 64 * 1024;
/** Legacy whole-row reads: windows are at least this big and at most this many. */
export const LEGACY_MIN_WINDOW_BYTES = 8 * 1024 * 1024;
export const LEGACY_WINDOWS = 16;
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
      // SQLite reaches a BLOB offset by walking its overflow pages, so a read
      // at offset N costs O(N). One read per 64 KiB chunk is quadratic (a
      // 64 MiB row took 37 s). Reading windows of size/WINDOWS_PER_BLOB bounds
      // the walk to a constant multiple of the blob and memory to a fraction.
      const readWindow = db.prepare(
        `SELECT substr(bytes, ?, ?) AS bytes FROM ${table} WHERE blob_id=?`,
      );
      const window =
        Math.ceil(
          Math.max(LEGACY_MIN_WINDOW_BYTES, row.size / LEGACY_WINDOWS) /
            BINARY_CHUNK_BYTES,
        ) * BINARY_CHUNK_BYTES;
      for (let start = 0; start < row.size; start += window) {
        const part = readWindow.get(start + 1, window, id) as
          { bytes: Buffer } | undefined;
        if (!part?.bytes.length) throw new Error("corrupt binary chunks");
        for (
          let offset = 0;
          offset < part.bytes.length;
          offset += BINARY_CHUNK_BYTES
        )
          yield part.bytes.subarray(offset, offset + BINARY_CHUNK_BYTES);
      }
      return;
    }
  }
  const size = binaryLength(db, namespace, id);
  if (size === undefined) throw new Error("missing binary bytes");
  const read = db.prepare(
    "SELECT bytes FROM pdpp_binary_chunks WHERE namespace=? AND blob_id=? AND position=?",
  );
  let offset = 0,
    position = 0;
  while (offset < size) {
    const row = read.get(namespace, id, position++) as
      { bytes: Buffer } | undefined;
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

/** Where a chunked read resumes: a chunk row and a byte offset inside it. */
export interface BinaryCursor {
  position: number;
  offset: number;
}

/**
 * Read exactly `length` bytes of chunked (manifest) bytes from `from`, and
 * return them with the cursor after them. Rows may have any length, so a
 * caller that reads a value in parts keeps the returned cursor; it never
 * seeks by arithmetic. Memory is `length`. Legacy whole-row values are not
 * supported: only namespaces without a legacy table use this.
 */
export function readBinaryWindow(
  db: Database,
  namespace: BinaryNamespace,
  id: string,
  from: BinaryCursor,
  length: number,
): { bytes: Uint8Array; next: BinaryCursor } {
  if (legacy[namespace]) throw new Error("legacy binary windows unsupported");
  const size = binaryLength(db, namespace, id);
  if (
    size === undefined ||
    !Number.isSafeInteger(length) ||
    length < 1 ||
    !Number.isSafeInteger(from.position) ||
    from.position < 0 ||
    !Number.isSafeInteger(from.offset) ||
    from.offset < 0
  )
    throw new Error("missing binary bytes");
  const bytes = new Uint8Array(length);
  const read = db.prepare(
    "SELECT bytes FROM pdpp_binary_chunks WHERE namespace=? AND blob_id=? AND position=?",
  );
  let filled = 0;
  let { position, offset } = from;
  while (filled < length) {
    const row = read.get(namespace, id, position) as
      { bytes: Buffer } | undefined;
    if (
      !row ||
      !row.bytes.length ||
      row.bytes.length > BINARY_CHUNK_BYTES ||
      offset >= row.bytes.length
    )
      throw new Error("corrupt binary chunks");
    const take = Math.min(row.bytes.length - offset, length - filled);
    bytes.set(row.bytes.subarray(offset, offset + take), filled);
    filled += take;
    offset += take;
    if (offset === row.bytes.length) {
      position++;
      offset = 0;
    }
  }
  return { bytes, next: { position, offset } };
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
  const insert = db.prepare("INSERT INTO pdpp_binary_chunks VALUES (?,?,?,?)");
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
        insert.run(namespace, id, position++, part);
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
 * Main's whole-value row owns canonical bytes the server writes from a value
 * it already holds. A large value also gets a chunk copy for the transport.
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

/**
 * Promote verified bytes to canonical in the caller's transaction. A value up
 * to CANONICAL_INLINE_BYTES (one Lite fragment) becomes main's whole row. A
 * larger one is copied chunk by chunk and is stored only in the chunk form:
 * no whole value is assembled or stored twice. Canonical readers accept both
 * forms; the flag-off boot that retires replication writes main's row for
 * chunk-only blobs (`materializeCanonicalBinaries`).
 */
export function copyBinaryToCanonical(
  db: Database,
  from: BinaryNamespace,
  sourceId: string,
  targetId = sourceId,
): void {
  const size = binaryLength(db, from, sourceId);
  if (size === undefined) throw new Error("missing binary bytes");
  if (size > CANONICAL_INLINE_BYTES) {
    db.prepare(`DELETE FROM ${legacy.canonical} WHERE blob_id=?`).run(targetId);
    copyBinary(db, from, sourceId, "canonical", targetId);
    return;
  }
  const bytes = readBinary(db, from, sourceId);
  if (!bytes) throw new Error("missing binary bytes");
  writeCanonicalBinary(db, targetId, bytes);
}

/**
 * Write main's whole row for each verified canonical blob that has only the
 * chunk form, so a flag-off or plain main build can read it. One blob per
 * transaction; each costs one whole value in memory. Run it only when
 * replication is retired: an enabled store keeps large blobs chunk-only.
 */
export function materializeCanonicalBinaries(db: Database): number {
  const missing = db
    .prepare(
      `SELECT m.blob_id, b.size_bytes, b.sha256
       FROM pdpp_binary_manifests m
       JOIN pdpp_blobs b ON b.blob_id = m.blob_id
       LEFT JOIN ${legacy.canonical} c ON c.blob_id = m.blob_id
       WHERE m.namespace = 'canonical' AND c.blob_id IS NULL`,
    )
    .all() as { blob_id: string; size_bytes: number; sha256: string }[];
  let written = 0;
  for (const blob of missing)
    db.transaction(() => {
      if (
        !verifyBinary(
          db,
          "canonical",
          blob.blob_id,
          `sha256:${blob.sha256}`,
          blob.size_bytes,
        )
      )
        return;
      const bytes = readBinary(db, "canonical", blob.blob_id);
      if (!bytes) return;
      // Main's row becomes the only copy.
      db.prepare(
        `INSERT INTO ${legacy.canonical} (blob_id, bytes) VALUES (?, ?)`,
      ).run(blob.blob_id, Buffer.from(bytes.buffer, 0, bytes.byteLength));
      deleteBinary(db, "canonical", blob.blob_id);
      written++;
    }).immediate();
  return written;
}

/**
 * Explicit whole-value read for HTTP consumers, rollback materialization and
 * inline-size promotion. Replication never calls it on a value larger than
 * CANONICAL_INLINE_BYTES.
 */
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
