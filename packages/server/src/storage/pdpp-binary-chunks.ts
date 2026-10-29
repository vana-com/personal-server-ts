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
 * Write canonical bytes the server holds as one value, in one form only. A
 * value up to CANONICAL_INLINE_BYTES (one Lite fragment) is main's whole row.
 * A larger one is chunks only: the transport and capture's pin read those
 * chunks, and the flag-off boot that retires replication writes main's row
 * (`materializeCanonicalBinaries`).
 */
export function writeCanonicalBinary(
  db: Database,
  id: string,
  bytes: Uint8Array,
): void {
  deleteBinary(db, "canonical", id);
  if (bytes.length > CANONICAL_INLINE_BYTES) {
    db.prepare(`DELETE FROM ${legacy.canonical} WHERE blob_id=?`).run(id);
    const writer = binaryWriter(db, "canonical", id);
    for (let offset = 0; offset < bytes.length; offset += BINARY_CHUNK_BYTES)
      writer.write(bytes.subarray(offset, offset + BINARY_CHUNK_BYTES));
    writer.finish();
    return;
  }
  const view = Buffer.from(
    bytes.buffer as ArrayBuffer,
    bytes.byteOffset,
    bytes.byteLength,
  );
  db.prepare(
    `INSERT INTO ${legacy.canonical} (blob_id, bytes) VALUES (?, ?)
     ON CONFLICT(blob_id) DO UPDATE SET bytes = excluded.bytes`,
  ).run(id, view);
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
 * Make verified bytes in `from` the canonical copy, and leave none in `from`,
 * in the caller's transaction. Large chunked bytes change namespace in place:
 * no byte is written. The manifest is deleted and inserted, not updated, so
 * the visibility view's manifest triggers see both namespaces change.
 */
export function moveBinaryToCanonical(
  db: Database,
  from: BinaryNamespace,
  id: string,
): void {
  const size = binaryLength(db, from, id);
  if (size === undefined) throw new Error("missing binary bytes");
  const chunked =
    db
      .prepare(
        "SELECT 1 FROM pdpp_binary_manifests WHERE namespace=? AND blob_id=?",
      )
      .get(from, id) !== undefined;
  if (size > CANONICAL_INLINE_BYTES && chunked) {
    db.prepare(`DELETE FROM ${legacy.canonical} WHERE blob_id=?`).run(id);
    deleteBinary(db, "canonical", id);
    db.prepare(
      "DELETE FROM pdpp_binary_manifests WHERE namespace=? AND blob_id=?",
    ).run(from, id);
    db.prepare(
      "UPDATE pdpp_binary_chunks SET namespace='canonical' WHERE namespace=? AND blob_id=?",
    ).run(from, id);
    db.prepare(
      "INSERT INTO pdpp_binary_manifests VALUES ('canonical',?,?)",
    ).run(id, size);
  } else copyBinaryToCanonical(db, from, id);
  deleteBinaryCopy(db, from, id);
}

/** Delete a namespace's copy in both forms: chunks and the legacy whole row. */
export function deleteBinaryCopy(
  db: Database,
  namespace: BinaryNamespace,
  id: string,
): void {
  deleteBinary(db, namespace, id);
  const table = legacy[namespace];
  if (table) db.prepare(`DELETE FROM ${table} WHERE blob_id=?`).run(id);
}

/**
 * Write main's whole row for each verified canonical blob that has only the
 * chunk form, so a flag-off or plain main build can read it. One blob per
 * transaction; each costs one whole value in memory. Run it only when
 * replication is retired: an enabled store keeps large blobs chunk-only.
 * A first enable that stopped after the door committed, before the replica
 * schema, left no chunk store, so there is nothing to write.
 */
export function materializeCanonicalBinaries(db: Database): number {
  const chunkStore = db
    .prepare(
      "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'pdpp_binary_manifests'",
    )
    .get();
  if (!chunkStore) return 0;
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

/**
 * Bring blobs an earlier build stored more than once down to one copy, a few
 * blobs per call. Each candidate costs one verified read; the caller runs
 * each `step` in its own write transaction. A copy goes only when canonical
 * storage holds the blob and it verifies:
 *
 * - a received custody copy (the receiver now moves it at promotion);
 * - main's whole row of a large blob that also has the chunk form;
 * - a capture pin's own copy, which becomes a pin row that references the
 *   canonical chunks (`captureBlob`).
 *
 * A candidate that fails verification is skipped for the compactor's life,
 * so one corrupt blob cannot hold back the rest. Once a search finds nothing,
 * the compactor stops for good: current writes keep one copy, so only a
 * database an earlier build wrote has work, and an idle step then reads none
 * of these tables.
 */
export function createBinaryCompactor(db: Database) {
  const skipped = new Set<string>();
  let exhausted = false;
  const canonicalVerifies = (id: string) => {
    const meta = db
      .prepare(
        "SELECT size_bytes AS size, sha256 FROM pdpp_blobs WHERE blob_id=?",
      )
      .get(id) as { size: number; sha256: string } | undefined;
    return (
      !!meta &&
      verifyBinary(db, "canonical", id, `sha256:${meta.sha256}`, meta.size)
    );
  };
  const kinds = [
    {
      kind: "received",
      candidates: `SELECT blob_id FROM pdpp_binary_manifests WHERE namespace='received'
        UNION SELECT blob_id FROM ${legacy.received}`,
      compact(id: string) {
        deleteBinaryCopy(db, "received", id);
      },
    },
    {
      kind: "whole",
      candidates: `SELECT c.blob_id FROM ${legacy.canonical} c
        JOIN pdpp_binary_manifests m ON m.namespace='canonical' AND m.blob_id=c.blob_id
        WHERE m.size_bytes > ${CANONICAL_INLINE_BYTES}`,
      compact(id: string) {
        db.prepare(`DELETE FROM ${legacy.canonical} WHERE blob_id=?`).run(id);
      },
    },
    {
      kind: "pinned",
      candidates: `SELECT p.blob_id FROM pdpp_binary_manifests p
        JOIN pdpp_binary_manifests m ON m.namespace='canonical' AND m.blob_id=p.blob_id
        WHERE p.namespace='pinned'`,
      compact(id: string) {
        db.prepare(
          "INSERT OR IGNORE INTO pdpp_replica_blob_pins VALUES (?)",
        ).run(id);
        deleteBinary(db, "pinned", id);
      },
    },
  ] as const;
  /** The next blob to compact, or undefined when none is left. */
  function next(): { kind: string; id: string } | undefined {
    for (const { kind, candidates } of kinds) {
      const rows = db
        .prepare(
          `SELECT blob_id FROM (${candidates}) WHERE blob_id IN (SELECT blob_id FROM pdpp_blobs) ORDER BY blob_id`,
        )
        .all() as { blob_id: string }[];
      const row = rows.find((row) => !skipped.has(`${kind}:${row.blob_id}`));
      if (row) return { kind, id: row.blob_id };
    }
    return undefined;
  }
  return {
    /** Compact one blob; false when none is left. Call it in a write transaction. */
    step(): boolean {
      if (exhausted) return false;
      const candidate = next();
      if (!candidate) {
        exhausted = true;
        return false;
      }
      const kind = kinds.find((k) => k.kind === candidate.kind)!;
      if (canonicalVerifies(candidate.id)) kind.compact(candidate.id);
      else skipped.add(`${candidate.kind}:${candidate.id}`);
      return true;
    },
  };
}
