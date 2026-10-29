import type { Database } from "better-sqlite3";
import { createHash } from "node:crypto";

export const BINARY_CHUNK_BYTES = 64 * 1024;
/** Legacy whole-row reads: windows are at least this big and at most this many. */
export const LEGACY_MIN_WINDOW_BYTES = 8 * 1024 * 1024;
export const LEGACY_WINDOWS = 16;
export const CANONICAL_INLINE_BYTES = 1024 * 1024;
/** Candidates one compaction step may examine, so skipped ones cannot stall it. */
const COMPACT_CANDIDATES_PER_STEP = 8;
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
 * Bring blobs an earlier build stored more than once down to one copy. The
 * caller runs each `step` in its own write transaction. A
 * copy goes only when canonical storage holds the blob and it verifies:
 *
 * - a received custody copy (the receiver now moves it at promotion);
 * - main's whole row of a large blob that also has the chunk form;
 * - a capture pin's own copy, which becomes a pin row that references the
 *   canonical chunks (`captureBlob`).
 *
 * Verification reads a bounded number of chunks per call, so a large blob
 * is verified across calls. The hash in progress lives in memory: after a
 * restart that blob is verified again from its start. A canonical whole row
 * up to 1 MiB verifies in one call; a larger one has no bounded read and is
 * skipped, and so is canonical storage with a chunk past the blob's end. A
 * candidate that fails verification is skipped for the compactor's life,
 * and a step examines at most 8 candidates, so corrupt blobs cannot hold
 * back the rest or stall a step. Once a
 * search finds nothing, the compactor stops for good: current writes keep
 * one copy, so only a database an earlier build wrote has work, and an idle
 * step then reads none of these tables.
 */
export function createBinaryCompactor(db: Database) {
  const known = "IN (SELECT blob_id FROM pdpp_blobs)";
  /** Per kind: queries for its candidates after `@after`, first by blob id. */
  const kinds = {
    received: {
      arms: [
        `SELECT blob_id FROM pdpp_binary_manifests
         WHERE namespace='received' AND blob_id>@after AND blob_id ${known}`,
        `SELECT blob_id FROM ${legacy.received}
         WHERE blob_id>@after AND blob_id ${known}`,
      ],
      compact(id: string) {
        deleteBinaryCopy(db, "received", id);
      },
    },
    whole: {
      arms: [
        `SELECT c.blob_id FROM ${legacy.canonical} c
         JOIN pdpp_binary_manifests m ON m.namespace='canonical' AND m.blob_id=c.blob_id
         WHERE m.size_bytes > ${CANONICAL_INLINE_BYTES} AND c.blob_id>@after AND c.blob_id ${known}`,
      ],
      compact(id: string) {
        db.prepare(`DELETE FROM ${legacy.canonical} WHERE blob_id=?`).run(id);
      },
    },
    pinned: {
      arms: [
        `SELECT p.blob_id FROM pdpp_binary_manifests p
         JOIN pdpp_binary_manifests m ON m.namespace='canonical' AND m.blob_id=p.blob_id
         WHERE p.namespace='pinned' AND p.blob_id>@after AND p.blob_id ${known}`,
      ],
      compact(id: string) {
        // Export may have released the pin since verification began.
        if (binaryLength(db, "pinned", id) === undefined) return;
        db.prepare(
          "INSERT OR IGNORE INTO pdpp_replica_blob_pins VALUES (?)",
        ).run(id);
        deleteBinary(db, "pinned", id);
      },
    },
  } as const;
  type Kind = keyof typeof kinds;
  const order = Object.keys(kinds) as Kind[];
  /**
   * Keyset position: the kind being searched and the last blob examined in
   * it. A candidate is examined once per process, so a skipped one costs no
   * later search.
   */
  let cursor = { kind: 0, after: "" };
  let current:
    | {
        kind: Kind;
        id: string;
        size: number;
        digest: string;
        hash: ReturnType<typeof createHash>;
        position: number;
        read: number;
      }
    | undefined;
  /** The next candidate, or undefined when none is left. */
  function next(): { kind: Kind; id: string } | undefined {
    while (cursor.kind < order.length) {
      const kind = order[cursor.kind]!;
      const row = db
        .prepare(
          `SELECT min(blob_id) AS blob_id FROM (${kinds[kind].arms
            .map((arm) => `SELECT * FROM (${arm} ORDER BY 1 LIMIT 1)`)
            .join(" UNION ALL ")})`,
        )
        .get({ after: cursor.after }) as { blob_id: string | null };
      if (row.blob_id !== null) {
        cursor.after = row.blob_id;
        return { kind, id: row.blob_id };
      }
      cursor = { kind: cursor.kind + 1, after: "" };
    }
    return undefined;
  }
  /**
   * Begin verifying a candidate. A canonical whole row up to 1 MiB verifies
   * and compacts at once; a larger whole row has no bounded read and is
   * skipped. Returns the bytes read.
   */
  function begin(candidate: { kind: Kind; id: string }): number {
    const meta = db
      .prepare(
        "SELECT size_bytes AS size, sha256 FROM pdpp_blobs WHERE blob_id=?",
      )
      .get(candidate.id) as { size: number; sha256: string } | undefined;
    const size = binaryLength(db, "canonical", candidate.id);
    if (!meta || size !== meta.size) return 0;
    const digest = `sha256:${meta.sha256}`;
    const chunked = db
      .prepare(
        "SELECT 1 FROM pdpp_binary_manifests WHERE namespace='canonical' AND blob_id=?",
      )
      .get(candidate.id);
    if (!chunked) {
      if (size > CANONICAL_INLINE_BYTES) return 0;
      if (verifyBinary(db, "canonical", candidate.id, digest, size))
        kinds[candidate.kind].compact(candidate.id);
      return size;
    }
    current = {
      ...candidate,
      size,
      digest,
      hash: createHash("sha256"),
      position: 0,
      read: 0,
    };
    return 0;
  }
  /**
   * Hash up to `bytes` more of the current blob, at least one chunk, and
   * compact it once it verifies. Returns the bytes read.
   */
  function advance(bytes: number): number {
    const blob = current!;
    const rows = db
      .prepare(
        "SELECT position, bytes FROM pdpp_binary_chunks WHERE namespace='canonical' AND blob_id=? AND position>=? ORDER BY position",
      )
      .iterate(blob.id, blob.position) as Iterable<{
      position: number;
      bytes: Buffer;
    }>;
    let read = 0;
    let corrupt = true;
    for (const row of rows) {
      corrupt =
        row.position !== blob.position ||
        !row.bytes.length ||
        row.bytes.length > BINARY_CHUNK_BYTES ||
        blob.read + row.bytes.length > blob.size;
      if (corrupt || (read && read + row.bytes.length > bytes)) break;
      blob.hash.update(row.bytes);
      blob.position++;
      blob.read += row.bytes.length;
      read += row.bytes.length;
      if (blob.read === blob.size) break;
    }
    if (corrupt) current = undefined;
    else if (blob.read === blob.size) {
      current = undefined;
      // Readers reject a chunk past the blob's end, so verification does too.
      const trailing = db
        .prepare(
          "SELECT 1 FROM pdpp_binary_chunks WHERE namespace='canonical' AND blob_id=? AND position>=?",
        )
        .get(blob.id, blob.position);
      if (
        !trailing &&
        `sha256:${blob.hash.digest("hex")}` === blob.digest &&
        binaryLength(db, "canonical", blob.id) === blob.size
      )
        kinds[blob.kind].compact(blob.id);
    }
    return Math.max(read, 1);
  }
  return {
    /**
     * Spend up to about `bytes` of canonical reads, and at most
     * `COMPACT_CANDIDATES_PER_STEP` new candidates, toward compaction. Call it
     * in a write transaction.
     */
    step(bytes: number) {
      let started = 0;
      while (bytes >= BINARY_CHUNK_BYTES) {
        if (current) {
          bytes -= advance(bytes);
          continue;
        }
        if (started === COMPACT_CANDIDATES_PER_STEP) return;
        const candidate = next();
        if (!candidate) return;
        started++;
        bytes -= begin(candidate);
      }
    },
  };
}
