import { seenStamp } from "./merge.js";
import { holdMemory } from "./transfer-memory.js";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex } from "@noble/hashes/utils";
import { streamScope } from "@opendatalabs/personal-server-ts-stream-sync";
import type { LocalSyncDeps } from "./deps.js";
import type { SqlDriver, SqlStatement } from "./driver.js";
import { meteredBlobs, type PublishMeter } from "./publish-meter.js";

/**
 * E.1: run blobs (at most 32 MiB). `PUT /v1/stream-sync/runs/:runId/blobs/:sha256`
 * lands here: bytes into `blobs`, a ref into `blob_refs` for the record that
 * names it. Publish uploads `g<gen>-b-<sha256>`; apply fetches lazily.
 */
export interface BlobStore {
  put(input: {
    readonly runId: string;
    readonly sha256: string;
    readonly mimeType: string;
    readonly bytes: Uint8Array;
  }): Promise<void>;
  /** Local bytes, else a lazy fetch from Vana storage; `null` when absent. */
  get(
    blobId: string,
  ): Promise<{ readonly mimeType: string; readonly bytes: Uint8Array } | null>;
}

const MAX_BLOB_BYTES = 32 * 1024 * 1024;

// There is no record argument in put: find exact hash values in this run's
// JSON records, rather than matching substrings or assuming a connector shape.
function namesBlob(body: string, blobId: string): boolean {
  const pending: unknown[] = [JSON.parse(body)];
  while (pending.length > 0) {
    const value = pending.pop();
    if (value === blobId || value === `sha256:${blobId}`) return true;
    if (value !== null && typeof value === "object") {
      for (const child of Object.values(value)) pending.push(child);
    }
  }
  return false;
}

function checkBytes(blobId: string, bytes: Uint8Array): void {
  if (bytes.byteLength > MAX_BLOB_BYTES)
    throw new RangeError("blob exceeds 32 MiB");
  if (!/^[0-9a-f]{64}$/.test(blobId) || bytesToHex(sha256(bytes)) !== blobId)
    throw new Error("blob sha256 does not match bytes");
}

export function createBlobStore(deps: LocalSyncDeps): BlobStore {
  return {
    async put(input) {
      if (input.bytes.byteLength > MAX_BLOB_BYTES)
        throw new RangeError("blob exceeds 32 MiB");
      const bytes = new Uint8Array(input.bytes);
      checkBytes(input.sha256, bytes);
      const [run] = await deps.db.query<{
        connection_id: string;
        generation: number | null;
      }>("SELECT connection_id, generation FROM runs WHERE run_id = ?", [
        input.runId,
      ]);
      if (!run) throw new Error("blob run not found");
      const rows = await deps.db.query<{
        stream: string;
        pk_hash: string;
        body: string;
        staged: number;
      }>(
        `SELECT stream, pk_hash, body, 1 AS staged FROM run_rows WHERE run_id = ?
         UNION ALL
         SELECT stream, pk_hash, body, 0 AS staged FROM records
         WHERE connection_id = ? AND ${seenStamp().r} = ?`,
        [input.runId, run.connection_id, input.runId],
      );
      const statements: SqlStatement[] = [
        {
          sql: "INSERT OR IGNORE INTO blobs(blob_id, mime_type, size_bytes, generation, bytes) VALUES (?, ?, ?, ?, ?)",
          params: [
            input.sha256,
            input.mimeType,
            bytes.byteLength,
            run.generation,
            bytes,
          ],
        },
        {
          sql: "UPDATE blobs SET mime_type = ?, size_bytes = ?, generation = COALESCE(generation, ?), bytes = ? WHERE blob_id = ? AND bytes IS NULL",
          params: [
            input.mimeType,
            bytes.byteLength,
            run.generation,
            bytes,
            input.sha256,
          ],
        },
      ];
      for (const row of rows) {
        if (!namesBlob(row.body, input.sha256)) continue;
        // Recheck the row in the same transaction as the ref insertion, so
        // a deletion or replacement during the earlier reads cannot add a stale ref.
        statements.push(
          row.staged === 1
            ? {
                sql: `INSERT OR IGNORE INTO blob_refs(blob_id, connection_id, stream, pk_hash)
                SELECT ?, ?, stream, pk_hash FROM run_rows
                WHERE run_id = ? AND stream = ? AND pk_hash = ? AND body = ?`,
                params: [
                  input.sha256,
                  run.connection_id,
                  input.runId,
                  row.stream,
                  row.pk_hash,
                  row.body,
                ],
              }
            : {
                sql: `INSERT OR IGNORE INTO blob_refs(blob_id, connection_id, stream, pk_hash)
                SELECT ?, connection_id, stream, pk_hash FROM records
                WHERE connection_id = ? AND stream = ? AND pk_hash = ?
                  AND ${seenStamp().r} = ? AND body = ?`,
                params: [
                  input.sha256,
                  run.connection_id,
                  row.stream,
                  row.pk_hash,
                  input.runId,
                  row.body,
                ],
              },
        );
      }
      await deps.db.batch(statements);
    },

    async get(blobId) {
      const [local] = await deps.db.query<{
        mime_type: string;
        generation: number | null;
        bytes: Uint8Array | null;
      }>("SELECT mime_type, generation, bytes FROM blobs WHERE blob_id = ?", [
        blobId,
      ]);
      if (local?.bytes !== null && local?.bytes !== undefined) {
        checkBytes(blobId, local.bytes);
        return { mimeType: local.mime_type, bytes: local.bytes };
      }
      // A new device has records before it has fetched any blob bytes. Rebuild
      // refs from exact hash values in those records, without retaining bodies
      // or assuming which surface wrote them. Recheck each body at insertion.
      const candidates = await deps.db.query<{
        connection_id: string;
        stream: string;
        pk_hash: string;
        body: string;
      }>(
        `SELECT r.connection_id,r.stream,r.pk_hash,r.body FROM records r
        JOIN connections c ON c.connection_id=r.connection_id
        WHERE c.control_state='active' AND instr(r.body,?)>0
        AND NOT EXISTS(SELECT 1 FROM delete_intents d WHERE d.connector=c.connector)`,
        [blobId],
      );
      const refs = candidates.filter((row) => namesBlob(row.body, blobId));
      if (refs.length)
        await deps.db.batch(
          refs.map((row) => ({
            sql: `INSERT OR IGNORE INTO blob_refs(blob_id,connection_id,stream,pk_hash)
          SELECT ?,connection_id,stream,pk_hash FROM records WHERE connection_id=? AND stream=? AND pk_hash=? AND body=?
          AND EXISTS(SELECT 1 FROM connections c WHERE c.connection_id=records.connection_id AND c.control_state='active'
            AND NOT EXISTS(SELECT 1 FROM delete_intents d WHERE d.connector=c.connector))`,
            params: [
              blobId,
              row.connection_id,
              row.stream,
              row.pk_hash,
              row.body,
            ],
          })),
        );
      const locations = await deps.db.query<{
        connector: string;
        ns: string;
        stream: string;
        generation: number;
      }>(
        `SELECT DISTINCT c.connector, c.ns, r.stream,
                COALESCE(s.head_generation, ?, c.generation) AS generation
         FROM blob_refs r JOIN connections c ON c.connection_id = r.connection_id
         LEFT JOIN stream_state s ON s.connection_id = r.connection_id AND s.stream = r.stream
         WHERE r.blob_id = ?
         ORDER BY c.connector, c.ns, r.stream`,
        [local?.generation ?? null, blobId],
      );
      let bytes: Uint8Array | null = null;
      let generation = local?.generation ?? null;
      for (const location of locations) {
        const scope = streamScope(
          location.connector,
          location.ns,
          location.stream,
        );
        const cipher = await deps.blobs.get(
          `${scope}/g${location.generation}-b-${blobId}`,
        );
        if (cipher === null) continue;
        bytes = await deps.keys.decrypt(scope, cipher);
        generation = location.generation;
        break;
      }
      // With no reference metadata, the caller's id is the only available port
      // key. Known stream references always use the scoped encrypted path above.
      if (locations.length === 0) bytes = await deps.blobs.get(blobId);
      if (bytes === null) return null;
      checkBytes(blobId, bytes);
      const mimeType = local?.mime_type ?? "application/octet-stream";
      await deps.db.batch([
        {
          sql: "INSERT OR IGNORE INTO blobs(blob_id, mime_type, size_bytes, generation, bytes) VALUES (?, ?, ?, ?, ?)",
          params: [blobId, mimeType, bytes.byteLength, generation, bytes],
        },
        {
          sql: "UPDATE blobs SET bytes = ?, size_bytes = ? WHERE blob_id = ? AND bytes IS NULL",
          params: [bytes, bytes.byteLength, blobId],
        },
      ]);
      return { mimeType, bytes };
    },
  };
}

// Remote object keys are immutable. Avoid downloading a 32 MiB object every
// idle cycle just to test existence; restart safely probes the durable cache.
const uploadedBlobs = new WeakMap<SqlDriver, Set<string>>();

/**
 * Forget what this process uploaded. A name carries its lifetime
 * (`g<generation>`), so a later lifetime never meets an earlier one's entries;
 * this also removes them when a lifetime ends (a purge), so the cache never
 * vouches for objects a connection delete may have removed. Not called on a
 * routine apply: a foreign head says nothing about the remote store, and
 * probing again after each one would cost a request per attachment.
 */
export function forgetUploadedBlobs(db: SqlDriver): void {
  uploadedBlobs.delete(db);
}

/** One attachment a stream's records name, and where it is published. */
export interface BlobDescriptor {
  readonly blobId: string;
  /** `<scope>/g<generation>-b-<sha256>`. */
  readonly key: string;
  readonly scope: string;
}

/** The attachment bytes a descriptor names are gone from the local store. */
export class MissingAttachmentError extends Error {
  constructor(readonly blobId: string) {
    super(`attachment ${blobId} has no local bytes to publish`);
    this.name = "MissingAttachmentError";
  }
}

/** Rows of one blob's referring records read at a time. */
const REFERRER_PAGE_ROWS = 8;

/**
 * Whether a record of the stream names the blob. A blob can be referred to by
 * every record of a stream, so the records are read a page at a time, in key
 * order, and the search stops at the first that names it. The `instr` test is
 * a necessary condition of `namesBlob` (the id is a JSON string in the body),
 * so a record that cannot name the blob is never read into memory.
 */
async function someRecordNamesBlob(
  deps: LocalSyncDeps,
  input: { readonly connectionId: string; readonly stream: string },
  blobId: string,
): Promise<boolean> {
  let after = "";
  for (;;) {
    const records = await deps.db.query<{ pk_hash: string; body: string }>(
      `SELECT r.pk_hash, r.body FROM blob_refs f JOIN records r
        ON r.connection_id=f.connection_id AND r.stream=f.stream AND r.pk_hash=f.pk_hash
       WHERE f.blob_id=? AND f.connection_id=? AND f.stream=? AND f.pk_hash>?
         AND instr(r.body, ?)>0
       ORDER BY f.pk_hash LIMIT ${REFERRER_PAGE_ROWS}`,
      [blobId, input.connectionId, input.stream, after, blobId],
    );
    if (records.some((record) => namesBlob(record.body, blobId))) return true;
    if (records.length < REFERRER_PAGE_ROWS) return false;
    after = records[records.length - 1]!.pk_hash;
  }
}

/**
 * List the cached run bytes a stream's records name and that are not yet
 * known to be published (E.1). Local reads only, paged by metadata: no blob
 * payload is read. The result is the whole input of `uploadBlobs`.
 */
export async function listStreamBlobs(
  deps: LocalSyncDeps,
  input: {
    readonly connectionId: string;
    readonly stream: string;
    readonly scope: string;
    readonly generation: number;
  },
): Promise<readonly BlobDescriptor[]> {
  const uploaded = uploadedBlobs.get(deps.db);
  const found: BlobDescriptor[] = [];
  let after = "";
  for (;;) {
    const rows = await deps.db.query<{ blob_id: string }>(
      `SELECT DISTINCT b.blob_id
      FROM blobs b JOIN blob_refs f ON f.blob_id=b.blob_id
      JOIN records r ON r.connection_id=f.connection_id AND r.stream=f.stream AND r.pk_hash=f.pk_hash
      WHERE f.connection_id=? AND f.stream=? AND b.bytes IS NOT NULL AND b.blob_id>?
      ORDER BY b.blob_id LIMIT 100`,
      [input.connectionId, input.stream, after],
    );
    for (const row of rows) {
      const key = `${input.scope}/g${input.generation}-b-${row.blob_id}`;
      if (uploaded?.has(key)) continue;
      if (!(await someRecordNamesBlob(deps, input, row.blob_id))) continue;
      found.push({ blobId: row.blob_id, key, scope: input.scope });
    }
    if (rows.length < 100) return found;
    after = rows.at(-1)!.blob_id;
  }
}

/**
 * Publish the listed attachments before the head that references them (E.1),
 * one blob in memory at a time. It reads `blobs` by exact id and checks the
 * bytes against the id: it never takes the lazy-fetch path of
 * `BlobStore.get`, which rebuilds references from live records. An attachment
 * with no bytes fails the upload; it is never skipped. Needs no queue slot.
 *
 * With `probe` false a blob is uploaded without asking storage whether it is
 * there. A name is the hash of the clear bytes, so an upload of a stored name
 * keeps or replaces the object with another encryption of the same clear
 * bytes: skipping the probe can repeat an upload and never leave a blob
 * missing. For a stream with no registry row only.
 */
export async function uploadBlobs(
  deps: LocalSyncDeps,
  blobs: readonly BlobDescriptor[],
  meter?: PublishMeter,
  /** Called before each probe and before each upload request, after the storage layer's waits; a throw stops it. */
  beforeUpload?: () => void,
  probe = true,
): Promise<void> {
  const store = meter ? meteredBlobs(deps, meter) : deps.blobs;
  let uploaded = uploadedBlobs.get(deps.db);
  if (!uploaded) uploadedBlobs.set(deps.db, (uploaded = new Set()));
  for (const { blobId, key, scope } of blobs) {
    if (uploaded.has(key)) continue;
    beforeUpload?.();
    if (probe && (await store.exists(key))) {
      uploaded.add(key);
      continue;
    }
    const [stored] = await deps.db.query<{ size: number | null }>(
      "SELECT length(bytes) AS size FROM blobs WHERE blob_id = ?",
      [blobId],
    );
    if (stored?.size === null || stored?.size === undefined) {
      throw new MissingAttachmentError(blobId);
    }
    // The attachment is in memory as plain bytes and again as ciphertext, so
    // twice its size is held from before the read until its upload settles.
    const release = await holdMemory(store, 2 * stored.size, stored.size);
    try {
      const [local] = await deps.db.query<{ bytes: Uint8Array | null }>(
        "SELECT bytes FROM blobs WHERE blob_id = ?",
        [blobId],
      );
      if (local?.bytes === null || local?.bytes === undefined) {
        throw new MissingAttachmentError(blobId);
      }
      checkBytes(blobId, local.bytes);
      const cipher = await deps.keys.encrypt(scope, local.bytes);
      beforeUpload?.();
      await store.put(key, cipher, beforeUpload);
    } finally {
      release();
    }
    uploaded.add(key);
  }
}
