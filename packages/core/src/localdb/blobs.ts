import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex } from "@noble/hashes/utils";
import { streamScope } from "@opendatalabs/personal-server-ts-stream-sync";
import type { LocalSyncDeps } from "./deps.js";
import type { SqlStatement } from "./driver.js";

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
    if (value === blobId) return true;
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
         WHERE connection_id = ? AND stamp_r = ?`,
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
                  AND stamp_r = ? AND body = ?`,
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
      if (local?.bytes !== null && local?.bytes !== undefined)
        return { mimeType: local.mime_type, bytes: local.bytes };
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
