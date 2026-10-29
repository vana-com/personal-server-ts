/**
 * Retained batch payloads, as storage effects over the binary chunk tables
 * (`pdpp_binary_chunks`, `pdpp_binary_manifests`) in their `payload`
 * namespace. Node's `pdpp-binary-chunks.ts` owns the same tables for every
 * namespace; the `payload` namespace never had a legacy whole-value table,
 * so its rows mean the same on both hosts.
 */
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "@noble/hashes/utils";
import { sql, type ReplicaEffect } from "./effects.js";

export const REPLICA_PAYLOAD_CHUNK_BYTES = 64 * 1024;
const NAMESPACE = "payload";

/** The tables, for a host whose storage does not create them already. */
export const REPLICA_PAYLOAD_MIGRATION = `
CREATE TABLE IF NOT EXISTS pdpp_binary_manifests (
 namespace TEXT NOT NULL, blob_id TEXT NOT NULL, size_bytes INTEGER NOT NULL,
 PRIMARY KEY(namespace,blob_id));
CREATE TABLE IF NOT EXISTS pdpp_binary_chunks (
 namespace TEXT NOT NULL, blob_id TEXT NOT NULL, position INTEGER NOT NULL, bytes BLOB NOT NULL,
 PRIMARY KEY(namespace,blob_id,position));
`;

export function* deleteReplicaPayload(key: string): ReplicaEffect<void> {
  yield* sql.run(
    "DELETE FROM pdpp_binary_chunks WHERE namespace=? AND blob_id=?",
    NAMESPACE,
    key,
  );
  yield* sql.run(
    "DELETE FROM pdpp_binary_manifests WHERE namespace=? AND blob_id=?",
    NAMESPACE,
    key,
  );
}

export interface ReplicaPayloadWriter {
  write(bytes: Uint8Array): ReplicaEffect<void>;
  /** Publish the manifest, after the last chunk. Returns the size. */
  finish(): ReplicaEffect<number>;
}

/** Drop any bytes under `key`, then write fresh ones. */
export function* replicaPayloadWriter(
  key: string,
): ReplicaEffect<ReplicaPayloadWriter> {
  yield* deleteReplicaPayload(key);
  let size = 0,
    position = 0;
  return {
    *write(bytes) {
      for (
        let offset = 0;
        offset < bytes.length;
        offset += REPLICA_PAYLOAD_CHUNK_BYTES
      ) {
        const part = bytes.subarray(
          offset,
          offset + REPLICA_PAYLOAD_CHUNK_BYTES,
        );
        yield* sql.run(
          "INSERT INTO pdpp_binary_chunks VALUES (?,?,?,?)",
          NAMESPACE,
          key,
          position++,
          part,
        );
        size += part.length;
      }
    },
    *finish() {
      yield* sql.run(
        "INSERT INTO pdpp_binary_manifests VALUES (?,?,?)",
        NAMESPACE,
        key,
        size,
      );
      return size;
    },
  };
}

/** The published size, or undefined when absent or malformed. */
export function* replicaPayloadLength(
  key: string,
): ReplicaEffect<number | undefined> {
  const manifest = yield* sql.get<{ size: number }>(
    "SELECT size_bytes AS size FROM pdpp_binary_manifests WHERE namespace=? AND blob_id=?",
    NAMESPACE,
    key,
  );
  return manifest && Number.isSafeInteger(manifest.size) && manifest.size >= 0
    ? manifest.size
    : undefined;
}

/** Chunk `position` of `key`, checked against the published size. */
export function* replicaPayloadChunk(
  key: string,
  position: number,
  offset: number,
  size: number,
): ReplicaEffect<Uint8Array> {
  const row = yield* sql.get<{ bytes: Uint8Array }>(
    "SELECT bytes FROM pdpp_binary_chunks WHERE namespace=? AND blob_id=? AND position=?",
    NAMESPACE,
    key,
    position,
  );
  if (
    !row ||
    !row.bytes.length ||
    row.bytes.length > REPLICA_PAYLOAD_CHUNK_BYTES ||
    offset + row.bytes.length > size
  )
    throw new Error("corrupt binary chunks");
  return row.bytes;
}

function* assertNoExcess(key: string, position: number): ReplicaEffect<void> {
  if (
    yield* sql.get(
      "SELECT 1 FROM pdpp_binary_chunks WHERE namespace=? AND blob_id=? AND position>=? LIMIT 1",
      NAMESPACE,
      key,
      position,
    )
  )
    throw new Error("excess binary chunks");
}

/**
 * Stream a payload one chunk per storage call, so no transaction spans the
 * consumer's awaits. `run` is the host's one-effect runner.
 */
export async function* readReplicaPayload(
  run: <T>(effect: ReplicaEffect<T>) => T | Promise<T>,
  key: string,
): AsyncGenerator<Uint8Array> {
  const size = await run(replicaPayloadLength(key));
  if (size === undefined) throw new Error("missing binary bytes");
  let offset = 0,
    position = 0;
  while (offset < size) {
    const bytes = await run(replicaPayloadChunk(key, position++, offset, size));
    offset += bytes.length;
    yield bytes;
  }
  await run(assertNoExcess(key, position));
}

/** In the caller's transaction: do the bytes under `key` hash to `digest`? */
export function* verifyReplicaPayload(
  key: string,
  digest: string,
  size: number,
): ReplicaEffect<boolean> {
  if ((yield* replicaPayloadLength(key)) !== size) return false;
  const hash = sha256.create();
  try {
    let offset = 0,
      position = 0;
    while (offset < size) {
      const bytes = yield* replicaPayloadChunk(key, position++, offset, size);
      offset += bytes.length;
      hash.update(bytes);
    }
    yield* assertNoExcess(key, position);
  } catch {
    return false;
  }
  return `sha256:${bytesToHex(hash.digest())}` === digest;
}
