import { readBinaryChunks } from "./pdpp-binary-chunks.js";
/** Isolated real-worker memory probe. Loopback-free, disk-backed transport; no accounts. */
import Database from "better-sqlite3";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { createReplicaRecordStore } from "./pdpp-replica-canonical-port.js";
import { createReplicaReceiver } from "./pdpp-replication-receiver.js";
import { createReplicaTransportWorker } from "./pdpp-replication-transport.js";
import {
  replicaChainCommitment,
  type ReplicaTransportPort,
  type ReplicaCommitment,
} from "@opendatalabs/personal-server-ts-core/replication/dpv2";

const [mode, directory, sizeArg] = process.argv.slice(2);
if (!directory) throw new Error("probe directory required");
const size = Number(sizeArg);
const owner = "0x0000000000000000000000000000000000000001";
const sourceId = "https://memory.invalid/declaration";
const binding = {
  digest: `sha256:${"a".repeat(64)}`,
  version: "1",
  stream: "messages",
  semantics: "mutable_state" as const,
  primaryKey: ["id"],
  schemaDigest: `sha256:${"b".repeat(64)}`,
};
const expected = { owner, declarations: [{ sourceId, binding }] };
const open = (role: string) => {
  const db = new Database(join(directory, `${role}.sqlite`));
  db.pragma("cache_size=-2048");
  const store = createReplicaRecordStore(db);
  store.registerConnection({
    instance: "conn",
    sourceId,
    method: "export",
    label: "memory",
  });
  store.replication.beginBaseline(expected);
  return { db, store };
};
if (mode === "seed" || mode === "seed-legacy") {
  const { db, store } = open("source");
  const blob = store.storeBlobBytesForInstance({
    instance: "conn",
    method: "export",
    generation: 1,
    bytes: Buffer.alloc(size, 31),
    mimeType: "application/octet-stream",
  });
  store.ingestBatch(
    [
      {
        instance: "conn",
        stream: "messages",
        key: "large",
        data: {
          id: "large",
          blob_ref: {
            blob_id: blob.blobId,
            mime_type: blob.mimeType,
            size_bytes: size,
          },
        },
        emitted_at: "2026-10-20T00:00:00.000Z",
      },
    ],
    () => "mutable_state",
    () => ["id"],
    { method: "export", generation: 1 },
  );
  if (mode === "seed-legacy") {
    // Keep only main's legacy whole-value row to exercise its fallback reader.
    db.prepare(
      "DELETE FROM pdpp_binary_chunks WHERE namespace='canonical' AND blob_id=?",
    ).run(blob.blobId);
    db.prepare(
      "DELETE FROM pdpp_binary_manifests WHERE namespace='canonical' AND blob_id=?",
    ).run(blob.blobId);
  }
  writeFileSync(join(directory, "blob-id"), blob.blobId);
  store.close();
} else if (mode === "legacy-read") {
  const { store } = open("source");
  const bytes = store.getBlobBytes(
    readFileSync(join(directory, "blob-id"), "utf8"),
  );
  if (bytes?.length !== size) throw new Error("legacy read failed");
  console.log(JSON.stringify({ size: bytes.length }));
  store.close();
} else if (mode === "measure" || mode === "probe") {
  const source = open("source"),
    destination = open("destination");
  const heads = new Map<string, ReplicaCommitment>();
  let published = 0;
  const transport: ReplicaTransportPort = {
    // Crypto scratch is bounded by fragment size. The worker still validates every fragment and commitment.
    encrypt: async (_scope, bytes) => new Uint8Array(bytes),
    decrypt: async (_scope, bytes) => new Uint8Array(bytes),
    async evidence(scope) {
      const head = heads.get(scope) ?? null;
      return {
        head,
        pending: false,
        chain: {
          owner,
          scope,
          version: "1",
          currentVersion: head ? "1" : "0",
          status: head ? "Active" : "None",
          commitment: head
            ? replicaChainCommitment(
                head.dataHash as `0x${string}`,
                head.metadataHash as `0x${string}`,
              )
            : `0x${"0".repeat(64)}`,
          chainId: 14800,
          registry: `0x${"2".repeat(40)}`,
          blockNumber: 123n,
          blockHash: `0x${"3".repeat(64)}`,
          blockTimestamp: 1000n,
        },
      };
    },
    async put(part) {
      writeFileSync(
        join(directory, createHash("sha256").update(part.scope).digest("hex")),
        part.encrypted,
      );
    },
    async register(part) {
      heads.set(part.scope, {
        owner,
        scope: part.scope,
        version: "1",
        dataHash: part.dataHash,
        metadataHash: part.metadataHash,
        deleted: false,
      });
      published++;
    },
    async get(scope) {
      return readFileSync(
        join(directory, createHash("sha256").update(scope).digest("hex")),
      );
    },
    async list() {
      return { scopes: [...heads.keys()], cursor: null };
    },
  };
  const worker = (device: typeof source) =>
    createReplicaTransportWorker({
      ...device,
      enabled: true,
      exporter: device.store.replication,
      expected: () => expected,
      receiver: createReplicaReceiver({
        ...device,
        owner,
        authenticate: () => owner,
        declarations: () => [
          {
            sourceId,
            binding,
            validateData: (data) => typeof data.id === "string",
          },
        ],
      }),
      credential: "memory",
      transport,
      targetChunkBytes: 3 * 1024 * 1024,
    });
  if (process.env.REPLICA_PAUSE_DIR) {
    const read = source.store.replication.readPinnedBlobChunks;
    source.store.replication.readPinnedBlobChunks = function* (id) {
      let paused = false;
      for (const chunk of read(id)) {
        yield chunk;
        if (!paused) {
          paused = true;
          writeFileSync(
            join(process.env.REPLICA_PAUSE_DIR!, "paused"),
            "ready",
          );
          const sleep = new Int32Array(new SharedArrayBuffer(4));
          while (!existsSync(join(process.env.REPLICA_PAUSE_DIR!, "resume")))
            Atomics.wait(sleep, 0, 0, 20);
        }
      }
    };
  }
  const a = worker(source),
    b = worker(destination);
  if (mode === "probe") {
    try {
      await a.cycle();
    } catch (error) {
      if (
        error &&
        typeof error === "object" &&
        "code" in error &&
        error.code === "replica_worker_active"
      )
        process.exit(2);
      throw error;
    }
    console.log(JSON.stringify({ probe: true }));
    source.store.close();
    destination.store.close();
    process.exit(0);
  }
  for (let cycle = 0; cycle < 12; cycle++) {
    await a.cycle();
    await b.cycle();
    if (destination.store.getRecord("conn", "messages", "large")) break;
  }
  if (!destination.store.getRecord("conn", "messages", "large"))
    throw new Error("worker failed to import");
  const blobId = readFileSync(join(directory, "blob-id"), "utf8");
  const hash = createHash("sha256");
  // Verify destination bytes without adding an object-sized test allocation to the peak.
  let length = 0;
  for (const chunk of readBinaryChunks(destination.db, "canonical", blobId)) {
    hash.update(chunk);
    length += chunk.length;
  }
  if (`sha256:${hash.digest("hex")}` !== blobId || length !== size)
    throw new Error("imported bytes changed");
  console.log(
    JSON.stringify({
      size,
      published,
      peakRssKiB: process.resourceUsage().maxRSS,
    }),
  );
  source.store.close();
  destination.store.close();
} else throw new Error("unknown probe mode");
