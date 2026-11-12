// Workload for the publish memory test: a first publish of a many-row stream,
// measured in a fresh child by the memory oracle. The database is built by the
// parent (not measured); the child opens it and publishes once.
import { createHash } from "node:crypto";
import { keccak_256 } from "@noble/hashes/sha3";
import { openLocalDb } from "../../../core/src/localdb/open.js";
import { connectionQueue } from "../../../core/src/localdb/queue.js";
import { createLocalSync } from "../../../core/src/localdb/sync.js";
import { publishConnection } from "../../../core/src/localdb/publish.js";
import { listStreamBlobs } from "../../../core/src/localdb/blobs.js";
import { encodePrefixes } from "../../../core/src/localdb/encode.js";
import type { LocalSyncDeps } from "../../../core/src/localdb/deps.js";
import { createMemoryStreamSyncRegistry } from "../../../core/src/stream-sync/memory-registry.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const identity = {
  owner: "0x1111111111111111111111111111111111111111" as const,
  network: "test",
  deviceId: "publish-memory",
};
const CONNECTOR = "memory-source";
export const PUBLISH_MEMORY_CONNECTION = `pdpp.${CONNECTOR}~`;

async function makeDeps(
  path: string,
  sink: { puts: number; bytes: number },
  slots: number[] = [],
) {
  const db = await openLocalDb(openBetterSqlite3(path), identity);
  let op = 0;
  const real = connectionQueue();
  const deps: LocalSyncDeps = {
    db,
    // Each slot turn is timed, so the snapshot's hold time can be reported.
    queue: {
      async run(id, kind, fn) {
        return real.run(id, kind, async () => {
          const started = performance.now();
          try {
            return await fn();
          } finally {
            if (kind === "publish") slots.push(performance.now() - started);
          }
        });
      },
    },
    registry: createMemoryStreamSyncRegistry(),
    // Uploaded objects are counted and dropped: a test double that kept them
    // would itself grow with the stream and hide what the publisher holds.
    blobs: {
      get: async () => null,
      put: async (_key, bytes) => {
        sink.puts += 1;
        sink.bytes += bytes.length;
      },
    },
    ownerAddress: identity.owner,
    keys: {
      namespaceHmac: async () => new Uint8Array(32),
      encrypt: async (_s, b) => b,
      encryptPart: async (_s, b) => b,
      decrypt: async (_s, b) => b,
    },
    signer: { signAddData: async () => "0x00" },
    logger: { info: () => {}, warn: () => {} },
    now: () => 1_000,
    newOp: () => `publish-memory-${++op}`,
  };
  return deps;
}

/** Parent side, unmeasured: `rows` records of about `rowBytes` each, one run. */
export async function buildPublishMemoryDb(
  path: string,
  rows: number,
  rowBytes: number,
): Promise<void> {
  const deps = await makeDeps(path, { puts: 0, bytes: 0 });
  try {
    const sync = createLocalSync(deps, {
      resolveArtifact: (digest) => ({
        connector: digest,
        version: "1",
        streams: [
          { name: "items", semantics: "mutable_state", primaryKey: ["id"] },
        ],
      }),
      declaredStreams: () => ["items"],
      olderVersionReads: () => true,
    });
    await sync.intake.begin("seed", {
      connector: CONNECTOR,
      artifactDigest: CONNECTOR,
      wantFull: true,
      owner: { address: identity.owner, leaseId: null },
    });
    const perBatch = 50;
    let batch = 0;
    for (let at = 0; at < rows; at += perBatch, batch++) {
      const records = [];
      for (let i = at; i < Math.min(rows, at + perBatch); i++) {
        records.push({
          stream: "items",
          data: { id: `row-${i}`, text: `${i}:`.padEnd(rowBytes, "x") },
        });
      }
      await sync.intake.batch("seed", { batch, records });
    }
    await sync.intake.end("seed", {
      outcome: "succeeded",
      coveredStreams: ["items"],
      lastBatch: batch - 1,
    });
  } finally {
    await deps.db.close();
  }
}

export interface PublishMemoryResult {
  outcome: string;
  puts: number;
  uploadedBytes: number;
  /** Milliseconds each publish slot turn held the connection (snapshot, commit). */
  slotMs: number[];
}

/** Child side, measured: one publish of the whole stream. */
export async function publishMemoryWorkload(input: {
  path: string;
}): Promise<PublishMemoryResult> {
  const sink = { puts: 0, bytes: 0 };
  const slots: number[] = [];
  const deps = await makeDeps(input.path, sink, slots);
  try {
    // keccak is loaded by the publisher; touch it so import cost is not measured.
    keccak_256(new Uint8Array(1));
    const results = await publishConnection(deps, PUBLISH_MEMORY_CONNECTION);
    return {
      outcome: results.map((r) => r.outcome).join(","),
      puts: sink.puts,
      uploadedBytes: sink.bytes,
      slotMs: slots,
    };
  } finally {
    await deps.db.close();
  }
}

/**
 * Parent side, unmeasured: `rows` records straight into `records`, each of
 * about `rowBytes`, every key in one part prefix. With `blobId`, each record
 * names the one attachment, which is stored once and referred to by every row.
 */
export async function buildRowsDb(
  path: string,
  rows: number,
  rowBytes: number,
  blobId?: string,
): Promise<void> {
  const db = await openLocalDb(openBetterSqlite3(path), identity);
  try {
    const perBatch = Math.max(
      1,
      Math.min(100, Math.floor(8_000_000 / rowBytes)),
    );
    if (blobId) {
      await db.batch([
        {
          sql: "INSERT INTO blobs (blob_id, mime_type, size_bytes, bytes) VALUES (?, 'text/plain', 1, ?)",
          params: [blobId, new Uint8Array([1])],
        },
      ]);
    }
    for (let at = 0; at < rows; at += perBatch) {
      const statements = [];
      for (let i = at; i < Math.min(rows, at + perBatch); i++) {
        const body = JSON.stringify({
          id: i,
          ...(blobId ? { attachment: blobId } : {}),
          text: `${i}:`.padEnd(rowBytes, "x"),
        });
        const pk = i.toString(16).padStart(64, "0");
        statements.push({
          sql: `INSERT INTO records (connection_id, stream, pk_hash, record_key, stamp_o, stamp_r, body, body_sha256, first_o)
                VALUES (?, 'items', ?, ?, 1, 'r', ?, ?, NULL)`,
          params: [
            PUBLISH_MEMORY_CONNECTION,
            pk,
            String(i),
            body,
            createHash("sha256").update(body).digest("hex"),
          ],
        });
        if (blobId) {
          statements.push({
            sql: "INSERT INTO blob_refs (blob_id, connection_id, stream, pk_hash) VALUES (?, ?, 'items', ?)",
            params: [blobId, PUBLISH_MEMORY_CONNECTION, pk],
          });
        }
      }
      await db.batch(statements);
    }
  } finally {
    await db.close();
  }
}

/** Child side, measured: find the attachments a stream names (one, many referrers). */
export async function listBlobsWorkload(input: {
  path: string;
}): Promise<{ blobs: number }> {
  const db = await openLocalDb(openBetterSqlite3(input.path), identity);
  try {
    const found = await listStreamBlobs({ db } as LocalSyncDeps, {
      connectionId: PUBLISH_MEMORY_CONNECTION,
      stream: "items",
      scope: "memory-scope",
      generation: 1,
    });
    return { blobs: found.length };
  } finally {
    await db.close();
  }
}

/** Child side, measured: encode and upload one prefix that holds every row. */
export async function encodeOnePrefixWorkload(input: {
  path: string;
}): Promise<{ puts: number; uploadedBytes: number }> {
  const sink = { puts: 0, bytes: 0 };
  const deps = await makeDeps(input.path, sink);
  try {
    keccak_256(new Uint8Array(1));
    await encodePrefixes(deps, {
      connectionId: PUBLISH_MEMORY_CONNECTION,
      stream: "items",
      scope: "memory-scope",
      generation: 1,
      changedPrefixes: [""],
      upToSeq: 0,
    });
    return { puts: sink.puts, uploadedBytes: sink.bytes };
  } finally {
    await deps.db.close();
  }
}
