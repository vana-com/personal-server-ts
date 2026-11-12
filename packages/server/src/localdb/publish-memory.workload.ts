// Workload for the publish memory test: a first publish of a many-row stream,
// measured in a fresh child by the memory oracle. The database is built by the
// parent (not measured); the child opens it and publishes once.
import { keccak_256 } from "@noble/hashes/sha3";
import { openLocalDb } from "../../../core/src/localdb/open.js";
import { connectionQueue } from "../../../core/src/localdb/queue.js";
import { createLocalSync } from "../../../core/src/localdb/sync.js";
import { publishConnection } from "../../../core/src/localdb/publish.js";
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

async function makeDeps(path: string, sink: { puts: number; bytes: number }) {
  const db = await openLocalDb(openBetterSqlite3(path), identity);
  let op = 0;
  const deps: LocalSyncDeps = {
    db,
    queue: connectionQueue(),
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
}

/** Child side, measured: one publish of the whole stream. */
export async function publishMemoryWorkload(input: {
  path: string;
}): Promise<PublishMemoryResult> {
  const sink = { puts: 0, bytes: 0 };
  const deps = await makeDeps(input.path, sink);
  try {
    // keccak is loaded by the publisher; touch it so import cost is not measured.
    keccak_256(new Uint8Array(1));
    const results = await publishConnection(deps, PUBLISH_MEMORY_CONNECTION);
    return {
      outcome: results.map((r) => r.outcome).join(","),
      puts: sink.puts,
      uploadedBytes: sink.bytes,
    };
  } finally {
    await deps.db.close();
  }
}
