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
import {
  createTestReplicaRoster,
  createTestReplicaSigner,
} from "@opendatalabs/personal-server-ts-core/replication/writer-identity.test-utils";
import { establishReplicaWriterIdentity } from "./pdpp-replica-writer-identity.js";

const [mode, directory, sizeArg] = process.argv.slice(2);
// Peak RSS only rises, so each marker bounds everything that ran before it.
const maxRssKiB = () => process.resourceUsage().maxRSS;
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
// Fixed server keys and registration ids, so seed and measure runs agree.
const roster = createTestReplicaRoster();
const authorityOf = (role: string) => {
  const signer = createTestReplicaSigner(role);
  const id = `0x${createHash("sha256").update(role).digest("hex")}`;
  roster.register(signer.address, owner, id);
  return {
    signer,
    id,
    roster: roster.port,
    chainId: 14800,
    environment: "dev" as const,
  };
};
const open = (role: string) => {
  const db = new Database(join(directory, `${role}.sqlite`));
  db.pragma("cache_size=-2048");
  const store = createReplicaRecordStore(db);
  const authority = authorityOf(role);
  establishReplicaWriterIdentity(db, {
    owner,
    server: authority.signer.address,
    record: { owner, id: authority.id, revokedAt: null },
  });
  store.registerConnection({
    instance: "conn",
    sourceId,
    method: "export",
    label: "memory",
  });
  store.replication.beginBaseline(expected);
  return { db, store, authority };
};
if (mode === "seed") {
  const { store } = open("source");
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
  writeFileSync(join(directory, "blob-id"), blob.blobId);
  store.close();
} else if (mode === "measure" || mode === "probe") {
  const startKiB = maxRssKiB();
  // Backfill guard: opening the source runs the canonical port's chunk-only
  // backfill when a manifest has no whole row. The seed writes main's whole
  // row, so check that read-only before any writable open can touch it.
  const preflight = new Database(join(directory, "source.sqlite"), {
    readonly: true,
    fileMustExist: true,
  });
  const seeded = readFileSync(join(directory, "blob-id"), "utf8");
  if (
    !preflight
      .prepare("SELECT 1 FROM pdpp_blob_bytes WHERE blob_id=?")
      .get(seeded)
  )
    throw new Error("seed lacks main's whole row; open would backfill");
  preflight.close();
  const source = open("source"),
    destination = open("destination");
  // Every registered version of each scope, in order: versions append.
  const slots = new Map<string, ReplicaCommitment[]>();
  let published = 0;
  const file = (key: string) =>
    join(directory, createHash("sha256").update(key).digest("hex"));
  const transport: ReplicaTransportPort = {
    // Crypto scratch is bounded by fragment size. The worker still validates every fragment and commitment.
    encryptedByteLength: (bytes) => bytes,
    encrypt: async (_scope, bytes) => new Uint8Array(bytes),
    decrypt: async (_scope, bytes) => new Uint8Array(bytes),
    async evidence(scope, version) {
      const rows = slots.get(scope) ?? [];
      const row = rows[version - 1];
      return {
        head: rows.at(-1) ?? null,
        pending: false,
        chain: {
          owner,
          scope,
          version: String(version),
          currentVersion: String(rows.length),
          status: rows.length ? "Active" : "None",
          commitment: row
            ? replicaChainCommitment(
                row.dataHash as `0x${string}`,
                row.metadataHash as `0x${string}`,
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
    async putFragment(fragment) {
      writeFileSync(
        file(`${fragment.scope}#${fragment.digest}`),
        fragment.encrypted,
      );
    },
    async getFragment(scope, digest) {
      return readFileSync(file(`${scope}#${digest}`));
    },
    async hasFragment(scope, digest) {
      return existsSync(file(`${scope}#${digest}`));
    },
    async put(manifest) {
      writeFileSync(
        file(`${manifest.scope}/${manifest.version}`),
        manifest.encrypted,
      );
    },
    async register(manifest) {
      const rows = slots.get(manifest.scope) ?? [];
      if (manifest.version !== rows.length + 1)
        throw new Error("409 stale expectedVersion");
      rows.push({
        owner,
        scope: manifest.scope,
        version: String(manifest.version),
        dataHash: manifest.dataHash,
        metadataHash: manifest.metadataHash,
        deleted: false,
      });
      slots.set(manifest.scope, rows);
      published++;
    },
    async get(scope, version) {
      return readFileSync(file(`${scope}/${version}`));
    },
    async list() {
      return {
        points: [...slots].map(([scope, rows]) => ({
          scope,
          version: String(rows.length),
        })),
        cursor: null,
      };
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
  // Phase markers live in the fixture, not the worker. Materialization runs
  // INSERT OR IGNORE INTO pdpp_blobs before the canonical promotion and
  // INSERT INTO pdpp_blob_claims after it, so the two prepares bracket it.
  let beforePromotionKiB: number | undefined;
  let afterPromotionKiB: number | undefined;
  const prepareStatement = destination.db.prepare.bind(destination.db);
  destination.db.prepare = ((sql: string) => {
    if (sql.startsWith("INSERT OR IGNORE INTO pdpp_blobs"))
      beforePromotionKiB ??= maxRssKiB();
    if (sql.startsWith("INSERT INTO pdpp_blob_claims"))
      afterPromotionKiB ??= maxRssKiB();
    return prepareStatement(sql);
  }) as typeof destination.db.prepare;
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
  // cycle() steps with the finite default byte budget (64 MiB), so a
  // 128 MiB blob takes more steps than the old unbounded cycle did.
  for (let cycle = 0; cycle < 48; cycle++) {
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
      startKiB,
      workerPeakKiB: beforePromotionKiB,
      afterPromotionKiB,
      peakRssKiB: maxRssKiB(),
    }),
  );
  source.store.close();
  destination.store.close();
} else throw new Error("unknown probe mode");
