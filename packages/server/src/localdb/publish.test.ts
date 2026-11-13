// Publish integration uses real P06 apply, SQL merge/delete, and part encoding.
import { createHash, createHmac } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { keccak_256 } from "@noble/hashes/sha3";
import {
  HEAD_FORMAT,
  controlHashes,
  controlScope,
  decodeHead,
  deriveKeyCheck,
  digestHead,
  encodeHead,
  headBlobName,
  streamScope,
  type Head,
  canonicalJson,
  pkHash,
  pkHashBits,
  linesOfParts,
  type JsonObject,
} from "@opendatalabs/personal-server-ts-stream-sync";
import {
  connectionQueue,
  openLocalDb,
  publishConnection,
  type LocalSyncDeps,
  type SqlDriver,
} from "@opendatalabs/personal-server-ts-core/localdb";
import {
  MemoryStreamSyncRegistry,
  type StreamSyncRegistry,
  createMemoryStreamSyncBlobs,
  createMemoryStreamSyncRegistry,
  type StreamSyncBlobs,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { encodePrefixes } from "../../../core/src/localdb/encode.js";

import { deleteMetadataHash } from "../../../core/src/stream-sync/delete-metadata.js";
import { applyConnection } from "../../../core/src/localdb/apply.js";
import { remoteFixture } from "./apply-fixture.js";

// Lets one test make the publisher build a head the reader would refuse.
const heads = vi.hoisted(() => ({ corrupt: false }));
vi.mock(
  "@opendatalabs/personal-server-ts-stream-sync",
  async (importOriginal) => {
    const real = (await importOriginal()) as {
      encodeHead: (head: Head) => Uint8Array;
    };
    return {
      ...real,
      encodeHead: (head: Head) => {
        const bytes = real.encodeHead(head);
        return heads.corrupt
          ? new TextEncoder().encode(
              JSON.stringify(
                JSON.parse(new TextDecoder().decode(bytes)),
                null,
                1,
              ),
            )
          : bytes;
      },
    };
  },
);

const CONNECTOR = "test-conn";
const NS = "0123456789abcdef";
const OWNER = "0x0000000000000000000000000000000000000001";
const NOW = 1780000000000;
const CONNECTION_ID = "c1";
const STREAM = "s1";
const SCOPE = streamScope(CONNECTOR, NS, STREAM);
const CONTROL = controlScope(CONNECTOR, NS);

const keccak = async (data: Uint8Array) => keccak_256(data);

function sha256Hex(data: string): string {
  return createHash("sha256").update(data).digest("hex");
}

type World = {
  dir: string;
  driver: SqlDriver;
  deps: LocalSyncDeps;
  registry: StreamSyncRegistry;
  blobs: ReturnType<typeof createMemoryStreamSyncBlobs>;
};

const worlds: World[] = [];

afterEach(async () => {
  for (const world of worlds) {
    await world.driver.close();
    rmSync(world.dir, { recursive: true, force: true });
  }
  worlds.length = 0;
  heads.corrupt = false;
  vi.resetAllMocks();
});

async function makeWorld(registry?: StreamSyncRegistry): Promise<World> {
  const dir = mkdtempSync(join(process.cwd(), ".localdb-publish-"));
  const driver = openBetterSqlite3(join(dir, "db.sqlite"));
  await openLocalDb(driver, {
    owner: OWNER,
    network: "test",
    deviceId: "test-device",
  });
  const blobs = createMemoryStreamSyncBlobs();
  let op = 0;
  const deps: LocalSyncDeps = {
    db: driver,
    queue: connectionQueue(),
    ownerAddress: OWNER,
    registry: registry ?? createMemoryStreamSyncRegistry(),
    blobs,
    keys: {
      namespaceHmac: async (message) =>
        createHmac("sha256", Buffer.from("test-namespace-key"))
          .update(message)
          .digest(),
      encrypt: async (_scope, clear) => clear,
      encryptPart: async (_scope, clear) => clear,
      decrypt: async (_scope, cipher) => cipher,
    },
    signer: {
      signAddData: async () => ("0x" + "0".repeat(128)) as `0x${string}`,
    },
    logger: { info: () => {}, warn: () => {} },
    now: () => NOW,
    newOp: () => `op-${++op}`,
    partTargetBytes: 4096,
  };
  const world: World = {
    dir,
    driver,
    deps,
    registry: deps.registry,
    blobs,
  };
  worlds.push(world);
  return world;
}

async function seedConnection(deps: LocalSyncDeps, generation = 1) {
  if (deps.registry instanceof MemoryStreamSyncRegistry) {
    const hashes = await controlHashes(
      keccak,
      await deriveKeyCheck(deps.keys.namespaceHmac),
    );
    for (let version = 1; version <= generation; version++)
      await deps.registry.post({
        ownerAddress: OWNER,
        scope: CONTROL,
        dataHash: hashes.activeData,
        metadataHash: hashes.activeMetadata,
        expectedVersion: String(version),
        signature: "0x00",
      });
  }
  await deps.db.batch([
    {
      sql: `INSERT INTO connections (connection_id, connector, ns, generation, control_state, control_version)
            VALUES (?, ?, ?, ?, 'active', 1)`,
      params: [CONNECTION_ID, CONNECTOR, NS, generation],
    },
  ]);
}

async function seedStream(deps: LocalSyncDeps) {
  await deps.db.batch([
    {
      sql: `INSERT INTO stream_state (connection_id, stream, primary_key, semantics, incremental,
              profile_key, profile_version, complete, needs_full, floor_version, floor_o, floor_r,
              last_delete_version, head_version, head_generation, head_data_hash, head_blob, publish_watermark)
            VALUES (?, ?, '["id"]', 'mutable_state', 0, NULL, NULL, 0, 0, NULL, NULL, NULL, 0, 0, NULL, NULL, NULL, 0)`,
      params: [CONNECTION_ID, STREAM],
    },
  ]);
}

async function seedRun(
  deps: LocalSyncDeps,
  runId: string,
  o: number,
  options?: {
    generation?: number;
    decision?: string;
    fullRead?: number;
    seed?: string;
  },
) {
  await deps.db.batch([
    {
      sql: `INSERT INTO runs (run_id, connection_id, o, generation, artifact_version, collection_mode, state, last_batch)
            VALUES (?, ?, ?, ?, ?, 'full_refresh', 'ended', 0)`,
      params: [runId, CONNECTION_ID, o, options?.generation ?? 1, "1.0.0"],
    },
    {
      sql: `INSERT INTO run_streams (run_id, stream, delete_snapshot, basis_version, basis_generation,
              basis_data_hash, primary_key, profile_key, profile_version, full_read, foreign_checkpoint,
              seed, replace, decision, reason)
            VALUES (?, ?, 0, NULL, NULL, NULL, '["id"]', NULL, '1.0.0', ?, 0, ?, 0, ?, NULL)`,
      params: [
        runId,
        STREAM,
        options?.fullRead ?? 1,
        options?.seed ?? "none",
        options?.decision ?? "publish",
      ],
    },
  ]);
}

async function seedRecord(
  deps: LocalSyncDeps,
  recordKey: string,
  body: string,
  options?: {
    origin?: string;
    stampO?: number;
    stampR?: string;
  },
) {
  await deps.db.batch([
    {
      sql: `UPDATE write_ctx SET origin = ? WHERE id = 1`,
      params: [options?.origin ?? "local"],
    },
    {
      sql: `INSERT INTO records (connection_id, stream, pk_hash, record_key, stamp_o, stamp_r, body, body_sha256, first_o)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
      params: [
        CONNECTION_ID,
        STREAM,
        await pkHash(
          async (b) => new Uint8Array(createHash("sha256").update(b).digest()),
          JSON.parse(body),
          ["id"],
        ),
        recordKey,
        options?.stampO ?? 1000,
        options?.stampR ?? "r1",
        body,
        sha256Hex(body),
      ],
    },
  ]);
}

async function seedRunRow(
  deps: LocalSyncDeps,
  runId: string,
  recordKey: string,
  body: string,
) {
  await deps.db.batch([
    {
      sql: `INSERT INTO run_rows (run_id, stream, pk_hash, record_key, body, body_sha256)
            VALUES (?, ?, ?, ?, ?, ?)`,
      params: [
        runId,
        STREAM,
        await pkHash(
          async (b) => new Uint8Array(createHash("sha256").update(b).digest()),
          JSON.parse(body),
          ["id"],
        ),
        recordKey,
        body,
        sha256Hex(body),
      ],
    },
  ]);
}

async function seedLedger(deps: LocalSyncDeps) {
  await deps.db.batch([
    {
      sql: `INSERT INTO import_ledger (source, connection_id, stream, state, rows, fingerprint, reason, at)
            VALUES ('test-import', ?, ?, 'imported', 1, 'fp', NULL, ?)`,
      params: [CONNECTION_ID, STREAM, NOW],
    },
  ]);
}

async function maxSeq(deps: LocalSyncDeps): Promise<number> {
  const [row] = await deps.db.query<{ w: number | null }>(
    `SELECT MAX(seq) AS w FROM record_changes WHERE connection_id = ? AND stream = ?`,
    [CONNECTION_ID, STREAM],
  );
  return row?.w ?? 0;
}

describe("publishConnection", () => {
  it("keeps a row merged while the upload is in flight queued", async () => {
    const world = await makeWorld();
    await seedConnection(world.deps, 1);
    await seedStream(world.deps);
    await seedRun(world.deps, "r1", 1000);
    await seedRecord(world.deps, "rec-1", JSON.stringify({ id: 1 }));
    await seedRunRow(world.deps, "r1", "rec-1", JSON.stringify({ id: 1 }));
    const W = await maxSeq(world.deps);

    // Merge a row during the first part upload, while the head is still
    // being built from the step-1 snapshot.
    const realPut = world.deps.blobs.put.bind(world.deps.blobs);
    let merged = false;
    world.deps.blobs.put = async (key, bytes) => {
      if (!merged) {
        merged = true;
        await seedRecord(world.deps, "rec-2", JSON.stringify({ id: 2 }));
      }
      return realPut(key, bytes);
    };

    const results = await publishConnection(world.deps, CONNECTION_ID);
    expect(results).toHaveLength(1);
    expect(results[0]).toMatchObject({
      stream: STREAM,
      outcome: "published",
      watermark: W,
      publication: { stream: STREAM, watermark: W, runIds: ["r1"] },
    });

    const [state] = await world.deps.db.query<{
      publish_watermark: number;
      head_data_hash: string;
      head_blob: string;
    }>(
      `SELECT publish_watermark, head_data_hash, head_blob FROM stream_state
        WHERE connection_id = ? AND stream = ?`,
      [CONNECTION_ID, STREAM],
    );
    // The watermark is the max(seq) read in step 1, not the newest at commit.
    expect(state.publish_watermark).toBe(W);
    // The published head holds only the row from the snapshot.
    const cipher = await world.deps.blobs.get(`${SCOPE}/${state.head_blob}`);
    expect(cipher).not.toBeNull();
    const decoded = decodeHead(cipher!);
    expect(decoded.kind).toBe("ok");
    if (decoded.kind === "ok") {
      expect(decoded.head.format).toBe(HEAD_FORMAT);
      expect(decoded.head.recordCount).toBe(1);
      expect(decoded.head.parts).toHaveLength(1);
    }
    // The late row is still in records and its change is still queued.
    const [late] = await world.deps.db.query<{ n: number }>(
      `SELECT COUNT(*) AS n FROM records WHERE connection_id = ? AND stream = ? AND record_key = 'rec-2'`,
      [CONNECTION_ID, STREAM],
    );
    expect(late.n).toBe(1);
    const [pending] = await world.deps.db.query<{ n: number }>(
      `SELECT COUNT(*) AS n FROM record_changes WHERE connection_id = ? AND stream = ? AND seq > ?`,
      [CONNECTION_ID, STREAM, W],
    );
    expect(pending.n).toBeGreaterThan(0);
  });

  it("logs one line per stream publish with where the time went", async () => {
    const world = await makeWorld();
    await seedConnection(world.deps, 1);
    await seedStream(world.deps);
    await seedRun(world.deps, "r1", 1000);
    await seedRecord(world.deps, "rec-1", JSON.stringify({ id: 1 }));
    await seedRunRow(world.deps, "r1", "rec-1", JSON.stringify({ id: 1 }));

    // A clock the ports advance, so each phase has a known duration.
    let clock = 0;
    const lines: Array<Record<string, unknown>> = [];
    const { deps } = world;
    const blobs = deps.blobs;
    const registry = deps.registry;
    const sizes: number[] = [];
    Object.assign(deps, {
      now: () => clock,
      logger: {
        info: (line: Record<string, unknown>) => lines.push(line),
        warn: () => {},
      },
      blobs: {
        get: async (key: string) => {
          clock += 2;
          return blobs.get(key);
        },
        exists: async (key: string) => {
          clock += 2;
          return blobs.exists(key);
        },
        put: async (key: string, bytes: Uint8Array) => {
          clock += 5;
          sizes.push(bytes.length);
          return blobs.put(key, bytes);
        },
      },
      keys: {
        ...deps.keys,
        encryptPart: async (_scope: string, clear: Uint8Array) => {
          clock += 4;
          return clear;
        },
        encrypt: async (_scope: string, clear: Uint8Array) => {
          clock += 6;
          return clear;
        },
      },
      registry: {
        read: async (scope: string) => {
          clock += 1;
          return registry.read(scope);
        },
        listControlRows: registry.listControlRows.bind(registry),
        listStreamRows: registry.listStreamRows.bind(registry),
        post: async (post: Parameters<typeof registry.post>[0]) => {
          clock += 11;
          return registry.post(post);
        },
      },
      signer: {
        signAddData: async () => {
          clock += 3;
          return ("0x" + "0".repeat(128)) as `0x${string}`;
        },
      },
    });

    const results = await publishConnection(deps, CONNECTION_ID);
    expect(results[0]).toMatchObject({ outcome: "published" });

    expect(lines).toHaveLength(1);
    expect(lines[0]).toEqual({
      connectionId: CONNECTION_ID,
      stream: STREAM,
      outcome: "published",
      // The snapshot reads the control row and the stream row.
      planMs: 2,
      // Part encrypt 4 and head encrypt 6; the wire time is the upload.
      encodeEncryptMs: 10,
      partsUploaded: 1,
      bytesUploaded: sizes.reduce((sum, size) => sum + size, 0),
      // A first publish has no registry row, so nothing is probed: both files are written (5 ms each).
      blobGets: 0,
      blobPuts: 2,
      uploadMs: 10,
      // Signing 3 and posting 11.
      headRegisterMs: 14,
      totalMs: clock,
    });
    expect(sizes).toHaveLength(2);
  });

  it("logs nothing for a stream that has nothing to publish", async () => {
    const world = await makeWorld();
    await seedConnection(world.deps, 1);
    await seedStream(world.deps);
    const lines: unknown[] = [];
    Object.assign(world.deps, {
      logger: { info: (line: unknown) => lines.push(line), warn: () => {} },
    });
    await publishConnection(world.deps, CONNECTION_ID);
    expect(lines).toEqual([]);
  });

  it("applies the winner and re-plans, at most 5 tries, then backs off", async () => {
    const world = await makeWorld();
    await seedConnection(world.deps, 1);
    await seedStream(world.deps);
    await seedRun(world.deps, "r1", 1000);
    await seedRecord(world.deps, "rec-1", JSON.stringify({ id: 1 }));
    await seedRunRow(world.deps, "r1", "rec-1", JSON.stringify({ id: 1 }));
    const registry = world.registry as MemoryStreamSyncRegistry;
    const keyCheck = await deriveKeyCheck(world.deps.keys.namespaceHmac);

    // Every post is beaten by a winner committed just before it.
    let injecting = false;
    registry.beforePost = async () => {
      if (injecting) return;
      injecting = true;
      try {
        const version =
          registry.log.filter((entry) => entry.scope === SCOPE).length + 1;
        const winner: Head = {
          complete: false,
          connector: CONNECTOR,
          format: HEAD_FORMAT,
          generation: 1,
          keyCheck,
          lastDeleteVersion: 0,
          ns: NS,
          observedAt: NOW,
          parts: [],
          primaryKey: ["id"],
          profile: { key: CONNECTOR, version: "1.0.0" },
          recordCount: 0,
          stream: STREAM,
        };
        const winnerBytes = encodeHead(winner);
        const { dataHash, blobName } = await digestHead(keccak, winnerBytes);
        await world.deps.blobs.put(`${SCOPE}/${blobName}`, winnerBytes);
        await registry.post({
          ownerAddress: OWNER,
          scope: SCOPE,
          dataHash,
          metadataHash: `0x${"22".repeat(32)}`,
          expectedVersion: String(version),
          signature: "0x" + "0".repeat(128),
        });
      } finally {
        injecting = false;
      }
    };

    const results = await publishConnection(world.deps, CONNECTION_ID);
    expect(results).toHaveLength(1);
    expect(results[0]?.outcome).toBe("backoff");
    // Five CAS tries, one apply per conflict except the last.
    expect(
      await world.deps.db.query("SELECT head_version FROM stream_state"),
    ).toEqual([{ head_version: 4 }]);
    expect(
      await world.deps.db.query("SELECT count(*) AS n FROM stream_versions"),
    ).toEqual([{ n: 4 }]);
    expect(registry.log.filter((entry) => entry.scope === SCOPE)).toHaveLength(
      5,
    );
  });

  it("publishes seed rows only into generation 1", async () => {
    const world = await makeWorld();
    await seedConnection(world.deps, 1);
    await seedStream(world.deps);
    await seedRun(world.deps, "r1", 1000, { seed: "merged" });
    await seedRecord(world.deps, "seed-1", JSON.stringify({ id: 0 }), {
      origin: "import",
      stampO: 0,
      stampR: "seed",
    });
    await seedRunRow(world.deps, "r1", "seed-1", JSON.stringify({ id: 0 }));
    await seedLedger(world.deps);

    const results = await publishConnection(world.deps, CONNECTION_ID);
    expect(results[0]?.outcome).toBe("published");
    const [seed] = await world.deps.db.query<{ n: number }>(
      `SELECT COUNT(*) AS n FROM records WHERE connection_id = ? AND stream = ? AND stamp_r = 'seed'`,
      [CONNECTION_ID, STREAM],
    );
    expect(seed.n).toBe(1);
    const [ledger] = await world.deps.db.query<{ state: string }>(
      `SELECT state FROM import_ledger WHERE connection_id = ? AND stream = ?`,
      [CONNECTION_ID, STREAM],
    );
    expect(ledger.state).toBe("imported");
  });

  it("purges seed rows and records excluded(seed_skipped) above generation 1", async () => {
    const world = await makeWorld();
    await seedConnection(world.deps, 2);
    await seedStream(world.deps);
    await seedRun(world.deps, "r1", 1000, { generation: 2, seed: "merged" });
    await seedRecord(world.deps, "seed-1", JSON.stringify({ id: 0 }), {
      origin: "import",
      stampO: 0,
      stampR: "seed",
    });
    await seedRunRow(world.deps, "r1", "seed-1", JSON.stringify({ id: 0 }));
    await seedLedger(world.deps);

    const results = await publishConnection(world.deps, CONNECTION_ID);
    expect(results[0]?.outcome).toBe("published");
    const [seed] = await world.deps.db.query<{ n: number }>(
      `SELECT COUNT(*) AS n FROM records WHERE connection_id = ? AND stream = ? AND stamp_r = 'seed'`,
      [CONNECTION_ID, STREAM],
    );
    expect(seed.n).toBe(0);
    const [ledger] = await world.deps.db.query<{
      state: string;
      reason: string | null;
    }>(
      `SELECT state, reason FROM import_ledger WHERE connection_id = ? AND stream = ?`,
      [CONNECTION_ID, STREAM],
    );
    expect(ledger.state).toBe("excluded");
    expect(ledger.reason).toBe("seed_skipped");
  });

  it("purges the connection and stops when the control row is deleted", async () => {
    const keyCheck = await deriveKeyCheck(async (message) =>
      createHmac("sha256", Buffer.from("test-namespace-key"))
        .update(message)
        .digest(),
    );
    const hashes = await controlHashes(keccak, keyCheck);
    const registry = {
      read: async (scope: string) => {
        if (scope === CONTROL) {
          return {
            found: true,
            version: 2,
            dataHash: hashes.tombstoneData,
            metadataHash: hashes.tombstoneMetadata,
            deleted: true,
          };
        }
        return { found: false };
      },
      post: async () => ({ kind: "committed" as const }),
      listControlRows: async () => [],
      listStreamRows: async () => [],
    } as unknown as StreamSyncRegistry;

    const world = await makeWorld(registry);
    await seedConnection(world.deps, 1);
    await seedStream(world.deps);
    await seedRun(world.deps, "r1", 1000);
    await seedRecord(world.deps, "rec-1", JSON.stringify({ id: 1 }));
    await seedRunRow(world.deps, "r1", "rec-1", JSON.stringify({ id: 1 }));

    const results = await publishConnection(world.deps, CONNECTION_ID);
    expect(results).toEqual([
      { stream: STREAM, outcome: "purged", watermark: 1 },
    ]);
    const [conn] = await world.deps.db.query<{ control_state: string }>(
      `SELECT control_state FROM connections WHERE connection_id = ?`,
      [CONNECTION_ID],
    );
    expect(conn.control_state).toBe("deleted");
    const [records] = await world.deps.db.query<{ n: number }>(
      `SELECT COUNT(*) AS n FROM records WHERE connection_id = ?`,
      [CONNECTION_ID],
    );
    expect(records.n).toBe(0);
    const [state] = await world.deps.db.query<{
      last_delete_version: number;
    }>(
      `SELECT last_delete_version FROM stream_state WHERE connection_id = ? AND stream = ?`,
      [CONNECTION_ID, STREAM],
    );
    expect(state.last_delete_version).toBe(2);
  });
});

async function registryHead(
  world: World,
  values: readonly JsonObject[],
  options: {
    format?: Head["format"];
    generation?: number;
    profile?: Head["profile"];
    partition?: boolean;
  } = {},
) {
  const remote = await remoteFixture(world.deps.keys, CONNECTOR, NS);
  const generated = await remote.head(STREAM, values, {
    format: options.format,
    generation: options.generation,
    f: 23,
  });
  const decoded = decodeHead(
    remote.blobs.get(`${SCOPE}/${generated.blobName}`)!,
  );
  if (decoded.kind !== "ok") throw new Error("invalid fixture head");
  const bytes = encodeHead({
    ...decoded.head,
    parts: options.partition
      ? decoded.head.parts.map((part) => {
          const frame = remote.blobs.get(
            `${SCOPE}/g${decoded.head.generation}-p-${part.hash}`,
          )!;
          const envelope = JSON.parse(
            new TextDecoder().decode(frame.subarray(0, frame.indexOf(10))),
          );
          return { ...part, prefix: pkHashBits(envelope.k, 1) };
        })
      : decoded.head.parts,
    profile: options.profile ?? { key: CONNECTOR, version: "1.0.0" },
  });
  const digest = await digestHead(keccak, bytes);
  for (const [key, value] of remote.blobs)
    await world.deps.blobs.put(key, value);
  await world.deps.blobs.put(`${SCOPE}/${digest.blobName}`, bytes);
  const previous = await world.registry.read(SCOPE);
  const version = previous.found ? previous.version + 1 : 1;
  await world.registry.post({
    ownerAddress: OWNER,
    scope: SCOPE,
    dataHash: digest.dataHash,
    metadataHash: `0x${"22".repeat(32)}`,
    expectedVersion: String(version),
    signature: "0x00",
  });
  return { ...digest, version };
}

async function published(world: World) {
  const read = await world.registry.read(SCOPE);
  if (!read.found) throw new Error("fixture has no registry head");
  const bytes = await world.deps.blobs.get(
    `${SCOPE}/h-${read.dataHash.slice(2)}`,
  );
  if (!bytes) throw new Error("fixture has no head blob");
  const decoded = decodeHead(bytes);
  if (decoded.kind !== "ok") throw new Error("invalid published head");
  const values = [];
  for await (const row of linesOfParts(
    async (b) => new Uint8Array(createHash("sha256").update(b).digest()),
    decoded.head,
    async (part) => {
      const cipher = await world.deps.blobs.get(
        `${SCOPE}/g${decoded.head.generation}-p-${part.hash}`,
      );
      if (!cipher) throw new Error("missing published part");
      return cipher;
    },
  ))
    values.push(row.v);
  return { head: decoded.head, values };
}

async function localRun(
  world: World,
  id = "r1",
  options?: {
    replace?: boolean;
    basisVersion?: number | null;
    basisHash?: string | null;
  },
) {
  await seedRun(world.deps, id, 1000);
  if (options?.replace)
    await world.deps.db.batch([
      {
        sql: "UPDATE run_streams SET replace=1,basis_version=?,basis_data_hash=? WHERE run_id=?",
        params: [options.basisVersion ?? null, options.basisHash ?? null, id],
      },
    ]);
}

describe("publish with real apply", () => {
  it("publishes format 4 with f and installs it on another database", async () => {
    const world = await makeWorld();
    await seedConnection(world.deps);
    await seedStream(world.deps);
    await localRun(world);
    await seedRecord(world.deps, "a", canonicalJson({ id: "a" }));
    await world.deps.db.batch([{ sql: "UPDATE records SET first_o=12" }]);
    expect(
      (await publishConnection(world.deps, CONNECTION_ID))[0]?.outcome,
    ).toBe("published");
    expect((await published(world)).head.format).toBe(4);
    const reader = await makeWorld(world.registry);
    await seedConnection(reader.deps);
    await applyConnection(
      { ...reader.deps, blobs: world.deps.blobs },
      CONNECTION_ID,
    );
    expect(
      await reader.deps.db.query("SELECT record_key,first_o FROM records"),
    ).toEqual([{ record_key: "a", first_o: 12 }]);
    expect(
      await reader.deps.db.query("SELECT complete FROM stream_state"),
    ).toEqual([{ complete: 1 }]);
  });

  it("upgrades every retained old-format part before publishing format 4", async () => {
    const world = await makeWorld();
    await seedConnection(world.deps);
    await seedStream(world.deps);
    const oldValues = [{ id: "old" }];
    const hash = async (v: JsonObject) =>
      pkHash(
        async (b) => new Uint8Array(createHash("sha256").update(b).digest()),
        v,
        ["id"],
      );
    const first = pkHashBits(await hash(oldValues[0]!), 1);
    for (let i = 0; ; i++) {
      const other = { id: `kept-${i}` };
      if (pkHashBits(await hash(other), 1) !== first) {
        oldValues.push(other);
        break;
      }
    }
    await registryHead(world, oldValues, { format: 3, partition: true });
    await applyConnection(world.deps, CONNECTION_ID);
    await localRun(world);
    await seedRecord(world.deps, "new", canonicalJson({ id: "new" }));
    await publishConnection(world.deps, CONNECTION_ID);
    const image = await published(world);
    expect(image.head.format).toBe(4);
    expect(image.values.map((v) => v.id).sort()).toEqual(
      ["new", ...oldValues.map((v) => v.id)].sort(),
    );
    const reader = await makeWorld(world.registry);
    await seedConnection(reader.deps);
    await applyConnection(
      { ...reader.deps, blobs: world.deps.blobs },
      CONNECTION_ID,
    );
    expect(
      await reader.deps.db.query("SELECT count(*) AS n FROM records"),
    ).toEqual([{ n: 3 }]);
  });

  it("an empty changed prefix removes its old parts", async () => {
    const world = await makeWorld();
    await seedConnection(world.deps);
    await seedStream(world.deps);
    const basis = await registryHead(world, [{ id: "old" }]);
    await applyConnection(world.deps, CONNECTION_ID);
    await localRun(world, "r1", {
      replace: true,
      basisVersion: basis.version,
      basisHash: basis.dataHash,
    });
    await publishConnection(world.deps, CONNECTION_ID);
    expect((await published(world)).values).toEqual([]);
    expect((await published(world)).head.parts).toEqual([]);
    expect(await world.deps.db.query("SELECT * FROM records")).toEqual([]);
  });

  it.each([true, false])(
    "full replacement uses the exact recorded basis (match=%s)",
    async (matches) => {
      const world = await makeWorld();
      await seedConnection(world.deps);
      await seedStream(world.deps);
      const basis = await registryHead(world, [{ id: "old" }]);
      await applyConnection(world.deps, CONNECTION_ID);
      await localRun(world, "r1", {
        replace: true,
        basisVersion: basis.version,
        basisHash: matches ? basis.dataHash : `0x${"ab".repeat(32)}`,
      });
      await seedRecord(world.deps, "new", canonicalJson({ id: "new" }));
      await publishConnection(world.deps, CONNECTION_ID);
      expect((await published(world)).values.map((v) => v.id).sort()).toEqual(
        matches ? ["new"] : ["new", "old"],
      );
      expect(
        await world.deps.db.query("SELECT count(*) AS n FROM records"),
      ).toEqual([{ n: matches ? 1 : 2 }]);
    },
  );

  it("a refused local run is unwritten and its overwritten row restored by real apply", async () => {
    const world = await makeWorld();
    await seedConnection(world.deps);
    await seedStream(world.deps);
    await registryHead(world, [{ id: "a", value: "winner" }], {
      profile: { key: CONNECTOR, version: "2.0.0" },
    });
    await localRun(world);
    await seedRecord(
      world.deps,
      "a",
      canonicalJson({ id: "a", value: "local" }),
    );
    await seedRecord(
      world.deps,
      "local-only",
      canonicalJson({ id: "local-only" }),
    );
    const result = await publishConnection(world.deps, CONNECTION_ID);
    expect(result[0]?.outcome).toBe("refused");
    expect(
      await world.deps.db.query("SELECT record_key,stamp_r FROM records"),
    ).toEqual([{ record_key: "a", stamp_r: "remote-run" }]);
    expect(
      await world.deps.db.query("SELECT decision,reason FROM run_streams"),
    ).toEqual([{ decision: "refused", reason: "connector_update_required" }]);
  });

  it("a delete during upload purges and never posts a stream head", async () => {
    const world = await makeWorld();
    await seedConnection(world.deps);
    await seedStream(world.deps);
    await localRun(world);
    await seedRecord(world.deps, "a", canonicalJson({ id: "a" }));
    const hashes = await controlHashes(
      keccak,
      await deriveKeyCheck(world.deps.keys.namespaceHmac),
    );
    const put = world.deps.blobs.put;
    let deleted = false;
    world.deps.blobs.put = async (key, value) => {
      if (!deleted) {
        deleted = true;
        await world.registry.post({
          ownerAddress: OWNER,
          scope: CONTROL,
          dataHash: hashes.tombstoneData,
          metadataHash: hashes.tombstoneMetadata,
          expectedVersion: "2",
          signature: "0x00",
        });
      }
      return put(key, value);
    };
    expect(
      (await publishConnection(world.deps, CONNECTION_ID))[0]?.outcome,
    ).toBe("purged");
    expect(await world.registry.read(SCOPE)).toEqual({ found: false });
    expect(await world.deps.db.query("SELECT * FROM records")).toEqual([]);
  });

  it("a stream tombstone after collection discards the run at the publish fence", async () => {
    const world = await makeWorld();
    await seedConnection(world.deps);
    await seedStream(world.deps);
    await localRun(world);
    await seedRecord(world.deps, "a", canonicalJson({ id: "a" }));
    const hashes = await controlHashes(
      keccak,
      await deriveKeyCheck(world.deps.keys.namespaceHmac),
    );
    await world.registry.post({
      ownerAddress: OWNER,
      scope: SCOPE,
      dataHash: hashes.tombstoneData,
      metadataHash: hashes.tombstoneMetadata,
      expectedVersion: "1",
      signature: "0x00",
    });
    await publishConnection(world.deps, CONNECTION_ID);
    expect(
      await world.deps.db.query("SELECT decision,reason FROM run_streams"),
    ).toEqual([
      { decision: "discarded", reason: "stream_deleted_after_start" },
    ]);
    expect(await world.deps.db.query("SELECT * FROM records")).toEqual([]);
    expect(
      (world.registry as MemoryStreamSyncRegistry).log.filter(
        (r) => r.scope === SCOPE,
      ),
    ).toHaveLength(1);
  });

  it("creates and verifies an absent control before publishing a first generation", async () => {
    const world = await makeWorld();
    // Local work can predate the first successful registry read.
    await world.deps.db.batch([
      {
        sql: "INSERT INTO connections(connection_id,connector,ns,generation) VALUES (?,?,?,1)",
        params: [CONNECTION_ID, CONNECTOR, NS],
      },
    ]);
    await seedStream(world.deps);
    await localRun(world);
    await seedRecord(world.deps, "a", canonicalJson({ id: "a" }));
    expect(
      (await publishConnection(world.deps, CONNECTION_ID))[0]?.outcome,
    ).toBe("published");
    expect(
      (world.registry as MemoryStreamSyncRegistry).log.map((r) => r.scope),
    ).toEqual([CONTROL, SCOPE]);
  });
});

it("two publishing databases converge through CAS and real apply", async () => {
  const a = await makeWorld();
  const b = await makeWorld(a.registry);
  b.deps = { ...b.deps, blobs: a.deps.blobs };
  for (const world of [a, b]) {
    await seedConnection(world.deps);
    await seedStream(world.deps);
    await localRun(world);
  }
  await seedRecord(a.deps, "a", canonicalJson({ id: "a" }));
  await seedRecord(b.deps, "b", canonicalJson({ id: "b" }));
  const results = await Promise.all([
    publishConnection(a.deps, CONNECTION_ID),
    publishConnection(b.deps, CONNECTION_ID),
  ]);
  expect(results.map((r) => r[0]?.outcome)).toEqual(["published", "published"]);
  expect((await published(a)).values.map((v) => v.id).sort()).toEqual([
    "a",
    "b",
  ]);
  for (const world of [a, b]) {
    await applyConnection(world.deps, CONNECTION_ID);
    expect(
      await world.deps.db.query(
        "SELECT record_key FROM records ORDER BY record_key",
      ),
    ).toEqual([{ record_key: "a" }, { record_key: "b" }]);
  }
});

it("an identical head skips CAS without regressing the compacted watermark", async () => {
  const world = await makeWorld();
  await seedConnection(world.deps);
  await seedStream(world.deps);
  await localRun(world);
  await seedRecord(world.deps, "a", canonicalJson({ id: "a" }));
  await seedRunRow(world.deps, "r1", "a", canonicalJson({ id: "a" }));
  const watermark = await maxSeq(world.deps);
  await publishConnection(world.deps, CONNECTION_ID);
  const before = (world.registry as MemoryStreamSyncRegistry).log.length;
  expect((await publishConnection(world.deps, CONNECTION_ID))[0]?.outcome).toBe(
    "noop",
  );
  expect((world.registry as MemoryStreamSyncRegistry).log).toHaveLength(before);
  expect(
    await world.deps.db.query("SELECT publish_watermark FROM stream_state"),
  ).toEqual([{ publish_watermark: watermark }]);
});

it("a primary-key transition publishes only the new shape and real apply accepts it", async () => {
  const world = await makeWorld();
  await seedConnection(world.deps);
  await seedStream(world.deps);
  await registryHead(world, [{ id: "old" }]);
  await applyConnection(world.deps, CONNECTION_ID);
  await localRun(world);
  const value = { id: "new", other: "stable" };
  await seedRecord(world.deps, "new", canonicalJson(value));
  const key = await pkHash(
    async (b) => new Uint8Array(createHash("sha256").update(b).digest()),
    value,
    ["other"],
  );
  await world.deps.db.batch([
    {
      sql: "UPDATE run_streams SET primary_key='[\"other\"]',profile_version='2.0.0'",
    },
    {
      sql: "UPDATE records SET pk_hash=? WHERE record_key='new'",
      params: [key],
    },
  ]);
  expect((await publishConnection(world.deps, CONNECTION_ID))[0]?.outcome).toBe(
    "published",
  );
  const image = await published(world);
  expect(image.head.primaryKey).toEqual(["other"]);
  expect(image.values).toEqual([value]);
  const reader = await makeWorld(world.registry);
  await seedConnection(reader.deps);
  await applyConnection(
    { ...reader.deps, blobs: world.deps.blobs },
    CONNECTION_ID,
  );
  expect(await reader.deps.db.query("SELECT record_key FROM records")).toEqual([
    { record_key: "stable" },
  ]);
});

it("a deleted control purges a connection even without declared streams", async () => {
  const world = await makeWorld();
  await seedConnection(world.deps);
  await seedRecord(world.deps, "a", canonicalJson({ id: "a" }));
  const hashes = await controlHashes(
    keccak,
    await deriveKeyCheck(world.deps.keys.namespaceHmac),
  );
  await world.registry.post({
    ownerAddress: OWNER,
    scope: CONTROL,
    dataHash: hashes.tombstoneData,
    metadataHash: hashes.tombstoneMetadata,
    expectedVersion: "2",
    signature: "0x00",
  });
  expect(await publishConnection(world.deps, CONNECTION_ID)).toEqual([]);
  expect(await world.deps.db.query("SELECT * FROM records")).toEqual([]);
});

it("a fresh offline run binds its generation when the registry answers", async () => {
  const world = await makeWorld();
  await seedConnection(world.deps);
  await seedStream(world.deps);
  await localRun(world);
  await world.deps.db.batch([{ sql: "UPDATE runs SET generation=NULL" }]);
  await seedRecord(world.deps, "a", canonicalJson({ id: "a" }));
  expect((await publishConnection(world.deps, CONNECTION_ID))[0]?.outcome).toBe(
    "published",
  );
  expect(await world.deps.db.query("SELECT generation FROM runs")).toEqual([
    { generation: 1 },
  ]);
});

// The part layout of a stream with no covering parts. A fresh stream goes into
// a few parts sized by `partTargetBytes`, not one part per record: each part is
// one object upload now and one object read for every reader later.
describe("part layout of records with no covering part", () => {
  const sha256Bytes = async (b: Uint8Array) =>
    new Uint8Array(createHash("sha256").update(b).digest());

  async function seedMany(
    deps: LocalSyncDeps,
    count: number,
    pad = 400,
    from = 0,
  ) {
    const statements = [
      {
        sql: `UPDATE write_ctx SET origin = 'local' WHERE id = 1`,
        params: [],
      },
    ];
    for (let i = from; i < from + count; i += 1) {
      const body = canonicalJson({ id: `k${i}`, pad: "x".repeat(pad) });
      statements.push({
        sql: `INSERT INTO records (connection_id, stream, pk_hash, record_key, stamp_o, stamp_r, body, body_sha256, first_o)
              VALUES (?, ?, ?, ?, 1000, 'r1', ?, ?, NULL)`,
        params: [
          CONNECTION_ID,
          STREAM,
          await pkHash(sha256Bytes, JSON.parse(body), ["id"]),
          `k${i}`,
          body,
          sha256Hex(body),
        ] as never,
      });
    }
    await deps.db.batch(statements);
  }

  /** Deps whose blob store counts the uploads the publisher makes. */
  function counting(world: World) {
    const puts: string[] = [];
    const gets: string[] = [];
    const deps: LocalSyncDeps = {
      ...world.deps,
      blobs: {
        get: (key) => {
          gets.push(key);
          return world.blobs.get(key);
        },
        // A probe is an object request too: the simulated cost counts it.
        exists: (key) => {
          gets.push(key);
          return world.blobs.exists(key);
        },
        put: async (key, bytes) => {
          puts.push(key);
          await world.blobs.put(key, bytes);
        },
      },
    };
    return {
      deps,
      puts,
      gets,
      partPuts: () => puts.filter((k) => k.includes("-p-")),
    };
  }

  async function freshWorld(records: number, target?: number) {
    const world = await makeWorld();
    if (target !== undefined) world.deps.partTargetBytes = target;
    await seedConnection(world.deps);
    await seedStream(world.deps);
    await localRun(world);
    await seedMany(world.deps, records);
    return world;
  }

  it("puts a 350-record stream in a few parts, not one part per record", async () => {
    const world = await freshWorld(350, 4 * 1024 * 1024);
    const counted = counting(world);
    expect(
      (await publishConnection(counted.deps, CONNECTION_ID))[0]?.outcome,
    ).toBe("published");
    const { head, values } = await published(world);
    expect(values).toHaveLength(350);
    expect(head.parts.length).toBeLessThanOrEqual(2);
    expect(counted.partPuts().length).toBe(head.parts.length);
  });

  it("publishes a 350-record stream in seconds at 1 s per object upload", async () => {
    const world = await freshWorld(350, 4 * 1024 * 1024);
    const counted = counting(world);
    await publishConnection(counted.deps, CONNECTION_ID);
    // Every object request (the existence GET before a put, and the put) costs
    // one second. Before the layout fix this was 350 parts: over 700 s.
    const simulatedSeconds = counted.puts.length + counted.gets.length;
    process.stdout.write(
      `PART_LAYOUT ${JSON.stringify({ puts: counted.puts.length, gets: counted.gets.length, simulatedSeconds })}\n`,
    );
    expect(simulatedSeconds).toBeLessThanOrEqual(10);
  });

  it("sizes parts by the byte target and reads back every record", async () => {
    // About 150 KB of rows against a 16 KB target: several parts, far fewer
    // than 350.
    const world = await freshWorld(350, 16 * 1024);
    await publishConnection(world.deps, CONNECTION_ID);
    const { head, values } = await published(world);
    expect(values).toHaveLength(350);
    expect(head.parts.length).toBeGreaterThan(4);
    expect(head.parts.length).toBeLessThan(64);
    for (const part of head.parts)
      expect(part.bytes).toBeLessThanOrEqual(16 * 1024);
  });

  it("rewrites only the part that holds a changed record", async () => {
    const world = await freshWorld(350, 16 * 1024);
    await publishConnection(world.deps, CONNECTION_ID);
    const before = (await published(world)).head.parts;
    await seedRun(world.deps, "r2", 2000);
    const body = canonicalJson({ id: "k7", pad: "y".repeat(400) });
    await world.deps.db.batch([
      { sql: `UPDATE write_ctx SET origin = 'local' WHERE id = 1`, params: [] },
      {
        sql: `UPDATE records SET body = ?, body_sha256 = ?, stamp_o = 2000, stamp_r = 'r2'
               WHERE connection_id = ? AND stream = ? AND record_key = 'k7'`,
        params: [body, sha256Hex(body), CONNECTION_ID, STREAM],
      },
    ]);
    const counted = counting(world);
    await publishConnection(counted.deps, CONNECTION_ID);
    const after = (await published(world)).head.parts;
    // The bucket that holds the record, and no other part.
    expect(counted.partPuts().length).toBeLessThanOrEqual(2);
    expect(counted.partPuts().length).toBeLessThan(before.length / 3);
    expect(after.length).toBeLessThanOrEqual(before.length + 1);
  });

  it("puts a record that no part covers into the same layout", async () => {
    const world = await freshWorld(3, 16 * 1024);
    await publishConnection(world.deps, CONNECTION_ID);
    await seedRun(world.deps, "r2", 2000);
    await seedMany(world.deps, 200, 400, 3);
    await world.deps.db.batch([
      {
        sql: `UPDATE records SET stamp_o = 2000, stamp_r = 'r2' WHERE record_key != 'k0' AND stamp_r = 'r1'`,
        params: [],
      },
    ]);
    await publishConnection(world.deps, CONNECTION_ID);
    const { head, values } = await published(world);
    expect(values).toHaveLength(203);
    expect(head.parts.length).toBeLessThan(40);
  });

  it("splits a grown stream by the byte target, then rewrites a bucket per change", async () => {
    const world = await freshWorld(3, 16 * 1024);
    await publishConnection(world.deps, CONNECTION_ID);
    expect((await published(world)).head.parts.map((p) => p.prefix)).toEqual([
      "",
    ]);
    // The stream grows far past one part: the planner cuts it by the target.
    await seedRun(world.deps, "r2", 2000);
    await seedMany(world.deps, 347, 400, 3);
    await publishConnection(world.deps, CONNECTION_ID);
    const grown = await published(world);
    expect(grown.values).toHaveLength(350);
    expect(grown.head.parts.length).toBeGreaterThan(4);
    expect(grown.head.parts.length).toBeLessThan(64);
    expect(grown.head.parts.every((p) => p.prefix.length > 0)).toBe(true);
    for (const p of grown.head.parts)
      expect(p.bytes).toBeLessThanOrEqual(16 * 1024);
  });

  // A 16-bit prefix group heavier than the target: the planner must split
  // below 8 bits there, which needs that shard's 16-bit counts.
  describe("a publish that re-encodes parts already in storage", () => {
    /**
     * Blob port that counts the body bytes it serves through `get`. `exists`
     * answers from storage without serving a body, as a HEAD does; keys in
     * `hidden` are reported missing.
     */
    function probeStore(world: World, hidden = new Set<string>()) {
      let bytesServed = 0;
      const puts: string[] = [];
      const deps: LocalSyncDeps = {
        ...world.deps,
        blobs: {
          get: async (key) => {
            const body = await world.blobs.get(key);
            bytesServed += body?.length ?? 0;
            return body;
          },
          exists: async (key) =>
            !hidden.has(key) && (await world.blobs.get(key)) !== null,
          put: async (key, bytes) => {
            puts.push(key);
            await world.blobs.put(key, bytes);
          },
        },
      };
      return { deps, puts, bytesServed: () => bytesServed };
    }

    async function publishedWithParts(records: number) {
      const world = await freshWorld(records, 4 * 1024 * 1024);
      const first = probeStore(world);
      expect(
        (await publishConnection(first.deps, CONNECTION_ID))[0]?.outcome,
      ).toBe("published");
      const { head } = await published(world);
      const encodeAgain = (deps: LocalSyncDeps) =>
        encodePrefixes(deps, {
          connectionId: CONNECTION_ID,
          stream: STREAM,
          scope: SCOPE,
          generation: 1,
          changedPrefixes: head.parts.map((part) => part.prefix),
          upToSeq: 0,
        });
      return { world, first, head, encodeAgain };
    }

    it("downloads no part body when every part is already stored", async () => {
      const { world, head, encodeAgain } = await publishedWithParts(350);
      const again = probeStore(world);
      // The re-encode is what a resumed publish runs: same rows, same parts.
      await encodeAgain(again.deps);
      expect(again.bytesServed()).toBe(0);
      expect(again.puts).toEqual([]);
      expect(head.parts.length).toBeGreaterThan(0);
    });

    it("uploads a part that storage does not have", async () => {
      const { world, first, encodeAgain } = await publishedWithParts(350);
      const missing = first.puts.find((key) => key.includes("-p-"));
      expect(missing).toBeDefined();
      const again = probeStore(world, new Set([missing!]));
      await encodeAgain(again.deps);
      expect(again.puts).toEqual([missing]);
      expect(again.bytesServed()).toBe(0);
    });
  });

  describe("a base group heavier than the target", () => {
    const TARGET = 1024;

    /** Two ids whose pk hashes share their first 16 bits. */
    async function sharedPrefixPair() {
      const seen = new Map<string, string>();
      for (let i = 0; ; i += 1) {
        const id = `p${i}`;
        const hash = await pkHash(sha256Bytes, { id }, ["id"]);
        const shard = hash.slice(0, 4);
        const first = seen.get(shard);
        if (first !== undefined) return { ids: [first, id], shard, hash };
        seen.set(shard, id);
      }
    }

    /** An id whose pk hash starts in a different shard than `shard`. */
    async function idOutsideShard(shard: string) {
      for (let i = 0; ; i += 1) {
        const id = `o${i}`;
        const hash = await pkHash(sha256Bytes, { id }, ["id"]);
        if (hash.slice(0, 2) !== shard.slice(0, 2)) return id;
      }
    }

    async function seedIds(deps: LocalSyncDeps, ids: readonly string[]) {
      const statements: { sql: string; params: never[] | unknown[] }[] = [
        {
          sql: `UPDATE write_ctx SET origin = 'local' WHERE id = 1`,
          params: [],
        },
      ];
      for (const id of ids) {
        const body = canonicalJson({ id, pad: "x".repeat(600) });
        statements.push({
          sql: `INSERT INTO records (connection_id, stream, pk_hash, record_key, stamp_o, stamp_r, body, body_sha256, first_o)
                VALUES (?, ?, ?, ?, 1000, 'r1', ?, ?, NULL)`,
          params: [
            CONNECTION_ID,
            STREAM,
            await pkHash(sha256Bytes, { id }, ["id"]),
            id,
            body,
            sha256Hex(body),
          ],
        });
      }
      await deps.db.batch(statements as never);
    }

    /** A published stream whose two ids share one 16-bit group above target. */
    async function heavyGroup() {
      const { ids, shard, hash } = await sharedPrefixPair();
      const world = await makeWorld();
      world.deps.partTargetBytes = TARGET;
      await seedConnection(world.deps);
      await seedStream(world.deps);
      await localRun(world);
      await seedIds(world.deps, ids);
      expect(
        (await publishConnection(world.deps, CONNECTION_ID))[0]?.outcome,
      ).toBe("published");
      const bits = pkHashBits(hash, 16);
      const before = await published(world);
      expect(before.values.map((v) => v.id).sort()).toEqual([...ids].sort());
      expect(before.head.parts.some((p) => p.prefix === bits)).toBe(true);
      return { world, ids, bits, shard, before };
    }

    it("a delete of a row in that group publishes without counts and drops the row", async () => {
      const { world, ids } = await heavyGroup();
      await seedRun(world.deps, "r2", 2000);
      await world.deps.db.batch([
        {
          sql: `UPDATE write_ctx SET origin = 'local' WHERE id = 1`,
          params: [],
        },
        {
          sql: `DELETE FROM records WHERE connection_id = ? AND stream = ? AND record_key = ?`,
          params: [CONNECTION_ID, STREAM, ids[1]!],
        },
      ]);
      expect(
        (await publishConnection(world.deps, CONNECTION_ID))[0]?.outcome,
      ).toBe("published");
      const after = await published(world);
      expect(after.values.map((v) => v.id)).toEqual([ids[0]]);
      // No part prefix is a prefix of another part's prefix.
      const prefixes = after.head.parts.map((p) => p.prefix);
      for (const a of prefixes)
        for (const b of prefixes)
          if (a !== b) expect(b.startsWith(a)).toBe(false);
    });

    it("a replace run over that group publishes without counts", async () => {
      const { world } = await heavyGroup();
      const read = await world.registry.read(SCOPE);
      if (!read.found) throw new Error("no head");
      await localRun(world, "r2", {
        replace: true,
        basisVersion: read.version,
        basisHash: read.dataHash,
      });
      // Stamped by the replace run r2, so it is at or above the replace bound.
      await seedRecord(world.deps, "c", canonicalJson({ id: "c" }), {
        stampO: 2000,
        stampR: "r2",
      });
      expect(
        (await publishConnection(world.deps, CONNECTION_ID))[0]?.outcome,
      ).toBe("published");
      expect((await published(world)).values.map((v) => v.id)).toEqual(["c"]);
    });

    it("an unchanged heavy group is retained while a row in another shard publishes", async () => {
      const { world, ids, bits, shard, before } = await heavyGroup();
      const other = await idOutsideShard(shard);
      await seedRun(world.deps, "r2", 2000);
      await seedIds(world.deps, [other]);
      expect(
        (await publishConnection(world.deps, CONNECTION_ID))[0]?.outcome,
      ).toBe("published");
      const after = await published(world);
      expect(after.values.map((v) => v.id).sort()).toEqual(
        [...ids, other].sort(),
      );
      const heavy = (head: Head) =>
        head.parts.filter((p) => p.prefix.startsWith(bits)).map((p) => p.hash);
      expect(heavy(before.head).length).toBeGreaterThan(1);
      expect(heavy(after.head)).toEqual(heavy(before.head));
    });
  });
});

describe("the head this device committed", () => {
  const OTHER_HMAC = async (message: Uint8Array) =>
    new Uint8Array(
      createHmac("sha256", Buffer.from("another-namespace-key"))
        .update(message)
        .digest(),
    );
  const headKey = (hash: string) => `${SCOPE}/${headBlobName(hash)}`;

  /** A blob port that counts reads, and can hide or replace a key. */
  function countingBlobs(inner: StreamSyncBlobs) {
    const gets = new Map<string, number>();
    const puts: string[] = [];
    const hidden = new Set<string>();
    const replaced = new Map<string, Uint8Array>();
    const port = {
      gets,
      puts,
      hidden,
      replaced,
      get: async (key: string) => {
        gets.set(key, (gets.get(key) ?? 0) + 1);
        if (hidden.has(key)) return null;
        return replaced.get(key) ?? inner.get(key);
      },
      exists: async (key: string) =>
        !hidden.has(key) && (replaced.has(key) || inner.exists(key)),
      put: async (key: string, bytes: Uint8Array) => {
        puts.push(key);
        return inner.put(key, bytes);
      },
    };
    return port;
  }

  /** A world whose blob port is one counting object, kept for the whole test. */
  async function countedWorld(registry?: StreamSyncRegistry) {
    const world = await makeWorld(registry);
    const blobs = countingBlobs(world.blobs);
    Object.assign(world.deps, { blobs });
    await seedConnection(world.deps);
    await seedStream(world.deps);
    return { world, blobs };
  }

  async function publishRun(world: World, runId: string, o: number) {
    await seedRun(world.deps, runId, o);
    await seedRecord(world.deps, `rec-${runId}`, canonicalJson({ id: runId }), {
      stampO: o,
      stampR: runId,
    });
    const results = await publishConnection(world.deps, CONNECTION_ID);
    return results[0]!;
  }

  async function registryHash(world: World): Promise<string> {
    const read = await world.registry.read(SCOPE);
    if (!read.found) throw new Error("no registry head");
    return read.dataHash;
  }

  /**
   * Does a snapshot of a stream whose registry head is `hash` download that
   * head? Another database on the same blob port, whose blob store has lost
   * the head: the snapshot reads it from the cache, or fails because storage
   * has no such blob. Returns the error message (null when it did not fail on
   * the missing head) and the number of GETs of the head blob. Any other
   * failure is rethrown.
   */
  async function missingHeadError(
    blobs: ReturnType<typeof countingBlobs>,
    hash: string,
  ): Promise<{ error: string | null; headGets: number }> {
    const probe = await makeWorld();
    Object.assign(probe.deps, { blobs });
    await seedConnection(probe.deps);
    await seedStream(probe.deps);
    await probe.registry.post({
      ownerAddress: OWNER,
      scope: SCOPE,
      dataHash: hash as `0x${string}`,
      metadataHash: `0x${"22".repeat(32)}`,
      expectedVersion: "1",
      signature: "0x00",
    });
    // The registry version is already applied here, so apply never reads the
    // head: the only possible GET is the snapshot's own.
    await probe.deps.db.batch([
      {
        sql: "UPDATE stream_state SET head_version = 1 WHERE connection_id = ? AND stream = ?",
        params: [CONNECTION_ID, STREAM],
      },
    ]);
    const key = headKey(hash);
    const before = blobs.gets.get(key) ?? 0;
    blobs.hidden.add(key);
    try {
      await publishConnection(probe.deps, CONNECTION_ID);
      return { error: null, headGets: (blobs.gets.get(key) ?? 0) - before };
    } catch (error) {
      const message = String((error as Error).message);
      // Any other failure is not a cache hit: let the test see it.
      if (!message.includes("registry head blob")) throw error;
      return {
        error: message,
        headGets: (blobs.gets.get(key) ?? 0) - before,
      };
    } finally {
      blobs.hidden.delete(key);
    }
  }
  /** The head was fetched from storage, and storage had lost it. */
  const downloads = (probe: { error: string | null; headGets: number }) =>
    probe.error !== null && probe.headGets > 0;
  /** The head came from the cache: no GET of its blob, and no failure. */
  const servedFromCache = (probe: { error: string | null; headGets: number }) =>
    probe.error === null && probe.headGets === 0;

  it("is not downloaded by the next snapshot of that stream", async () => {
    const { world, blobs } = await countedWorld();
    const registry = world.registry;
    const reads = new Map<string, number>();
    Object.assign(world.deps, {
      registry: {
        read: async (scope: string) => {
          reads.set(scope, (reads.get(scope) ?? 0) + 1);
          return registry.read(scope);
        },
        post: registry.post.bind(registry),
        listControlRows: registry.listControlRows.bind(registry),
        listStreamRows: registry.listStreamRows.bind(registry),
      },
    });

    expect((await publishRun(world, "r1", 1000)).outcome).toBe("published");
    const first = await registryHash(world);
    blobs.gets.clear();
    reads.clear();

    expect((await publishRun(world, "r2", 2000)).outcome).toBe("published");
    expect(await registryHash(world)).not.toBe(first);
    // No GET for the head this device wrote; the control and stream rows are
    // still read from the registry.
    expect(blobs.gets.get(headKey(first)) ?? 0).toBe(0);
    expect(reads.get(CONTROL)).toBeGreaterThan(0);
    expect(reads.get(SCOPE)).toBeGreaterThan(0);

    // The probe sees the difference: the head just committed is remembered,
    // an unknown head is not.
    expect(
      servedFromCache(await missingHeadError(blobs, await registryHash(world))),
    ).toBe(true);
    expect(
      downloads(await missingHeadError(blobs, `0x${"cd".repeat(32)}`)),
    ).toBe(true);
  });

  it("a foreign head costs one verified GET and a tampered one is neither accepted nor remembered", async () => {
    const { world, blobs } = await countedWorld();
    const foreign = await registryHead(world, [{ id: "theirs" }]);
    await applyConnection(world.deps, CONNECTION_ID);
    blobs.gets.clear();
    // Tampered: the bytes no longer hash to the registry's data hash.
    const good = (await world.blobs.get(headKey(foreign.dataHash)))!;
    blobs.replaced.set(
      headKey(foreign.dataHash),
      new TextEncoder().encode(
        new TextDecoder()
          .decode(good)
          .replace('"stream":"s1"', '"stream":"s2"'),
      ),
    );
    await seedRun(world.deps, "r1", 2000);
    await seedRecord(world.deps, "mine", canonicalJson({ id: "mine" }), {
      stampO: 2000,
      stampR: "r1",
    });
    await expect(publishConnection(world.deps, CONNECTION_ID)).rejects.toThrow(
      /failed verification: hash_mismatch/,
    );
    expect(blobs.gets.get(headKey(foreign.dataHash))).toBe(1);

    // Honest bytes again: the rejected head was not remembered, so it is read
    // (once) and verified now, and the publish goes through.
    blobs.replaced.clear();
    blobs.gets.clear();
    const results = await publishConnection(world.deps, CONNECTION_ID);
    expect(results[0]?.outcome).toBe("published");
    expect(blobs.gets.get(headKey(foreign.dataHash))).toBe(1);
    expect(
      servedFromCache(await missingHeadError(blobs, foreign.dataHash)),
    ).toBe(true);
  });

  it("is not remembered after a CAS conflict", async () => {
    const { world, blobs } = await countedWorld();
    const registry = world.registry as MemoryStreamSyncRegistry;
    // Another device's head lands between this device's upload and its post.
    let beaten = false;
    registry.beforePost = async (post) => {
      if (post.scope !== SCOPE || beaten) return;
      beaten = true;
      await registryHead(world, [{ id: "theirs" }]);
    };
    expect((await publishRun(world, "r1", 1000)).outcome).toBe("published");
    const uploaded = blobs.puts
      .filter((key) => key.includes("/h-"))
      .map((key) => `0x${key.split("/h-")[1]}`);
    // This device's first head (the loser), the other device's (the fixture
    // writes two blobs), then the re-planned head that won on the retry.
    expect(uploaded.length).toBeGreaterThan(2);
    const loser = uploaded[0]!;
    const retried = uploaded[uploaded.length - 1]!;
    expect(retried).toBe(await registryHash(world));
    expect(downloads(await missingHeadError(blobs, loser))).toBe(true);
    expect(servedFromCache(await missingHeadError(blobs, retried))).toBe(true);
  });

  it("is not remembered when a delete purges the connection before the CAS", async () => {
    const { world, blobs } = await countedWorld();
    const hashes = await controlHashes(
      keccak,
      await deriveKeyCheck(world.deps.keys.namespaceHmac),
    );
    const put = blobs.put;
    blobs.put = async (key, value) => {
      if (key.includes("/h-")) {
        await world.registry.post({
          ownerAddress: OWNER,
          scope: CONTROL,
          dataHash: hashes.tombstoneData,
          metadataHash: hashes.tombstoneMetadata,
          expectedVersion: "2",
          signature: "0x00",
        });
      }
      return put(key, value);
    };
    expect((await publishRun(world, "r1", 1000)).outcome).toBe("purged");
    expect(await world.registry.read(SCOPE)).toEqual({ found: false });
    const uploaded = blobs.puts.filter((key) => key.includes("/h-"));
    expect(uploaded).toHaveLength(1);
    expect(
      downloads(
        await missingHeadError(blobs, `0x${uploaded[0]!.split("/h-")[1]}`),
      ),
    ).toBe(true);
  });

  it("is not remembered when a delete purges the connection after the CAS", async () => {
    const { world, blobs } = await countedWorld();
    const hashes = await controlHashes(
      keccak,
      await deriveKeyCheck(world.deps.keys.namespaceHmac),
    );
    const registry = world.registry;
    Object.assign(world.deps, {
      registry: {
        read: registry.read.bind(registry),
        listControlRows: registry.listControlRows.bind(registry),
        listStreamRows: registry.listStreamRows.bind(registry),
        post: async (post: Parameters<typeof registry.post>[0]) => {
          const result = await registry.post(post);
          if (post.scope === SCOPE)
            await registry.post({
              ownerAddress: OWNER,
              scope: CONTROL,
              dataHash: hashes.tombstoneData,
              metadataHash: hashes.tombstoneMetadata,
              expectedVersion: "2",
              signature: "0x00",
            });
          return result;
        },
      },
    });
    expect((await publishRun(world, "r1", 1000)).outcome).toBe("purged");
    const head = await registryHash(world);
    // The CAS landed; the local commit never ran; this device did not vouch
    // for the head.
    expect(downloads(await missingHeadError(blobs, head))).toBe(true);
  });

  it("is not remembered when the local commit fails", async () => {
    const { world, blobs } = await countedWorld();
    const db = world.deps.db;
    Object.assign(world.deps, {
      db: {
        ...db,
        query: db.query.bind(db),
        batch: async (statements: Parameters<typeof db.batch>[0]) => {
          if (statements.some((s) => s.sql.includes("INTO stream_versions")))
            throw new Error("disk full");
          return db.batch(statements);
        },
      },
    });
    await seedRun(world.deps, "r1", 1000);
    await seedRecord(world.deps, "a", canonicalJson({ id: "a" }));
    await expect(publishConnection(world.deps, CONNECTION_ID)).rejects.toThrow(
      /disk full/,
    );
    const head = await registryHash(world);
    expect(downloads(await missingHeadError(blobs, head))).toBe(true);
  });

  it("is verified before it is uploaded, posted or remembered", async () => {
    const { world, blobs } = await countedWorld();
    heads.corrupt = true;
    await seedRun(world.deps, "r1", 1000);
    await seedRecord(world.deps, "a", canonicalJson({ id: "a" }));
    await expect(publishConnection(world.deps, CONNECTION_ID)).rejects.toThrow(
      /the head built for s1 failed verification: malformed/,
    );
    expect(blobs.puts.filter((key) => key.includes("/h-"))).toEqual([]);
    expect(
      (world.registry as MemoryStreamSyncRegistry).log.filter(
        (entry) => entry.scope === SCOPE,
      ),
    ).toEqual([]);
  });

  it("misses when the key check changed", async () => {
    const { world, blobs } = await countedWorld();
    expect((await publishRun(world, "r1", 1000)).outcome).toBe("published");
    const head = await registryHash(world);
    expect(servedFromCache(await missingHeadError(blobs, head))).toBe(true);
    // A namespace key that derives another key check cannot use the entry:
    // the head is downloaded and refused as another key's.
    const probe = await makeWorld();
    Object.assign(probe.deps, {
      blobs,
      keys: { ...probe.deps.keys, namespaceHmac: OTHER_HMAC },
    });
    await seedConnection(probe.deps);
    await seedStream(probe.deps);
    await probe.registry.post({
      ownerAddress: OWNER,
      scope: SCOPE,
      dataHash: head as `0x${string}`,
      metadataHash: `0x${"22".repeat(32)}`,
      expectedVersion: "1",
      signature: "0x00",
    });
    blobs.gets.clear();
    await expect(publishConnection(probe.deps, CONNECTION_ID)).rejects.toThrow(
      /failed verification: key_mismatch/,
    );
    expect(blobs.gets.get(headKey(head))).toBe(1);
  });

  it("does not stop a newer lifetime from deferring the publish", async () => {
    const { world: first, blobs } = await countedWorld();
    // Generation 2: the head this device remembers is a newer lifetime's.
    await first.deps.db.batch([
      { sql: "DELETE FROM stream_state" },
      { sql: "DELETE FROM connections" },
    ]);
    await seedConnection(first.deps, 2);
    await seedStream(first.deps);
    await seedRun(first.deps, "r1", 1000, { generation: 2 });
    await seedRecord(first.deps, "a", canonicalJson({ id: "a" }));
    expect(
      (await publishConnection(first.deps, CONNECTION_ID))[0]?.outcome,
    ).toBe("published");
    const head = await registryHash(first);

    // A database still at generation 1 meets that head at the registry.
    const behind = await makeWorld();
    Object.assign(behind.deps, { blobs });
    await seedConnection(behind.deps, 1);
    await seedStream(behind.deps);
    await behind.registry.post({
      ownerAddress: OWNER,
      scope: SCOPE,
      dataHash: head as `0x${string}`,
      metadataHash: `0x${"22".repeat(32)}`,
      expectedVersion: "1",
      signature: "0x00",
    });
    await seedRun(behind.deps, "r9", 3000, { generation: 1 });
    await seedRecord(behind.deps, "b", canonicalJson({ id: "b" }));
    blobs.gets.clear();
    const results = await publishConnection(behind.deps, CONNECTION_ID);
    expect(results[0]?.outcome).toBe("deferred");
    // Served from the cache, and still not published over.
    expect(blobs.gets.get(headKey(head)) ?? 0).toBe(0);
    expect(
      (behind.registry as MemoryStreamSyncRegistry).log.filter(
        (entry) => entry.scope === SCOPE,
      ),
    ).toHaveLength(1);
  });

  it("does not record a newer lifetime's delete fence as this lifetime's", async () => {
    const { world: first, blobs } = await countedWorld();
    await first.deps.db.batch([
      { sql: "DELETE FROM stream_state" },
      { sql: "DELETE FROM connections" },
    ]);
    await seedConnection(first.deps, 2);
    await seedStream(first.deps);
    await seedRun(first.deps, "r1", 1000, { generation: 2 });
    await seedRecord(first.deps, "a", canonicalJson({ id: "a" }));
    expect(
      (await publishConnection(first.deps, CONNECTION_ID))[0]?.outcome,
    ).toBe("published");
    const head = await registryHash(first);

    // The registry row of that generation-2 head also carries a delete mark.
    // Taken as an older lifetime's head it would raise this database's delete
    // fence; a newer lifetime's head must leave the fence alone.
    const behind = await makeWorld();
    Object.assign(behind.deps, { blobs });
    await seedConnection(behind.deps, 1);
    await seedStream(behind.deps);
    await behind.registry.post({
      ownerAddress: OWNER,
      scope: SCOPE,
      dataHash: head as `0x${string}`,
      metadataHash: deleteMetadataHash(SCOPE, 1),
      expectedVersion: "1",
      signature: "0x00",
    });
    await seedRun(behind.deps, "r9", 3000, { generation: 1 });
    await seedRecord(behind.deps, "b", canonicalJson({ id: "b" }));
    const results = await publishConnection(behind.deps, CONNECTION_ID);
    expect(results[0]?.outcome).toBe("deferred");
    const rows = await behind.deps.db.query<{ last_delete_version: number }>(
      "SELECT last_delete_version FROM stream_state WHERE connection_id = ? AND stream = ?",
      [CONNECTION_ID, STREAM],
    );
    expect(rows[0]?.last_delete_version).toBe(0);
  });
});

describe("the commit step's stream-row fence", () => {
  /** A registry that counts reads and the results of posts, per scope. */
  function countingRegistry(inner: StreamSyncRegistry) {
    const reads = new Map<string, number>();
    const posts: Array<{ scope: string; kind: string }> = [];
    return {
      reads,
      posts,
      read: async (scope: string) => {
        reads.set(scope, (reads.get(scope) ?? 0) + 1);
        return inner.read(scope);
      },
      post: async (request: Parameters<StreamSyncRegistry["post"]>[0]) => {
        const result = await inner.post(request);
        posts.push({ scope: request.scope, kind: result.kind });
        return result;
      },
      listControlRows: inner.listControlRows.bind(inner),
      listStreamRows: inner.listStreamRows.bind(inner),
    };
  }

  async function setup() {
    const world = await makeWorld();
    await seedConnection(world.deps);
    await seedStream(world.deps);
    const counted = countingRegistry(world.registry);
    Object.assign(world.deps, { registry: counted });
    return { world, counted };
  }

  it("reads the stream row once per published stream: the snapshot's read, not a second one before the CAS", async () => {
    const { world, counted } = await setup();
    await seedRun(world.deps, "r1", 1000);
    await seedRecord(world.deps, "a", canonicalJson({ id: "a" }));
    expect(
      (await publishConnection(world.deps, CONNECTION_ID))[0]?.outcome,
    ).toBe("published");
    expect(counted.reads.get(SCOPE)).toBe(1);
    expect(counted.posts.filter((p) => p.scope === SCOPE)).toEqual([
      { scope: SCOPE, kind: "committed" },
    ]);
  });

  it("a row that moved between the snapshot and the commit is a 409: the stream re-plans on top of it and is never published over it", async () => {
    const { world, counted } = await setup();
    await seedRun(world.deps, "r1", 1000);
    await seedRecord(world.deps, "mine", canonicalJson({ id: "mine" }));
    // Another device's head lands while this device uploads.
    const put = world.deps.blobs.put.bind(world.deps.blobs);
    let moved = false;
    world.deps.blobs.put = async (key, bytes) => {
      if (!moved) {
        moved = true;
        await registryHead(world, [{ id: "theirs" }]);
      }
      return put(key, bytes);
    };
    expect(
      (await publishConnection(world.deps, CONNECTION_ID))[0]?.outcome,
    ).toBe("published");
    // The CAS lost (the other device's own post is not counted here), then
    // the re-planned head won on top of it.
    expect(
      counted.posts.filter((p) => p.scope === SCOPE).map((p) => p.kind),
    ).toEqual(["conflict", "committed"]);
    const read = await world.registry.read(SCOPE);
    expect(read.found && read.version).toBe(2);
    expect((await published(world)).values.map((v) => v.id).sort()).toEqual([
      "mine",
      "theirs",
    ]);
  });

  it("the no-op path sends no CAS, so it still re-reads the row and catches a move", async () => {
    const { world, counted } = await setup();
    await localRun(world);
    await seedRecord(world.deps, "a", canonicalJson({ id: "a" }));
    await seedRunRow(world.deps, "r1", "a", canonicalJson({ id: "a" }));
    await publishConnection(world.deps, CONNECTION_ID);
    counted.reads.clear();
    counted.posts.length = 0;

    // An identical head is a no-op: two reads (snapshot, then the fence).
    expect(
      (await publishConnection(world.deps, CONNECTION_ID))[0]?.outcome,
    ).toBe("noop");
    expect(counted.reads.get(SCOPE)).toBe(2);
    expect(counted.posts).toEqual([]);

    // Another device's head lands just after that snapshot's read of the row.
    const read = counted.read;
    let moved = false;
    counted.read = async (scope) => {
      const row = await read(scope);
      if (scope === SCOPE && !moved) {
        moved = true;
        await registryHead(world, [{ id: "theirs" }]);
      }
      return row;
    };
    const [result] = await publishConnection(world.deps, CONNECTION_ID);
    // Not committed as a no-op over the moved row (version 2, the other
    // device's): re-planned onto it and published as version 3 by one CAS.
    expect(result?.outcome).toBe("published");
    expect(counted.posts).toEqual([{ scope: SCOPE, kind: "committed" }]);
    const row = await world.registry.read(SCOPE);
    expect(row.found && row.version).toBe(3);
  });
});
