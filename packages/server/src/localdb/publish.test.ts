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
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

import { applyConnection } from "../../../core/src/localdb/apply.js";
import { remoteFixture } from "./apply-fixture.js";

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
    expect(results[0]).toEqual({
      stream: STREAM,
      outcome: "published",
      watermark: W,
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
