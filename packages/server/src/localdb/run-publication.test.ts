// Durable run publication state: "is ended run R saved?" answered from the
// database alone, after a lost publish reply or a restart.
import { createHash, createHmac } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { keccak_256 } from "@noble/hashes/sha3";
import {
  canonicalJson,
  controlHashes,
  controlScope,
  deriveKeyCheck,
  pkHash,
  streamScope,
} from "@opendatalabs/personal-server-ts-stream-sync";
import {
  MemoryStreamSyncRegistry,
  createMemoryStreamSyncBlobs,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import { RunIntakeError } from "../../../core/src/stream-sync/intake.js";
import type { LocalSyncDeps } from "../../../core/src/localdb/deps.js";
import type { SqlDriver } from "../../../core/src/localdb/driver.js";
import { openLocalDb } from "../../../core/src/localdb/open.js";
import { connectionQueue } from "../../../core/src/localdb/queue.js";
import { MIGRATIONS } from "../../../core/src/localdb/schema.js";
import { publishConnection } from "../../../core/src/localdb/publish.js";
import { purgeConnection } from "../../../core/src/localdb/purge.js";
import { createRunEndStore } from "../../../core/src/localdb/run-end.js";
import { unwriteRefusedRun } from "../../../core/src/localdb/unwrite.js";
import { createLocalSync } from "../../../core/src/localdb/sync.js";
import {
  readBeginReceipt,
  readEndReceipt,
  readPublicationStatus,
} from "../../../core/src/localdb/run-receipts.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const CONNECTOR = "test-conn";
const NS = "0123456789abcdef";
const OWNER = "0x0000000000000000000000000000000000000001";
const CONNECTION_ID = controlScope(CONNECTOR, "");
const A = "stream-a";
const B = "stream-b";
const CONTROL = controlScope(CONNECTOR, NS);
const keccak = async (data: Uint8Array) => keccak_256(data);
const sha256 = (data: string) =>
  createHash("sha256").update(data).digest("hex");

type World = {
  dir: string;
  driver: SqlDriver;
  deps: LocalSyncDeps;
  registry: MemoryStreamSyncRegistry;
};
const worlds: World[] = [];
afterEach(async () => {
  for (const world of worlds.splice(0)) {
    await world.driver.close().catch(() => {});
    rmSync(world.dir, { recursive: true, force: true });
  }
});

async function openDeps(world: Pick<World, "dir" | "registry">, blobs: object) {
  const driver = openBetterSqlite3(join(world.dir, "db.sqlite"));
  await openLocalDb(driver, {
    owner: OWNER,
    network: "test",
    deviceId: "test-device",
  });
  let op = 0;
  const deps: LocalSyncDeps = {
    db: driver,
    queue: connectionQueue(),
    ownerAddress: OWNER,
    registry: world.registry,
    blobs: blobs as LocalSyncDeps["blobs"],
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
    now: () => 1780000000000,
    newOp: () => `op-${++op}`,
    partTargetBytes: 4096,
  };
  return { driver, deps };
}

const blobsByWorld = new WeakMap<World, object>();

async function makeWorld(
  streams: readonly string[] = [A],
  existingDir?: string,
): Promise<World> {
  const dir =
    existingDir ?? mkdtempSync(join(process.cwd(), ".run-publication-"));
  const registry = new MemoryStreamSyncRegistry();
  const blobs = createMemoryStreamSyncBlobs();
  const { driver, deps } = await openDeps({ dir, registry }, blobs);
  const world: World = { dir, driver, deps, registry };
  blobsByWorld.set(world, blobs);
  worlds.push(world);
  const hashes = await controlHashes(
    keccak,
    await deriveKeyCheck(deps.keys.namespaceHmac),
  );
  await registry.post({
    ownerAddress: OWNER,
    scope: CONTROL,
    dataHash: hashes.activeData,
    metadataHash: hashes.activeMetadata,
    expectedVersion: "1",
    signature: "0x00",
  });
  await driver.batch([
    {
      sql: `INSERT INTO connections (connection_id, connector, ns, generation, control_state, control_version)
            VALUES (?, ?, ?, 1, 'active', 1)`,
      params: [CONNECTION_ID, CONNECTOR, NS],
    },
    ...streams.map((stream) => ({
      sql: `INSERT INTO stream_state (connection_id, stream, primary_key, semantics, incremental, publish_watermark)
            VALUES (?, ?, '["id"]', 'mutable_state', 0, 0)`,
      params: [CONNECTION_ID, stream],
    })),
  ]);
  return world;
}

/** Close the database and open the same file again: a process restart. */
async function restart(world: World): Promise<void> {
  await world.driver.close();
  const { driver, deps } = await openDeps(world, blobsByWorld.get(world)!);
  world.driver = driver;
  world.deps = deps;
}

const BEGIN_REQUEST = JSON.stringify({
  connector: CONNECTOR,
  artifactDigest: "digest",
});

/** A run that collected rows for its streams, as begin and batch leave it. */
async function collect(
  world: World,
  runId: string,
  o: number,
  streams: Readonly<Record<string, readonly string[]>> = { [A]: ["x"] },
  options: { full?: boolean } = {},
): Promise<void> {
  const statements = [
    {
      sql: `INSERT INTO runs (run_id, connection_id, o, generation, artifact_version, collection_mode,
              state, last_batch, begin_request, begin_response)
            VALUES (?, ?, ?, 1, '1.0.0', 'incremental', 'collecting', 0, ?, ?)`,
      params: [
        runId,
        CONNECTION_ID,
        o,
        BEGIN_REQUEST,
        JSON.stringify({ runId, status: "collecting" }),
      ],
    },
  ];
  for (const [stream, ids] of Object.entries(streams)) {
    statements.push({
      sql: `INSERT INTO run_streams (run_id, stream, delete_snapshot, primary_key, profile_version, full_read)
            VALUES (?, ?, 0, '["id"]', '1.0.0', ?)`,
      params: [runId, stream, options.full === false ? 0 : 1],
    });
    for (const id of ids) {
      const body = canonicalJson({ id });
      statements.push({
        sql: `INSERT INTO run_rows (run_id, stream, pk_hash, record_key, body, body_sha256) VALUES (?, ?, ?, ?, ?, ?)`,
        params: [
          runId,
          stream,
          await pkHash(
            async (b) =>
              new Uint8Array(createHash("sha256").update(b).digest()),
            JSON.parse(body),
            ["id"],
          ),
          id,
          body,
          sha256(body),
        ],
      });
    }
  }
  await world.deps.db.batch(statements);
}

async function endRun(world: World, runId: string, streams = [A]) {
  return createRunEndStore(world.deps).end(runId, {
    outcome: "succeeded",
    coveredStreams: streams,
    lastBatch: 0,
  });
}

const status = (world: World, runId: string) =>
  readPublicationStatus(world.deps.db, runId);
const stateOf = (result: Awaited<ReturnType<typeof status>>, stream: string) =>
  result.streams.find((s) => s.name === stream);
const head = async (world: World, stream: string) => {
  const read = await world.registry.read(streamScope(CONNECTOR, NS, stream));
  if (!read.found) throw new Error("no registry head");
  return read;
};
const streamPosts = (world: World, stream: string) =>
  world.registry.log.filter(
    (post) => post.scope === streamScope(CONNECTOR, NS, stream),
  );
const failStream = (world: World, stream: string, active: () => boolean) => {
  world.registry.beforePost = async (request) => {
    if (active() && request.scope === streamScope(CONNECTOR, NS, stream))
      throw new Error("storage unavailable");
  };
};

describe("run publication state", () => {
  it("answers saved after the publish reply is lost and the process restarts", async () => {
    const world = await makeWorld();
    await collect(world, "r1", 1000);
    const endReceipt = await endRun(world, "r1");
    const savedReceipt = JSON.stringify(
      (await world.deps.db.query("SELECT end_response FROM runs"))[0],
    );
    expect((await status(world, "r1")).state).toBe("pending");

    await publishConnection(world.deps, CONNECTION_ID); // the reply is dropped
    await restart(world);

    const after = await status(world, "r1");
    const registered = await head(world, A);
    expect(after).toEqual({
      runId: "r1",
      state: "published",
      streams: [
        {
          name: A,
          state: "published",
          publication: {
            generation: 1,
            version: registered.version,
            dataHash: registered.dataHash,
            watermark: 1,
          },
        },
      ],
    });
    // The end receipt is immutable, and a repeated begin still gets it back.
    expect(
      JSON.stringify(
        (await world.deps.db.query("SELECT end_response FROM runs"))[0],
      ),
    ).toBe(savedReceipt);
    expect(
      await readBeginReceipt(world.deps.db, "r1", JSON.parse(BEGIN_REQUEST)),
    ).toMatchObject({
      status: "ended",
      receipt: { ...endReceipt, stuck: false },
    });
    // Asking uploads nothing and posts nothing.
    const posts = world.registry.log.length;
    await status(world, "r1");
    expect(world.registry.log).toHaveLength(posts);
  });

  it("stays pending while the publication fails, then flips in the publishing batch", async () => {
    const world = await makeWorld();
    await collect(world, "r1", 1000);
    await endRun(world, "r1");
    const before = await readEndReceipt(world.deps.db, "r1");
    let down = true;
    failStream(world, A, () => down);

    await expect(publishConnection(world.deps, CONNECTION_ID)).rejects.toThrow(
      "storage unavailable",
    );
    expect((await status(world, "r1")).state).toBe("pending");
    expect(await readEndReceipt(world.deps.db, "r1")).toEqual(before);

    down = false;
    await publishConnection(world.deps, CONNECTION_ID);
    expect((await status(world, "r1")).state).toBe("published");
    // Head and evidence moved together: the stored head is the evidence's head.
    const [state] = await world.deps.db.query(
      "SELECT head_version, head_data_hash FROM stream_state",
    );
    expect(stateOf(await status(world, "r1"), A)?.publication).toMatchObject({
      version: state!.head_version,
      dataHash: state!.head_data_hash,
    });
  });

  it("writes evidence when no new publication is needed, so the watermark does not grow", async () => {
    const world = await makeWorld();
    await collect(world, "r1", 1000, { [A]: ["x"] }, { full: false });
    await endRun(world, "r1");
    await publishConnection(world.deps, CONNECTION_ID);
    const posts = streamPosts(world, A).length;

    // A later run found nothing new. Nothing is posted, yet it is saved.
    await collect(world, "r2", 2000, { [A]: [] }, { full: false });
    await endRun(world, "r2");
    expect((await status(world, "r2")).state).toBe("pending");
    const [again] = await publishConnection(world.deps, CONNECTION_ID);
    expect(again).toMatchObject({ outcome: "noop", watermark: 1 });
    expect(again?.publication).toBeUndefined(); // no transient receipt
    expect(streamPosts(world, A)).toHaveLength(posts);
    expect(stateOf(await status(world, "r2"), A)?.publication).toMatchObject({
      version: 1,
      watermark: 1,
    });
    expect((await status(world, "r2")).state).toBe("published");
    // Older evidence is not rewritten by the later publication.
    expect((await status(world, "r1")).state).toBe("published");
  });

  it("recovers a lost local commit of an empty full run without a new post", async () => {
    const world = await makeWorld();
    await collect(world, "r1", 1000, { [A]: ["x"] }, { full: false });
    await endRun(world, "r1");
    await publishConnection(world.deps, CONNECTION_ID);
    // r2 flips the head to complete; the registry commits, the local commit is lost.
    await collect(world, "r2", 2000, { [A]: [] });
    await endRun(world, "r2");
    world.registry.afterPost = async (request) => {
      if (request.scope === streamScope(CONNECTOR, NS, A))
        throw new Error("crash after the registry committed");
    };
    await expect(publishConnection(world.deps, CONNECTION_ID)).rejects.toThrow(
      "crash after",
    );
    expect(streamPosts(world, A)).toHaveLength(2);
    expect((await status(world, "r2")).state).toBe("pending");

    world.registry.afterPost = undefined;
    await restart(world);
    await publishConnection(world.deps, CONNECTION_ID);
    expect(streamPosts(world, A)).toHaveLength(2);
    expect(stateOf(await status(world, "r2"), A)?.publication?.version).toBe(2);
    expect((await status(world, "r2")).state).toBe("published");
  });

  it("never marks published when the crash is after the CAS, then recovers through the hash-equal path", async () => {
    const world = await makeWorld();
    await collect(world, "r1", 1000);
    await endRun(world, "r1");
    world.registry.afterPost = async (request) => {
      if (request.scope === streamScope(CONNECTOR, NS, A))
        throw new Error("crash after the registry committed");
    };
    await expect(publishConnection(world.deps, CONNECTION_ID)).rejects.toThrow(
      "crash after",
    );
    expect(streamPosts(world, A)).toHaveLength(1);
    expect((await status(world, "r1")).state).toBe("pending");

    world.registry.afterPost = undefined;
    await restart(world);
    await publishConnection(world.deps, CONNECTION_ID);
    expect(streamPosts(world, A)).toHaveLength(1); // matched the head, no second post
    expect(stateOf(await status(world, "r1"), A)?.publication?.version).toBe(1);
    expect((await status(world, "r1")).state).toBe("published");
  });

  describe("after publication", () => {
    async function published(streams: readonly string[] = [A, B]) {
      const world = await makeWorld(streams);
      await collect(
        world,
        "r1",
        1000,
        Object.fromEntries(streams.map((stream) => [stream, ["x"]])),
      );
      await endRun(world, "r1", [...streams]);
      await publishConnection(world.deps, CONNECTION_ID);
      expect((await status(world, "r1")).state).toBe("published");
      return world;
    }

    it("is superseded once the connection is deleted, whatever the old watermark", async () => {
      const world = await published();
      const [mark] = await world.deps.db.query(
        "SELECT MIN(publish_watermark) AS w FROM stream_state",
      );
      expect(mark!.w).toBeGreaterThan(0);
      await purgeConnection(world.deps, CONNECTION_ID, { controlVersion: 2 });
      const result = await status(world, "r1");
      expect(result.state).toBe("superseded");
      expect(result.streams.map((s) => s.reason)).toEqual([
        "connection_deleted",
        "connection_deleted",
      ]);
      // The evidence stays; only the verdict changes.
      expect(result.streams[0]?.publication).toBeDefined();
    });

    it("is superseded when the generation changed or a delete is requested", async () => {
      const world = await published();
      await world.deps.db.batch([
        { sql: "UPDATE connections SET generation = 2" },
      ]);
      expect(await status(world, "r1")).toMatchObject({
        state: "superseded",
        streams: [
          { reason: "generation_changed" },
          { reason: "generation_changed" },
        ],
      });
      await world.deps.db.batch([
        { sql: "UPDATE connections SET generation = 1" },
        {
          sql: "INSERT INTO delete_intents (connector, delete_id, intent) VALUES (?, 'd', 'x')",
          params: [CONNECTOR],
        },
      ]);
      expect((await status(world, "r1")).streams[0]?.reason).toBe(
        "connection_delete_requested",
      );
    });

    it("is superseded when the stream was deleted after publication", async () => {
      const world = await published([A]);
      await world.deps.db.batch([
        { sql: "UPDATE stream_state SET last_delete_version = 5" },
      ]);
      expect((await status(world, "r1")).streams[0]).toMatchObject({
        state: "superseded",
        reason: "stream_deleted",
      });
    });

    it("reads one snapshot while a delete lands", async () => {
      const world = await published();
      const reads: Awaited<ReturnType<typeof status>>[] = [];
      await Promise.all([
        purgeConnection(world.deps, CONNECTION_ID, { controlVersion: 2 }),
        ...Array.from({ length: 40 }, async () => {
          reads.push(await status(world, "r1"));
        }),
      ]);
      expect(reads.length).toBe(40);
      // Every read is wholly before or wholly after the delete.
      for (const read of reads)
        expect(new Set(read.streams.map((s) => s.state)).size).toBe(1);
      expect((await status(world, "r1")).state).toBe("superseded");
    });

    it("keeps its evidence after record changes are compacted and staged rows are gone", async () => {
      const world = await published([A]);
      const counts = await world.deps.db.query(
        `SELECT (SELECT COUNT(*) FROM record_changes) AS changes,
                (SELECT COUNT(*) FROM run_rows) AS staged`,
      );
      expect(counts).toEqual([{ changes: 0, staged: 0 }]);
      await restart(world);
      expect((await status(world, "r1")).state).toBe("published");
    });
  });

  it("publishes a multi-stream run per stream: A saved, B pending, then both after B finishes", async () => {
    const world = await makeWorld([A, B]);
    await collect(world, "r1", 1000, { [A]: ["a1"], [B]: ["b1"] });
    await endRun(world, "r1", [A, B]);
    let down = true;
    failStream(world, B, () => down);
    await expect(
      publishConnection(world.deps, CONNECTION_ID),
    ).rejects.toThrow();

    const partial = await status(world, "r1");
    expect(partial.state).toBe("pending");
    expect(partial.streams.map((s) => [s.name, s.state])).toEqual([
      [A, "published"],
      [B, "pending"],
    ]);
    const evidenceA = stateOf(partial, A)?.publication;

    await restart(world);
    down = false;
    await publishConnection(world.deps, CONNECTION_ID);
    const done = await status(world, "r1");
    expect(done.state).toBe("published");
    expect(stateOf(done, A)?.publication).toEqual(evidenceA);
    expect(stateOf(done, B)?.publication?.version).toBe(1);
  });

  it("never compares the publish watermark with the run's observation time", async () => {
    // A tiny observation time under a large prior watermark: not saved.
    const small = await makeWorld();
    await small.deps.db.batch([
      { sql: "UPDATE stream_state SET publish_watermark = 100" },
    ]);
    await collect(small, "r1", 1);
    await endRun(small, "r1");
    expect((await status(small, "r1")).state).toBe("pending");

    // A huge observation time over a tiny sequence: saved once published.
    const huge = await makeWorld();
    await collect(huge, "r1", 8_000_000_000_000_000);
    await endRun(huge, "r1");
    await publishConnection(huge.deps, CONNECTION_ID);
    expect(stateOf(await status(huge, "r1"), A)?.publication?.watermark).toBe(
      1,
    );
    expect((await status(huge, "r1")).state).toBe("published");
  });

  it("leaves a run from before the column unknown, even after a later publication", async () => {
    const dir = mkdtempSync(join(process.cwd(), ".run-publication-"));
    const old = openBetterSqlite3(join(dir, "db.sqlite"));
    const last = MIGRATIONS.length - 1;
    for (const [index, sqls] of MIGRATIONS.slice(0, last).entries())
      await old.batch([
        ...sqls.map((sql) => ({ sql })),
        { sql: `PRAGMA user_version = ${index + 1}` },
      ]);
    await old.batch([
      {
        sql: `INSERT INTO runs (run_id, connection_id, o, generation, artifact_version, collection_mode, state, last_batch)
              VALUES ('old', ?, 500, 1, '1.0.0', 'incremental', 'ended', 0)`,
        params: [CONNECTION_ID],
      },
      {
        sql: `INSERT INTO run_streams (run_id, stream, delete_snapshot, primary_key, profile_version, full_read, decision)
              VALUES ('old', 'stream-a', 0, '["id"]', '1.0.0', 1, 'publish')`,
      },
    ]);
    await old.close();
    const world = await makeWorld([A], dir);

    expect(await status(world, "old")).toMatchObject({
      state: "unknown",
      streams: [{ name: A, state: "unknown" }],
    });
    await collect(world, "new", 2000);
    await endRun(world, "new");
    await publishConnection(world.deps, CONNECTION_ID);
    expect((await status(world, "new")).state).toBe("published");
    expect((await status(world, "old")).state).toBe("unknown");
  });

  it("never reads a run that was refused, discarded or checkpoint-only as saved", async () => {
    // Refused at publish: accepted at end, then the registry head needs a newer connector.
    const refused = await makeWorld();
    await collect(refused, "r1", 1000);
    await endRun(refused, "r1");
    expect((await status(refused, "r1")).state).toBe("pending");
    await refused.deps.db.batch([
      {
        sql: `UPDATE stream_state SET floor_version = '2.0.0'`,
      },
    ]);
    await publishConnection(refused.deps, CONNECTION_ID);
    expect(await status(refused, "r1")).toMatchObject({
      state: "unknown",
      reason: "no_accepted_streams",
      streams: [
        { name: A, state: "superseded", reason: "connector_update_required" },
      ],
    });

    // Failed run: every stream discarded.
    const failed = await makeWorld();
    await collect(failed, "r1", 1000);
    await createRunEndStore(failed.deps).end("r1", {
      outcome: "failed",
      coveredStreams: [],
      lastBatch: -1,
    });
    expect(await status(failed, "r1")).toMatchObject({
      state: "unknown",
      streams: [{ state: "superseded", reason: "failed" }],
    });

    // A run that ended with no stream at all: checkpoint only.
    const bare = await makeWorld();
    await bare.deps.db.batch([
      {
        sql: `INSERT INTO runs (run_id, connection_id, o, generation, artifact_version, collection_mode, state, last_batch)
              VALUES ('r1', ?, 1000, 1, '1.0.0', 'incremental', 'collecting', 0)`,
        params: [CONNECTION_ID],
      },
    ]);
    await createRunEndStore(bare.deps).end("r1", {
      outcome: "succeeded",
      coveredStreams: [],
      lastBatch: 0,
      checkpointCandidate: { x: 1 },
    });
    expect(await readEndReceipt(bare.deps.db, "r1")).toMatchObject({
      result: "checkpoint_only",
    });
    expect(await status(bare, "r1")).toEqual({
      runId: "r1",
      state: "unknown",
      reason: "no_accepted_streams",
      streams: [],
    });

    // A run still collecting is not saved either.
    const open = await makeWorld();
    await collect(open, "r1", 1000);
    expect(await status(open, "r1")).toEqual({
      runId: "r1",
      state: "unknown",
      reason: "run_not_ended",
      streams: [],
    });
  });

  it("marks a run refused after end superseded with the refusal reason", async () => {
    const world = await makeWorld();
    await collect(world, "r1", 1000);
    await endRun(world, "r1");
    await unwriteRefusedRun(world.deps, {
      connectionId: CONNECTION_ID,
      stream: A,
      runId: "r1",
      reason: "out_of_order",
    });
    expect((await status(world, "r1")).streams[0]).toMatchObject({
      state: "superseded",
      reason: "out_of_order",
    });
    expect(
      await world.deps.db.query(
        "SELECT decision, publication_state, publication_reason FROM run_streams",
      ),
    ).toEqual([
      {
        decision: "refused",
        publication_state: "superseded",
        publication_reason: "out_of_order",
      },
    ]);
  });

  it("says a newer replacing run supersedes older runs, but a per-key overwrite does not", async () => {
    const world = await makeWorld();
    await collect(world, "r1", 1000, { [A]: ["a", "b"] });
    await endRun(world, "r1");
    await publishConnection(world.deps, CONNECTION_ID);

    // A later incremental run overwrites key a. The old run was still saved:
    // "saved" is a historical fact, not a claim that its bodies are current.
    await collect(world, "r2", 2000, { [A]: ["a"] }, { full: false });
    await endRun(world, "r2");
    await publishConnection(world.deps, CONNECTION_ID);
    expect((await status(world, "r1")).state).toBe("published");
    expect((await status(world, "r2")).state).toBe("published");

    // A newer replacing run drops everything below it.
    await collect(world, "r3", 3000, { [A]: ["c"] });
    const head1 = await head(world, A);
    await endRun(world, "r3");
    await world.deps.db.batch([
      {
        sql: `UPDATE run_streams SET replace = 1, basis_version = ?, basis_generation = 1, basis_data_hash = ? WHERE run_id = 'r3'`,
        params: [head1.version, head1.dataHash],
      },
    ]);
    await publishConnection(world.deps, CONNECTION_ID);
    expect((await status(world, "r3")).state).toBe("published");
    for (const older of ["r1", "r2"])
      expect((await status(world, older)).streams[0]).toMatchObject({
        state: "superseded",
        reason: "replaced_by:r3",
        publication: { version: expect.any(Number) },
      });
  });

  describe("authorization and binding", () => {
    it("fails like the other intake reads for an unknown run, another owner or another connector", async () => {
      const world = await makeWorld();
      await collect(world, "r1", 1000);
      await endRun(world, "r1");
      const sync = createLocalSync(world.deps, {
        resolveArtifact: () => null,
        declaredStreams: () => [],
        olderVersionReads: () => false,
      });
      const code = (work: Promise<unknown>) =>
        work.then(
          () => "answered",
          (error) => (error instanceof RunIntakeError ? error.code : error),
        );
      expect(await code(sync.intake.publicationStatus("missing"))).toBe("gone");
      expect(
        await code(
          sync.intake.publicationStatus("r1", {
            owner: "0x0000000000000000000000000000000000000002",
          }),
        ),
      ).toBe("owner_mismatch");
      expect(
        await code(
          sync.intake.publicationStatus("r1", { connector: "other-conn" }),
        ),
      ).toBe("run_conflict");
      expect(
        await code(
          sync.intake.publicationStatus("r1", {
            owner: OWNER.toUpperCase().replace("0X", "0x"),
            connector: CONNECTOR,
          }),
        ),
      ).toBe("answered");
    });
  });
});
