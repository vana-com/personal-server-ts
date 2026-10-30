/**
 * The PS-Lite replication engine (lite `replication-engine.ts`) against a
 * Node writer, over one simulated network: the same core phase engine on
 * both hosts, the Lite side over the Lite ports (SQLite-backed persistence
 * double, in-memory native transfers sharing the network's object store).
 */
import { createHash } from "node:crypto";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createDpv2ReplicaTransport } from "@opendatalabs/personal-server-ts-core/replication/dpv2";
import type { ReplicaTransportPort } from "@opendatalabs/personal-server-ts-core/replication/dpv2";
import type { ReplicaEngine } from "@opendatalabs/personal-server-ts-core/replication/engine";
import {
  REPLICA_DEFAULT_FRAGMENT_BYTES,
  REPLICA_LIMITS_VERSION,
} from "@opendatalabs/personal-server-ts-core/replication/limits";
import {
  createLiteCanonicalStore,
  createLiteReplicaEngine,
  createLiteReplicaStorage,
  createLiteReplicationRuntime,
  LITE_CANONICAL_MAX_OPERATION_BYTES,
  LITE_REPLICA_SQL_BYTES,
  LITE_REPLICATION_LIMITS,
  type LiteReplicaPersistence,
} from "@opendatalabs/personal-server-ts-lite";
import { createMemoryReplicaObjectTransfers } from "../../../lite/src/test-support/replication.js";
import {
  createSqliteLiteReplicaPersistence,
  previousRawSqlBytes,
} from "./lite-replica-sqlite.test-utils.js";
import {
  at,
  binding,
  cleanupHarness,
  clock,
  credential,
  expected,
  network,
  owner,
  scratchDirectory,
  sourceId,
  transportDevice,
} from "./pdpp-replica-contract.test-utils.js";
import {
  REPLICA_TEST_CHAIN_ID,
  replicaTestAuthority,
} from "./pdpp-replica-writer-identity.test-utils.js";

type Network = ReturnType<typeof network>;

afterEach(() => cleanupHarness());

class SimulatedCrash extends Error {}

/**
 * The Lite persistence as a crashable process. After `crashAfter(k)`, the
 * k-th next transaction runs its callback and then dies before commit; from
 * then on every transaction, stage and network call fails, as after
 * process loss.
 */
function crashable(inner: LiteReplicaPersistence) {
  let count = 0;
  let crashAt: number | undefined;
  /** The transaction call that marks its transaction to die before commit. */
  let crashOn:
    { method: "put" | "releaseBytes"; when(arg: string): boolean } | undefined;
  let crashInRead = false;
  let crashInUpload = false;
  let dead = false;
  const alive = () => {
    if (dead) throw new SimulatedCrash("process lost");
  };
  const die = (where: string): never => {
    dead = true;
    throw new SimulatedCrash(`crash ${where}`);
  };
  const port: LiteReplicaPersistence = {
    ...inner,
    transaction(run) {
      const index = ++count;
      return inner.transaction(async (tx) => {
        alive();
        let marked = false;
        const trigger = crashOn;
        const view = trigger
          ? new Proxy(tx, {
              get(target, key) {
                const value = Reflect.get(target, key) as unknown;
                if (typeof value !== "function") return value;
                if (key !== trigger.method) return value.bind(target);
                return (arg: string, ...rest: unknown[]) => {
                  if (trigger.when(arg)) marked = true;
                  return (value as (...args: unknown[]) => unknown).call(
                    target,
                    arg,
                    ...rest,
                  );
                };
              },
            })
          : tx;
        const result = await run(view);
        alive();
        if (index === crashAt || marked) die(`at transaction ${index}`);
        return result;
      });
    },
    async stageBytes(chunks) {
      alive();
      return inner.stageBytes(chunks);
    },
    readBytes(id) {
      alive();
      if (crashInRead) die("reading attached bytes");
      return inner.readBytes(id);
    },
  };
  return {
    port,
    count: () => count,
    crashAfter(k: number) {
      crashAt = count + k;
    },
    /** Die in the first transaction that releases replica bytes. */
    crashAtRelease() {
      crashOn = { method: "releaseBytes", when: () => true };
    },
    /** Die in the first transaction that writes a key under `prefix`. */
    crashAtPut(prefix: string) {
      crashOn = { method: "put", when: (key) => key.startsWith(prefix) };
    },
    /** Die when a download reads the bytes it attached. */
    crashInRead() {
      crashInRead = true;
    },
    /** Die during the next native upload, after its object reached storage. */
    crashInUpload() {
      crashInUpload = true;
    },
    uploaded() {
      if (crashInUpload) die("during the native upload");
    },
    get dead() {
      return dead;
    },
    alive,
  };
}

/**
 * A phone: Lite canonical store and Lite replication engine on one SQLite
 * file, its own server key in the owner's roster, connection `conn` bound
 * to the same source and method as the Node device's.
 */
async function liteDevice(
  net: Network,
  opts: {
    enabled?: boolean;
    maxBlobBytes?: number;
    targetChunkBytes?: number;
  } = {},
) {
  const path = join(scratchDirectory("lite-engine"), "native.sqlite");
  const context = () => ({
    owner,
    declarations: expected.declarations.map((d) => ({
      ...d,
      validateData: (data: Record<string, unknown>) =>
        typeof data.id === "string",
    })),
  });
  const authenticateReplica = (c: unknown) =>
    c === credential ? owner : undefined;
  const authority = replicaTestAuthority(net.roster, "lite-phone");
  net.roster.register(authority.signer.address, owner);
  let native = createSqliteLiteReplicaPersistence(path);
  let process = crashable(native.port);
  // Registrations fail while offline: retained batches stay unpublished.
  let offline = false;
  const open = () => {
    const persistence = process.port;
    const canonical = createLiteCanonicalStore({
      persistence,
      enabled: true,
      context,
      authenticateReplica,
    });
    const memory = createMemoryReplicaObjectTransfers(persistence, {
      objects: net.blobs,
    }).port;
    const crash = process;
    const storage = createLiteReplicaStorage({
      persistence,
      transfers: {
        ...memory,
        async upload(request, call) {
          crash.alive();
          const result = await memory.upload(request, call);
          crash.uploaded();
          return result;
        },
      },
      urlForKey: (key) => key,
    });
    const bytes = createDpv2ReplicaTransport({
      owner,
      masterKey: new Uint8Array(32).fill(5),
      storage,
      gateway: {
        registerDataPoint: () => Promise.reject(new Error("unused")),
      },
      feed: {
        listDataPointsByOwner: () => Promise.reject(new Error("unused")),
        getDataPoint: () => Promise.reject(new Error("unused")),
      },
      signer: { signAddData: () => Promise.reject(new Error("unused")) },
      evidence: () => Promise.reject(new Error("unused")),
    });
    // Gateway calls stay in JS core (the network's gateway); object bytes
    // move over the native transfers.
    const guarded =
      <A extends unknown[], R>(call: (...args: A) => Promise<R>) =>
      async (...args: A) => {
        process.alive();
        return call(...args);
      };
    const transport: ReplicaTransportPort = {
      ...net.port,
      register: guarded((...args: Parameters<typeof net.port.register>) =>
        offline
          ? Promise.reject(new Error("gateway unreachable"))
          : net.port.register(...args),
      ),
      evidence: guarded(net.port.evidence),
      list: guarded(net.port.list),
      putFragment: guarded(bytes.putFragment),
      getFragment: guarded(bytes.getFragment),
      hasFragment: guarded(bytes.hasFragment),
      put: guarded(bytes.put),
      get: guarded(bytes.get),
    };
    const engine = createLiteReplicaEngine({
      persistence,
      canonical: { context, authenticateReplica },
      engine: {
        enabled: opts.enabled ?? true,
        expected: () => expected,
        credential,
        transport,
        authority,
        now: clock.now,
        targetChunkBytes: opts.targetChunkBytes ?? 4000,
        maxBlobBytes: opts.maxBlobBytes ?? 8192,
      },
    });
    return { canonical, engine };
  };
  let { canonical, engine } = open();
  await canonical.provisionConnection("conn", {
    sourceId,
    methodId: "export",
  });
  let writes = 0;
  const connection = {
    owner,
    sourceId,
    connectionId: "conn",
    methodId: "export",
    generation: 1 as const,
  };
  const device = {
    get engine(): ReplicaEngine {
      return engine;
    },
    get process() {
      return process;
    },
    native: () => native,
    offline(value: boolean) {
      offline = value;
    },
    /** Log entries past the outbox acknowledgment: not yet published. */
    outbox: () =>
      native.db
        .prepare(
          `SELECT count(*) AS n FROM lite_kv WHERE key LIKE 'log/%'
             AND CAST(substr(key, 5) AS INTEGER) >
               COALESCE((SELECT CAST(value AS INTEGER) FROM lite_kv WHERE key='outbox-ack'), 0)`,
        )
        .get(),
    /**
     * A local write. The first one also registers the connection. Writes
     * name the writer bound at the first enable, so they come after it.
     */
    put: (text: string, id = "a") =>
      canonical.commitLocal(`lite-${++writes}`, [
        ...(writes === 1
          ? [{ ...connection, kind: "connection-register" as const }]
          : []),
        {
          ...connection,
          kind: "upsert",
          declaration: binding,
          recordKey: id,
          emittedAt: at,
          data: { id, text },
          blobs: [],
        },
      ]),
    async get(id = "a") {
      return (await canonical.readRecord("conn", "messages", id))?.data;
    },
    async blob(blobId: string) {
      const parts: Uint8Array[] = [];
      for await (const part of canonical.readBlob(blobId)) parts.push(part);
      return new Uint8Array(Buffer.concat(parts));
    },
    cycle: () => engine.cycle(),
    /** Process loss: drop every component, reopen the file without injection. */
    crashReopen() {
      native.close();
      native = createSqliteLiteReplicaPersistence(path);
      process = crashable(native.port);
      ({ canonical, engine } = open());
    },
    close: () => native.close(),
  };
  return device;
}

type TransportDevice = ReturnType<typeof transportDevice>;
type LiteDevice = Awaited<ReturnType<typeof liteDevice>>;
type Device = {
  cycle(): Promise<void>;
  get(id?: string): unknown;
};

/** Cycle every device n times on the shared clock; Lite cycles may report. */
async function run(devices: Device[], n = 12) {
  for (let i = 0; i < n; i++) {
    clock.advance(10_000);
    for (const device of devices) await device.cycle();
  }
}

/** Rebuild one due preparation without allowing later publish phases to run. */
async function rebuildOnePreparation(
  lite: LiteDevice,
  batch: string,
  attempts = 5,
) {
  const states: string[] = [];
  for (let attempt = 0; attempt < attempts; attempt++) {
    const db = lite.native().db;
    db.prepare(
      "UPDATE pdpp_transport_coordinator SET rotation_json=? WHERE id=1",
    ).run(JSON.stringify({ nextPhase: "prepare", writers: {} }));
    clock.advance(10_000);
    await lite.engine.step({ budget: { units: 1 } });
    const preparation = db
      .prepare(
        "SELECT state,wait_json FROM pdpp_transport_preparation WHERE batch=?",
      )
      .get(batch) as { state: string; wait_json: string | null };
    states.push(preparation.state);
    if (preparation.state === "prepared" && preparation.wait_json === null)
      return;
    if (
      !["preparing", "rebuilding"].includes(preparation.state) ||
      preparation.wait_json
    )
      throw new Error(
        `legacy preparation state: ${JSON.stringify(preparation)}`,
      );
  }
  throw new Error(`legacy preparation did not finish: ${states.join(",")}`);
}

function payloadSnapshot(
  db: ReturnType<LiteDevice["native"]>["db"],
  batch: string,
) {
  const rows = db
    .prepare(
      "SELECT bytes FROM pdpp_binary_chunks WHERE namespace='payload' AND blob_id=? ORDER BY position",
    )
    .all(batch) as { bytes: Buffer }[];
  const bytes = Buffer.concat(rows.map((row) => row.bytes));
  const manifest = db
    .prepare(
      "SELECT size_bytes FROM pdpp_binary_manifests WHERE namespace='payload' AND blob_id=?",
    )
    .get(batch) as { size_bytes: number } | undefined;
  return {
    size: manifest?.size_bytes,
    bytes: bytes.byteLength,
    digest: createHash("sha256").update(bytes).digest("hex"),
  };
}

async function preparedMultipartFixture() {
  const net = network();
  const lite = await liteDevice(net, {
    maxBlobBytes: 8 * 1024 * 1024,
    targetChunkBytes: 512 * 1024,
  });
  await lite.cycle();
  await lite.put("seed", "seed");
  await run([lite], 8);
  const restoreNetwork = net.snapshot();
  lite.offline(true);
  const boundaryBytes = 512 * 1024;
  const marker = "漢🙂";
  const markerBytes = Buffer.byteLength(marker);
  const text =
    "x".repeat(boundaryBytes - 64) +
    marker +
    "x".repeat(boundaryBytes - markerBytes) +
    marker +
    "x".repeat(300_000);
  await lite.put(text, "integrity-large");

  const db = lite.native().db;
  const retained = await prepareWithoutPublishing(
    lite,
    restoreNetwork,
    `SELECT r.batch,r.position FROM pdpp_transport_operation_retention r
     WHERE r.representation='parts' ORDER BY r.batch,r.position LIMIT 1`,
  );
  const batch = retained.batch;
  const position = retained.position;
  const parts = db
    .prepare(
      "SELECT part,json FROM pdpp_transport_operation_parts WHERE batch=? AND position=? ORDER BY part",
    )
    .all(batch, position) as { part: number; json: string }[];
  expect(parts.length).toBeGreaterThanOrEqual(3);
  expect(
    db
      .prepare("SELECT state FROM pdpp_transport_preparation WHERE batch=?")
      .get(batch),
  ).toEqual({ state: "prepared" });

  const state = db
    .prepare("SELECT sequence FROM pdpp_transport_state WHERE id=1")
    .get() as { sequence: number };
  return {
    net,
    lite,
    batch,
    position,
    text,
    parts,
    sequence: state.sequence,
    payload: payloadSnapshot(db, batch),
    publishedFragmentCalls: net.calls.puts.length,
    registrationCalls: net.calls.registrations.length,
  };
}

async function prepareWithoutPublishing(
  lite: LiteDevice,
  restoreNetwork: () => void,
  lookupSql: string,
  params: readonly unknown[] = [],
) {
  await run([lite], 16);
  const db = lite.native().db;
  const retained = db.prepare(lookupSql).get(...params) as
    { batch: string; position: number } | undefined;
  if (!retained) throw new Error("batch was not retained");
  const manifest = db
    .prepare(
      "SELECT scope,version FROM pdpp_transport_manifests_out WHERE batch=?",
    )
    .get(retained.batch) as { scope: string; version: number } | undefined;
  const previous = db
    .prepare("SELECT previous_json FROM pdpp_transport_batches WHERE batch=?")
    .get(retained.batch) as { previous_json: string | null };
  const preparation = db
    .prepare("SELECT version FROM pdpp_transport_preparation WHERE batch=?")
    .get(retained.batch) as { version: number };
  const ack = db
    .prepare("SELECT value FROM lite_kv WHERE key='outbox-ack'")
    .get() as { value: string } | undefined;

  // The fixture holds the durable local preparation before publication. The
  // test network is restored to its pre-write snapshot, then local upload and
  // registration witnesses from the setup run are removed with their bytes.
  restoreNetwork();
  db.prepare("DELETE FROM pdpp_transport_upload_attempts WHERE batch=?").run(
    retained.batch,
  );
  db.prepare("DELETE FROM pdpp_transport_fragments_out WHERE batch=?").run(
    retained.batch,
  );
  db.prepare("DELETE FROM pdpp_transport_manifests_out WHERE batch=?").run(
    retained.batch,
  );
  db.prepare(
    "DELETE FROM pdpp_transport_registration_recovery WHERE batch=?",
  ).run(retained.batch);
  db.prepare(
    "DELETE FROM pdpp_transport_registration_intents WHERE version=?",
  ).run(manifest?.version ?? preparation.version);
  db.prepare("UPDATE pdpp_transport_state SET previous_json=? WHERE id=1").run(
    previous.previous_json,
  );
  if (ack)
    db.prepare("UPDATE lite_kv SET value=? WHERE key='outbox-ack'").run(
      ack.value,
    );
  else db.prepare("DELETE FROM lite_kv WHERE key='outbox-ack'").run();
  db.prepare(
    "UPDATE pdpp_transport_preparation SET state='prepared',wait_json=NULL WHERE batch=?",
  ).run(retained.batch);
  db.prepare("UPDATE pdpp_transport_batches SET prepared=1 WHERE batch=?").run(
    retained.batch,
  );
  const effects = db
    .prepare(
      `SELECT
         (SELECT count(*) FROM pdpp_transport_upload_attempts WHERE batch=?) AS uploads,
         (SELECT count(*) FROM pdpp_transport_registration_intents WHERE version=?) AS intents,
         (SELECT count(*) FROM pdpp_transport_fragments_out WHERE batch=? AND (state<>'ready' OR attempts>0)) AS fragments,
         (SELECT count(*) FROM pdpp_transport_manifests_out WHERE batch=? AND (state<>'ready' OR attempts>0)) AS manifests`,
    )
    .get(retained.batch, preparation.version, retained.batch, retained.batch);
  if (
    Object.values(effects as Record<string, number>).some(
      (count) => count !== 0,
    )
  )
    throw new Error(
      `fixture still has publish witnesses: ${JSON.stringify(effects)}`,
    );
  return retained;
}

/** Records both writers wrote: their own, the other's and one shared key. */
async function write(node: TransportDevice, lite: LiteDevice) {
  node.put("from node", "n");
  await lite.put("from lite", "l");
  node.put("node edit", "k");
  await lite.put("lite edit", "k");
}
async function converged(node: TransportDevice, lite: LiteDevice) {
  expect(node.get("l")).toEqual({ id: "l", text: "from lite" });
  expect(await lite.get("n")).toEqual({ id: "n", text: "from node" });
  expect(await lite.get("l")).toEqual({ id: "l", text: "from lite" });
  expect(node.get("n")).toEqual({ id: "n", text: "from node" });
  // One winner for the key both wrote, the same on both hosts.
  const shared = node.get("k");
  expect(["node edit", "lite edit"]).toContain(
    (shared as { text?: string } | undefined)?.text,
  );
  expect(await lite.get("k")).toEqual(shared);
}

describe("PS-Lite replication engine with a Node writer", () => {
  it("converges a Node writer and a Lite writer", async () => {
    const net = network();
    const node = transportDevice(net);
    const lite = await liteDevice(net);
    // The first step binds the phone's writer before any local write.
    await lite.cycle();
    await write(node, lite);
    await run([node, lite]);
    await converged(node, lite);
    // Both writers published under their own scope, once per batch.
    const scopes = [...net.head.keys()].map((slot) =>
      slot.slice(0, slot.lastIndexOf("/")),
    );
    expect(new Set(scopes).size).toBe(2);
    for (const db of [node.db, lite.native().db]) {
      expect(
        db
          .prepare(
            `SELECT count(*) AS n FROM pdpp_transport_manifests_in i
        JOIN pdpp_transport_manifests_out o ON i.scope=o.scope AND i.version=o.version`,
          )
          .get(),
      ).toEqual({ n: 0 });
      expect(
        db
          .prepare(
            `SELECT count(*) AS n FROM pdpp_transport_fragment_parts p
        JOIN pdpp_transport_manifests_in i ON i.slot=p.slot WHERE i.state='imported'`,
          )
          .get(),
      ).toEqual({ n: 0 });
    }
  });

  it("imports a Node record's blob as a canonical blob on the phone", async () => {
    const net = network();
    const node = transportDevice(net);
    const lite = await liteDevice(net);
    await lite.cycle();
    const blob = node.store.storeBlobBytesForInstance({
      instance: "conn",
      method: "export",
      generation: 1,
      bytes: new Uint8Array([7, 8, 9]),
      mimeType: "application/octet-stream",
    });
    const data = {
      id: "b",
      blob_ref: { blob_id: blob.blobId, mime_type: blob.mimeType },
    };
    node.store.ingestBatch(
      [
        {
          instance: "conn",
          stream: "messages",
          key: "b",
          data,
          emitted_at: at,
        },
      ],
      () => "mutable_state",
      () => ["id"],
      { method: "export", generation: 1 },
    );
    await run([node, lite]);
    expect(await lite.get("b")).toEqual(data);
    expect(await lite.blob(blob.blobId)).toEqual(new Uint8Array([7, 8, 9]));
    // Received bytes are released once the copy is promoted.
    expect(
      lite.native().db.prepare("SELECT count(*) AS n FROM lite_bytes").get(),
    ).toEqual({ n: 0 });
  });

  it("steps through the Lite runtime at the phone's step bound", async () => {
    const net = network();
    const node = transportDevice(net);
    const lite = await liteDevice(net);
    const runtime = createLiteReplicationRuntime({
      door: { state: "on" },
      config: {
        enabled: true,
        owner,
        environment: "dev",
        chainId: REPLICA_TEST_CHAIN_ID,
        limits: LITE_REPLICATION_LIMITS,
      },
      engine: lite.engine,
      // Steps only when triggered here.
      timers: { now: clock.now, setTimeout: () => 0, clearTimeout: () => {} },
    });
    runtime.resume();
    await runtime.trigger("foreground");
    await write(node, lite);
    for (let i = 0; i < 16; i++) {
      clock.advance(10_000);
      await node.cycle();
      await runtime.trigger("local_write");
    }
    expect(runtime.status()).toMatchObject({ state: "on" });
    await converged(node, lite);
    expect(await runtime.stop(1_000)).toBe(true);
  });

  /**
   * Off is today's behaviour: on main the phone had no engine, so nothing
   * stepped. With the opt-in off the runtime is inert, and the engine it
   * was given never runs: no native statement, no replication table, no
   * network call. The Node writer alone still publishes, and the phone
   * imports nothing.
   */
  it("does nothing on the phone with replication off", async () => {
    const net = network();
    const node = transportDevice(net);
    const lite = await liteDevice(net, { enabled: false });
    const statements = lite.native().statements();
    const calls = JSON.stringify(net.calls);
    const runtime = createLiteReplicationRuntime({
      door: { state: "on" },
      config: {
        enabled: false,
        owner,
        environment: "dev",
        chainId: REPLICA_TEST_CHAIN_ID,
        limits: LITE_REPLICATION_LIMITS,
      },
      engine: lite.engine,
    });
    runtime.resume();
    expect(await runtime.trigger("sync_now")).toBeUndefined();
    expect(runtime.status()).toEqual({ state: "off" });
    expect(lite.native().statements()).toBe(statements);
    expect(JSON.stringify(net.calls)).toBe(calls);
    expect(
      lite
        .native()
        .db.prepare(
          "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'pdpp_%'",
        )
        .all(),
    ).toEqual([]);
    // A disabled engine steps idle when called directly.
    await lite.put("local only", "l");
    node.put("from node", "n");
    await run([node, lite]);
    expect(await lite.get("n")).toBeUndefined();
    expect(node.get("l")).toBeUndefined();
    expect(await lite.get("l")).toEqual({ id: "l", text: "local only" });
    // Every registration is the Node writer's: one scope.
    const scopes = net.calls.registrations.map((slot) =>
      slot.slice(0, slot.lastIndexOf("/")),
    );
    expect(scopes.length).toBeGreaterThan(0);
    expect(new Set(scopes).size).toBe(1);
  });

  /**
   * Process loss on the phone at sampled native transactions of the steps
   * that publish, download and import (every PHASE_STRIDE-th of the first
   * two steps, which hold all of that work): the callback ran, the commit
   * did not, and nothing in memory survives. Reopening the same file and
   * stepping on converges to the uninterrupted result.
   */
  const PHASE_TRANSACTIONS = 175;
  const PHASE_STRIDE = 7;
  it(
    "converges after the phone restarts mid-phase",
    { timeout: 120_000 },
    async () => {
      const crashed: number[] = [];
      for (let k = 1; k <= PHASE_TRANSACTIONS; k += PHASE_STRIDE) {
        const net = network();
        const node = transportDevice(net);
        const lite = await liteDevice(net);
        await lite.cycle();
        await write(node, lite);
        lite.process.crashAfter(k);
        for (let i = 0; i < 16; i++) {
          clock.advance(10_000);
          await node.cycle();
          await lite.cycle().catch((error: unknown) => {
            if (!lite.process.dead) throw error;
          });
          if (lite.process.dead) {
            crashed.push(k);
            await lite.crashReopen();
          }
        }
        await converged(node, lite);
        node.close();
        lite.close();
      }
      // Every sampled point was inside the stepped work.
      expect(crashed).toEqual(
        Array.from(
          { length: Math.ceil(PHASE_TRANSACTIONS / PHASE_STRIDE) },
          (_, i) => 1 + i * PHASE_STRIDE,
        ),
      );
    },
  );
});

/** Records `prefix0..prefix{n-1}` as one host holds them. */
async function records(
  device: { get(id: string): unknown },
  prefix: string,
  n: number,
) {
  const found: Record<string, unknown> = {};
  for (let i = 0; i < n; i++)
    found[`${prefix}${i}`] = await device.get(`${prefix}${i}`);
  return found;
}
const written = (prefix: string, text: string, n: number) =>
  Object.fromEntries(
    Array.from({ length: n }, (_, i) => [
      `${prefix}${i}`,
      { id: `${prefix}${i}`, text: `${text} ${i}` },
    ]),
  );

describe("PS-Lite replication engine: writer changes and bounded storage", () => {
  const N = 6;
  /** Storage objects as large as a Node writer's default 4 MiB fragment. */
  const OBJECT_CAP = 8 * 1024 * 1024;

  /**
   * Team phones already hold data when replication turns on, and a restore,
   * clone or reinstall rotates the writer (host contract §3.2). Each time
   * the phone re-exports its canonical state under the new writer: the
   * records written before the first enable, and the ones the old writer
   * retained but never published.
   */
  it("converges a phone's writes from before its first enable and across a writer rotation", async () => {
    const net = network();
    const node = transportDevice(net);
    const lite = await liteDevice(net);
    for (let i = 0; i < N; i++) await lite.put(`before enable ${i}`, `r${i}`);
    await run([node, lite]);
    expect(await records(node, "r", N)).toEqual(
      written("r", "before enable", N),
    );

    // The old writer retains these but the gateway never registers them.
    lite.offline(true);
    for (let i = 0; i < N; i++) await lite.put(`unpublished ${i}`, `s${i}`);
    await run([node, lite], 4);
    expect(await records(node, "s", N)).toEqual(
      Object.fromEntries(
        Array.from({ length: N }, (_, i) => [`s${i}`, undefined]),
      ),
    );
    const scopes = () =>
      new Set(
        net.calls.registrations.map((slot) =>
          slot.slice(0, slot.lastIndexOf("/")),
        ),
      );
    const before = scopes();

    await lite.engine.rotateWriter();
    lite.offline(false);
    await run([node, lite]);
    expect(await records(node, "s", N)).toEqual(written("s", "unpublished", N));
    expect(await records(node, "r", N)).toEqual(
      written("r", "before enable", N),
    );
    // The new writer published under its own scope.
    expect(scopes().size).toBe(before.size + 1);

    // A peer that joins after the rotation converges too.
    const late = transportDevice(net);
    await run([node, lite, late]);
    expect(await records(late, "s", N)).toEqual(written("s", "unpublished", N));
    expect(await records(late, "r", N)).toEqual(
      written("r", "before enable", N),
    );
  }, 60_000);

  /**
   * Steady use must not grow the phone's outbox: once the gateway confirms
   * a batch's registration, its operations leave the outbox. Node keeps its
   * append-only journal (rebaseline and completions read it); what it
   * publishes leaves no batch waiting for registration.
   */
  it("empties the phone's outbox once the gateway confirms what it published", async () => {
    const net = network();
    const node = transportDevice(net);
    const lite = await liteDevice(net);
    await lite.cycle();
    for (let round = 0; round < 3; round++) {
      for (let i = 0; i < N; i++)
        await lite.put(`round ${round} ${i}`, `r${i}`);
      node.put(`node round ${round}`, "n");
      await run([node, lite], 6);
      expect(lite.outbox()).toEqual({ n: 0 });
    }
    expect(await records(node, "r", N)).toEqual(written("r", "round 2", N));
    for (const db of [node.db, lite.native().db])
      expect(
        db
          .prepare(
            `SELECT count(*) AS n FROM pdpp_transport_batches b
             WHERE NOT EXISTS (SELECT 1 FROM pdpp_transport_manifests_out m
               JOIN pdpp_transport_registration_intents i ON i.scope=m.scope AND i.version=m.version
               WHERE m.batch=b.batch AND m.state='published' AND i.status='confirmed')`,
          )
          .get(),
      ).toEqual({ n: 0 });
  }, 60_000);

  /**
   * Node batches target 32 MiB, so one batch of many small records is far
   * above the phone's 192 KiB local batch bound and its 1 MiB SQL call
   * bound. The phone imports the batch whole, in one transaction under one
   * receipt, and then its successor. Process loss at that import's commit
   * leaves none of the batch visible; the reopened phone converges.
   */
  it("imports a Node batch above 1 MiB and its successor, all or nothing across a crash", async () => {
    const net = network({ cap: OBJECT_CAP });
    const node = transportDevice(net, {
      chunk: REPLICA_DEFAULT_FRAGMENT_BYTES,
      cap: OBJECT_CAP,
    });
    const lite = await liteDevice(net, { maxBlobBytes: OBJECT_CAP });
    // The phone first imports the Node writer's baseline batch.
    await run([node, lite], 4);
    const receipts = () =>
      (
        lite
          .native()
          .db.prepare(
            "SELECT count(*) AS n FROM lite_kv WHERE key LIKE 'import/%'",
          )
          .get() as { n: number }
      ).n;
    const imported = receipts();
    expect(imported).toBeGreaterThan(0);
    const M = 1000;
    for (let i = 0; i < M; i++) node.put(`${i} ${"x".repeat(1000)}`, `b${i}`);
    await run([node], 4);
    node.put("successor edit", "b0");
    node.put("successor", "z");
    await run([node], 4);

    lite.process.crashAtPut("import/");
    for (let i = 0; i < 12 && !lite.process.dead; i++) {
      clock.advance(10_000);
      await lite.cycle().catch((error: unknown) => {
        if (!lite.process.dead) throw error;
      });
    }

    expect(lite.process.dead).toBe(true);
    lite.crashReopen();
    expect(receipts()).toBe(imported);
    expect(Object.values(await records(lite, "b", M)).filter(Boolean)).toEqual(
      [],
    );

    await run([node, lite]);
    expect(await records(lite, "b", M)).toEqual(await records(node, "b", M));
    expect(await lite.get("b0")).toEqual({ id: "b0", text: "successor edit" });
    expect(await lite.get("z")).toEqual({ id: "z", text: "successor" });
    // One receipt per batch: the large batch was not split or relabelled.
    expect(receipts()).toBe(imported + 2);
  }, 120_000);

  /**
   * An operation above what the phone keeps as one native value waits as
   * `resource_unsupported`, with the limits version that refused it, until
   * a build with a larger bound re-admits it. It is not terminal and not
   * retried, and other writers keep importing.
   */
  it("holds an operation above the phone's value bound as unsupported and keeps importing other writers", async () => {
    const net = network({ cap: OBJECT_CAP });
    const big = transportDevice(net, {
      chunk: REPLICA_DEFAULT_FRAGMENT_BYTES,
      cap: OBJECT_CAP,
    });
    const other = transportDevice(net);
    const lite = await liteDevice(net, { maxBlobBytes: OBJECT_CAP });
    await lite.cycle();
    big.put("y".repeat(LITE_CANONICAL_MAX_OPERATION_BYTES), "big");
    other.put("from another writer", "q");
    await run([big, other, lite]);
    expect(await lite.get("q")).toEqual({
      id: "q",
      text: "from another writer",
    });
    expect(await lite.get("big")).toBeUndefined();
    const db = lite.native().db;
    const held = () =>
      db
        .prepare(
          `SELECT w.sequence, w.outcome, w.reason, w.attempts, w.next_attempt AS next,
             m.resource_limits_version AS version
           FROM pdpp_transport_import_work w
           JOIN pdpp_transport_manifests_in m ON m.writer=w.writer AND m.batch=w.batch
           WHERE w.outcome<>'progress'`,
        )
        .all();
    const before = held();
    expect(before).toEqual([
      {
        sequence: 2,
        outcome: "unsupported",
        reason: "resource_unsupported",
        attempts: 0,
        next: Number.MAX_SAFE_INTEGER,
        version: REPLICA_LIMITS_VERSION,
      },
    ]);
    expect(
      db
        .prepare(
          "SELECT count(*) AS n FROM pdpp_replica_batch_disposition WHERE state='terminal'",
        )
        .get(),
    ).toEqual({ n: 0 });
    // Held, not retried: more steps change nothing, and other work flows.
    other.put("still flowing", "q2");
    await run([big, other, lite], 6);
    expect(await lite.get("q2")).toEqual({ id: "q2", text: "still flowing" });
    expect(held()).toEqual(before);
  }, 60_000);

  it("bounds serialized Lite SQL contract inputs and replies for escaped preparation rows", async () => {
    const net = network();
    const lite = await liteDevice(net, {
      maxBlobBytes: 8 * 1024 * 1024,
      targetChunkBytes: 512 * 1024,
    });
    await lite.cycle();
    await lite.put("seed", "seed");
    await run([lite], 8);

    // Each canonical operation is about 300 KiB. Backslashes double in the
    // SQL reply's JSON string; CJK and emoji exercise UTF-8 boundaries too.
    const escaped = (id: string) =>
      `${"\\".repeat(149_000)}${id}漢字🙂${"\\".repeat(1_000)}`;
    const first = escaped("first");
    const second = escaped("second");
    await lite.put(first, "escaped-1");
    await lite.put(second, "escaped-2");
    // Force an outgoing SQL parameter near the 512 KiB raw-part cap to be
    // mostly backslashes, whose compact JSON contract representation is almost 1 MiB.
    const partEscaped = "\\".repeat(260_000);
    await lite.put(partEscaped, "escaped-part");

    await run([lite], 20);

    const wire = lite.native().sqlWireStats();
    expect(wire.rawObserverAcceptedOverflows).toBe(0);
    expect(wire.maxRequestBytes).toBeLessThanOrEqual(LITE_REPLICA_SQL_BYTES);
    expect(wire.maxRequestBytes).toBeGreaterThan(1_000_000);
    expect(Math.max(...wire.maxRequestParameterBytes)).toBeGreaterThan(
      1_000_000,
    );
    expect(wire.maxReplyBytes).toBeLessThanOrEqual(LITE_REPLICA_SQL_BYTES);
    expect(wire.maxReplyBytes).toBeGreaterThan(1_000_000);

    // Re-run the former page shape over these retained outcomes. Its raw
    // byte total fits even though the PS host's JSON reply envelope does not.
    const db = lite.native().db;
    const batch = (
      db
        .prepare(
          "SELECT batch FROM pdpp_transport_operation_outcomes WHERE operation_json LIKE '%escaped-1%' LIMIT 1",
        )
        .get() as { batch: string }
    ).batch;
    const previousPageSql = `WITH pieces AS (
      SELECT o.position,0 AS part,o.operation_json,o.encoding_failed
      FROM pdpp_transport_operation_outcomes o
      WHERE o.batch=? AND o.outcome IS NULL AND o.operation_json IS NOT NULL
      UNION ALL
      SELECT o.position,0 AS part,NULL AS operation_json,o.encoding_failed
      FROM pdpp_transport_operation_outcomes o
      WHERE o.batch=? AND o.outcome IS NULL AND o.operation_json IS NULL
        AND o.encoding_failed=1
      UNION ALL
      SELECT p.position,p.part,p.json AS operation_json,o.encoding_failed
      FROM pdpp_transport_operation_parts p
      JOIN pdpp_transport_operation_outcomes o
        ON o.batch=p.batch AND o.position=p.position
      WHERE p.batch=? AND o.outcome IS NULL
    ), remaining AS (
      SELECT position,part,operation_json,encoding_failed,
        sum(length(CAST(coalesce(operation_json,'') AS BLOB))) OVER (
          ORDER BY position,part ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
        ) - length(CAST(coalesce(operation_json,'') AS BLOB)) AS bytes_before
      FROM pieces
      WHERE position>? OR (position=? AND part>?)
    )
    SELECT position,part,operation_json,encoding_failed FROM remaining
    WHERE bytes_before<? ORDER BY position,part`;
    const previousParams = [batch, batch, batch, -1, -1, -1, 512 * 1024];
    const previousRows = db
      .prepare(previousPageSql)
      .all(...previousParams) as Record<string, unknown>[];
    const previousRawBytes = previousRawSqlBytes(
      previousPageSql,
      previousParams,
      previousRows,
    );
    const previousReplyBytes = Buffer.byteLength(
      JSON.stringify({ ok: true, value: previousRows }),
    );
    const previousOperations = previousRows
      .map(
        (row) =>
          JSON.parse(row.operation_json as string) as {
            data?: { id?: string };
          },
      )
      .map((operation) => operation.data?.id);
    expect(previousOperations).toContain("escaped-1");
    expect(previousOperations).toContain("escaped-2");
    expect(previousRawBytes).toBeLessThanOrEqual(LITE_REPLICA_SQL_BYTES);
    expect(previousReplyBytes).toBeGreaterThan(LITE_REPLICA_SQL_BYTES);
    expect(await lite.get("escaped-1")).toEqual({
      id: "escaped-1",
      text: first,
    });
    expect(await lite.get("escaped-2")).toEqual({
      id: "escaped-2",
      text: second,
    });
    expect(await lite.get("escaped-part")).toEqual({
      id: "escaped-part",
      text: partEscaped,
    });
    expect(
      lite
        .native()
        .db.prepare(
          "SELECT state FROM pdpp_transport_preparation WHERE batch=?",
        )
        .get(batch),
    ).toEqual({ state: "prepared" });
  }, 120_000);

  it.each([
    "middle part removed",
    "all parts removed",
    "same-length valid edit",
    "truncated part with matching digest",
    "extra part index",
    "negative part index",
    "skipped part index",
    "inline and parts both present",
  ])(
    "fails closed after restart when retained operation integrity is damaged: %s",
    async (fault) => {
      const fixture = await preparedMultipartFixture();
      const db = fixture.lite.native().db;
      const currentParts = [...fixture.parts];
      const joined = currentParts.map((part) => part.json).join("");
      const original = JSON.parse(joined) as { data: { text: string } };
      expect(original.data.text).toBe(fixture.text);
      const partBoundaries: number[] = [];
      let boundaryOffset = 0;
      for (const part of currentParts.slice(0, -1)) {
        boundaryOffset += Buffer.byteLength(part.json);
        partBoundaries.push(boundaryOffset);
      }
      const markerOffsets = [...joined.matchAll(/漢🙂/g)].map((match) =>
        Buffer.byteLength(joined.slice(0, match.index!)),
      );
      expect(markerOffsets).toHaveLength(2);
      for (const markerOffset of markerOffsets) {
        expect(
          Math.min(
            ...partBoundaries.map((partBoundary) =>
              Math.abs(partBoundary - markerOffset),
            ),
          ),
        ).toBeLessThanOrEqual(128);
      }

      if (fault === "middle part removed") {
        db.prepare(
          "DELETE FROM pdpp_transport_operation_parts WHERE batch=? AND position=? AND part=1",
        ).run(fixture.batch, fixture.position);
        const changed = JSON.parse(
          currentParts
            .filter((part) => part.part !== 1)
            .map((part) => part.json)
            .join(""),
        ) as { data: { text: string } };
        expect(changed.data.text).not.toBe(fixture.text);
      } else if (fault === "all parts removed") {
        db.prepare(
          "DELETE FROM pdpp_transport_operation_parts WHERE batch=? AND position=?",
        ).run(fixture.batch, fixture.position);
      } else if (fault === "same-length valid edit") {
        const changed = currentParts[1]!.json.replace("x", "y");
        expect(changed).toHaveLength(currentParts[1]!.json.length);
        db.prepare(
          "UPDATE pdpp_transport_operation_parts SET json=? WHERE batch=? AND position=? AND part=1",
        ).run(changed, fixture.batch, fixture.position);
        const changedOperation = JSON.parse(
          currentParts
            .map((part) => (part.part === 1 ? changed : part.json))
            .join(""),
        ) as { data: { text: string } };
        expect(changedOperation.data.text).not.toBe(fixture.text);
      } else if (fault === "truncated part with matching digest") {
        const truncated = currentParts[1]!.json.slice(1);
        db.prepare(
          "UPDATE pdpp_transport_operation_parts SET json=? WHERE batch=? AND position=? AND part=1",
        ).run(truncated, fixture.batch, fixture.position);
        const changed = currentParts
          .map((part) => (part.part === 1 ? truncated : part.json))
          .join("");
        expect(JSON.parse(changed)).toBeDefined();
        db.prepare(
          "UPDATE pdpp_transport_operation_retention SET operation_sha256=? WHERE batch=? AND position=?",
        ).run(
          `sha256:${createHash("sha256").update(changed).digest("hex")}`,
          fixture.batch,
          fixture.position,
        );
      } else if (fault === "extra part index") {
        db.prepare(
          "INSERT INTO pdpp_transport_operation_parts (batch,position,part,json) VALUES (?,?,?,?)",
        ).run(
          fixture.batch,
          fixture.position,
          currentParts.length,
          "ignored-extra-part",
        );
      } else if (fault === "negative part index") {
        db.prepare(
          "UPDATE pdpp_transport_operation_parts SET part=-1 WHERE batch=? AND position=? AND part=1",
        ).run(fixture.batch, fixture.position);
      } else if (fault === "skipped part index") {
        db.prepare(
          "UPDATE pdpp_transport_operation_parts SET part=99 WHERE batch=? AND position=? AND part=1",
        ).run(fixture.batch, fixture.position);
      } else {
        db.prepare(
          "UPDATE pdpp_transport_operation_outcomes SET operation_json=? WHERE batch=? AND position=?",
        ).run(joined, fixture.batch, fixture.position);
      }

      const retainedOutcome = db
        .prepare(
          "SELECT operation_json,encoding_failed FROM pdpp_transport_operation_outcomes WHERE batch=? AND position=?",
        )
        .get(fixture.batch, fixture.position);
      const retainedMetadata = db
        .prepare(
          "SELECT representation,part_count,operation_bytes,operation_sha256 FROM pdpp_transport_operation_retention WHERE batch=? AND position=?",
        )
        .get(fixture.batch, fixture.position);
      const retainedParts = db
        .prepare(
          "SELECT part,json FROM pdpp_transport_operation_parts WHERE batch=? AND position=? ORDER BY part",
        )
        .all(fixture.batch, fixture.position);

      db.prepare(
        "UPDATE pdpp_transport_preparation SET state='rebuilding',wait_json=NULL WHERE batch=?",
      ).run(fixture.batch);
      db.prepare(
        "UPDATE pdpp_transport_batches SET prepared=-2 WHERE batch=?",
      ).run(fixture.batch);
      fixture.lite.crashReopen();
      await run([fixture.lite], 8);

      const reopened = fixture.lite.native().db;
      const preparation = reopened
        .prepare(
          "SELECT state,wait_json FROM pdpp_transport_preparation WHERE batch=?",
        )
        .get(fixture.batch) as { state: string; wait_json: string | null };
      expect(preparation.state).toBe("prep_failed_unknown");
      expect(JSON.parse(preparation.wait_json!).dependency).toMatchObject({
        kind: "preparation",
        reason: "integrity",
      });
      expect(
        reopened
          .prepare(
            "SELECT operation_json,encoding_failed FROM pdpp_transport_operation_outcomes WHERE batch=? AND position=?",
          )
          .get(fixture.batch, fixture.position),
      ).toEqual(retainedOutcome);
      expect(
        reopened
          .prepare(
            "SELECT representation,part_count,operation_bytes,operation_sha256 FROM pdpp_transport_operation_retention WHERE batch=? AND position=?",
          )
          .get(fixture.batch, fixture.position),
      ).toEqual(retainedMetadata);
      expect(
        reopened
          .prepare(
            "SELECT part,json FROM pdpp_transport_operation_parts WHERE batch=? AND position=? ORDER BY part",
          )
          .all(fixture.batch, fixture.position),
      ).toEqual(retainedParts);
      expect(
        reopened
          .prepare("SELECT sequence FROM pdpp_transport_state WHERE id=1")
          .get(),
      ).toEqual({ sequence: fixture.sequence });
      expect(
        reopened
          .prepare("SELECT prepared FROM pdpp_transport_batches WHERE batch=?")
          .get(fixture.batch),
      ).toEqual({ prepared: -2 });
      expect(payloadSnapshot(reopened, fixture.batch)).toEqual(fixture.payload);
      expect(fixture.net.calls.puts).toHaveLength(
        fixture.publishedFragmentCalls,
      );
      expect(fixture.net.calls.registrations).toHaveLength(
        fixture.registrationCalls,
      );
      expect(
        reopened
          .prepare(
            "SELECT count(*) AS n FROM pdpp_transport_manifests_out WHERE batch=? AND state='published'",
          )
          .get(fixture.batch),
      ).toEqual({ n: 0 });
    },
    120_000,
  );

  it("reopens and replays supported inline preparations from the pre-parts schema", async () => {
    const net = network();
    const lite = await liteDevice(net, {
      maxBlobBytes: 1024 * 1024,
      targetChunkBytes: 512 * 1024,
    });
    await lite.cycle();
    await lite.put("seed", "seed");
    await run([lite], 8);
    const restoreNetwork = net.snapshot();
    lite.offline(true);
    const text = "legacy inline text ".repeat(10_000);
    await lite.put(text, "legacy-small");

    const db = lite.native().db;
    const retained = await prepareWithoutPublishing(
      lite,
      restoreNetwork,
      "SELECT batch,position FROM pdpp_transport_operation_outcomes WHERE operation_json LIKE '%legacy-small%' LIMIT 1",
    );
    const operation = db
      .prepare(
        "SELECT operation_json FROM pdpp_transport_operation_outcomes WHERE batch=? AND position=?",
      )
      .get(retained.batch, retained.position) as { operation_json: string };
    expect(Buffer.byteLength(operation.operation_json)).toBeLessThanOrEqual(
      256 * 1024 - 8 * 1024,
    );
    const batch = retained.batch;
    const payload = payloadSnapshot(db, batch);
    const sequence = (
      db
        .prepare("SELECT sequence FROM pdpp_transport_state WHERE id=1")
        .get() as {
        sequence: number;
      }
    ).sequence;

    // This matches the actual ea20eae pre-change schema: outcomes existed,
    // but the parts and new retention metadata tables did not.
    db.exec(
      "DROP TABLE pdpp_transport_operation_retention; DROP TABLE pdpp_transport_operation_parts;",
    );
    expect(
      db
        .prepare(
          "SELECT count(*) AS n FROM sqlite_master WHERE type='table' AND name IN ('pdpp_transport_operation_retention','pdpp_transport_operation_parts')",
        )
        .get(),
    ).toEqual({ n: 0 });

    for (let replay = 0; replay < 2; replay++) {
      const current = lite.native().db;
      if (replay > 0) {
        current
          .prepare(
            "UPDATE pdpp_transport_preparation SET state='rebuilding',wait_json=NULL WHERE batch=?",
          )
          .run(batch);
        current
          .prepare(
            "UPDATE pdpp_transport_batches SET prepared=-2 WHERE batch=?",
          )
          .run(batch);
      }
      lite.crashReopen();
      await rebuildOnePreparation(lite, batch);

      const reopened = lite.native().db;
      expect(
        reopened
          .prepare(
            "SELECT count(*) AS n FROM sqlite_master WHERE type='table' AND name IN ('pdpp_transport_operation_retention','pdpp_transport_operation_parts')",
          )
          .get(),
      ).toEqual({ n: 2 });
      const legacyState = reopened
        .prepare(
          "SELECT state,wait_json FROM pdpp_transport_preparation WHERE batch=?",
        )
        .get(batch) as { state: string; wait_json: string | null };
      expect(legacyState).toEqual({ state: "prepared", wait_json: null });
      expect(
        reopened
          .prepare(
            "SELECT operation_json FROM pdpp_transport_operation_outcomes WHERE batch=? AND position=?",
          )
          .get(batch, retained.position),
      ).toEqual({ operation_json: operation.operation_json });
      expect(
        reopened
          .prepare(
            "SELECT count(*) AS n FROM pdpp_transport_operation_retention WHERE batch=?",
          )
          .get(batch),
      ).toEqual({ n: 0 });
      expect(payloadSnapshot(reopened, batch)).toEqual(payload);
      expect(
        reopened
          .prepare("SELECT sequence FROM pdpp_transport_state WHERE id=1")
          .get(),
      ).toEqual({ sequence });
      expect(await lite.get("legacy-small")).toEqual({
        id: "legacy-small",
        text,
      });
    }
  }, 120_000);

  it("reopens a near-bound legacy inline preparation without publishing", async () => {
    const net = network();
    const lite = await liteDevice(net, {
      maxBlobBytes: 1024 * 1024,
      targetChunkBytes: 512 * 1024,
    });
    await lite.cycle();
    await lite.put("seed", "seed");
    await run([lite], 8);
    const restoreNetwork = net.snapshot();
    lite.offline(true);
    const text = "\\".repeat(250_000);
    await lite.put(text, "legacy-near-bound");

    const db = lite.native().db;
    const retained = await prepareWithoutPublishing(
      lite,
      restoreNetwork,
      "SELECT batch,position FROM pdpp_transport_operation_outcomes WHERE operation_json LIKE '%legacy-near-bound%' LIMIT 1",
    );
    const operation = db
      .prepare(
        "SELECT operation_json FROM pdpp_transport_operation_outcomes WHERE batch=? AND position=?",
      )
      .get(retained.batch, retained.position) as { operation_json: string };
    expect(Buffer.byteLength(operation.operation_json)).toBeGreaterThan(
      256 * 1024 - 8 * 1024,
    );
    expect(Buffer.byteLength(operation.operation_json)).toBeLessThanOrEqual(
      512 * 1024,
    );
    const batch = retained.batch;
    const payload = payloadSnapshot(db, batch);
    const sequence = (
      db
        .prepare("SELECT sequence FROM pdpp_transport_state WHERE id=1")
        .get() as {
        sequence: number;
      }
    ).sequence;
    // The pushed PR511 schema already had parts; this upgrade adds retention metadata.
    expect(
      db
        .prepare(
          "SELECT count(*) AS n FROM sqlite_master WHERE type='table' AND name='pdpp_transport_operation_parts'",
        )
        .get(),
    ).toEqual({ n: 1 });
    db.exec("DROP TABLE pdpp_transport_operation_retention;");
    db.prepare(
      "UPDATE pdpp_transport_preparation SET state='rebuilding',wait_json=NULL WHERE batch=?",
    ).run(batch);
    db.prepare(
      "UPDATE pdpp_transport_batches SET prepared=-2 WHERE batch=?",
    ).run(batch);
    const fragmentCalls = net.calls.puts.length;
    const registrationCalls = net.calls.registrations.length;
    lite.crashReopen();
    await rebuildOnePreparation(lite, batch, 64);

    const reopened = lite.native().db;
    const preparation = reopened
      .prepare(
        "SELECT state,wait_json FROM pdpp_transport_preparation WHERE batch=?",
      )
      .get(batch) as { state: string; wait_json: string | null };
    expect(preparation).toEqual({ state: "prepared", wait_json: null });
    expect(payloadSnapshot(reopened, batch)).toEqual(payload);
    expect(
      reopened
        .prepare("SELECT sequence FROM pdpp_transport_state WHERE id=1")
        .get(),
    ).toEqual({ sequence });
    expect(
      reopened
        .prepare("SELECT prepared FROM pdpp_transport_batches WHERE batch=?")
        .get(batch),
    ).toEqual({ prepared: 1 });
    expect(net.calls.puts).toHaveLength(fragmentCalls);
    expect(net.calls.registrations).toHaveLength(registrationCalls);
    expect(await lite.get("legacy-near-bound")).toEqual({
      id: "legacy-near-bound",
      text,
    });
    const wire = lite.native().sqlWireStats();
    expect(wire.maxRequestBytes).toBeLessThanOrEqual(LITE_REPLICA_SQL_BYTES);
    expect(wire.maxReplyBytes).toBeLessThanOrEqual(LITE_REPLICA_SQL_BYTES);
    expect(wire.maxReplyBytes).toBeGreaterThan(1_000_000);
  }, 120_000);

  it("reads a large pre-parts Node inline preparation in bounded SQL slices", async () => {
    const net = network();
    const lite = await liteDevice(net, {
      maxBlobBytes: 2 * 1024 * 1024,
      targetChunkBytes: 512 * 1024,
    });
    await lite.cycle();
    await lite.put("seed", "seed");
    await run([lite], 8);
    const restoreNetwork = net.snapshot();
    lite.offline(true);
    const text = `${"\\".repeat(449_995)}漢🙂${"\\".repeat(5)}`;
    await lite.put(text, "legacy-node-large");

    const db = lite.native().db;
    const retained = await prepareWithoutPublishing(
      lite,
      restoreNetwork,
      `SELECT o.batch,o.position FROM pdpp_transport_operation_outcomes o
       JOIN pdpp_transport_operation_parts p USING(batch,position)
       WHERE p.json LIKE '%legacy-node-large%' LIMIT 1`,
    );
    const operationParts = db
      .prepare(
        "SELECT json FROM pdpp_transport_operation_parts WHERE batch=? AND position=? ORDER BY part",
      )
      .all(retained.batch, retained.position) as { json: string }[];
    expect(operationParts.length).toBeGreaterThan(1);
    const operation = operationParts.map((part) => part.json).join("");
    expect(Buffer.byteLength(operation)).toBeGreaterThan(512 * 1024);
    const batch = retained.batch;
    const payload = payloadSnapshot(db, batch);
    const sequence = (
      db
        .prepare("SELECT sequence FROM pdpp_transport_state WHERE id=1")
        .get() as { sequence: number }
    ).sequence;

    // Model a supported pre-parts Node row: the old shared engine retained
    // this admitted operation inline, before Lite introduced its 248 KiB cap.
    db.prepare(
      "UPDATE pdpp_transport_operation_outcomes SET operation_json=?,encoding_failed=0 WHERE batch=? AND position=?",
    ).run(operation, batch, retained.position);
    db.prepare(
      "DELETE FROM pdpp_transport_operation_parts WHERE batch=? AND position=?",
    ).run(batch, retained.position);
    db.exec(
      "DROP TABLE pdpp_transport_operation_retention; DROP TABLE pdpp_transport_operation_parts;",
    );
    db.prepare(
      "UPDATE pdpp_transport_preparation SET state='rebuilding',wait_json=NULL WHERE batch=?",
    ).run(batch);
    db.prepare(
      "UPDATE pdpp_transport_batches SET prepared=-2 WHERE batch=?",
    ).run(batch);
    const fragmentCalls = net.calls.puts.length;
    const registrationCalls = net.calls.registrations.length;

    lite.crashReopen();
    await rebuildOnePreparation(lite, batch, 64);

    const reopened = lite.native().db;
    expect(
      reopened
        .prepare(
          "SELECT state,wait_json FROM pdpp_transport_preparation WHERE batch=?",
        )
        .get(batch),
    ).toEqual({ state: "prepared", wait_json: null });
    expect(
      reopened
        .prepare(
          "SELECT operation_json FROM pdpp_transport_operation_outcomes WHERE batch=? AND position=?",
        )
        .get(batch, retained.position),
    ).toEqual({ operation_json: operation });
    expect(payloadSnapshot(reopened, batch)).toEqual(payload);
    expect(
      reopened
        .prepare("SELECT sequence FROM pdpp_transport_state WHERE id=1")
        .get(),
    ).toEqual({ sequence });
    expect(
      reopened
        .prepare("SELECT prepared FROM pdpp_transport_batches WHERE batch=?")
        .get(batch),
    ).toEqual({ prepared: 1 });
    expect(net.calls.puts).toHaveLength(fragmentCalls);
    expect(net.calls.registrations).toHaveLength(registrationCalls);
    expect(await lite.get("legacy-node-large")).toEqual({
      id: "legacy-node-large",
      text,
    });

    const wire = lite.native().sqlWireStats();
    expect(wire.maxRequestBytes).toBeLessThanOrEqual(LITE_REPLICA_SQL_BYTES);
    expect(wire.maxReplyBytes).toBeLessThanOrEqual(LITE_REPLICA_SQL_BYTES);
    expect(wire.maxReplyBytes).toBeLessThan(600_000);
  }, 120_000);

  it("holds pre-retention multipart preparations without releasing the payload", async () => {
    const net = network();
    const lite = await liteDevice(net, {
      maxBlobBytes: 2 * 1024 * 1024,
      targetChunkBytes: 512 * 1024,
    });
    await lite.cycle();
    await lite.put("seed", "seed");
    await run([lite], 8);
    const restoreNetwork = net.snapshot();
    lite.offline(true);
    const text = "x".repeat(600_000);
    await lite.put(text, "legacy-parts");

    const db = lite.native().db;
    const retained = await prepareWithoutPublishing(
      lite,
      restoreNetwork,
      `SELECT o.batch,o.position FROM pdpp_transport_operation_outcomes o
       JOIN pdpp_transport_operation_parts p USING(batch,position)
       WHERE p.json LIKE '%legacy-parts%' LIMIT 1`,
    );
    const batch = retained.batch;
    const payload = payloadSnapshot(db, batch);
    const sequence = (
      db
        .prepare("SELECT sequence FROM pdpp_transport_state WHERE id=1")
        .get() as { sequence: number }
    ).sequence;
    const partRows = db
      .prepare(
        "SELECT part,json FROM pdpp_transport_operation_parts WHERE batch=? AND position=? ORDER BY part",
      )
      .all(batch, retained.position);
    expect(partRows.length).toBeGreaterThan(1);
    // Pushed PR511 kept parts without expected count/hash; never infer a new
    // digest from whichever part rows happen to survive.
    db.exec("DROP TABLE pdpp_transport_operation_retention;");
    db.prepare(
      "UPDATE pdpp_transport_preparation SET state='rebuilding',wait_json=NULL WHERE batch=?",
    ).run(batch);
    db.prepare(
      "UPDATE pdpp_transport_batches SET prepared=-2 WHERE batch=?",
    ).run(batch);
    const fragmentCalls = net.calls.puts.length;
    const registrationCalls = net.calls.registrations.length;

    lite.crashReopen();
    await expect(rebuildOnePreparation(lite, batch, 8)).rejects.toThrow(
      "legacy preparation state",
    );

    const reopened = lite.native().db;
    const preparation = reopened
      .prepare(
        "SELECT state,wait_json FROM pdpp_transport_preparation WHERE batch=?",
      )
      .get(batch) as { state: string; wait_json: string | null };
    expect(preparation.state).toBe("prep_failed_unknown");
    expect(JSON.parse(preparation.wait_json!).dependency).toMatchObject({
      kind: "preparation",
      reason: "integrity",
    });
    expect(
      reopened
        .prepare(
          "SELECT count(*) AS n FROM pdpp_transport_operation_retention WHERE batch=?",
        )
        .get(batch),
    ).toEqual({ n: 0 });
    expect(
      reopened
        .prepare(
          "SELECT part,json FROM pdpp_transport_operation_parts WHERE batch=? AND position=? ORDER BY part",
        )
        .all(batch, retained.position),
    ).toEqual(partRows);
    expect(payloadSnapshot(reopened, batch)).toEqual(payload);
    expect(
      reopened
        .prepare("SELECT sequence FROM pdpp_transport_state WHERE id=1")
        .get(),
    ).toEqual({ sequence });
    expect(
      reopened
        .prepare("SELECT prepared FROM pdpp_transport_batches WHERE batch=?")
        .get(batch),
    ).toEqual({ prepared: -2 });
    expect(net.calls.puts).toHaveLength(fragmentCalls);
    expect(net.calls.registrations).toHaveLength(registrationCalls);
  }, 120_000);

  it("prepares a large local operation through bounded native SQL", async () => {
    const net = network();
    const lite = await liteDevice(net, {
      maxBlobBytes: 8 * 1024 * 1024,
      targetChunkBytes: 512 * 1024,
    });
    await lite.cycle();
    await lite.put("seed", "seed");
    await run([lite], 8);

    // This 8.5 MiB operation is over the phone's SQL call bound but within
    // Lite's canonical value limit. Its retained prepare row must be split.
    const text = "x".repeat(8_500_000);
    const receipt = await lite.put(text, "large");
    expect(receipt.operationCount).toBe(1);
    expect(await lite.get("large")).toEqual({ id: "large", text });

    await run([lite], 16);

    // The SQLite-backed Lite SQL contract oracle enforces
    // LITE_REPLICA_SQL_BYTES on each input and result. Reaching prepared proves
    // the retained operation was read back without one oversized contract call.
    const prepared = lite
      .native()
      .db.prepare(
        `SELECT p.state,p.wait_json,b.sequence,b.prepared,b.admission_json,
                b.total_bytes,m.state AS manifest_state,m.outcome AS manifest_outcome
         FROM pdpp_transport_preparation p
         JOIN pdpp_transport_batches b ON b.batch=p.batch
         LEFT JOIN pdpp_transport_manifests_out m ON m.batch=p.batch
         WHERE b.total_bytes>1000000 ORDER BY b.sequence DESC LIMIT 1`,
      )
      .get() as
      { state: string; prepared: number; total_bytes: number } | undefined;
    expect(prepared).toMatchObject({ state: "prepared", prepared: 1 });
    expect(prepared?.total_bytes).toBeGreaterThan(1_000_000);
    const stored = lite
      .native()
      .db.prepare(
        `SELECT o.operation_json, count(p.part) AS parts,
                max(length(CAST(p.json AS BLOB))) AS maxPartBytes
         FROM pdpp_transport_operation_outcomes o
         LEFT JOIN pdpp_transport_operation_parts p
           ON p.batch=o.batch AND p.position=o.position
         WHERE o.operation_json IS NULL AND o.encoding_failed=0
         GROUP BY o.batch,o.position ORDER BY parts DESC LIMIT 1`,
      )
      .get() as
      { operation_json: null; parts: number; maxPartBytes: number } | undefined;
    expect(stored?.operation_json).toBeNull();
    expect(stored?.parts).toBeGreaterThan(1);
    expect(stored?.maxPartBytes).toBeLessThanOrEqual(512 * 1024);
    expect(await lite.get("large")).toEqual({ id: "large", text });
  }, 120_000);

  it("pairs the phone's operation bound with the limits version that re-admits held batches", () => {
    // A build that raises the bound must raise REPLICA_LIMITS_VERSION too, or
    // batches held under the old bound stay held after the upgrade.
    expect({
      bound: LITE_CANONICAL_MAX_OPERATION_BYTES,
      version: REPLICA_LIMITS_VERSION,
    }).toEqual({ bound: 17 * 1024 * 1024, version: 3 });
  });

  /**
   * Process loss after an upload attached its staged bytes and before it
   * released them: the attach committed, the release did not. The next step
   * reclaims the bytes before it transfers anything.
   */
  it("reclaims replica bytes an upload crash left attached", async () => {
    const net = network();
    const node = transportDevice(net);
    const lite = await liteDevice(net);
    await lite.cycle();
    await lite.put("crash mid upload", "u");
    lite.process.crashAtRelease();
    for (let i = 0; i < 4 && !lite.process.dead; i++) {
      clock.advance(10_000);
      await lite.cycle().catch((error: unknown) => {
        if (!lite.process.dead) throw error;
      });
    }
    expect(lite.process.dead).toBe(true);
    const bytes = () =>
      lite.native().db.prepare("SELECT count(*) AS n FROM lite_bytes").get();
    // The orphan: attached, never released.
    expect(bytes()).not.toEqual({ n: 0 });
    lite.crashReopen();
    await run([node, lite]);
    expect(node.get("u")).toEqual({ id: "u", text: "crash mid upload" });
    expect(bytes()).toEqual({ n: 0 });
    expect(
      lite
        .native()
        .db.prepare("SELECT count(*) AS n FROM pdpp_lite_replica_transient")
        .get(),
    ).toEqual({ n: 0 });
  }, 60_000);

  /** Cycle the phone until its armed crash fires. */
  async function crashUntilDead(lite: LiteDevice) {
    for (let i = 0; i < 6 && !lite.process.dead; i++) {
      clock.advance(10_000);
      await lite.cycle().catch((error: unknown) => {
        if (!lite.process.dead) throw error;
      });
    }
    expect(lite.process.dead).toBe(true);
  }
  /** Replica bytes the phone holds, and the transient rows that list them. */
  const inventory = (lite: LiteDevice) =>
    lite
      .native()
      .db.prepare(
        `SELECT (SELECT count(*) FROM lite_bytes) AS bytes,
                (SELECT count(*) FROM pdpp_lite_replica_transient) AS transient`,
      )
      .get();
  /**
   * Reopen after the crash and step on: every step starts by reclaiming
   * what a dead process left attached, and releases what it attaches, so
   * no replica bytes remain between steps.
   */
  async function recoverBounded(lite: LiteDevice, node: TransportDevice) {
    expect(inventory(lite)).not.toEqual({ bytes: 0, transient: 0 });
    lite.crashReopen();
    for (let i = 0; i < 12; i++) {
      clock.advance(10_000);
      await node.cycle();
      await lite.cycle();
      expect(inventory(lite)).toEqual({ bytes: 0, transient: 0 });
    }
  }

  /**
   * Process loss during the native PUT, after the attach committed: the
   * object is in storage and the release never ran. The reopened phone
   * frees the bytes and publishes the batch.
   */
  it("bounds replica bytes after a crash during the native upload, then publishes", async () => {
    const net = network();
    const node = transportDevice(net);
    const lite = await liteDevice(net);
    await lite.cycle();
    await lite.put("crash in put", "u");
    lite.process.crashInUpload();
    await crashUntilDead(lite);
    await recoverBounded(lite, node);
    expect(node.get("u")).toEqual({ id: "u", text: "crash in put" });
  }, 60_000);

  /**
   * Process loss during a download, after its bytes were attached and
   * before they were read and released. The reopened phone frees them and
   * imports the batch.
   */
  it("bounds replica bytes after a crash during a download, then imports", async () => {
    const net = network();
    const node = transportDevice(net);
    const lite = await liteDevice(net);
    await lite.cycle();
    node.put("crash in get", "d");
    await run([node], 4);
    lite.process.crashInRead();
    await crashUntilDead(lite);
    await recoverBounded(lite, node);
    expect(await lite.get("d")).toEqual({ id: "d", text: "crash in get" });
  }, 60_000);
});
