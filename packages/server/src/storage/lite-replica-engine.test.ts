/**
 * The PS-Lite replication engine (lite `replication-engine.ts`) against a
 * Node writer, over one simulated network: the same core phase engine on
 * both hosts, the Lite side over the Lite ports (SQLite-backed persistence
 * double, in-memory native transfers sharing the network's object store).
 */
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
  LITE_REPLICATION_LIMITS,
  type LiteReplicaPersistence,
} from "@opendatalabs/personal-server-ts-lite";
import { createMemoryReplicaObjectTransfers } from "../../../lite/src/test-support/replication.js";
import { createSqliteLiteReplicaPersistence } from "./lite-replica-sqlite.test-utils.js";
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
  opts: { enabled?: boolean; maxBlobBytes?: number } = {},
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
        targetChunkBytes: 4000,
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

  it("pairs the phone's operation bound with the limits version that re-admits held batches", () => {
    // A build that raises the bound must raise REPLICA_LIMITS_VERSION too, or
    // batches held under the old bound stay held after the upgrade.
    expect({
      bound: LITE_CANONICAL_MAX_OPERATION_BYTES,
      version: REPLICA_LIMITS_VERSION,
    }).toEqual({ bound: 256 * 1024 - 8 * 1024, version: 2 });
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
