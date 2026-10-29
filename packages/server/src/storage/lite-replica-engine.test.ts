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
  createLiteCanonicalStore,
  createLiteReplicaEngine,
  createLiteReplicaStorage,
  createLiteReplicationRuntime,
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
  let dead = false;
  const alive = () => {
    if (dead) throw new SimulatedCrash("process lost");
  };
  const port: LiteReplicaPersistence = {
    ...inner,
    transaction(run) {
      const index = ++count;
      return inner.transaction(async (tx) => {
        alive();
        const result = await run(tx);
        alive();
        if (index === crashAt) {
          dead = true;
          throw new SimulatedCrash(`crash at transaction ${index}`);
        }
        return result;
      });
    },
    async stageBytes(chunks) {
      alive();
      return inner.stageBytes(chunks);
    },
  };
  return {
    port,
    count: () => count,
    crashAfter(k: number) {
      crashAt = count + k;
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
async function liteDevice(net: Network, opts: { enabled?: boolean } = {}) {
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
  const open = () => {
    const persistence = process.port;
    const canonical = createLiteCanonicalStore({
      persistence,
      enabled: true,
      context,
      authenticateReplica,
    });
    const storage = createLiteReplicaStorage({
      persistence,
      transfers: createMemoryReplicaObjectTransfers(persistence, {
        objects: net.blobs,
      }).port,
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
      register: guarded(net.port.register),
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
        maxBlobBytes: 8192,
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
