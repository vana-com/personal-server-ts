// The view-change event: one call per operation that changed what the local
// database serves, none for an operation that changed nothing.
//
// Two real SQLite devices share one in-memory registry and blob store. Device
// A collects and publishes; device B is the consumer (the Web tab) whose
// listener is under test.
import { afterEach, describe, expect, it } from "vitest";
import {
  connectionQueue,
  createLocalSync,
  openLocalDb,
  type LocalSync,
  type SqlDriver,
  type ViewChange,
} from "@opendatalabs/personal-server-ts-core/localdb";
import {
  createMemoryStreamSyncBlobs,
  createMemoryStreamSyncRegistry,
  type MemoryStreamSyncRegistry,
  type StreamSyncBlobs,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const OWNER = `0x${"11".repeat(20)}` as const;
const STREAMS = ["s0", "s1"];
const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
});

interface Shared {
  registry: MemoryStreamSyncRegistry;
  blobs: StreamSyncBlobs;
}

async function device(
  shared: Shared,
  id: string,
  hooks: {
    blobs?: (inner: StreamSyncBlobs, db: SqlDriver) => StreamSyncBlobs;
  } = {},
): Promise<LocalSync & { readonly db: SqlDriver }> {
  const db = await openLocalDb(openBetterSqlite3(":memory:"), {
    owner: OWNER,
    network: "test",
    deviceId: id,
  });
  drivers.push(db);
  let op = 0;
  const sync = createLocalSync(
    {
      db,
      queue: connectionQueue(),
      registry: shared.registry,
      blobs: hooks.blobs?.(shared.blobs, db) ?? shared.blobs,
      ownerAddress: OWNER,
      keys: {
        namespaceHmac: async () => new Uint8Array(32),
        encrypt: async (_s, b) => b,
        encryptPart: async (_s, b) => b,
        decrypt: async (_s, b) => b,
      },
      signer: { signAddData: async () => "0x00" },
      logger: { info: () => {}, warn: () => {} },
      now: () => 1000,
      newOp: () => `${id}-op-${++op}`,
    },
    {
      resolveArtifact: (digest) => ({
        connector: digest,
        version: "1",
        streams: STREAMS.map((name) => ({
          name,
          semantics: "mutable_state" as const,
          primaryKey: ["id"],
        })),
      }),
      declaredStreams: () => STREAMS,
      olderVersionReads: () => true,
    },
  );
  return Object.assign(sync, { db });
}

let runs = 0;
async function collect(sync: LocalSync, connector: string, version = 1) {
  const runId = `run-${++runs}`;
  await sync.intake.begin(runId, {
    connector,
    artifactDigest: connector,
    wantFull: true,
    owner: { address: OWNER, leaseId: null },
  });
  await sync.intake.batch(runId, {
    batch: 0,
    records: STREAMS.map((stream) => ({
      stream,
      data: { id: `${stream}-0`, version },
    })),
  });
  await sync.intake.end(runId, {
    outcome: "succeeded",
    coveredStreams: STREAMS,
    lastBatch: 0,
  });
}

function shared(): Shared {
  return {
    registry: createMemoryStreamSyncRegistry() as MemoryStreamSyncRegistry,
    blobs: createMemoryStreamSyncBlobs(),
  };
}

function listen(sync: LocalSync) {
  const seen: ViewChange[] = [];
  const unsubscribe = sync.viewChanges.subscribe((c) => seen.push(c));
  return { seen, unsubscribe };
}

/** Let the subscriber's baseline read land before the operation under test. */
const settled = () => new Promise((r) => setTimeout(r, 20));

describe("view changes", () => {
  it("a cycle that applies nothing and publishes nothing emits nothing", async () => {
    const s = shared();
    const a = await device(s, "a");
    const b = await device(s, "b");
    await collect(a, "c0");
    await a.cycle();
    await b.cycle();
    const { seen } = listen(b);
    await settled();
    await b.cycle();
    await b.cycle();
    expect(seen).toEqual([]);
  });

  it("a cycle that applies a head emits once, naming the connection", async () => {
    const s = shared();
    const a = await device(s, "a");
    const b = await device(s, "b");
    const { seen } = listen(b);
    await settled();
    await collect(a, "c0");
    await collect(a, "c1");
    await a.cycle();
    await b.cycle();
    // Two connections applied by one cycle: one event for the cycle's
    // operations, not one per record or per stream.
    const ids = seen.flatMap((c) => c.connectionIds);
    expect(new Set(ids).size).toBe(2);
    expect(seen.length).toBeLessThanOrEqual(2); // one per connection operation
    expect(seen.length).toBeGreaterThanOrEqual(1);
    const before = seen.length;
    await b.cycle();
    expect(seen).toHaveLength(before); // the follow-up cycle is silent
  });

  it("a connection's own cycle emits exactly once for one applied head", async () => {
    const s = shared();
    const a = await device(s, "a");
    const b = await device(s, "b");
    await collect(a, "c0");
    await a.cycle();
    await b.cycle();
    const { seen } = listen(b);
    await settled();
    await collect(a, "c0", 2);
    await a.cycle();
    await b.cycle();
    expect(seen).toHaveLength(1);
    expect(seen[0]!.connectionIds).toHaveLength(1);
  });

  it("a publish that moves no records or control state emits nothing", async () => {
    const s = shared();
    const a = await device(s, "a");
    await collect(a, "c0");
    await a.cycle(); // the first publish activates the connection's control row
    await collect(a, "c0", 2);
    const { seen } = listen(a);
    await settled();
    await a.cycle(); // publishes run 2's rows; the view already shows them
    expect(seen).toEqual([]);
  });

  it("the first publish emits once: the connection's control state moves", async () => {
    const s = shared();
    const a = await device(s, "a");
    await collect(a, "c0");
    const { seen } = listen(a);
    await settled();
    await a.cycle();
    expect(seen).toHaveLength(1);
  });

  it("a connection delete emits for the purge", async () => {
    const s = shared();
    const a = await device(s, "a");
    const b = await device(s, "b");
    await collect(a, "c0");
    await a.cycle();
    await b.cycle();
    const { seen } = listen(b);
    await settled();
    await b.deleter.requestConnectionDelete("c0");
    expect(seen.length).toBeGreaterThanOrEqual(1);
    expect(seen.flatMap((c) => c.connectionIds)).toHaveLength(seen.length);
  });

  it("a run end on the device itself emits for its records", async () => {
    const s = shared();
    const a = await device(s, "a");
    const { seen } = listen(a);
    await settled();
    await collect(a, "c0");
    await settled();
    expect(seen.length).toBeGreaterThanOrEqual(1);
  });

  it("an apply that commits one connection then throws still emits", async () => {
    const s = shared();
    const a = await device(s, "a");
    await collect(a, "c0");
    await collect(a, "c1");
    await a.cycle();
    // Once any record has landed on B, the next blob read fails: the apply
    // has committed part of its work when it throws.
    let armed = false;
    const b = await device(s, "b", {
      blobs: (inner, db) => ({
        ...inner,
        get: async (key) => {
          if (armed) {
            const rows = await db.query("SELECT 1 AS x FROM records LIMIT 1");
            if (rows.length > 0) throw new Error("storage down");
          }
          return inner.get(key);
        },
      }),
    });
    const { seen } = listen(b);
    await settled();
    armed = true;
    await expect(b.apply()).rejects.toThrow("storage down");
    const landed = await b.db.query(
      "SELECT DISTINCT connection_id FROM records",
    );
    expect(landed.length).toBeGreaterThan(0);
    expect(seen).toHaveLength(1);
    expect(seen[0]!.connectionIds.length).toBeGreaterThan(0);
  });

  it("unsubscribe stops delivery, and a throwing listener does not hurt the others", async () => {
    const s = shared();
    const a = await device(s, "a");
    const b = await device(s, "b");
    const first: ViewChange[] = [];
    const second: ViewChange[] = [];
    const off = b.viewChanges.subscribe((c) => first.push(c));
    b.viewChanges.subscribe(() => {
      throw new Error("listener bug");
    });
    b.viewChanges.subscribe((c) => second.push(c));
    await settled();
    await collect(a, "c0");
    await a.cycle();
    await b.cycle();
    expect(first.length).toBeGreaterThanOrEqual(1);
    expect(second).toHaveLength(first.length);
    off();
    off(); // a second call is harmless
    const delivered = first.length;
    await collect(a, "c0", 2);
    await a.cycle();
    await b.cycle();
    expect(first).toHaveLength(delivered);
    expect(second.length).toBeGreaterThan(delivered);
  });

  it("an event carries connection ids only", async () => {
    const s = shared();
    const a = await device(s, "a");
    const b = await device(s, "b");
    const { seen } = listen(b);
    await settled();
    await collect(a, "c0");
    await a.cycle();
    await b.cycle();
    expect(Object.keys(seen[0]!)).toEqual(["connectionIds"]);
  });
});
