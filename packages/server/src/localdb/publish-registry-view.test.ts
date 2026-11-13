// What a publish reads from the registry before it posts.
//
// A publish of several streams lists the connection's stream rows once, and a
// stream's first snapshot starts from that listing and from the control row
// another stream's turn just read, instead of reading each row again. The
// listing is only a starting point: the commit's own read of the stream row,
// made right before the compare-and-set, is always live, and a snapshot that
// repeats (a retry, a discarded candidate) reads live too.
//
// Memory registry and storage, the real SQLite driver and queue. The registry
// wrapper records every call in order, so a test can say what was read when.
import { describe, expect, it, afterEach, vi } from "vitest";
import {
  connectionQueue,
  createLocalSync,
  openLocalDb,
  publishConnection,
  type LocalSyncDeps,
  type SqlDriver,
} from "@opendatalabs/personal-server-ts-core/localdb";
import {
  createMemoryStreamSyncBlobs,
  createMemoryStreamSyncRegistry,
  type StreamSyncBlobs,
  type StreamSyncRegistry,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import { controlScope } from "@opendatalabs/personal-server-ts-stream-sync";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const OWNER = `0x${"11".repeat(20)}` as const;
const CONNECTOR = "fixture";
const CONNECTION_ID = `pdpp.${CONNECTOR}~`;
const CONTROL = controlScope(CONNECTOR, "");

type Call = {
  readonly kind: "read" | "post" | "list" | "get" | "put";
  readonly scope: string;
  readonly expectedVersion?: string;
};

type Stores = {
  readonly registry: StreamSyncRegistry;
  readonly blobs: StreamSyncBlobs;
};

type Options = {
  readonly streams: number;
  /** Distinguishes the rows of two devices that publish the same streams. */
  readonly tag?: string;
  /** Devices that share one registry and one store. */
  readonly stores?: Stores;
  /** What the listing answers; by default the registry's own answer. */
  readonly listing?: StreamSyncRegistry["listStreamRows"];
};

const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
});

const streamOfKey = (key: string) => /\.(s\d+)\//.exec(key)?.[1] ?? null;
const streamOfScope = (scope: string) => /\.(s\d+)$/.exec(scope)?.[1] ?? null;

function sharedStores(): Stores {
  return {
    registry: createMemoryStreamSyncRegistry(),
    blobs: createMemoryStreamSyncBlobs(),
  };
}

async function device(options: Options) {
  const stores = options.stores ?? sharedStores();
  const db = await openLocalDb(openBetterSqlite3(":memory:"), {
    owner: OWNER,
    network: "test",
    deviceId: options.tag ?? "d",
  });
  drivers.push(db);
  const names = Array.from({ length: options.streams }, (_, i) => `s${i}`);
  const calls: Call[] = [];
  const registry: StreamSyncRegistry = {
    async read(scope) {
      calls.push({ kind: "read", scope });
      return stores.registry.read(scope);
    },
    async post(request) {
      calls.push({
        kind: "post",
        scope: request.scope,
        expectedVersion: request.expectedVersion,
      });
      return stores.registry.post(request);
    },
    listControlRows: () => stores.registry.listControlRows(),
    async listStreamRows(connector) {
      calls.push({ kind: "list", scope: connector });
      return (options.listing ?? ((c) => stores.registry.listStreamRows(c)))(
        connector,
      );
    },
  };
  const blobs: StreamSyncBlobs = {
    async get(key) {
      calls.push({ kind: "get", scope: key });
      return stores.blobs.get(key);
    },
    async put(key, bytes, beforeAttempt) {
      calls.push({ kind: "put", scope: key });
      return stores.blobs.put(key, bytes, beforeAttempt);
    },
  };
  const warn = vi.fn();
  let op = 0;
  const deps: LocalSyncDeps = {
    db,
    queue: connectionQueue(),
    registry,
    blobs,
    ownerAddress: OWNER,
    keys: {
      namespaceHmac: async () => new Uint8Array(32),
      encrypt: async (_scope, b) => b,
      encryptPart: async (_scope, b) => b,
      decrypt: async (_scope, b) => b,
    },
    signer: { signAddData: async () => "0x00" },
    logger: { info: () => {}, warn },
    now: () => 1000,
    newOp: () => `op-${++op}`,
  };
  const sync = createLocalSync(deps, {
    resolveArtifact: (digest) => ({
      connector: digest,
      version: "1",
      streams: names.map((name) => ({
        name,
        semantics: "mutable_state" as const,
        primaryKey: ["id"],
      })),
    }),
    declaredStreams: () => names,
    olderVersionReads: () => true,
  });
  await sync.intake.begin("run-1", {
    connector: CONNECTOR,
    artifactDigest: CONNECTOR,
    wantFull: true,
    owner: { address: OWNER, leaseId: null },
  });
  await sync.intake.batch("run-1", {
    batch: 0,
    records: names.flatMap((stream) =>
      [1, 2].map((n) => ({
        stream,
        data: { id: `${stream}-${options.tag ?? "d"}-${n}` },
      })),
    ),
  });
  await sync.intake.end("run-1", {
    outcome: "succeeded",
    coveredStreams: names,
    lastBatch: 0,
  });
  // What the run's intake called is not part of the publish.
  calls.length = 0;
  return { deps, calls, names, stores, warn };
}

const reads = (calls: readonly Call[], scope: (s: string) => boolean) =>
  calls.filter((c) => c.kind === "read" && scope(c.scope));

describe("what a publish reads before it posts", () => {
  it("does not make the first stream wait for the listing", async () => {
    // From the publish on, the listing is held until the first stream has
    // read its own row and uploaded. If the first snapshot waited for the
    // listing this would never finish.
    let holding = false;
    let release: () => void = () => {};
    const held = new Promise<void>((resolve) => (release = resolve));
    const stores = sharedStores();
    const { deps, calls } = await device({
      streams: 3,
      stores,
      listing: async (connector) => {
        if (holding) await held;
        return stores.registry.listStreamRows(connector);
      },
    });
    holding = true;
    const done = publishConnection(deps, CONNECTION_ID);
    await vi.waitFor(() => {
      expect(calls.some((c) => c.kind === "put")).toBe(true);
    });
    expect(
      calls.some((c) => c.kind === "read" && streamOfScope(c.scope) === "s0"),
    ).toBe(true);
    release();
    const results = await done;
    expect(results.map((r) => r.outcome)).toEqual(Array(3).fill("published"));
  });

  it("lists the stream rows once, and reads each stream's row only right before its post", async () => {
    const { deps, calls, names } = await device({ streams: 6 });
    const results = await publishConnection(deps, CONNECTION_ID);
    expect(results.map((r) => r.outcome)).toEqual(Array(6).fill("published"));

    expect(calls.filter((c) => c.kind === "list")).toHaveLength(1);
    // One strict read per stream before its post, plus the first stream's
    // snapshot read (it does not wait for the listing). The other five
    // snapshots used the listing.
    const streamReads = reads(calls, (s) => s !== CONTROL);
    expect(streamReads).toHaveLength(6 + 1);
    for (const stream of names) {
      const at = (pred: (c: Call) => boolean) => calls.findIndex(pred);
      const post = at(
        (c) => c.kind === "post" && streamOfScope(c.scope) === stream,
      );
      // The read the post rests on is the LAST read of the stream's row.
      const read = calls.reduce(
        (last, c, i) =>
          c.kind === "read" && streamOfScope(c.scope) === stream ? i : last,
        -1,
      );
      const lastPut = calls.reduce(
        (last, c, i) =>
          c.kind === "put" && streamOfKey(c.scope) === stream ? i : last,
        -1,
      );
      // The read the post rests on was made after the stream's own uploads.
      expect(read).toBeGreaterThan(lastPut);
      expect(read).toBeLessThan(post);
    }
  });

  it("reads the control row in the first stream's snapshot, and around every post", async () => {
    const { deps, calls } = await device({ streams: 6 });
    await publishConnection(deps, CONNECTION_ID);
    // First stream: the read that finds it absent, then the read that
    // confirms its own post. The other five snapshots reuse that read. Every
    // stream then checks the control row before and after its post.
    expect(reads(calls, (s) => s === CONTROL)).toHaveLength(2 + 2 * 6);
  });

  it("does not list for a connection of one stream", async () => {
    const { deps, calls } = await device({ streams: 1 });
    const results = await publishConnection(deps, CONNECTION_ID);
    expect(results.map((r) => r.outcome)).toEqual(["published"]);
    expect(calls.filter((c) => c.kind === "list")).toHaveLength(0);
    // Its snapshot and its commit each read the stream row.
    expect(reads(calls, (s) => s !== CONTROL)).toHaveLength(2);
  });

  it("publishes by reading each row itself when the listing fails", async () => {
    const { deps, calls, warn } = await device({
      streams: 3,
      listing: async () => {
        throw new Error("listing down");
      },
    });
    const results = await publishConnection(deps, CONNECTION_ID);
    expect(results.map((r) => r.outcome)).toEqual(Array(3).fill("published"));
    expect(warn).toHaveBeenCalled();
    expect(reads(calls, (s) => s !== CONTROL)).toHaveLength(6);
  });

  it("a stale listing cannot stand in for the read before the post", async () => {
    // Device one publishes every stream. Device two's listing is from before
    // that: it says the rows are absent.
    const stores = sharedStores();
    const first = await device({ streams: 2, tag: "one", stores });
    await publishConnection(first.deps, CONNECTION_ID);
    const second = await device({
      streams: 2,
      tag: "two",
      stores,
      listing: async () => [],
    });
    const results = await publishConnection(second.deps, CONNECTION_ID);

    // The publish starts from the (stale) listing. A later apply lists again.
    expect(second.calls[0]).toEqual({ kind: "list", scope: CONNECTOR });
    // The candidate built on "absent" would post version 1. The row is at 1
    // already; the live read before the post found that and the post never
    // went out.
    expect(
      second.calls.filter(
        (c) => c.kind === "post" && c.expectedVersion === "1",
      ),
    ).toEqual([]);
    for (const stream of second.names) {
      const live = await stores.registry.read(`pdpp.${CONNECTOR}~.${stream}`);
      expect(live).toMatchObject({ found: true });
      if (live.found) expect(live.version).toBeGreaterThanOrEqual(1);
    }
    expect(results.every((r) => r.outcome !== "refused")).toBe(true);
    // The retry's snapshot read the registry itself, once per stream at least
    // on top of the reads before the posts.
    expect(reads(second.calls, (s) => s !== CONTROL).length).toBeGreaterThan(
      second.names.length,
    );
  });
});
