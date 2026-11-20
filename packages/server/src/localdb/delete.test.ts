import { AsyncLocalStorage } from "node:async_hooks";
import { afterEach, expect, it, vi } from "vitest";
import {
  connectionQueue,
  openLocalDb,
  type LocalSyncDeps,
  type SqlDriver,
} from "@opendatalabs/personal-server-ts-core/localdb";
import {
  createMemoryStreamSyncBlobs,
  createMemoryStreamSyncRegistry,
  type MemoryStreamSyncRegistry,
  type SignedRegistryBatch,
  type SignedRegistryPost,
  type StreamSyncRegistry,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import {
  controlScope,
  deriveKeyCheck,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { applyConnection } from "../../../core/src/localdb/apply.js";
import { bootstrapConnections } from "../../../core/src/localdb/bootstrap.js";
import {
  ConnectionLifetimeChanged,
  InvalidConnectionLifetime,
  createConnectionDeleter,
} from "../../../core/src/localdb/delete.js";
import { createLocalResolver } from "../../../core/src/localdb/resolve.js";
import { createRecordQuery } from "../../../core/src/localdb/query.js";
import {
  AmbiguousRegistryReplyError,
  RegistryRefusedError,
  RegistryUnavailableError,
} from "../../../core/src/stream-sync/ports.js";
import { remoteFixture } from "./apply-fixture.test-utils.js";
import { legacyHeadRow } from "./legacy-head-fixture.test-utils.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const owner = `0x${"12".repeat(20)}`;
const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
});

/**
 * Two devices of one owner over one registry. The connection has a control
 * row and a per-stream row and head blob for each of `names` (a delete must
 * leave them as they are). `namespaces` adds control rows of other namespaces, each
 * written by another key (`foreign`).
 */
async function world(
  file?: string,
  names: readonly string[] = ["items"],
  withControl = true,
  namespaces: readonly string[] = [],
) {
  const keys = {
    namespaceHmac: async () => new Uint8Array(32),
    encrypt: async (_s: string, b: Uint8Array) => b,
    encryptPart: async (_s: string, b: Uint8Array) => b,
    decrypt: async (_s: string, b: Uint8Array) => b,
  };
  const fixture = await remoteFixture(keys);
  // It serves the gateway's batch contract, as the gateway does.
  const registry = createMemoryStreamSyncRegistry() as MemoryStreamSyncRegistry;
  const blobs = createMemoryStreamSyncBlobs();
  const heads = [];
  for (const name of names)
    heads.push(
      await legacyHeadRow({
        ...fixture,
        keys,
        keyCheck: await deriveKeyCheck((m) => keys.namespaceHmac(m)),
        connector: "fixture-source",
        ns: "",
        stream: name,
      }),
    );
  for (const [key, value] of fixture.blobs) await blobs.put(key, value);
  for (const [scope, row] of fixture.reads)
    if (row.found && (withControl || scope !== fixture.control))
      await registry.post({
        ownerAddress: owner,
        scope,
        dataHash: row.dataHash as `0x${string}`,
        metadataHash: row.metadataHash as `0x${string}`,
        expectedVersion: "1",
        signature: "0x00",
      });
  const others = namespaces.map((ns) => controlScope("fixture-source", ns));
  for (const scope of others)
    await registry.post({
      ...FOREIGN,
      ownerAddress: owner,
      scope,
      expectedVersion: "1",
      signature: "0x00",
    });
  const devices = [];
  for (let n = 0; n < 2; n++) {
    const db = await openLocalDb(
      openBetterSqlite3(n === 0 && file ? file : ":memory:"),
      {
        owner,
        network: "test",
        deviceId: `delete-${n}`,
      },
    );
    drivers.push(db);
    let op = 0;
    const deps: LocalSyncDeps = {
      db,
      keys,
      registry,
      blobs,
      queue: connectionQueue(),
      ownerAddress: owner,
      signer: { signAddData: async () => "0x00" },
      logger: { info: vi.fn(), warn: vi.fn() },
      now: () => 1000,
      newOp: () => `delete-${n}-${++op}`,
    };
    await bootstrapConnections(deps);
    await applyConnection(deps, fixture.control);
    const deleter = createConnectionDeleter(deps);
    devices.push({ db, deps, deleter });
  }
  return {
    ...fixture,
    a: devices[0]!,
    b: devices[1]!,
    registry,
    blobs,
    head: heads[0]!,
    heads,
    others,
  };
}
type World = Awaited<ReturnType<typeof world>>;

const WORK = "a".repeat(16);
const HOME = "b".repeat(16);
/** A control row of another key: a delete tombstones it all the same. */
const FOREIGN = {
  dataHash: `0x${"ab".repeat(32)}` as `0x${string}`,
  metadataHash: `0x${"cd".repeat(32)}` as `0x${string}`,
};

let rivalWriting = false;
/** Another writer's post, made without re-entering the test hooks. */
async function rivalPost(
  f: World,
  scope: string,
  version: number,
  hashes: { dataHash: `0x${string}`; metadataHash: `0x${string}` },
  /** The deleting device signs "0x00"; a rival is another signer by default. */
  signature = "0x01",
) {
  const { beforePost, afterPost } = f.registry;
  f.registry.beforePost = undefined;
  f.registry.afterPost = undefined;
  rivalWriting = true;
  try {
    expect(
      await f.registry.post({
        ...hashes,
        ownerAddress: owner,
        scope,
        expectedVersion: String(version),
        signature,
      }),
    ).toEqual({ kind: "committed" });
  } finally {
    rivalWriting = false;
    f.registry.beforePost = beforePost;
    f.registry.afterPost = afterPost;
  }
}

/** A later write of that other key: not a tombstone. */
const OTHER = {
  dataHash: `0x${"ef".repeat(32)}` as `0x${string}`,
  metadataHash: `0x${"fe".repeat(32)}` as `0x${string}`,
};
const tombstone = (f: World) => ({
  dataHash: f.hashes.tombstoneData,
  metadataHash: f.hashes.tombstoneMetadata,
});
const active = (f: World) => ({
  dataHash: f.hashes.activeData,
  metadataHash: f.hashes.activeMetadata,
});

/** The posts the delete sends one row at a time, outside a batch request. */
function countSingles(f: World) {
  const singles: string[] = [];
  const post = f.registry.post.bind(f.registry);
  f.registry.post = async (request: SignedRegistryPost) => {
    if (!rivalWriting) singles.push(request.scope);
    return post(request);
  };
  return singles;
}

const controlWrites = (f: World) =>
  f.registry.log.filter((row) => row.scope === f.control).map((r) => r.version);

it("persists the intent before the first registry write, writes the fence and nothing else, and a second device stays deleted", async () => {
  const f = await world();
  const events: string[] = [];
  f.registry.beforePost = async (request) => {
    expect(
      await f.a.db.query("SELECT count(*) AS n FROM delete_intents"),
    ).toEqual([{ n: 1 }]);
    events.push(request.scope);
  };
  const before = f.registry.log.length;
  const started = await f.a.deleter.requestConnectionDelete("fixture-source");
  expect(started).toMatchObject({ deleteId: expect.any(String), fenced: true });
  expect(await f.a.deleter.resumeDeletes()).toEqual([]);
  expect(events).toEqual([f.control]);
  expect(f.registry.log.slice(before)).toEqual([
    { scope: f.control, version: 2, dataHash: f.hashes.tombstoneData },
  ]);
  await applyConnection(f.b.deps, f.control);
  for (const device of [f.a, f.b]) {
    expect(await device.db.query("SELECT * FROM records")).toEqual([]);
    expect(
      await device.db.query("SELECT control_state FROM connections"),
    ).toEqual([{ control_state: "deleted" }]);
  }
});

it("a delete reads no stream row and no head blob, and leaves any per-stream row as it is (mutant: STREAM_CLEANUP)", async () => {
  const f = await world(undefined, ["items", "events", "profile", "history"]);
  const reads: string[] = [];
  const read = f.registry.read.bind(f.registry);
  f.registry.read = async (scope) => {
    reads.push(scope);
    return read(scope);
  };
  const listStreamRows = vi.spyOn(f.registry, "listStreamRows");
  const blobReads = vi.spyOn(f.blobs, "get");
  const before = f.registry.log.length;
  await f.a.deleter.requestConnectionDelete("fixture-source");
  expect(await f.a.deleter.resumeDeletes()).toEqual([]);
  expect(listStreamRows).not.toHaveBeenCalled();
  expect(blobReads).not.toHaveBeenCalled();
  // The listing reads the control rows; nothing else is read.
  expect(reads.filter((scope) => scope !== f.control)).toEqual([]);
  expect(f.registry.log.slice(before).map((row) => row.scope)).toEqual([
    f.control,
  ]);
  for (const head of f.heads)
    expect(await f.registry.read(head.scope)).toMatchObject({ version: 1 });
});

it("the pins come from the listing with no reread, and each fence is a compare-and-set on the control head the listing showed (mutant: NO_HEAD_CAS)", async () => {
  const f = await world();
  const readsAfterListing: string[] = [];
  let listing = 0;
  const list = f.registry.listControlRows.bind(f.registry);
  f.registry.listControlRows = async () => {
    listing++;
    try {
      return await list();
    } finally {
      listing--;
    }
  };
  const read = f.registry.read.bind(f.registry);
  f.registry.read = async (scope) => {
    if (listing === 0) readsAfterListing.push(scope);
    return read(scope);
  };
  await f.a.deleter.requestConnectionDelete("fixture-source");
  expect(await f.a.deleter.resumeDeletes()).toEqual([]);
  expect(readsAfterListing).toEqual([]);
  // On the head itself, not only its version: a head replaced at the same
  // version after the listing makes the fence lose.
  expect(f.registry.batches).toHaveLength(1);
  expect(f.registry.batches[0]).toMatchObject({
    rows: [
      {
        scope: f.control,
        expectedVersion: "2",
        expectedHeadDataHash: f.hashes.activeData,
        dataHash: f.hashes.tombstoneData,
      },
    ],
    requires: [],
  });
  expect(await f.registry.read(f.control)).toMatchObject({
    version: 2,
    dataHash: f.hashes.tombstoneData,
  });
});

// ---------------------------------------------------------------------------
// Serial depth: every request a delete makes, with the requests that had
// already finished when it started. The depth is the longest chain.
// ---------------------------------------------------------------------------

/**
 * Gives every registry and blob request a fixed latency and records when it
 * started and ended. `depth` is the number of requests on the longest chain
 * where each started after the last ended: the time a delete takes, in
 * round trips, when every request costs the same. The batch policy is read
 * once per process, as the gateway client reads it.
 */
function withRequestClock(f: World, latencyMs: number) {
  type Call = {
    name: string;
    scope: string;
    start: number;
    end: number;
    depth: number;
  };
  const calls: Call[] = [];
  const inside = new AsyncLocalStorage<boolean>();
  const clock = () => performance.now();
  const timed = <A extends unknown[], R>(
    name: string,
    scopeOf: (...args: A) => string,
    send: (...args: A) => Promise<R>,
  ) => {
    return async (...args: A): Promise<R> => {
      // A request a registry makes of itself is part of the outer request.
      if (inside.getStore()) return send(...args);
      const call: Call = {
        name,
        scope: scopeOf(...args),
        start: clock(),
        end: 0,
        depth: 0,
      };
      // Requests that ended before this one began are what it waited for.
      // A little slack keeps timer jitter from ordering parallel requests.
      call.depth =
        1 +
        Math.max(
          0,
          ...calls
            .filter((c) => c.end > 0 && c.end <= call.start + 1)
            .map((c) => c.depth),
        );
      calls.push(call);
      await new Promise((resolve) => setTimeout(resolve, latencyMs));
      try {
        return await inside.run(true, () => send(...args));
      } finally {
        call.end = clock();
      }
    };
  };
  const registry: StreamSyncRegistry = f.registry;
  const read = f.registry.read.bind(f.registry);
  f.registry.read = timed("read", (scope: string) => scope, read);
  const post = f.registry.post.bind(f.registry);
  f.registry.post = timed("post", (r) => r.scope, post);
  const postBatch = f.registry.postBatch.bind(f.registry);
  f.registry.postBatch = timed(
    "batch",
    (r: SignedRegistryBatch) => r.rows.map((row) => row.scope).join(","),
    postBatch,
  );
  const readPolicy = timed(
    "policy",
    () => "",
    f.registry.readBatchPolicy.bind(f.registry),
  );
  let policyRead: ReturnType<typeof readPolicy> | undefined;
  registry.batchPolicy = () => undefined;
  registry.readBatchPolicy = () => (policyRead ??= readPolicy());
  const listControlRows = f.registry.listControlRows.bind(f.registry);
  f.registry.listControlRows = timed("list", () => "", listControlRows);
  const listStreamRows = f.registry.listStreamRows.bind(f.registry);
  f.registry.listStreamRows = timed(
    "listStreams",
    (c: string) => c,
    listStreamRows,
  );
  const get = f.blobs.get.bind(f.blobs);
  f.blobs.get = timed("blob.get", (k: string) => k, get);
  return {
    calls,
    get depth() {
      return Math.max(0, ...calls.map((c) => c.depth));
    },
    count: (name: string) => calls.filter((c) => c.name === name).length,
  };
}

it("a delete of three namespaces is two round trips: the listing beside the batch bounds, then one request holding every fence (mutant: SERIAL_POLICY_READ)", async () => {
  const f = await world(undefined, ["items"], true, [WORK, HOME]);
  const clock = withRequestClock(f, 40);
  const started = await f.a.deleter.requestConnectionDelete("fixture-source");
  expect(started.fenced).toBe(true);
  expect(await f.a.deleter.resumeDeletes()).toEqual([]);
  expect(clock.depth).toBe(2);
  expect(clock.count("list")).toBe(1);
  expect(clock.count("policy")).toBe(1);
  expect(clock.count("batch")).toBe(1);
  for (const name of ["read", "post", "listStreams", "blob.get"])
    expect(clock.count(name)).toBe(0);
  expect(f.registry.batches[0]!.rows.map((r) => r.scope).sort()).toEqual(
    [f.control, ...f.others].sort(),
  );
  for (const scope of [f.control, ...f.others])
    expect(await f.registry.read(scope)).toMatchObject({
      version: 2,
      dataHash: f.hashes.tombstoneData,
    });
});

it("fences past the advertised bound go in requests within it, in flight together (mutant: SERIAL_CHUNKS)", async () => {
  const f = await world(undefined, ["items"], true, [WORK, HOME]);
  f.registry.serveBatch({ rows: 2, requires: 1, bytes: 1 << 20 });
  const clock = withRequestClock(f, 40);
  await f.a.deleter.requestConnectionDelete("fixture-source");
  expect(await f.a.deleter.resumeDeletes()).toEqual([]);
  expect(f.registry.batches.map((b) => b.rows.length)).toEqual([2, 1]);
  expect(clock.depth).toBe(2);
  expect(clock.count("post")).toBe(0);
});

// ---------------------------------------------------------------------------
// Races: a fence the request did not store is read again and settled alone.
// ---------------------------------------------------------------------------

it("a fence another signer already wrote is refused by the batch, and the per-row pass confirms it: the tombstone is written once", async () => {
  const f = await world();
  const singles = countSingles(f);
  f.registry.beforePost = async (row) => {
    if (row.scope !== f.control) return;
    // Another device's delete lands the same tombstone first, under its own
    // signature. The registry replays only a row with the same data hash and
    // the same signature, so this row is not a replay of ours.
    await rivalPost(f, f.control, 2, tombstone(f));
  };
  await f.a.deleter.requestConnectionDelete("fixture-source");
  f.registry.beforePost = undefined;
  expect(await f.a.deleter.resumeDeletes()).toEqual([]);
  // The one batch lost its fence and wrote nothing; the fence went alone and
  // a read confirmed the rival's tombstone.
  expect(f.registry.batches).toHaveLength(1);
  expect(singles).toEqual([f.control]);
  expect(controlWrites(f)).toEqual([1, 2]);
  expect(await f.a.db.query("SELECT * FROM delete_intents")).toEqual([]);
});

it("a fence the same signer already wrote is a replay: the request commits and the tombstone is written once", async () => {
  const f = await world();
  const singles = countSingles(f);
  f.registry.beforePost = async (row) => {
    if (row.scope !== f.control) return;
    // This device's own earlier send landed (its reply was lost).
    await rivalPost(f, f.control, 2, tombstone(f), "0x00");
  };
  await f.a.deleter.requestConnectionDelete("fixture-source");
  f.registry.beforePost = undefined;
  expect(await f.a.deleter.resumeDeletes()).toEqual([]);
  expect(f.registry.batches).toHaveLength(1);
  expect(singles).toEqual([]);
  expect(controlWrites(f)).toEqual([1, 2]);
  expect(await f.a.db.query("SELECT * FROM delete_intents")).toEqual([]);
});

it("a reconnect that wins the fence race is never tombstoned, and the delete still finishes", async () => {
  const f = await world();
  let moved = false;
  f.registry.beforePost = async (row) => {
    if (row.scope !== f.control || moved) return;
    moved = true;
    // Another device lands the same fence, then reconnects (active, version 3).
    await rivalPost(f, f.control, 2, tombstone(f));
    await rivalPost(f, f.control, 3, active(f));
  };
  await f.a.deleter.requestConnectionDelete("fixture-source");
  const pending = await f.a.deleter.resumeDeletes();
  expect(moved).toBe(true);
  // Not superseded: the fence landed (control version >= pin + 1), so the
  // delete ends the lifetime it pinned.
  expect(pending).toEqual([]);
  expect(await f.registry.read(f.control)).toMatchObject({
    version: 3,
    dataHash: f.hashes.activeData,
  });
  expect(await f.a.db.query("SELECT * FROM delete_intents")).toEqual([]);
});

it("a fence that loses refuses its request; a replayed fence counts as written, the rest go again at once, and the lost one is settled alone by a read (mutants: NO_RESEND_REST, REPLAY_NOT_COUNTED)", async () => {
  const f = await world(undefined, ["items"], true, [WORK, HOME]);
  const [work, home] = f.others;
  const singles = countSingles(f);
  const raced = new Set<string>();
  f.registry.beforePost = async (row) => {
    if (raced.has(row.scope)) return;
    raced.add(row.scope);
    // This device's own earlier send already wrote this fence: a replay.
    if (row.scope === f.control)
      await rivalPost(f, f.control, 2, tombstone(f), "0x00");
    // Its other key moves the work namespace on, then deletes it: the fence
    // at version 2 loses, and the namespace is tombstoned past the pin.
    if (row.scope === work) {
      await rivalPost(f, work, 2, OTHER);
      await rivalPost(f, work, 3, tombstone(f));
    }
  };
  await f.a.deleter.requestConnectionDelete("fixture-source");
  f.registry.beforePost = undefined;
  expect(await f.a.deleter.resumeDeletes()).toEqual([]);
  // The first request was refused and wrote nothing but held the replay; the
  // second held the fence that neither lost nor was stored.
  expect(
    f.registry.batches.map((b) => b.rows.map((r) => r.scope).sort()),
  ).toEqual([[f.control, work!, home!].sort(), [home]]);
  // Only the lost fence goes alone, and a read settles it.
  expect(singles).toEqual([work]);
  expect(controlWrites(f)).toEqual([1, 2]);
  expect(await f.registry.read(work!)).toMatchObject({
    version: 3,
    dataHash: f.hashes.tombstoneData,
  });
  expect(await f.registry.read(home!)).toMatchObject({
    version: 2,
    dataHash: f.hashes.tombstoneData,
  });
  expect(await f.a.db.query("SELECT * FROM delete_intents")).toEqual([]);
});

it("a foreign row that moved past the pin without a tombstone supersedes the delete, and the intent is dropped", async () => {
  const f = await world(undefined, ["items"], true, [WORK]);
  const [work] = f.others;
  let raced = false;
  f.registry.beforePost = async (row) => {
    if (row.scope !== work || raced) return;
    raced = true;
    await rivalPost(f, work!, 2, OTHER);
  };
  const started = await f.a.deleter.requestConnectionDelete("fixture-source");
  f.registry.beforePost = undefined;
  expect(started.fenced).toBe(false);
  expect(await f.a.deleter.resumeDeletes()).toEqual([]);
  expect(f.a.deps.logger.warn).toHaveBeenCalledWith(
    expect.objectContaining({ reason: "ConnectionDeleteSuperseded" }),
    "connection delete pending",
  );
  expect(await f.registry.read(work!)).toMatchObject({
    version: 2,
    dataHash: OTHER.dataHash,
  });
  expect(await f.a.db.query("SELECT * FROM delete_intents")).toEqual([]);
});

it("a request with no answer is sent once more, then leaves its fences to the per-row pass, which lands them (mutant: NO_RESEND_AMBIGUOUS)", async () => {
  const f = await world();
  const singles = countSingles(f);
  const postBatch = f.registry.postBatch.bind(f.registry);
  let sent = 0;
  f.registry.postBatch = async (request) => {
    sent++;
    if (sent <= 2) throw new AmbiguousRegistryReplyError("no reply fixture");
    return postBatch(request);
  };
  const started = await f.a.deleter.requestConnectionDelete("fixture-source");
  expect(started.fenced).toBe(true);
  expect(await f.a.deleter.resumeDeletes()).toEqual([]);
  // Sent, resent once, then the fence goes alone.
  expect(sent).toBe(2);
  expect(singles).toEqual([f.control]);
  expect(controlWrites(f)).toEqual([1, 2]);
});

// ---------------------------------------------------------------------------
// Lost replies, refusals and restarts.
// ---------------------------------------------------------------------------

it("the request answers pending when the registry refuses the fence, and the delete finishes later", async () => {
  const f = await world();
  f.registry.beforePost = async () => {
    throw new Error("offline fixture");
  };
  const started = await f.a.deleter.requestConnectionDelete("fixture-source");
  expect(started.fenced).toBe(false);
  expect(await f.a.db.query("SELECT * FROM delete_intents")).toHaveLength(1);
  expect(await f.registry.read(f.control)).toMatchObject({ version: 1 });
  f.registry.beforePost = undefined;
  expect(await f.a.deleter.resumeDeletes()).toEqual([]);
  expect(await f.registry.read(f.control)).toMatchObject({ version: 2 });
});

it("resumes a saved intent after a failed post: the local data is gone at once, and the fence lands on resume", async () => {
  const f = await world();
  f.registry.beforePost = async () => {
    throw new Error("offline fixture");
  };
  await f.a.deleter.requestConnectionDelete("fixture-source");
  expect(await f.a.deleter.resumeDeletes()).toHaveLength(1);
  const [saved] = await f.a.db.query<{ intent: string }>(
    "SELECT intent FROM delete_intents",
  );
  expect(JSON.parse(saved!.intent)).toEqual({
    id: expect.any(String),
    pins: [{ ns: "", version: 1 }],
  });
  expect(await f.a.db.query("SELECT * FROM records")).toEqual([]);
  f.registry.beforePost = undefined;
  expect(await createConnectionDeleter(f.a.deps).resumeDeletes()).toEqual([]);
  expect(await f.registry.read(f.control)).toMatchObject({ version: 2 });
});

it("a fence whose reply was lost is confirmed from the registry; it never lands twice", async () => {
  const f = await world();
  f.registry.afterPost = async (post) => {
    if (post.scope === f.control) throw new Error("lost reply fixture");
  };
  // The tombstone committed and only its reply was lost: a read proves it, so
  // the request already answers fenced.
  const started = await f.a.deleter.requestConnectionDelete("fixture-source");
  expect(started.fenced).toBe(true);
  f.registry.afterPost = undefined;
  expect(await f.a.deleter.resumeDeletes()).toEqual([]);
  expect(controlWrites(f)).toEqual([1, 2]);
});

it("a committed fence with a lost reply is confirmed by a read when every later control post fails", async () => {
  const f = await world();
  let controlPosts = 0;
  f.registry.afterPost = async (post) => {
    if (post.scope === f.control) throw new Error("lost reply fixture");
  };
  f.registry.beforePost = async (post) => {
    if (post.scope !== f.control) return;
    controlPosts += 1;
    // Only the first post reaches the registry; the gateway then refuses
    // every control post while it still answers reads.
    if (controlPosts > 1) throw new Error("gateway refuses posts");
  };
  const started = await f.a.deleter.requestConnectionDelete("fixture-source");
  expect(started.fenced).toBe(true);
  // A restart before the fence was saved resumes through the same path.
  await f.a.db.query(
    "UPDATE delete_intents SET intent = json_remove(intent, '$.fences')",
  );
  f.registry.afterPost = undefined;
  expect(await f.a.deleter.resumeDeletes()).toEqual([]);
  expect(controlWrites(f)).toEqual([1, 2]);
  expect(await f.a.db.query("SELECT * FROM delete_intents")).toEqual([]);
});

it("a failed control post stays pending when the read cannot prove the fence", async () => {
  const f = await world();
  f.registry.beforePost = async (post) => {
    if (post.scope === f.control) throw new Error("gateway refuses posts");
  };
  const started = await f.a.deleter.requestConnectionDelete("fixture-source");
  expect(started.fenced).toBe(false);
  expect(await f.registry.read(f.control)).toMatchObject({ version: 1 });
  expect(await f.a.deleter.resumeDeletes()).toHaveLength(1);
});

it("a per-row fence the next read does not show yet stays pending, then confirms the same version", async () => {
  const f = await world();
  const read = f.registry.read.bind(f.registry);
  let lagging = false;
  // The batch request fails before it commits, so the fence goes alone.
  let batchFailed = false;
  f.registry.beforePost = async (post) => {
    if (post.scope !== f.control || batchFailed) return;
    batchFailed = true;
    throw new Error("connection reset fixture");
  };
  f.registry.afterPost = async (post) => {
    if (post.scope === f.control) lagging = true;
  };
  f.registry.read = async (scope) => {
    const row = await read(scope);
    if (lagging && scope === f.control && row.found) {
      lagging = false;
      return {
        ...row,
        version: 1,
        dataHash: f.hashes.activeData,
        metadataHash: f.hashes.activeMetadata,
        deleted: false,
      };
    }
    return row;
  };
  const started = await f.a.deleter.requestConnectionDelete("fixture-source");
  expect(started.fenced).toBe(false);
  expect(await f.a.deleter.resumeDeletes()).toEqual([]);
  expect(controlWrites(f)).toEqual([1, 2]);
});

it("the fence is saved with the version it wrote, and a restart finishes without posting it again", async () => {
  const f = await world();
  const stopping = createConnectionDeleter(f.a.deps, {
    eraseLegacy: async () => {
      throw new Error("stopped after the fence");
    },
  });
  const started = await stopping.requestConnectionDelete("fixture-source");
  expect(started.fenced).toBe(true);
  expect(await stopping.resumeDeletes()).toHaveLength(1);
  const [saved] = await f.a.db.query<{ intent: string }>(
    "SELECT intent FROM delete_intents",
  );
  expect(JSON.parse(saved!.intent).fences).toEqual([{ ns: "", version: 2 }]);
  const posts = vi.spyOn(f.registry, "post");
  const batches = f.registry.batches.length;
  expect(await createConnectionDeleter(f.a.deps).resumeDeletes()).toEqual([]);
  expect(posts).not.toHaveBeenCalled();
  expect(f.registry.batches).toHaveLength(batches);
  expect(await f.a.db.query("SELECT * FROM delete_intents")).toEqual([]);
});

it("a connection with no control row has nothing to fence: the delete purges this device and writes nothing", async () => {
  const f = await world(undefined, ["items"], false);
  const before = f.registry.log.length;
  const started = await f.a.deleter.requestConnectionDelete("fixture-source");
  expect(started.fenced).toBe(true);
  expect(await f.a.deleter.resumeDeletes()).toEqual([]);
  expect(f.registry.log.length).toBe(before);
  expect(f.registry.batches).toEqual([]);
  expect(await f.registry.read(f.control)).toEqual({ found: false });
  expect(await f.a.db.query("SELECT * FROM delete_intents")).toEqual([]);
});

it("a gateway without the batch route fails the delete closed: nothing is written, the intent stays and the cause is logged", async () => {
  const f = await world();
  f.registry.stopServingBatch();
  const singles = countSingles(f);
  const before = f.registry.log.length;
  const started = await f.a.deleter.requestConnectionDelete("fixture-source");
  expect(started.fenced).toBe(false);
  expect(await f.a.deleter.resumeDeletes()).toEqual([
    { connector: "fixture-source", why: "RegistryBatchRouteMissingError" },
  ]);
  // No row is written one at a time instead.
  expect(singles).toEqual([]);
  expect(f.registry.log.length).toBe(before);
  expect(await f.a.db.query("SELECT * FROM delete_intents")).toHaveLength(1);
  expect(f.a.deps.logger.warn).toHaveBeenCalledWith(
    expect.objectContaining({
      connector: "fixture-source",
      reason: "RegistryBatchRouteMissingError",
      message: expect.stringContaining("serves no batch contract"),
    }),
    "connection delete pending",
  );
});

it("a request the gateway refuses (400) fails the delete: no row is written one at a time, and the refusal is logged (mutant: REFUSAL_PER_ROW)", async () => {
  const f = await world();
  const singles = countSingles(f);
  f.registry.postBatch = async () => {
    throw new RegistryRefusedError("batch POST refused: shape", 400);
  };
  const before = f.registry.log.length;
  await f.a.deleter.requestConnectionDelete("fixture-source");
  expect(await f.a.deleter.resumeDeletes()).toEqual([
    { connector: "fixture-source", why: "RegistryRefusedError" },
  ]);
  expect(singles).toEqual([]);
  expect(f.registry.log.length).toBe(before);
  expect(f.a.deps.logger.warn).toHaveBeenCalledWith(
    expect.objectContaining({
      reason: "RegistryRefusedError",
      message: "batch POST refused: shape",
    }),
    "connection delete pending",
  );
});

it("a delete that cannot land logs the cause, with its message and stack", async () => {
  const f = await world();
  f.registry.beforePost = async () => {
    throw new Error("registry write failed: fixture detail");
  };
  await f.a.deleter.requestConnectionDelete("fixture-source").catch(() => {});
  expect(await f.a.deleter.resumeDeletes()).toHaveLength(1);
  expect(f.a.deps.logger.warn).toHaveBeenCalledWith(
    expect.objectContaining({
      connector: "fixture-source",
      reason: "Error",
      message: "registry write failed: fixture detail",
      stack: expect.stringContaining("fixture detail"),
    }),
    "connection delete pending",
  );
});

// ---------------------------------------------------------------------------
// The local side: purge, apply and runs after a delete.
// ---------------------------------------------------------------------------

it("an intent blocks local apply and publish until its landing can finish", async () => {
  const f = await world();
  f.registry.beforePost = async () => {
    throw new Error("offline fixture");
  };
  await f.a.deleter.requestConnectionDelete("fixture-source");
  await f.a.deleter.resumeDeletes();
  await bootstrapConnections(f.a.deps);
  await applyConnection(f.a.deps, f.control);
  expect(await f.a.db.query("SELECT * FROM records")).toEqual([]);
  expect(await f.a.db.query("SELECT control_state FROM connections")).toEqual([
    { control_state: "deleted" },
  ]);
  await f.a.db.batch([
    {
      sql: "INSERT INTO stream_state(connection_id,stream,primary_key,semantics,incremental) VALUES (?,'items','[\"id\"]','mutable_state',0)",
      params: [f.control],
    },
  ]);
  const { publishLog } =
    await import("../../../core/src/localdb/log-publish.js");
  expect((await publishLog(f.a.deps, f.control))?.[0]?.outcome).toBe(
    "deferred",
  );
  f.registry.beforePost = undefined;
  await f.a.deleter.resumeDeletes();
});

it("the second device's unpublished rows are purged along with its imported rows", async () => {
  const f = await world();
  await f.b.db.batch([
    { sql: "UPDATE write_ctx SET origin='local'" },
    {
      sql: "INSERT INTO records(connection_id,stream,pk_hash,record_key,stamp_o,stamp_r,body,body_sha256) VALUES (?,'items',?,'unsent',2000,'pending','{}','fixture')",
      params: [f.control, "f".repeat(64)],
    },
  ]);
  await f.a.deleter.requestConnectionDelete("fixture-source");
  await f.a.deleter.resumeDeletes();
  await applyConnection(f.b.deps, f.control);
  expect(await f.b.db.query("SELECT * FROM records")).toEqual([]);
});

it("resumes an intent from a reopened SQLite database after a crash", async () => {
  const { mkdtemp, rm } = await import("node:fs/promises");
  const { join } = await import("node:path");
  const { tmpdir } = await import("node:os");
  const dir = await mkdtemp(join(tmpdir(), "delete-reopen-"));
  try {
    const file = join(dir, "db.sqlite");
    const f = await world(file);
    f.registry.beforePost = async () => {
      throw new Error("lost process fixture");
    };
    await f.a.deleter.requestConnectionDelete("fixture-source");
    await f.a.deleter.resumeDeletes();
    await f.a.db.close();
    drivers.splice(drivers.indexOf(f.a.db), 1);
    const db = await openLocalDb(openBetterSqlite3(file), {
      owner,
      network: "test",
      deviceId: "delete-0",
    });
    drivers.push(db);
    f.registry.beforePost = undefined;
    const resumed = createConnectionDeleter({
      ...f.a.deps,
      db,
      queue: connectionQueue(),
    });
    expect(await resumed.resumeDeletes()).toEqual([]);
    expect(await f.registry.read(f.control)).toMatchObject({ version: 2 });
    expect(await db.query("SELECT * FROM delete_intents")).toEqual([]);
    await db.close();
    drivers.splice(drivers.indexOf(db), 1);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

it("a scheduled run observes a reconnect made on another device", async () => {
  const f = await world();
  await f.a.deleter.requestConnectionDelete("fixture-source");
  expect(await f.a.deleter.resumeDeletes()).toEqual([]);
  await applyConnection(f.b.deps, f.control);
  const { createRunIntakeStore } =
    await import("../../../core/src/localdb/run-intake.js");
  const decl = {
    connector: "fixture-source",
    version: "1",
    streams: [
      {
        name: "items",
        semantics: "mutable_state" as const,
        primaryKey: ["id"],
      },
    ],
  };
  const request = {
    connector: "fixture-source",
    artifactDigest: "fixture",
    owner: { address: owner, leaseId: null },
    observedAt: 2000,
  };
  await createRunIntakeStore(f.a.deps).begin(
    "explicit-reconnect",
    { ...request, connect: true },
    decl,
  );
  // A new lifetime made elsewhere is a connection this device must join.
  await expect(
    createRunIntakeStore(f.b.deps).begin(
      "scheduled-after-peer-connect",
      request,
      decl,
    ),
  ).rejects.toMatchObject({ code: "join_required" });
  const begun = await createRunIntakeStore(f.b.deps).begin(
    "scheduled-after-peer-connect",
    { ...request, join: true },
    decl,
  );
  expect(begun.status).toBe("collecting");
  expect(begun.start.collection_mode).toBe("full_refresh");
  expect(
    await f.b.db.query("SELECT generation,control_state FROM connections"),
  ).toEqual([{ generation: 3, control_state: "active" }]);
  expect(await f.b.db.query("SELECT * FROM records")).toEqual([]);
});

it("an absent registry answer never clears a local-only delete, but explicit connect does", async () => {
  const f = await world();
  const db = await openLocalDb(openBetterSqlite3(":memory:"), {
    owner,
    network: "test",
    deviceId: "offline",
  });
  drivers.push(db);
  const registry = createMemoryStreamSyncRegistry() as MemoryStreamSyncRegistry;
  const deps = { ...f.a.deps, db, queue: connectionQueue(), registry };
  const { createRunIntakeStore } =
    await import("../../../core/src/localdb/run-intake.js");
  const intake = createRunIntakeStore(deps);
  const decl = {
    connector: "fixture-source",
    version: "1",
    streams: [
      {
        name: "items",
        semantics: "mutable_state" as const,
        primaryKey: ["id"],
      },
    ],
  };
  const request = {
    connector: "fixture-source",
    artifactDigest: "fixture",
    owner: { address: owner, leaseId: null },
    observedAt: 2000,
  };
  // A device that joined earlier collects offline; one that never did is
  // refused (`join-gate.test.ts`).
  await db.batch([
    {
      sql: "INSERT INTO connection_participation(connection_id,joined_at) VALUES ('pdpp.fixture-source~',1)",
    },
  ]);
  registry.beforeRead = async () => {
    throw new RegistryUnavailableError("offline fixture");
  };
  expect((await intake.begin("offline-run", request, decl)).status).toBe(
    "collecting",
  );
  expect(
    await db.query("SELECT generation FROM runs WHERE run_id='offline-run'"),
  ).toEqual([{ generation: null }]);
  registry.beforeRead = undefined;
  await createConnectionDeleter(deps).requestConnectionDelete("fixture-source");
  for (const run of ["scheduled-1", "scheduled-2"]) {
    await applyConnection(deps, f.control);
    await bootstrapConnections(deps);
    await expect(intake.begin(run, request, decl)).rejects.toMatchObject({
      code: "connection_stopped",
    });
    expect(await db.query("SELECT control_state FROM connections")).toEqual([
      { control_state: "deleted" },
    ]);
  }
  expect(registry.log).toEqual([]);
  expect(
    (
      await intake.begin(
        "explicit-local-reconnect",
        { ...request, connect: true },
        decl,
      )
    ).status,
  ).toBe("collecting");
});

it("purges an interrupted delete before clearing a superseded intent", async () => {
  const f = await world(undefined, ["items"], true, [WORK]);
  const stale = await f.registry.read(f.control);
  await f.a.db.batch([
    { sql: "UPDATE write_ctx SET origin='local'" },
    {
      sql: `INSERT OR REPLACE INTO stream_state(connection_id,stream,primary_key,semantics,incremental,complete,head_version,head_generation,head_data_hash,head_blob) VALUES (?,'items','["id"]','mutable_state',0,1,1,1,'hash','head')`,
      params: [f.control],
    },
    {
      sql: "INSERT OR REPLACE INTO stream_versions(connection_id,stream,version,generation,head_blob,head_format,record_count,observed_at,complete,kind) VALUES (?,'items',1,1,'head',3,1,1000,1,'applied')",
      params: [f.control],
    },
    {
      sql: "INSERT INTO records(connection_id,stream,pk_hash,record_key,stamp_o,stamp_r,body,body_sha256) VALUES (?,'items',?,'old',2000,'pending','{}','fixture')",
      params: [f.control, "f".repeat(64)],
    },
  ]);
  const resolver = createLocalResolver(f.a.deps, {
    query: createRecordQuery(f.a.db),
  });
  const input = {
    scope: "pdpp.fixture-source.items",
    connection: "",
    cursor: null,
    legacyFile: false,
    isOwnerView: true,
  };
  expect((await resolver.resolve(input)).kind).toBe("view");
  const queue = f.a.deps.queue;
  const interrupted = createConnectionDeleter({
    ...f.a.deps,
    queue: {
      run: (id, kind, work) => {
        if (id === f.control && kind === "purge")
          throw new Error("crash before purge");
        return queue.run(id, kind, work);
      },
    },
  });
  await expect(
    interrupted.requestConnectionDelete("fixture-source"),
  ).rejects.toThrow("crash before purge");
  expect(await f.a.db.query("SELECT * FROM delete_intents")).toHaveLength(1);
  expect(await f.a.db.query("SELECT * FROM records")).toHaveLength(1);
  await f.a.db.batch([
    {
      sql: "UPDATE connections SET generation=2,control_state='active',control_version=2 WHERE connection_id=?",
      params: [f.others[0]!],
    },
    {
      sql: "INSERT INTO records(connection_id,stream,pk_hash,record_key,stamp_o,stamp_r,body,body_sha256) VALUES (?,'items',?,'new',2000,'pending','{}','fixture')",
      params: [f.others[0]!, "e".repeat(64)],
    },
  ]);
  await rivalPost(f, f.control, 2, FOREIGN);
  // A settled competing head cannot be refreshed at the same version.
  f.registry.settleHead(f.control);
  const failing = createConnectionDeleter({
    ...f.a.deps,
    queue: {
      run: (id, kind, work) => {
        if (id === f.control && kind === "purge")
          throw new Error("purge failed");
        return queue.run(id, kind, work);
      },
    },
  });
  expect(await failing.resumeDeletes()).toEqual([
    { connector: "fixture-source", why: "Error" },
  ]);
  expect(await f.a.db.query("SELECT * FROM delete_intents")).toHaveLength(1);
  const batch = f.a.db.batch.bind(f.a.db);
  f.a.db.batch = async (statements) => {
    if (
      statements.some((s) => s.sql.startsWith("DELETE FROM delete_intents"))
    ) {
      expect(
        await f.a.db.query(
          "SELECT record_key FROM records WHERE connection_id=?",
          [f.control],
        ),
      ).toEqual([]);
      expect(
        await f.a.db.query(
          "SELECT control_state FROM connections WHERE connection_id=?",
          [f.control],
        ),
      ).toEqual([{ control_state: "deleted" }]);
    }
    return batch(statements);
  };
  const resumed = createConnectionDeleter(f.a.deps);
  expect(await resumed.resumeDeletes()).toEqual([
    { connector: "fixture-source", why: "ConnectionDeleteSuperseded" },
  ]);
  expect(
    await f.a.db.query("SELECT connection_id,record_key FROM records"),
  ).toEqual([{ connection_id: f.others[0], record_key: "new" }]);
  expect(
    await f.a.db.query(
      "SELECT connection_id,control_state FROM connections ORDER BY connection_id",
    ),
  ).toEqual([
    { connection_id: f.control, control_state: "deleted" },
    { connection_id: f.others[0], control_state: "active" },
  ]);
  expect(await f.a.db.query("SELECT * FROM delete_intents")).toEqual([]);
  expect(await f.registry.read(f.control)).toMatchObject({
    version: 2,
    ...FOREIGN,
  });
  const read = f.registry.read.bind(f.registry);
  f.registry.read = async (scope) =>
    scope === f.control ? stale : read(scope);
  await applyConnection(f.a.deps, f.control);
  expect((await resolver.resolve(input)).kind).not.toBe("view");
  expect(
    await f.a.db.query("SELECT record_key FROM records WHERE connection_id=?", [
      f.control,
    ]),
  ).toEqual([]);
  expect(
    await f.a.db.query(
      "SELECT control_state FROM connections WHERE connection_id=?",
      [f.control],
    ),
  ).toEqual([{ control_state: "deleted" }]);
});

// ---------------------------------------------------------------------------
// The lifetime a delete names: a resend of a delete the person made cannot
// reach a lifetime the person never saw.
// ---------------------------------------------------------------------------

/**
 * The phone connects the source again. When this device's delete already
 * wrote the tombstone (version 2) the phone only connects; otherwise it
 * deletes (its own tombstone) and then connects.
 */
async function phoneReconnects(f: World, alreadyDeleted: boolean) {
  if (!alreadyDeleted) await rivalPost(f, f.control, 2, tombstone(f));
  await rivalPost(f, f.control, 3, active(f));
}

it("names the lifetime a connector holds now: one generation per namespace that is live (mutant: LIFETIME_NOT_READ)", async () => {
  const f = await world(undefined, ["items"], true, [WORK]);
  // The control row of the default namespace is at version 1 (active); the
  // other namespace's row is a foreign key's at version 1.
  expect(await f.a.deleter.readConnectionLifetime("fixture-source")).toBe(
    `v2:fixture-source:@1,${WORK}@1`,
  );
  await f.a.deleter.requestConnectionDelete("fixture-source");
  expect(await f.a.deleter.resumeDeletes()).toEqual([]);
  // Nothing is live after the delete: nothing to name.
  expect(await f.a.deleter.readConnectionLifetime("fixture-source")).toBe(
    "v2:fixture-source:",
  );
});

it("a delete that names the lifetime the connector holds deletes it", async () => {
  const f = await world();
  const lifetime = await f.a.deleter.readConnectionLifetime("fixture-source");
  const started = await f.a.deleter.requestConnectionDelete("fixture-source", {
    lifetime,
  });
  expect(started.fenced).toBe(true);
  expect(await f.registry.read(f.control)).toMatchObject({
    version: 2,
    dataHash: f.hashes.tombstoneData,
  });
});

it("a resend that names a lifetime another device has since replaced is refused, and nothing is tombstoned (mutant: NO_LIFETIME_FENCE)", async () => {
  const f = await world();
  const lifetime = await f.a.deleter.readConnectionLifetime("fixture-source");
  await f.a.deleter.requestConnectionDelete("fixture-source", { lifetime });
  expect(await f.a.deleter.resumeDeletes()).toEqual([]);
  await phoneReconnects(f, true);
  const before = f.registry.log.length;
  await expect(
    f.a.deleter.requestConnectionDelete("fixture-source", { lifetime }),
  ).rejects.toBeInstanceOf(ConnectionLifetimeChanged);
  // The new lifetime is untouched: no write, no intent, no batch.
  expect(f.registry.log.length).toBe(before);
  expect(f.registry.batches).toHaveLength(1);
  expect(await f.registry.read(f.control)).toMatchObject({
    version: 3,
    dataHash: f.hashes.activeData,
  });
  expect(await f.a.db.query("SELECT * FROM delete_intents")).toEqual([]);
});

it("a resend of a lifetime this delete already ended is done: it writes nothing and refuses nothing", async () => {
  const f = await world();
  const lifetime = await f.a.deleter.readConnectionLifetime("fixture-source");
  await f.a.deleter.requestConnectionDelete("fixture-source", { lifetime });
  expect(await f.a.deleter.resumeDeletes()).toEqual([]);
  const before = f.registry.log.length;
  const again = await f.a.deleter.requestConnectionDelete("fixture-source", {
    lifetime,
  });
  expect(again.fenced).toBe(true);
  expect(f.registry.log.length).toBe(before);
  expect(await f.registry.read(f.control)).toMatchObject({
    version: 2,
    dataHash: f.hashes.tombstoneData,
  });
});

it("a resend of a lifetime this delete already ended writes nothing here either: no purge, no legacy erase, no intent", async () => {
  const f = await world();
  const eraseLegacy = vi.fn(async () => {});
  const deleter = createConnectionDeleter(f.a.deps, { eraseLegacy });
  const lifetime = await deleter.readConnectionLifetime("fixture-source");
  await deleter.requestConnectionDelete("fixture-source", { lifetime });
  expect(await deleter.resumeDeletes()).toEqual([]);
  eraseLegacy.mockClear();
  const batch = vi.spyOn(f.a.db, "batch");
  const registryWrites = f.registry.log.length;
  const again = await deleter.requestConnectionDelete("fixture-source", {
    lifetime,
  });
  expect(again.fenced).toBe(true);
  expect(batch).not.toHaveBeenCalled();
  expect(eraseLegacy).not.toHaveBeenCalled();
  expect(f.registry.log.length).toBe(registryWrites);
  expect(await f.a.db.query("SELECT * FROM delete_intents")).toEqual([]);
});

it("a delete that names a lifetime purges the connections its pins name, and leaves a local connection no pin names", async () => {
  const f = await world();
  // A connection of the connector in a namespace the lifetime does not name:
  // it has no control row, so it belongs to no lifetime a person read.
  await f.a.db.batch([
    {
      sql: "INSERT INTO connections(connection_id, connector, ns, generation, control_state) VALUES ('stray', 'fixture-source', ?, 1, 'absent')",
      params: [HOME],
    },
  ]);
  const lifetime = await f.a.deleter.readConnectionLifetime("fixture-source");
  await f.a.deleter.requestConnectionDelete("fixture-source", { lifetime });
  expect(await f.a.deleter.resumeDeletes()).toEqual([]);
  expect(
    await f.a.db.query(
      "SELECT connection_id, control_state, deleted_at FROM connections WHERE ns = ?",
      [HOME],
    ),
  ).toEqual([
    { connection_id: "stray", control_state: "absent", deleted_at: null },
  ]);
  expect(await f.registry.read(f.control)).toMatchObject({ version: 2 });
});

it("a lifetime read for one connector is refused for another, before any intent is saved or row written", async () => {
  const f = await world();
  // A second connector of the same owner holds the very same tuple: its
  // default-namespace control row is live at version 1.
  const other = "other-source";
  await f.registry.post({
    ownerAddress: owner,
    scope: controlScope(other, ""),
    ...active(f),
    expectedVersion: "1",
    signature: "0x00",
  });
  const lifetime = await f.a.deleter.readConnectionLifetime("fixture-source");
  const writes = f.registry.log.length;
  const batch = vi.spyOn(f.a.db, "batch");
  await expect(
    f.a.deleter.requestConnectionDelete(other, { lifetime }),
  ).rejects.toBeInstanceOf(InvalidConnectionLifetime);
  expect(f.registry.log.length).toBe(writes);
  expect(f.registry.batches).toEqual([]);
  expect(batch).not.toHaveBeenCalled();
  expect(await f.registry.read(controlScope(other, ""))).toMatchObject({
    version: 1,
    dataHash: f.hashes.activeData,
  });
  // The connector it was read for still takes it.
  await f.a.deleter.requestConnectionDelete("fixture-source", { lifetime });
  expect(await f.registry.read(f.control)).toMatchObject({ version: 2 });
});

it("a lifetime that names no live row refuses a delete when a row became live since (mutant: EMPTY_LIFETIME_PASSES)", async () => {
  const f = await world();
  const before = f.registry.log.length;
  await expect(
    f.a.deleter.requestConnectionDelete("fixture-source", {
      lifetime: "v2:fixture-source:",
    }),
  ).rejects.toBeInstanceOf(ConnectionLifetimeChanged);
  expect(f.registry.log.length).toBe(before);
});

it("a lifetime that is not one this server names is refused as invalid", async () => {
  const f = await world();
  for (const lifetime of [
    "",
    "1",
    "v1:@1",
    "v2:fixture-source:@0",
    "v2:fixture-source:@x",
    "v2:@1",
    "v2:fixture-source:zz@1",
  ])
    await expect(
      f.a.deleter.requestConnectionDelete("fixture-source", { lifetime }),
    ).rejects.toBeInstanceOf(InvalidConnectionLifetime);
  expect(await f.a.db.query("SELECT * FROM delete_intents")).toEqual([]);
});

it("a delete that names no lifetime is the delete it always was", async () => {
  const f = await world();
  await phoneReconnects(f, false);
  await applyConnection(f.a.deps, f.control);
  const started = await f.a.deleter.requestConnectionDelete("fixture-source");
  expect(started.fenced).toBe(true);
  expect(await f.registry.read(f.control)).toMatchObject({
    version: 4,
    dataHash: f.hashes.tombstoneData,
  });
});
