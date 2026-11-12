/**
 * Delete, then reconnect, then publish: every input to the publish decision is
 * produced by a production function in the order a user performs it.
 *
 * The delete writer posts an empty stream head at generation 1 (`delete.ts`);
 * a reconnect raises the connection to a later generation (`run-intake.ts`);
 * the registry row of the stream is that old empty head until a new lifetime
 * publishes over it (`publish.ts`, `lifetime-boundary.ts`). This file runs the
 * sequence through the real deleter, run intake and end stores, publisher,
 * applier and `classifyStreamRow`, over the in-memory registry and blob store,
 * with an independent database per device. Nothing writes a head or a
 * generation by hand, except where a test says it forges one.
 *
 * Limit: the in-memory registry always reports `deleted: false`. A registry
 * that flags a delete post as deleted would make `classifyStreamRow` answer
 * "tombstoned" and skip the head read.
 */
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
  type StreamSyncRegistry,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import { keccak_256 } from "@noble/hashes/sha3";
import {
  classifyStreamRow,
  decodeHead,
  digestHead,
  encodeHead,
  headBlobName,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { applyConnection } from "../../../core/src/localdb/apply.js";
import { bootstrapConnections } from "../../../core/src/localdb/bootstrap.js";
import { createConnectionDeleter } from "../../../core/src/localdb/delete.js";
import { publishConnection } from "../../../core/src/localdb/publish.js";
import { createRunEndStore } from "../../../core/src/localdb/run-end.js";
import { createRunIntakeStore } from "../../../core/src/localdb/run-intake.js";
import { syncConnection } from "../../../core/src/localdb/cycle.js";
import { deleteMetadataHash } from "../../../core/src/stream-sync/delete-metadata.js";
import { remoteFixture } from "./apply-fixture.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const owner = `0x${"12".repeat(20)}`;
const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
});

const declaration = {
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

const keys = {
  namespaceHmac: async () => new Uint8Array(32),
  encrypt: async (_s: string, b: Uint8Array) => b,
  encryptPart: async (_s: string, b: Uint8Array) => b,
  decrypt: async (_s: string, b: Uint8Array) => b,
};

async function world(deviceCount = 2) {
  const fixture = await remoteFixture(keys);
  const registry = createMemoryStreamSyncRegistry() as MemoryStreamSyncRegistry;
  const blobs = createMemoryStreamSyncBlobs();
  // Only the control row is seeded; no stream head exists until a real publish.
  await registry.post({
    ownerAddress: owner,
    scope: fixture.control,
    dataHash: fixture.hashes.activeData as `0x${string}`,
    metadataHash: fixture.hashes.activeMetadata as `0x${string}`,
    expectedVersion: "1",
    signature: "0x00",
  });
  const scope = `${fixture.control}.items`;
  const w = { fixture, registry, blobs, scope, devices: [] as Device[] };
  for (let n = 0; n < deviceCount; n++) await addDevice(w);
  return {
    ...w,
    a: w.devices[0]!,
    b: w.devices[1] ?? w.devices[0]!,
  };
}

/** A device: its own database over the shared registry and blob store. */
async function addDevice(w: {
  fixture: Awaited<ReturnType<typeof remoteFixture>>;
  registry: MemoryStreamSyncRegistry;
  blobs: ReturnType<typeof createMemoryStreamSyncBlobs>;
  devices: Device[];
}) {
  const n = w.devices.length;
  const db = await openLocalDb(openBetterSqlite3(":memory:"), {
    owner,
    network: "test",
    deviceId: `repro-${n}`,
  });
  drivers.push(db);
  let op = 0;
  let now = 1000;
  // `offline.on` makes every registry call throw, as an unreachable network.
  const offline = { on: false };
  // Looked up at call time, so a test can spy on the shared registry.
  const reach = <A extends unknown[], T>(
    call: (...args: A) => Promise<T>,
  ): ((...args: A) => Promise<T>) => {
    return async (...args) => {
      if (offline.on) throw new Error("registry unreachable");
      return call(...args);
    };
  };
  const registry: StreamSyncRegistry = {
    read: reach((scope) => w.registry.read(scope)),
    post: reach((request) => w.registry.post(request)),
    listControlRows: reach(() => w.registry.listControlRows()),
    listStreamRows: reach((key) => w.registry.listStreamRows(key)),
  };
  const deps: LocalSyncDeps = {
    db,
    keys,
    registry,
    blobs: w.blobs,
    queue: connectionQueue(),
    ownerAddress: owner,
    signer: { signAddData: async () => "0x00" },
    logger: { info: vi.fn(), warn: vi.fn() },
    now: () => ++now,
    newOp: () => `repro-${n}-${++op}`,
  };
  await bootstrapConnections(deps);
  await applyConnection(deps, w.fixture.control);
  const device = {
    db,
    deps,
    offline,
    deleter: createConnectionDeleter(deps, {
      declaredStreams: () => ["items"],
    }),
  };
  w.devices.push(device);
  return device;
}
type World = Awaited<ReturnType<typeof world>>;
type Device = {
  db: SqlDriver;
  deps: LocalSyncDeps;
  offline: { on: boolean };
  deleter: ReturnType<typeof createConnectionDeleter>;
};

let runs = 0;
/** One collector run through the real intake and end stores. */
async function collect(
  device: Device,
  ids: string[],
  options: { connect?: boolean; decl?: typeof declaration } = {},
) {
  const decl = options.decl ?? declaration;
  const key = decl.streams[0]!.primaryKey[0]!;
  const runId = `run-${++runs}`;
  const intake = createRunIntakeStore(device.deps);
  const begun = await intake.begin(
    runId,
    {
      connector: decl.connector,
      artifactDigest: "fixture",
      owner: { address: owner, leaseId: null },
      observedAt: 2000 + runs,
      ...(options.connect ? { connect: true } : {}),
    },
    decl,
  );
  await intake.batch(runId, {
    batch: 0,
    records: ids.map((id) => ({ stream: "items", data: { [key]: id } })),
  });
  await createRunEndStore(device.deps).end(runId, {
    outcome: "succeeded",
    coveredStreams: ["items"],
    lastBatch: 0,
    provenFullStreams: ["items"],
  });
  return { runId, mode: begun.start.collection_mode };
}

/** Delete from `device` until no intent is pending. */
async function deleteConnection(device: Device) {
  await device.deleter.requestConnectionDelete(declaration.connector);
  for (let i = 0; i < 5; i++) {
    if ((await device.deleter.resumeDeletes()).length === 0) return;
  }
  throw new Error("delete intent still pending");
}

/** The registry row of the stream now, decoded and classified. */
async function observeHead(w: World) {
  const row = await w.registry.read(w.scope);
  if (!row.found) return { found: false as const };
  const cipher = await w.blobs.get(`${w.scope}/${headBlobName(row.dataHash)}`);
  const decoded = cipher ? decodeHead(cipher) : null;
  const head = decoded?.kind === "ok" ? decoded.head : null;
  return {
    found: true as const,
    version: row.version,
    classification: classifyStreamRow(row, w.fixture.hashes),
    isDeleteMarker:
      row.metadataHash.toLowerCase() ===
      deleteMetadataHash(w.scope, row.version),
    generation: head?.generation ?? null,
    recordCount: head?.recordCount ?? null,
    lastDeleteVersion: head?.lastDeleteVersion ?? null,
    complete: head?.complete ?? null,
    primaryKey: head?.primaryKey ?? null,
    profile: head?.profile ?? null,
    partHashes: (head?.parts ?? []).map((p) => p.hash),
  };
}

async function generationOf(device: Device) {
  const [row] = await device.db.query<{ generation: number }>(
    "SELECT generation FROM connections",
  );
  return row!.generation;
}

/** The record ids a device holds for the stream, by the first key field. */
async function held(device: Device, field = "id") {
  const rows = await device.db.query<{ body: string }>(
    "SELECT body FROM records WHERE stream = 'items'",
  );
  return rows
    .map((r) => (JSON.parse(r.body) as Record<string, string>)[field]!)
    .sort();
}

async function streamState(device: Device) {
  const [row] = await device.db.query<{
    last_delete_version: number;
    head_version: number;
    head_generation: number | null;
  }>(
    "SELECT last_delete_version, head_version, head_generation FROM stream_state WHERE stream = 'items'",
  );
  return row;
}

async function snapshotOf(device: Device, runId: string) {
  const [row] = await device.db.query<{
    delete_snapshot: number;
    decision: string | null;
    reason: string | null;
  }>(
    "SELECT delete_snapshot, decision, reason FROM run_streams WHERE run_id = ?",
    [runId],
  );
  return row;
}

/** delete on `del`, reconnect + collect on `rec`, then the normal cycle. */
async function lifetime(w: World, del: Device, rec: Device, label: string) {
  await deleteConnection(del);
  const afterDelete = await observeHead(w);
  // The reconnecting device learns the deletion through a normal apply.
  if (rec !== del) await applyConnection(rec.deps, w.fixture.control);
  const { mode } = await collect(rec, [`${label}-new`], { connect: true });
  const generation = await generationOf(rec);
  const cycle = await syncConnection(rec.deps, w.fixture.control);
  return {
    afterDelete,
    mode,
    generation,
    outcomes: cycle.published.map((p) => p.outcome),
    cycleError: cycle.error,
    afterCycle: await observeHead(w),
  };
}

async function published(w: World, ids = ["old"]) {
  await collect(w.a, ids);
  expect(
    (await publishConnection(w.a.deps, w.fixture.control))[0]?.outcome,
  ).toBe("published");
  expect(await observeHead(w)).toMatchObject({
    generation: 1,
    recordCount: ids.length,
    classification: "present",
  });
}

const cycle = (device: Device, w: World) =>
  syncConnection(device.deps, w.fixture.control);

it("records the real inputs: delete head is generation 1 and 'present'; reconnect is generation 3", async () => {
  const w = await world();
  await published(w);
  const r = await lifetime(w, w.a, w.a, "one");
  expect(r.afterDelete).toMatchObject({
    version: 2,
    isDeleteMarker: true,
    generation: 1,
    recordCount: 0,
    lastDeleteVersion: 2,
    classification: "present",
  });
  expect(r.mode).toBe("full_refresh");
  expect(r.generation).toBe(3);
});

// 1. Same device.
it("a stream deleted and reconnected on the same device saves again, over the delete row", async () => {
  const w = await world();
  await published(w);
  const before = await observeHead(w);
  const r = await lifetime(w, w.a, w.a, "one");
  expect(r.cycleError).toBeNull();
  expect(r.outcomes).toEqual(["published"]);
  // CAS basis is the delete row's version: V=2, so the new head is V=3.
  expect(r.afterCycle).toMatchObject({
    found: true,
    version: 3,
    generation: 3,
    recordCount: 1,
    lastDeleteVersion: 2,
    classification: "present",
  });
  // No part of the old lifetime is reused.
  const after = await observeHead(w);
  for (const hash of (after.found && after.partHashes) || [])
    expect(before.found && before.partHashes).not.toContain(hash);
  expect(await held(w.a)).toEqual(["one-new"]);
  // A fresh reader sees the new data and nothing else.
  const fresh = await addDevice(w);
  await applyConnection(fresh.deps, w.fixture.control);
  expect(await held(fresh)).toEqual(["one-new"]);
});

// 2. Two devices, and a device with the old lifetime cached.
it("delete on one device, reconnect on another: both see only the new data", async () => {
  const w = await world();
  await published(w);
  const r = await lifetime(w, w.a, w.b, "one");
  expect(r.generation).toBe(3);
  expect(r.outcomes).toEqual(["published"]);
  expect(r.afterCycle).toMatchObject({
    version: 3,
    generation: 3,
    lastDeleteVersion: 2,
  });
  await applyConnection(w.a.deps, w.fixture.control);
  expect(await held(w.a)).toEqual(["one-new"]);
  expect(await held(w.b)).toEqual(["one-new"]);
});

it("the reconnecting device had the old lifetime cached: old rows and parts are not carried over", async () => {
  const w = await world();
  await published(w, ["a1", "a2", "a3"]);
  // Device b caches the old lifetime before the delete.
  await applyConnection(w.b.deps, w.fixture.control);
  expect(await held(w.b)).toEqual(["a1", "a2", "a3"]);
  const before = await observeHead(w);
  const r = await lifetime(w, w.a, w.b, "one");
  expect(r.outcomes).toEqual(["published"]);
  expect(r.afterCycle).toMatchObject({ recordCount: 1, generation: 3 });
  const after = await observeHead(w);
  for (const hash of (after.found && after.partHashes) || [])
    expect(before.found && before.partHashes).not.toContain(hash);
  expect(await held(w.b)).toEqual(["one-new"]);
});

it("a device that joins after the delete publishes the new lifetime from an empty database", async () => {
  const w = await world();
  await published(w);
  await deleteConnection(w.a);
  const late = await addDevice(w);
  // The late device never saw the old head: its first apply meets the delete row.
  await collect(late, ["late-new"], { connect: true });
  expect((await cycle(late, w)).published.map((p) => p.outcome)).toEqual([
    "published",
  ]);
  expect(await observeHead(w)).toMatchObject({
    version: 3,
    generation: 3,
    recordCount: 1,
    lastDeleteVersion: 2,
  });
});

// 3. Two rounds.
it("a second delete and reconnect saves again, with the latest delete as the fence", async () => {
  const w = await world();
  await published(w);
  const one = await lifetime(w, w.a, w.a, "one");
  expect(one.outcomes).toEqual(["published"]);
  const two = await lifetime(w, w.a, w.a, "two");
  expect(two.afterDelete).toMatchObject({ version: 4, generation: 1 });
  expect(two.generation).toBe(5);
  expect(two.outcomes).toEqual(["published"]);
  expect(two.afterCycle).toMatchObject({
    version: 5,
    generation: 5,
    recordCount: 1,
    lastDeleteVersion: 4,
  });
  expect(await held(w.a)).toEqual(["two-new"]);
});

// 4. Streams already stuck before this fix.
it("a stream stuck before the fix heals on its next publish, with no migration write", async () => {
  const w = await world();
  await published(w);
  await deleteConnection(w.a);
  const { runId } = await collect(w.a, ["stuck-new"], { connect: true });
  // The residue of a pre-fix client: it ignored the delete row, so the run
  // pinned snapshot 0 and the stream's local fence was 0.
  await w.a.db.batch([
    {
      sql: "UPDATE run_streams SET delete_snapshot = 0 WHERE run_id = ?",
      params: [runId],
    },
    { sql: "UPDATE stream_state SET last_delete_version = 0" },
  ]);
  const posts = vi.spyOn(w.registry, "post");
  const r = await cycle(w.a, w);
  expect(r.published.map((p) => p.outcome)).toEqual(["published"]);
  // The only post is the new head; nothing repaired the old row first.
  expect(
    posts.mock.calls.map(([req]) => [req.scope, req.expectedVersion]),
  ).toEqual([[w.scope, "3"]]);
  expect(await observeHead(w)).toMatchObject({
    version: 3,
    generation: 3,
    recordCount: 1,
    lastDeleteVersion: 2,
    // The delete row's default key and profile are not inherited.
    profile: { version: "1" },
  });
  expect(await held(w.a)).toEqual(["stuck-new"]);
  posts.mockRestore();
});

it("a stuck stream heals on a second device, and again after a second round (generation 5)", async () => {
  const w = await world();
  await published(w);
  await lifetime(w, w.a, w.a, "one");
  await deleteConnection(w.a);
  await applyConnection(w.b.deps, w.fixture.control);
  const { runId } = await collect(w.b, ["round-two"], { connect: true });
  await w.b.db.batch([
    {
      sql: "UPDATE run_streams SET delete_snapshot = 0 WHERE run_id = ?",
      params: [runId],
    },
    { sql: "UPDATE stream_state SET last_delete_version = 0" },
  ]);
  expect(await generationOf(w.b)).toBe(5);
  expect((await cycle(w.b, w)).published.map((p) => p.outcome)).toEqual([
    "published",
  ]);
  expect(await observeHead(w)).toMatchObject({
    version: 5,
    generation: 5,
    lastDeleteVersion: 4,
    recordCount: 1,
    profile: { version: "1" },
  });
});

// 5. Runs from before the delete never join the new lifetime.
it("a run that ended under the old lifetime on an offline device is discarded, never published", async () => {
  const w = await world();
  await published(w);
  await applyConnection(w.b.deps, w.fixture.control);
  const stale = await collect(w.b, ["stale"]); // ended under generation 1
  expect(await generationOf(w.b)).toBe(1);
  await lifetime(w, w.a, w.a, "one");
  const cycles = await cycle(w.b, w);
  void cycles;
  await cycle(w.b, w);
  expect(await snapshotOf(w.b, stale.runId)).toMatchObject({
    decision: "discarded",
    // Hydration does not rewrite the snapshot of an older lifetime's run.
    delete_snapshot: 0,
  });
  const head = await observeHead(w);
  expect(head).toMatchObject({ generation: 3, recordCount: 1 });
  expect(await held(w.b)).toEqual(["one-new"]);
  expect(await held(w.a)).toEqual(["one-new"]);
});

it("a run begun while the registry was unreachable is not handed the new lifetime", async () => {
  const w = await world();
  await published(w);
  await applyConnection(w.b.deps, w.fixture.control);
  w.b.offline.on = true;
  const unbound = await collect(w.b, ["unbound"]);
  w.b.offline.on = false;
  await lifetime(w, w.a, w.a, "one");
  await cycle(w.b, w);
  await cycle(w.b, w);
  expect(await snapshotOf(w.b, unbound.runId)).toMatchObject({
    decision: "discarded",
  });
  expect(await observeHead(w)).toMatchObject({ generation: 3, recordCount: 1 });
  expect(await held(w.b)).toEqual(["one-new"]);
});

// 6. The fence.
it("the delete fence is installed before a run begins, pinned by it, carried by every later head", async () => {
  const w = await world();
  await published(w);
  await deleteConnection(w.a);
  const { runId } = await collect(w.a, ["x"], { connect: true });
  expect(await streamState(w.a)).toMatchObject({ last_delete_version: 2 });
  expect(await snapshotOf(w.a, runId)).toMatchObject({ delete_snapshot: 2 });
  await cycle(w.a, w);
  expect(await observeHead(w)).toMatchObject({ lastDeleteVersion: 2 });
  // Another ordinary update in the same lifetime still carries it.
  await collect(w.a, ["y"]);
  await cycle(w.a, w);
  expect(await observeHead(w)).toMatchObject({
    version: 4,
    generation: 3,
    lastDeleteVersion: 2,
    recordCount: 2,
  });
  expect(await held(w.a)).toEqual(["x", "y"]);
});

// 7. Hygiene: nothing of the old lifetime enters the new head.
it("the new head has the new run's key and profile, not the delete row's", async () => {
  const other = {
    ...declaration,
    version: "7",
    streams: [{ ...declaration.streams[0]!, primaryKey: ["slug"] }],
  };
  const w = await world();
  await collect(w.a, ["s1", "s2", "s3", "s4"], { decl: other });
  await publishConnection(w.a.deps, w.fixture.control);
  await applyConnection(w.b.deps, w.fixture.control);
  const old = await observeHead(w);
  await deleteConnection(w.a);
  await applyConnection(w.b.deps, w.fixture.control);
  await collect(w.b, ["n1"], { connect: true, decl: other });
  await cycle(w.b, w);
  const head = await observeHead(w);
  expect(head).toMatchObject({
    generation: 3,
    recordCount: 1,
    primaryKey: ["slug"],
    profile: { version: "7" },
  });
  for (const hash of (head.found && head.partHashes) || [])
    expect(old.found && old.partHashes).not.toContain(hash);
  expect(await held(w.b, "slug")).toEqual(["n1"]);
});

// 8. Concurrency.
it("two devices publish the first new-lifetime head together: one wins, the other merges, no row is lost", async () => {
  const w = await world();
  await published(w);
  await deleteConnection(w.a);
  await collect(w.a, ["from-a"], { connect: true });
  await applyConnection(w.b.deps, w.fixture.control);
  await collect(w.b, ["from-b"]);
  await Promise.all([cycle(w.a, w), cycle(w.b, w)]);
  await cycle(w.a, w);
  await cycle(w.b, w);
  const head = await observeHead(w);
  expect(head).toMatchObject({ generation: 3, lastDeleteVersion: 2 });
  expect(await held(w.a)).toEqual(["from-a", "from-b"]);
  expect(await held(w.b)).toEqual(["from-a", "from-b"]);
  expect(head.found && head.recordCount).toBe(2);
});

// 9. Heads that must not heal.
async function forgeHead(w: World, generation: number, version: number) {
  const row = await w.registry.read(w.scope);
  if (!row.found) throw new Error("no row");
  const cipher = (await w.blobs.get(
    `${w.scope}/${headBlobName(row.dataHash)}`,
  ))!;
  const decoded = decodeHead(cipher);
  if (decoded.kind !== "ok") throw new Error("head");
  const bytes = encodeHead({ ...decoded.head, generation });
  const digest = await digestHead(async (b) => keccak_256(b), bytes);
  await w.blobs.put(`${w.scope}/${digest.blobName}`, bytes);
  await w.registry.post({
    ownerAddress: owner,
    scope: w.scope,
    dataHash: digest.dataHash,
    metadataHash: row.metadataHash as `0x${string}`,
    expectedVersion: String(version),
    signature: "0x00",
  });
}

it("a head of a later generation than the connection defers and is left as it is", async () => {
  const w = await world();
  await published(w);
  await deleteConnection(w.a);
  await collect(w.a, ["x"], { connect: true });
  await forgeHead(w, 9, 3);
  const posts = vi.spyOn(w.registry, "post");
  const r = await cycle(w.a, w);
  expect(r.published.map((p) => p.outcome)).toEqual(["deferred"]);
  expect(posts).not.toHaveBeenCalled();
  expect(await observeHead(w)).toMatchObject({ version: 3, generation: 9 });
  posts.mockRestore();
});

it("a head whose blob is missing never turns into an empty base", async () => {
  const w = await world();
  await published(w);
  await deleteConnection(w.a);
  await collect(w.a, ["x"], { connect: true });
  const row = await w.registry.read(w.scope);
  if (!row.found) throw new Error("no row");
  const posts = vi.spyOn(w.registry, "post");
  const blobs = vi.spyOn(w.blobs, "get").mockImplementation(async () => null);
  const r = await cycle(w.a, w);
  blobs.mockRestore();
  expect(r.error ?? r.published.map((p) => p.outcome)).not.toContain(
    "published",
  );
  expect(posts).not.toHaveBeenCalled();
  expect(await w.registry.read(w.scope)).toMatchObject({ version: 2 });
  posts.mockRestore();
});

it("a deleted connection never heals: its publish purges", async () => {
  const w = await world();
  await published(w);
  await deleteConnection(w.a);
  const r = await publishConnection(w.a.deps, w.fixture.control);
  expect(r.map((p) => p.outcome)).not.toContain("published");
  expect(await observeHead(w)).toMatchObject({ version: 2, generation: 1 });
});

// 12. An empty collection.
it("an empty collection after a reconnect posts nothing; the next real work carries the fence", async () => {
  const w = await world();
  await published(w);
  await deleteConnection(w.a);
  await collect(w.a, [], { connect: true });
  const posts = vi.spyOn(w.registry, "post");
  // As for a stream's first run, an empty run over no data is a no-op.
  expect((await cycle(w.a, w)).published.map((p) => p.outcome)).toEqual([
    "noop",
  ]);
  expect(posts).not.toHaveBeenCalled();
  await collect(w.a, ["z"]);
  expect((await cycle(w.a, w)).published.map((p) => p.outcome)).toEqual([
    "published",
  ]);
  expect(await observeHead(w)).toMatchObject({
    version: 3,
    generation: 3,
    recordCount: 1,
    lastDeleteVersion: 2,
    complete: true,
  });
  posts.mockRestore();
});
