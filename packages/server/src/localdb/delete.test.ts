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
  type RegistryBatchResult,
  type SignedRegistryBatch,
  type StreamSyncRegistry,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import { applyConnection } from "../../../core/src/localdb/apply.js";
import { bootstrapConnections } from "../../../core/src/localdb/bootstrap.js";
import { createConnectionDeleter } from "../../../core/src/localdb/delete.js";
import { batchBounds } from "../../../core/src/localdb/batch-commit.js";
import { gatewayBatchRefusal } from "../../../core/src/localdb/batch-contract.js";
import {
  RegistryRefusedError,
  RegistryUnavailableError,
} from "../../../core/src/stream-sync/ports.js";
import { remoteFixture } from "./apply-fixture.js";
import { postStreamDeleteOnly } from "./legacy-delete-fixture.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const owner = `0x${"12".repeat(20)}`;
const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
});
async function world(
  file?: string,
  names: readonly string[] = ["items"],
  withControl = true,
) {
  const keys = {
    namespaceHmac: async () => new Uint8Array(32),
    encrypt: async (_s: string, b: Uint8Array) => b,
    encryptPart: async (_s: string, b: Uint8Array) => b,
    decrypt: async (_s: string, b: Uint8Array) => b,
  };
  const fixture = await remoteFixture(keys);
  const registry = createMemoryStreamSyncRegistry() as MemoryStreamSyncRegistry;
  const blobs = createMemoryStreamSyncBlobs();
  const heads = [];
  for (const name of names)
    heads.push(await fixture.head(name, [{ id: "base" }]));
  const h = heads[0]!;
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
    const deleter = createConnectionDeleter(deps, {
      declaredStreams: () => names,
    });
    devices.push({ db, deps, deleter });
  }
  return {
    ...fixture,
    a: devices[0]!,
    b: devices[1]!,
    registry,
    blobs,
    head: h,
    heads,
  };
}
it("persists intent before the first registry write and a second device stays deleted", async () => {
  const f = await world();
  const events: string[] = [];
  f.registry.beforePost = async (request) => {
    expect(
      await f.a.db.query("SELECT count(*) AS n FROM delete_intents"),
    ).toEqual([{ n: 1 }]);
    events.push(request.scope);
  };
  const started = await f.a.deleter.requestConnectionDelete("fixture-source");
  expect(started.deleteId).toBeTruthy();
  expect(await f.a.deleter.resumeDeletes()).toEqual([]);
  // The control tombstone is the one linearization point: it lands first.
  expect(events).toEqual([f.control, f.head.scope]);
  await applyConnection(f.b.deps, f.control);
  await applyConnection(f.b.deps, f.control);
  for (const device of [f.a, f.b]) {
    expect(await device.db.query("SELECT * FROM records")).toEqual([]);
    expect(
      await device.db.query("SELECT control_state FROM connections"),
    ).toEqual([{ control_state: "deleted" }]);
  }
});

it("a conflicting control post is re-read as an already-landed tombstone", async () => {
  const f = await world();
  let conflicted = false;
  f.registry.beforePost = async (post) => {
    if (post.scope !== f.control) return;
    f.registry.beforePost = undefined;
    conflicted = true;
    await f.registry.post(post);
  };
  await f.a.deleter.requestConnectionDelete("fixture-source");
  expect(await f.a.deleter.resumeDeletes()).toEqual([]);
  expect(conflicted).toBe(true);
  expect(await f.registry.read(f.control)).toMatchObject({ version: 2 });
  expect(await f.a.db.query("SELECT * FROM delete_intents")).toEqual([]);
});

it("pins a control reread rather than a stale listing", async () => {
  const f = await world();
  await f.registry.post({
    ownerAddress: owner,
    scope: f.control,
    dataHash: f.hashes.tombstoneData,
    metadataHash: f.hashes.tombstoneMetadata,
    expectedVersion: "2",
    signature: "0x00",
  });
  await f.registry.post({
    ownerAddress: owner,
    scope: f.control,
    dataHash: f.hashes.activeData,
    metadataHash: f.hashes.activeMetadata,
    expectedVersion: "3",
    signature: "0x00",
  });
  const listed = f.registry.listControlRows.bind(f.registry);
  f.registry.listControlRows = async () =>
    (await listed()).map((row) => ({
      ...row,
      read: { ...row.read, version: 1 } as typeof row.read,
    }));
  await f.a.deleter.requestConnectionDelete("fixture-source");
  expect(await f.a.deleter.resumeDeletes()).toEqual([]);
  expect(await f.registry.read(f.control)).toMatchObject({ version: 4 });
});

it("resumes a saved stream pin after a failed post without losing the intent", async () => {
  const f = await world();
  f.registry.beforePost = async (post) => {
    if (post.scope !== f.control) throw new Error("offline fixture");
  };
  const first = await f.a.deleter.requestConnectionDelete("fixture-source");
  expect(await f.a.deleter.resumeDeletes()).toHaveLength(1);
  const [saved] = await f.a.db.query<{ intent: string }>(
    "SELECT intent FROM delete_intents",
  );
  expect(JSON.parse(saved!.intent).streams[0].pin).toBe(2);
  expect(await f.a.db.query("SELECT * FROM records")).toEqual([]);
  f.registry.beforePost = undefined;
  const resumed = createConnectionDeleter(f.a.deps, {
    declaredStreams: () => [],
  });
  expect(await resumed.resumeDeletes()).toEqual([]);
  expect(await f.registry.read(f.head.scope)).toMatchObject({ version: 2 });
  expect(await f.registry.read(f.control)).toMatchObject({ version: 2 });
  expect(first.deleteId).toBeTruthy();
});

it("resumes a pinned delete even when the old head cannot be read", async () => {
  const f = await world();
  f.registry.beforePost = async () => {
    throw new Error("offline fixture");
  };
  await f.a.deleter.requestConnectionDelete("fixture-source");
  await f.a.deleter.resumeDeletes();
  f.registry.beforePost = undefined;
  const resumed = createConnectionDeleter(
    {
      ...f.a.deps,
      blobs: {
        governor: f.blobs.governor,
        put: (...args) => f.blobs.put(...args),
        exists: (...args) => f.blobs.exists(...args),
        get: async () => {
          throw new Error("unreadable old head fixture");
        },
      },
    },
    { declaredStreams: () => [] },
  );
  expect(await resumed.resumeDeletes()).toEqual([]);
  expect(await f.registry.read(f.control)).toMatchObject({ version: 2 });
});

it("a reply lost after a stream delete does not post that stream twice", async () => {
  const f = await world();
  f.registry.afterPost = async (post) => {
    if (post.scope === f.head.scope) throw new Error("lost reply fixture");
  };
  await f.a.deleter.requestConnectionDelete("fixture-source");
  expect(await f.a.deleter.resumeDeletes()).toHaveLength(1);
  f.registry.afterPost = undefined;
  expect(await f.a.deleter.resumeDeletes()).toEqual([]);
  expect(await f.registry.read(f.head.scope)).toMatchObject({ version: 2 });
});

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
  const { publishConnection } =
    await import("../../../core/src/localdb/publish.js");
  expect((await publishConnection(f.a.deps, f.control))[0]?.outcome).toBe(
    "deferred",
  );
  f.registry.beforePost = undefined;
  await f.a.deleter.resumeDeletes();
});

it("a reconnect that wins the fence race is never tombstoned, and the ended lifetime is still cleaned", async () => {
  const f = await world();
  let moved = false;
  f.registry.beforePost = async (post) => {
    if (post.scope !== f.control) return;
    f.registry.beforePost = undefined;
    moved = true;
    // Another surface lands the same fence, then reconnects (active, version 3).
    await f.registry.post(post);
    await f.registry.post({
      ownerAddress: owner,
      scope: f.control,
      dataHash: f.hashes.activeData,
      metadataHash: f.hashes.activeMetadata,
      expectedVersion: "3",
      signature: "0x00",
    });
  };
  await f.a.deleter.requestConnectionDelete("fixture-source");
  const pending = await f.a.deleter.resumeDeletes();
  expect(moved).toBe(true);
  // No "superseded" exit: the fence landed (control version >= pin + 1), so the
  // delete goes on to remove the data of the lifetime it ended.
  expect(pending).toEqual([]);
  expect(await f.registry.read(f.control)).toMatchObject({
    version: 3,
    dataHash: f.hashes.activeData,
  });
  expect(await f.registry.read(f.head.scope)).toMatchObject({ version: 2 });
  expect(await f.a.db.query("SELECT * FROM delete_intents")).toEqual([]);
});

it("ConnectorNotVerifiedError refuses a pin-only connection before persisting or purging", async () => {
  const f = await world();
  f.registry.listStreamRows = async () => [];
  const store = createConnectionDeleter(f.a.deps, {
    declaredStreams: () => [],
  });
  await expect(
    store.requestConnectionDelete("fixture-source"),
  ).rejects.toMatchObject({ name: "ConnectorNotVerifiedError" });
  expect(await f.a.db.query("SELECT * FROM delete_intents")).toEqual([]);
  expect(await f.a.db.query("SELECT count(*) AS n FROM records")).toEqual([
    { n: 1 },
  ]);
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

it("deletion fences declared rowless streams after the control tombstone", async () => {
  const f = await world();
  const store = createConnectionDeleter(f.a.deps, {
    declaredStreams: () => ["items", "rowless"],
  });
  await store.requestConnectionDelete("fixture-source");
  expect(await store.resumeDeletes()).toEqual([]);
  expect(await f.registry.read(f.control + ".rowless")).toMatchObject({
    found: true,
    version: 1,
  });
  const scopes = f.registry.log.slice(-3).map((row) => row.scope);
  expect(scopes[0]).toBe(f.control);
  expect(scopes.slice(1).sort()).toEqual([
    f.head.scope,
    f.control + ".rowless",
  ]);
});

it("L11 publishes an incremental run over a stream tombstone as incomplete and needs_full", async () => {
  const f = await world();
  // A stream delete of the active lifetime with the control row still active.
  await postStreamDeleteOnly({
    registry: f.registry,
    blobs: f.blobs,
    keys: f.a.deps.keys,
    owner,
    connector: "fixture-source",
    ns: "",
    stream: "items",
    scope: f.head.scope,
    endedGeneration: 1,
  });
  await applyConnection(f.b.deps, f.control);
  await f.b.db.batch([
    {
      sql: "UPDATE connections SET checkpoint=?",
      params: [JSON.stringify({ items: "old-cursor" })],
    },
  ]);
  const { createRunIntakeStore } =
    await import("../../../core/src/localdb/run-intake.js");
  const { createRunEndStore } =
    await import("../../../core/src/localdb/run-end.js");
  const { publishConnection } =
    await import("../../../core/src/localdb/publish.js");
  const intake = createRunIntakeStore(f.b.deps);
  const req = {
    connector: "fixture-source",
    artifactDigest: "fixture",
    owner: { address: owner, leaseId: null },
    observedAt: 1000,
  };
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
  expect(
    (await intake.begin("incremental", req, decl)).start.collection_mode,
  ).toBe("incremental");
  await intake.batch("incremental", {
    batch: 0,
    records: [{ stream: "items", data: { id: "fresh" } }],
  });
  await createRunEndStore(f.b.deps).end("incremental", {
    outcome: "succeeded",
    coveredStreams: ["items"],
    lastBatch: 0,
  });
  expect((await publishConnection(f.b.deps, f.control))[0]?.outcome).toBe(
    "published",
  );
  expect(
    await f.b.db.query("SELECT complete,needs_full FROM stream_state"),
  ).toEqual([{ complete: 0, needs_full: 1 }]);
  expect(
    (await intake.begin("full-next", { ...req, observedAt: 1100 }, decl)).start
      .collection_mode,
  ).toBe("full_refresh");
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
    const resumed = createConnectionDeleter(
      { ...f.a.deps, db, queue: connectionQueue() },
      { declaredStreams: () => [] },
    );
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
  const begun = await createRunIntakeStore(f.b.deps).begin(
    "scheduled-after-peer-connect",
    request,
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
  await createConnectionDeleter(deps, {
    declaredStreams: () => ["items"],
  }).requestConnectionDelete("fixture-source");
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

// Makes the first `losses` posts to the stream head lose their CAS: a rival row
// takes the version the delete signed for, so the delete must re-read and re-sign.
function loseHeadRaces(f: Awaited<ReturnType<typeof world>>, losses: number) {
  let lost = 0;
  f.registry.beforePost = async (post) => {
    if (post.scope !== f.head.scope || lost === losses) return;
    lost++;
    const hook = f.registry.beforePost;
    f.registry.beforePost = undefined;
    const current = (await f.registry.read(post.scope)).version ?? 0;
    await f.registry.post({
      ownerAddress: owner,
      scope: post.scope,
      dataHash: `0x${"ab".repeat(32)}`,
      metadataHash: `0x${"cd".repeat(32)}`,
      expectedVersion: String(current + 1),
      signature: "0x00",
    });
    f.registry.beforePost = hook;
  };
  return () => lost;
}

it("a stream delete that wins its eighth CAS attempt still confirms and reports success", async () => {
  const f = await world();
  const lost = loseHeadRaces(f, 7);
  await f.a.deleter.requestConnectionDelete("fixture-source");
  expect(await f.a.deleter.resumeDeletes()).toEqual([]);
  expect(lost()).toBe(7);
  // Fixture version 1, seven rival rows, then the delete's own winning row.
  expect(await f.registry.read(f.head.scope)).toMatchObject({ version: 9 });
  expect(await f.a.db.query("SELECT * FROM delete_intents")).toEqual([]);
});

it("eight lost stream CAS races still end pending without a ninth post", async () => {
  const f = await world();
  const lost = loseHeadRaces(f, 8);
  await f.a.deleter.requestConnectionDelete("fixture-source");
  const pending = await f.a.deleter.resumeDeletes();
  expect(lost()).toBe(8);
  expect(await f.registry.read(f.head.scope)).toMatchObject({ version: 9 });
  expect(pending).toEqual([{ connector: "fixture-source", why: "Error" }]);
  expect(await f.a.db.query("SELECT * FROM delete_intents")).toHaveLength(1);
});

type World = Awaited<ReturnType<typeof world>>;
const EIGHT_ATTEMPTS = 8;
/** A row no delete signed: its head blob does not exist, so no read verifies it. */
const UNSHOWN = {
  dataHash: `0x${"ef".repeat(32)}` as `0x${string}`,
  metadataHash: `0x${"fe".repeat(32)}` as `0x${string}`,
};

/** Another writer's acknowledged post, made without re-entering the test hooks. */
async function rivalWrite(registry: MemoryStreamSyncRegistry, scope: string) {
  const { beforePost, afterPost } = registry;
  registry.beforePost = undefined;
  registry.afterPost = undefined;
  try {
    const current = (await registry.read(scope)).version ?? 0;
    await registry.post({
      ownerAddress: owner,
      scope,
      dataHash: UNSHOWN.dataHash,
      metadataHash: UNSHOWN.metadataHash,
      expectedVersion: String(current + 1),
      signature: "0x00",
    });
  } finally {
    registry.beforePost = beforePost;
    registry.afterPost = afterPost;
  }
}

/**
 * Scripts the registry's answer to each head post, 1-based: "lose" (a rival
 * takes the version first, so the CAS is rejected), "ack" (committed and
 * acknowledged, reads unchanged), or "overwrite" (committed, then a rival
 * overwrites it before the delete's next read). `hideHead` makes every head
 * read show an unsigned row. Returns the count of the delete's head posts; a
 * ninth post throws, so a broken budget fails fast with a count, not a hang.
 */
function scriptHeadPosts(
  f: World,
  outcome: (post: number) => "lose" | "ack" | "overwrite",
  hideHead = false,
) {
  const registry = f.registry;
  let posts = 0;
  let current: "lose" | "ack" | "overwrite" = "ack";
  if (hideHead) {
    const read = registry.read.bind(registry);
    registry.read = async (scope) => {
      const row = await read(scope);
      return scope === f.head.scope && row.found ? { ...row, ...UNSHOWN } : row;
    };
  }
  registry.beforePost = async (post) => {
    if (post.scope !== f.head.scope) return;
    posts++;
    if (posts > EIGHT_ATTEMPTS)
      throw new Error("runaway: more than eight stream posts");
    current = outcome(posts);
    if (current === "lose") await rivalWrite(registry, post.scope);
  };
  registry.afterPost = async (post) => {
    if (post.scope === f.head.scope && current === "overwrite")
      await rivalWrite(registry, post.scope);
  };
  return () => posts;
}

it("an acknowledged stream post that the next read never shows ends pending after eight posts", async () => {
  const f = await world();
  const posts = scriptHeadPosts(f, () => "ack", true);
  await f.a.deleter.requestConnectionDelete("fixture-source");
  const pending = await f.a.deleter.resumeDeletes();
  expect(posts()).toBe(EIGHT_ATTEMPTS);
  expect(pending).toEqual([{ connector: "fixture-source", why: "Error" }]);
  expect(await f.a.db.query("SELECT * FROM delete_intents")).toHaveLength(1);
});

it("an acknowledged stream post overwritten before the next read ends pending after eight posts", async () => {
  const f = await world();
  const posts = scriptHeadPosts(f, () => "overwrite");
  await f.a.deleter.requestConnectionDelete("fixture-source");
  const pending = await f.a.deleter.resumeDeletes();
  expect(posts()).toBe(EIGHT_ATTEMPTS);
  expect(pending).toEqual([{ connector: "fixture-source", why: "Error" }]);
  expect(await f.a.db.query("SELECT * FROM delete_intents")).toHaveLength(1);
});

it("rejected and overwritten stream posts share one budget of eight", async () => {
  const f = await world();
  const posts = scriptHeadPosts(f, (n) => (n % 2 === 1 ? "lose" : "overwrite"));
  await f.a.deleter.requestConnectionDelete("fixture-source");
  const pending = await f.a.deleter.resumeDeletes();
  expect(posts()).toBe(EIGHT_ATTEMPTS);
  expect(pending).toEqual([{ connector: "fixture-source", why: "Error" }]);
  expect(await f.a.db.query("SELECT * FROM delete_intents")).toHaveLength(1);
});

// ---------------------------------------------------------------------------
// The control fence. A delete lands the connection's control tombstone first:
// one registry write that every other surface reads to decide the connection
// is gone. Stream cleanup follows, stream by stream in parallel, and only ever
// removes data of the lifetime the fence ended.
// ---------------------------------------------------------------------------

function deferred() {
  let release!: () => void;
  const promise = new Promise<void>((resolve) => (release = resolve));
  return { promise, release };
}

const FOUR = ["items", "events", "profile", "history"] as const;

it("the fence is visible to another device before any stream is cleaned, and the request says so", async () => {
  const f = await world(undefined, FOUR);
  const gate = deferred();
  const streamPosts: string[] = [];
  f.registry.beforePost = async (post) => {
    if (post.scope === f.control) return;
    streamPosts.push(post.scope);
    await gate.promise;
  };
  const started = await f.a.deleter.requestConnectionDelete("fixture-source");
  // Cleanup is parked; the control tombstone has already landed.
  expect(started.fenced).toBe(true);
  expect(await f.registry.read(f.control)).toMatchObject({ version: 2 });
  for (const head of f.heads)
    expect(await f.registry.read(head.scope)).toMatchObject({ version: 1 });
  await applyConnection(f.b.deps, f.control);
  expect(await f.b.db.query("SELECT * FROM records")).toEqual([]);
  expect(await f.b.db.query("SELECT control_state FROM connections")).toEqual([
    { control_state: "deleted" },
  ]);
  gate.release();
  expect(await f.a.deleter.resumeDeletes()).toEqual([]);
  for (const head of f.heads)
    expect(await f.registry.read(head.scope)).toMatchObject({ version: 2 });
  expect(await f.a.db.query("SELECT * FROM delete_intents")).toEqual([]);
});

it("every stream's tombstone post is in flight at once", async () => {
  const f = await world(undefined, FOUR);
  const together = deferred();
  let inFlight = 0;
  f.registry.beforePost = async (post) => {
    if (post.scope === f.control) return;
    if (++inFlight === FOUR.length) together.release();
    await Promise.race([
      together.promise,
      new Promise<never>((_, reject) =>
        setTimeout(
          () =>
            reject(new Error(`serial: ${inFlight} stream post(s) in flight`)),
          500,
        ),
      ),
    ]);
  };
  await f.a.deleter.requestConnectionDelete("fixture-source");
  expect(await f.a.deleter.resumeDeletes()).toEqual([]);
  expect(inFlight).toBe(FOUR.length);
});

/**
 * A registry and blob store whose every call takes LATENCY ms (the shape of the
 * measured per-call cost; the ratio below does not depend on the number).
 */
const LATENCY = 25;
async function timedDelete(streamCount: number) {
  const names = FOUR.slice(0, streamCount);
  const f = await world(undefined, names);
  const wait = () =>
    new Promise<void>((resolve) => setTimeout(resolve, LATENCY));
  const slow = <A extends unknown[], T>(
    call: (...args: A) => Promise<T>,
  ): ((...args: A) => Promise<T>) => {
    return async (...args) => {
      await wait();
      return call(...args);
    };
  };
  f.registry.read = slow(f.registry.read.bind(f.registry));
  f.registry.post = slow(f.registry.post.bind(f.registry));
  f.registry.listControlRows = slow(
    f.registry.listControlRows.bind(f.registry),
  );
  f.registry.listStreamRows = slow(f.registry.listStreamRows.bind(f.registry));
  const blobs = f.a.deps.blobs;
  blobs.put = slow(blobs.put.bind(blobs));
  blobs.get = slow(blobs.get.bind(blobs));
  const started = performance.now();
  await f.a.deleter.requestConnectionDelete("fixture-source");
  const answeredMs = performance.now() - started;
  expect(await f.a.deleter.resumeDeletes()).toEqual([]);
  const totalMs = performance.now() - started;
  for (const head of f.heads)
    expect(await f.registry.read(head.scope)).toMatchObject({ version: 2 });
  return { answeredMs, totalMs };
}

it("deleting four streams takes about the time of deleting one, not four times as long", async () => {
  const one = await timedDelete(1);
  const four = await timedDelete(4);
  // Serial cleanup adds a whole stream chain per stream (about 3.5x here).
  expect(four.totalMs).toBeLessThan(one.totalMs * 1.8);
  // The request waits for the fence only: it answers before any stream chain ends.
  expect(four.answeredMs).toBeLessThan(four.totalMs * 0.8);
});

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

it("a fence whose reply was lost is confirmed from the registry; it never lands twice", async () => {
  const f = await world();
  f.registry.afterPost = async (post) => {
    if (post.scope === f.control) throw new Error("lost reply fixture");
  };
  // The tombstone committed and only its reply was lost: a read proves it, so
  // the request already answers fenced.
  const started = await f.a.deleter.requestConnectionDelete("fixture-source");
  expect(started.fenced).toBe(true);
  expect(await f.registry.read(f.control)).toMatchObject({ version: 2 });
  f.registry.afterPost = undefined;
  expect(await f.a.deleter.resumeDeletes()).toEqual([]);
  expect(
    f.registry.log
      .filter((post) => post.scope === f.control)
      .map((p) => p.version),
  ).toEqual([1, 2]);
  expect(await f.registry.read(f.head.scope)).toMatchObject({ version: 2 });
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
  // A restart before the fence phase was saved resumes through the same path.
  await f.a.db.query(
    "UPDATE delete_intents SET intent = json_remove(intent, '$.fences')",
  );
  f.registry.afterPost = undefined;
  expect(await f.a.deleter.resumeDeletes()).toEqual([]);
  // Cleanup ran with no further successful control post.
  expect(
    f.registry.log
      .filter((post) => post.scope === f.control)
      .map((p) => p.version),
  ).toEqual([1, 2]);
  expect(await f.registry.read(f.head.scope)).toMatchObject({ version: 2 });
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

it("a fence the next read does not show yet stays pending, then confirms the same version", async () => {
  const f = await world();
  const read = f.registry.read.bind(f.registry);
  let lagging = false;
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
  expect(
    f.registry.log
      .filter((post) => post.scope === f.control)
      .map((p) => p.version),
  ).toEqual([1, 2]);
});

it("the fence phase is saved with the version it expects, and a restart resumes cleanup without a second fence post", async () => {
  const f = await world();
  const gate = deferred();
  f.registry.beforePost = async (post) => {
    if (post.scope !== f.control) {
      await gate.promise;
      throw new Error("stopped before cleanup");
    }
  };
  gate.release();
  const started = await f.a.deleter.requestConnectionDelete("fixture-source");
  expect(started.fenced).toBe(true);
  await f.a.deleter.resumeDeletes();
  const [saved] = await f.a.db.query<{ intent: string }>(
    "SELECT intent FROM delete_intents",
  );
  expect(JSON.parse(saved!.intent).fences).toEqual([{ ns: "", version: 2 }]);
  f.registry.beforePost = undefined;
  const posts = vi.spyOn(f.registry, "post");
  const restarted = createConnectionDeleter(f.a.deps, {
    declaredStreams: () => [],
  });
  expect(await restarted.resumeDeletes()).toEqual([]);
  expect(posts.mock.calls.map(([post]) => post.scope)).toEqual([f.head.scope]);
});

it("an intent saved before the fence existed, with its streams landed, finishes with the control tombstone", async () => {
  const f = await world();
  f.registry.beforePost = async () => {
    throw new Error("offline fixture");
  };
  await f.a.deleter.requestConnectionDelete("fixture-source");
  const [saved] = await f.a.db.query<{ intent: string }>(
    "SELECT intent FROM delete_intents",
  );
  const legacy = { ...JSON.parse(saved!.intent), streamsLanded: true };
  delete legacy.fences;
  await f.a.db.batch([
    {
      sql: "UPDATE delete_intents SET intent=?",
      params: [JSON.stringify(legacy)],
    },
  ]);
  f.registry.beforePost = undefined;
  const resumed = createConnectionDeleter(f.a.deps, {
    declaredStreams: () => [],
  });
  expect(await resumed.resumeDeletes()).toEqual([]);
  expect(await f.registry.read(f.control)).toMatchObject({ version: 2 });
  expect(await f.a.db.query("SELECT * FROM delete_intents")).toEqual([]);
});

it("a connection with no control row cleans its streams under the old rule and posts no control tombstone", async () => {
  const f = await world(undefined, ["items"], false);
  const posts: string[] = [];
  f.registry.beforePost = async (post) => {
    posts.push(post.scope);
  };
  const started = await f.a.deleter.requestConnectionDelete("fixture-source");
  expect(await f.a.deleter.resumeDeletes()).toEqual([]);
  expect(started.deleteId).toBeTruthy();
  expect(posts).toEqual([f.head.scope]);
  expect(await f.registry.read(f.control)).toEqual({ found: false });
  expect(await f.a.db.query("SELECT * FROM delete_intents")).toEqual([]);
});

it("cleanup of a stream whose head cannot be read after the fence still finishes while no reconnect happened", async () => {
  const f = await world();
  const real = f.a.deps.blobs.get.bind(f.a.deps.blobs);
  f.a.deps.blobs.get = async () => {
    throw new Error("unreadable old head fixture");
  };
  try {
    await f.a.deleter.requestConnectionDelete("fixture-source");
    expect(await f.a.deleter.resumeDeletes()).toEqual([]);
  } finally {
    f.a.deps.blobs.get = real;
  }
  expect(await f.registry.read(f.head.scope)).toMatchObject({ version: 2 });
});

// ---------------------------------------------------------------------------
// Reads: a landing reuses the plan's listing and observes each unfenced
// control row once. Counts are of `registry.read` during the delete only.
// ---------------------------------------------------------------------------

function countReads(registry: MemoryStreamSyncRegistry) {
  const reads: string[] = [];
  const read = registry.read.bind(registry);
  registry.read = async (scope) => {
    reads.push(scope);
    return read(scope);
  };
  // The plan's listing reads every row it returns; the landing starts after it.
  const listed = registry.listStreamRows.bind(registry);
  registry.listStreamRows = async (connector) => {
    const rows = await listed(connector);
    reads.length = 0;
    return rows;
  };
  return reads;
}

const FIVE = ["s1", "s2", "s3", "s4", "s5"] as const;

it("five unfenced streams cost five confirming stream reads and one control read", async () => {
  const f = await world(undefined, FIVE, false);
  const reads = countReads(f.registry);
  await f.a.deleter.requestConnectionDelete("fixture-source");
  expect(await f.a.deleter.resumeDeletes()).toEqual([]);
  // Before: 5 first reads + 5 confirming reads + 10 control reads = 20.
  expect(reads.filter((scope) => scope === f.control)).toHaveLength(1);
  expect(reads).toHaveLength(6);
  for (const head of f.heads)
    expect(await f.registry.read(head.scope)).toMatchObject({ version: 2 });
});

it("a stale listed row costs one rejected write, one refresh read of the row and of its control", async () => {
  const f = await world(undefined, ["items"], false);
  const listed = f.registry.listStreamRows.bind(f.registry);
  f.registry.listStreamRows = async (connector) => {
    const stale = await listed(connector);
    await rivalWrite(f.registry, f.head.scope);
    return stale;
  };
  let rejected = 0;
  const post = f.registry.post.bind(f.registry);
  f.registry.post = async (request) => {
    const answer = await post(request);
    if (answer.kind === "conflict") rejected++;
    return answer;
  };
  const reads = countReads(f.registry);
  await f.a.deleter.requestConnectionDelete("fixture-source");
  expect(await f.a.deleter.resumeDeletes()).toEqual([]);
  expect(rejected).toBe(1);
  expect(reads.filter((scope) => scope === f.head.scope)).toHaveLength(2);
  expect(reads.filter((scope) => scope === f.control)).toHaveLength(2);
  expect(await f.registry.read(f.head.scope)).toMatchObject({ version: 3 });
  expect(await f.a.db.query("SELECT * FROM delete_intents")).toEqual([]);
});

// ---------------------------------------------------------------------------
// Two commits: with a batch route the fence goes in one POST /v1/data/batch and
// every stream row of the connection in the next (split at the gateway's 16
// rows). A fence and a condition on it cannot share a request.
// ---------------------------------------------------------------------------

const names = (n: number) => Array.from({ length: n }, (_, i) => `s${i + 1}`);

/**
 * Gives the memory registry the batch route's contract: conditions are judged
 * first against the state before the writes; then each row is its own
 * compare-and-set (version, and the head's data hash when the row names it).
 */
function withBatchRoute(f: World, route: "present" | 405 = "present") {
  const registry: StreamSyncRegistry = f.registry;
  const batches: SignedRegistryBatch[] = [];
  const singles: string[] = [];
  let inBatch = 0;
  const post = f.registry.post.bind(f.registry);
  f.registry.post = async (request) => {
    if (inBatch === 0) singles.push(request.scope);
    return post(request);
  };
  registry.postBatch = async (request): Promise<RegistryBatchResult> => {
    batches.push(request);
    if (route === 405) return { kind: "unsupported" };
    // The real route answers 400 to a request of a shape it refuses.
    const refusal = gatewayBatchRefusal(request, batchBounds(f.registry));
    if (refusal !== null)
      throw new RegistryRefusedError(`batch POST refused: ${refusal}`, 400);
    for (const need of request.requires) {
      const row = await f.registry.read(need.scope);
      const tombstoned = row.found && row.dataHash === f.hashes.tombstoneData;
      if (
        !row.found ||
        String(row.version) !== need.expectedVersion ||
        (need.notDeleted && tombstoned) ||
        (need.expectedDataHash !== undefined &&
          row.dataHash.toLowerCase() !== need.expectedDataHash.toLowerCase())
      )
        return { kind: "precondition_failed", failure: null };
    }
    const rows: Extract<
      RegistryBatchResult,
      { kind: "rows" }
    >["rows"][number][] = [];
    inBatch++;
    try {
      for (const row of request.rows) {
        const head = await f.registry.read(row.scope);
        const answer =
          row.expectedHeadDataHash !== undefined &&
          (!head.found || head.dataHash !== row.expectedHeadDataHash)
            ? ({
                kind: "conflict",
                latestVersion: head.found ? String(head.version) : null,
              } as const)
            : await f.registry.post({
                ownerAddress: request.ownerAddress,
                ...row,
              });
        rows.push(
          answer.kind === "committed"
            ? { kind: "committed" }
            : {
                kind: "conflict",
                latestVersion: answer.latestVersion,
                latestDataHash: head.found ? head.dataHash : null,
              },
        );
      }
    } finally {
      inBatch--;
    }
    return { kind: "rows", rows };
  };
  return { batches, singles };
}

it("a six-stream delete is two POSTs: the fence alone, then every stream row resting on it", async () => {
  const f = await world(undefined, names(6));
  const { batches, singles } = withBatchRoute(f);
  const started = await f.a.deleter.requestConnectionDelete("fixture-source");
  expect(started.fenced).toBe(true);
  expect(await f.a.deleter.resumeDeletes()).toEqual([]);
  expect(batches).toHaveLength(2);
  expect(singles).toEqual([]);
  const [fence, streams] = batches;
  // The fence row is its own compare-and-set, so it names no condition.
  expect(fence!.rows.map((r) => r.scope)).toEqual([f.control]);
  expect(fence!.requires).toEqual([]);
  expect(streams!.rows.map((r) => r.scope)).toEqual(
    f.heads.map((h) => h.scope).sort(),
  );
  // The stream rows rest on the fence having landed.
  expect(streams!.requires).toEqual([
    {
      scope: f.control,
      expectedVersion: "2",
      notDeleted: false,
      expectedDataHash: f.hashes.tombstoneData,
    },
  ]);
  expect(await f.registry.read(f.control)).toMatchObject({ version: 2 });
  for (const head of f.heads)
    expect(await f.registry.read(head.scope)).toMatchObject({ version: 2 });
  expect(await f.a.db.query("SELECT * FROM delete_intents")).toEqual([]);
});

it("without a batch route the same delete is a fence post and one post per stream", async () => {
  const f = await world(undefined, names(6));
  const before = f.registry.log.length;
  await f.a.deleter.requestConnectionDelete("fixture-source");
  expect(await f.a.deleter.resumeDeletes()).toEqual([]);
  expect(f.registry.log.length - before).toBe(7);
});

it("above sixteen stream rows the fence goes first and the stream requests follow it, each resting on it", async () => {
  const f = await world(undefined, names(20));
  const { batches, singles } = withBatchRoute(f);
  await f.a.deleter.requestConnectionDelete("fixture-source");
  expect(await f.a.deleter.resumeDeletes()).toEqual([]);
  expect(singles).toEqual([]);
  expect(batches.map((b) => b.rows.length)).toEqual([1, 16, 4]);
  expect(batches[0]!.rows[0]!.scope).toBe(f.control);
  for (const streams of batches.slice(1)) {
    expect(streams.rows.some((r) => r.scope === f.control)).toBe(false);
    expect(streams.requires).toEqual([
      {
        scope: f.control,
        expectedVersion: "2",
        notDeleted: false,
        expectedDataHash: f.hashes.tombstoneData,
      },
    ]);
  }
  expect(await f.registry.read(f.control)).toMatchObject({ version: 2 });
  for (const head of f.heads)
    expect(await f.registry.read(head.scope)).toMatchObject({ version: 2 });
});

it("a stream row that loses its compare-and-set is retried alone; the rest stay in the stream commit", async () => {
  const f = await world(undefined, names(6));
  const { batches, singles } = withBatchRoute(f);
  const loser = f.heads[2]!.scope;
  f.registry.beforePost = async (request) => {
    if (request.scope === loser) {
      f.registry.beforePost = undefined;
      await rivalWrite(f.registry, loser);
    }
  };
  await f.a.deleter.requestConnectionDelete("fixture-source");
  expect(await f.a.deleter.resumeDeletes()).toEqual([]);
  expect(batches).toHaveLength(2);
  expect(singles).toEqual([loser]);
  expect(await f.registry.read(loser)).toMatchObject({ version: 3 });
  for (const head of f.heads.filter((h) => h.scope !== loser))
    expect(await f.registry.read(head.scope)).toMatchObject({ version: 2 });
  expect(await f.a.db.query("SELECT * FROM delete_intents")).toEqual([]);
});

it("a reconnect before the fence request: the fence loses, no stream row is sent, and the per-stream path ends the delete", async () => {
  const f = await world(undefined, names(3));
  const { batches, singles } = withBatchRoute(f);
  const send = f.registry.postBatch!.bind(f.registry);
  (f.registry as StreamSyncRegistry).postBatch = async (request) => {
    // Another device deletes and reconnects after the plan read the control row.
    for (const [version, hashes] of [
      ["2", [f.hashes.tombstoneData, f.hashes.tombstoneMetadata]],
      ["3", [f.hashes.activeData, f.hashes.activeMetadata]],
    ] as const)
      await f.registry.post({
        ownerAddress: owner,
        scope: f.control,
        dataHash: hashes[0],
        metadataHash: hashes[1],
        expectedVersion: version,
        signature: "0x00",
      });
    return send(request);
  };
  await f.a.deleter.requestConnectionDelete("fixture-source");
  expect(await f.a.deleter.resumeDeletes()).toEqual([]);
  // The fence lost its compare-and-set (control moved on from version 1), so
  // no stream row was sent: the per-stream path cleaned each stream of the
  // ended lifetime, and the reconnected lifetime was never tombstoned.
  expect(batches).toHaveLength(1);
  expect(batches[0]!.rows.map((r) => r.scope)).toEqual([f.control]);
  expect(singles.filter((scope) => scope !== f.control)).toHaveLength(3);
  expect(await f.registry.read(f.control)).toMatchObject({
    version: 3,
    dataHash: f.hashes.activeData,
  });
  for (const head of f.heads)
    expect(await f.registry.read(head.scope)).toMatchObject({ version: 2 });
});

it("a gateway without the batch route (405) is asked once; the old path ends the delete and later deletes do not ask", async () => {
  const f = await world(undefined, names(6));
  const { batches, singles } = withBatchRoute(f, 405);
  await f.a.deleter.requestConnectionDelete("fixture-source");
  expect(await f.a.deleter.resumeDeletes()).toEqual([]);
  expect(batches).toHaveLength(1);
  expect(singles).toHaveLength(7);
  expect(singles[0]).toBe(f.control);
  expect(await f.registry.read(f.control)).toMatchObject({ version: 2 });
  // A reconnect, then a second delete in the same session.
  await f.registry.post({
    ownerAddress: owner,
    scope: f.control,
    dataHash: f.hashes.activeData,
    metadataHash: f.hashes.activeMetadata,
    expectedVersion: "3",
    signature: "0x00",
  });
  await f.a.deleter.requestConnectionDelete("fixture-source");
  expect(await f.a.deleter.resumeDeletes()).toEqual([]);
  expect(batches).toHaveLength(1);
});

it("a request the gateway refuses (400) is reported, the per-stream path ends the delete, and later deletes do not ask again", async () => {
  const f = await world(undefined, names(6));
  const { batches, singles } = withBatchRoute(f);
  (f.registry as StreamSyncRegistry).postBatch = async (request) => {
    batches.push(request);
    throw new RegistryRefusedError("batch POST refused: shape", 400);
  };
  await f.a.deleter.requestConnectionDelete("fixture-source");
  expect(await f.a.deleter.resumeDeletes()).toEqual([]);
  // The delete is complete, written one row at a time.
  expect(batches).toHaveLength(1);
  expect(singles).toHaveLength(7);
  expect(await f.registry.read(f.control)).toMatchObject({ version: 2 });
  for (const head of f.heads)
    expect(await f.registry.read(head.scope)).toMatchObject({ version: 2 });
  // The refusal is a defect to fix, so it is logged with its status.
  expect(f.a.deps.logger.warn).toHaveBeenCalledWith(
    expect.objectContaining({ status: 400 }),
    "registry refused the delete batch; deleting stream by stream",
  );
  // A reconnect, then a second delete in the same session.
  await f.registry.post({
    ownerAddress: owner,
    scope: f.control,
    dataHash: f.hashes.activeData,
    metadataHash: f.hashes.activeMetadata,
    expectedVersion: "3",
    signature: "0x00",
  });
  await f.a.deleter.requestConnectionDelete("fixture-source");
  expect(await f.a.deleter.resumeDeletes()).toEqual([]);
  expect(batches).toHaveLength(1);
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
// Serial depth: every request a delete makes, with the requests that had
// already finished when it started. The depth is the longest chain.
// ---------------------------------------------------------------------------

/**
 * Gives every registry and blob request a fixed latency and records when it
 * started and ended. `depth` is the number of requests on the longest chain
 * where each started after the last ended: the time a delete takes, in
 * round trips, when every request costs the same.
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
  const registry = f.registry as StreamSyncRegistry & {
    listControlRows: StreamSyncRegistry["listControlRows"];
  };
  const bind = <K extends keyof StreamSyncRegistry>(key: K) =>
    (registry[key] as (...args: never[]) => Promise<unknown>).bind(registry);
  const read = bind("read");
  registry.read = timed("read", (scope: string) => scope, read as never);
  const post = f.registry.post.bind(f.registry);
  f.registry.post = timed("post", (r) => r.scope, post);
  const postBatch = registry.postBatch!.bind(registry);
  registry.postBatch = timed(
    "batch",
    (r: SignedRegistryBatch) => r.rows.map((row) => row.scope).join(","),
    postBatch,
  );
  const listControlRows = bind("listControlRows");
  registry.listControlRows = timed(
    "listControlRows",
    () => "",
    listControlRows as never,
  );
  const listStreamRows = bind("listStreamRows");
  registry.listStreamRows = timed(
    "listStreamRows",
    (c: string) => c,
    listStreamRows as never,
  );
  const put = f.blobs.put.bind(f.blobs);
  f.blobs.put = timed("blob.put", (k: string) => k, put);
  const get = f.blobs.get.bind(f.blobs);
  f.blobs.get = timed("blob.get", (k: string) => k, get);
  return {
    calls,
    get depth() {
      return Math.max(0, ...calls.map((c) => c.depth));
    },
    summary: () =>
      calls
        .map((c) => `${c.depth} ${c.name}`)
        .sort()
        .join("\n"),
  };
}

const countOf = (clock: ReturnType<typeof withRequestClock>, name: string) =>
  clock.calls.filter((c) => c.name === name).length;

for (const count of [1, 6, 20]) {
  it(`a ${count}-stream delete is four round trips: list, reread the control row, fence beside the head uploads, stream rows`, async () => {
    const f = await world(undefined, names(count));
    withBatchRoute(f);
    const clock = withRequestClock(f, 60);
    const started = await f.a.deleter.requestConnectionDelete("fixture-source");
    expect(started.fenced).toBe(true);
    // The request answers when the fence is confirmed: the third round trip.
    const fence = clock.calls.find(
      (c) => c.name === "batch" && c.scope === f.control,
    )!;
    expect(fence.depth).toBe(3);
    expect(fence.end).toBeGreaterThan(0);
    expect(await f.a.deleter.resumeDeletes()).toEqual([]);
    expect(clock.depth).toBe(4);
    // Nothing is read or written one row at a time, and no old head is read.
    expect(countOf(clock, "post")).toBe(0);
    expect(countOf(clock, "blob.get")).toBe(0);
    expect(countOf(clock, "listControlRows")).toBe(1);
    expect(countOf(clock, "listStreamRows")).toBe(1);
    expect(countOf(clock, "read")).toBe(1);
    expect(countOf(clock, "blob.put")).toBe(count);
    // The head uploads and the fence request are in flight together.
    for (const put of clock.calls.filter((c) => c.name === "blob.put"))
      expect(put.start).toBeLessThan(fence.end);
    // Fence first, then the stream rows in as many requests as the bound needs.
    expect(countOf(clock, "batch")).toBe(1 + Math.ceil(count / 16));
  });
}

it("a batch bound the gateway advertised sets the size of the stream requests", async () => {
  const f = await world(undefined, names(20));
  const { batches } = withBatchRoute(f);
  (f.registry as StreamSyncRegistry).batchPolicy = () => ({
    rows: 32,
    requires: 4,
    bytes: 1 << 20,
  });
  await f.a.deleter.requestConnectionDelete("fixture-source");
  expect(await f.a.deleter.resumeDeletes()).toEqual([]);
  // More than the fixed 16: the advertised bound, not a constant, sets it.
  expect(batches.map((b) => b.rows.length)).toEqual([1, 20]);
  // Fewer: every request stays within it.
  const g = await world(undefined, names(20));
  const again = withBatchRoute(g);
  (g.registry as StreamSyncRegistry).batchPolicy = () => ({
    rows: 6,
    requires: 1,
    bytes: 1 << 20,
  });
  await g.a.deleter.requestConnectionDelete("fixture-source");
  expect(await g.a.deleter.resumeDeletes()).toEqual([]);
  expect(again.batches.map((b) => b.rows.length)).toEqual([1, 6, 6, 6, 2]);
  expect(again.singles).toEqual([]);
});
