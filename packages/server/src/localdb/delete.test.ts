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
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import { applyConnection } from "../../../core/src/localdb/apply.js";
import { bootstrapConnections } from "../../../core/src/localdb/bootstrap.js";
import { createConnectionDeleter } from "../../../core/src/localdb/delete.js";
import { remoteFixture } from "./apply-fixture.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const owner = `0x${"12".repeat(20)}`;
const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
});
async function world(file?: string) {
  const keys = {
    namespaceHmac: async () => new Uint8Array(32),
    encrypt: async (_s: string, b: Uint8Array) => b,
    encryptPart: async (_s: string, b: Uint8Array) => b,
    decrypt: async (_s: string, b: Uint8Array) => b,
  };
  const fixture = await remoteFixture(keys);
  const registry = createMemoryStreamSyncRegistry() as MemoryStreamSyncRegistry;
  const blobs = createMemoryStreamSyncBlobs();
  const h = await fixture.head("items", [{ id: "base" }]);
  for (const [key, value] of fixture.blobs) await blobs.put(key, value);
  for (const [scope, row] of fixture.reads)
    if (row.found)
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
      declaredStreams: () => ["items"],
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
  expect(events).toEqual([f.head.scope, f.control]);
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
  f.registry.beforePost = async () => {
    throw new Error("offline fixture");
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

it("supersession reports ConnectionDeleteSuperseded and never tombstones a reconnect", async () => {
  const f = await world();
  let moved = false;
  f.registry.beforePost = async (post) => {
    if (post.scope !== f.control) return;
    f.registry.beforePost = undefined;
    moved = true;
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
  expect(
    pending.some((p) => p.why === "ConnectionDeleteSuperseded") ||
      vi
        .mocked(f.a.deps.logger.warn)
        .mock.calls.some(([x]) => x.reason === "ConnectionDeleteSuperseded"),
  ).toBe(true);
  expect(await f.registry.read(f.control)).toMatchObject({
    version: 3,
    dataHash: f.hashes.activeData,
  });
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

it("deletion fences declared rowless streams before the control tombstone", async () => {
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
  expect(f.registry.log.slice(-3).map((row) => row.scope)).toEqual([
    f.head.scope,
    f.control + ".rowless",
    f.control,
  ]);
});

it("L11 publishes an incremental run over a stream tombstone as incomplete and needs_full", async () => {
  const f = await world();
  f.registry.beforePost = async (post) => {
    if (post.scope === f.control) throw new Error("control landing paused");
  };
  await f.a.deleter.requestConnectionDelete("fixture-source");
  await f.a.deleter.resumeDeletes();
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
    throw new Error("offline fixture");
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
