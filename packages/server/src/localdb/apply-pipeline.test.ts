import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it, vi } from "vitest";
import {
  connectionQueue,
  openLocalDb,
  type LocalSyncDeps,
  type SqlDriver,
} from "@opendatalabs/personal-server-ts-core/localdb";
import {
  applyConnection,
  applyStream,
} from "../../../core/src/localdb/apply.js";
import { createRunIntakeStore } from "../../../core/src/localdb/run-intake.js";
import { streamScope } from "@opendatalabs/personal-server-ts-stream-sync";
import {
  RegistryUnavailableBeforeWriteError,
  RegistryUnavailableError,
} from "../../../core/src/stream-sync/ports.js";
import { syncBeforeBegin } from "../../../core/src/localdb/bootstrap.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { remoteFixture } from "./apply-fixture.js";

const drivers: SqlDriver[] = [];
const dirs: string[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true });
});
const identity = { owner: "0xabc", network: "test", deviceId: "pipeline" };
async function fixture(path = ":memory:") {
  const db = await openLocalDb(openBetterSqlite3(path), identity);
  drivers.push(db);
  const keys = {
    namespaceHmac: async () => new Uint8Array(32),
    encrypt: async (_s: string, b: Uint8Array) => b,
    encryptPart: async (_s: string, b: Uint8Array) => b,
    decrypt: async (_s: string, b: Uint8Array) => b,
  };
  const remote = await remoteFixture(keys);
  const read = vi.fn(remote.registry.read),
    list = vi.fn(remote.registry.listStreamRows);
  let op = 0;
  const deps: LocalSyncDeps = {
    db,
    keys,
    blobs: remote.storage,
    registry: { ...remote.registry, read, listStreamRows: list },
    queue: connectionQueue(),
    ownerAddress: "0xabc",
    signer: { signAddData: async () => "0x00" },
    logger: { info: vi.fn(), warn: vi.fn() },
    now: () => 1000,
    newOp: () => `pipeline-${++op}`,
  };
  await db.batch([
    {
      sql: "INSERT INTO connections(connection_id,connector,ns,generation,control_state,control_version) VALUES (?,'fixture-source','',1,'active',1)",
      params: [remote.control],
    },
  ]);
  return { ...remote, db, deps, read, list, id: remote.control };
}
it("reuses listed snapshots and completed control fences without changing commit order", async () => {
  const f = await fixture();
  const a = await f.head("a", [{ id: "a" }]),
    b = await f.head("b", [{ id: "b" }]);
  const order: string[] = [];
  const batch = f.db.batch.bind(f.db);
  vi.spyOn(f.db, "batch").mockImplementation(async (statements) => {
    for (const s of statements)
      if (s.sql.includes("INSERT OR REPLACE INTO stream_versions"))
        order.push(String(s.params![1]));
    return batch(statements);
  });
  expect((await applyConnection(f.deps, f.id)).map((r) => r.stream)).toEqual([
    "a",
    "b",
  ]);
  expect(order).toEqual(["a", "b"]);
  expect(f.list).toHaveBeenCalledTimes(1);
  expect(f.read.mock.calls.filter(([s]) => s === f.control)).toHaveLength(3);
  expect(f.read.mock.calls.filter(([s]) => s === a.scope)).toHaveLength(1);
  expect(f.read.mock.calls.filter(([s]) => s === b.scope)).toHaveLength(1);
});
it("still refuses a changed stream head at the final authoritative recheck", async () => {
  const f = await fixture(),
    h = await f.head("a", [{ id: "a" }]);
  const get = f.deps.blobs.get.bind(f.deps.blobs);
  f.deps.blobs.get = async (key) => {
    const value = await get(key);
    if (key.includes("/g1-p-")) {
      const row = f.reads.get(h.scope)!;
      if (row.found) f.reads.set(h.scope, { ...row, version: row.version + 1 });
    }
    return value;
  };
  await expect(applyConnection(f.deps, f.id)).rejects.toThrow(
    "apply: stream changed during download",
  );
  expect(await f.db.query("SELECT * FROM stream_versions")).toEqual([]);
});
it("missing stream two aborts after stream one with no stream three commit", async () => {
  const f = await fixture();
  await f.head("a", [{ id: "a" }]);
  const b = await f.head("b", [{ id: "b" }]);
  await f.head("c", [{ id: "c" }]);
  f.blobs.delete(`${b.scope}/g1-p-${b.parts[0]!.hash}`);
  await expect(applyConnection(f.deps, f.id)).rejects.toThrow(
    "apply: missing part blob",
  );
  expect(
    await f.db.query("SELECT stream FROM stream_versions ORDER BY stream"),
  ).toEqual([{ stream: "a" }]);
});
it("a late applyStream runs in the next flight and reads its stream itself", async () => {
  const f = await fixture();
  await f.head("a", [{ id: "a" }]);
  let release!: () => void, started!: () => void;
  const gate = new Promise<void>((r) => {
      release = r;
    }),
    entered = new Promise<void>((r) => {
      started = r;
    });
  const get = f.deps.blobs.get.bind(f.deps.blobs);
  let held = false;
  f.deps.blobs.get = async (key) => {
    if (!held) {
      held = true;
      started();
      await gate;
    }
    return get(key);
  };
  const all = applyConnection(f.deps, f.id);
  await entered;
  const b = await f.head("b", [{ id: "b" }]);
  const joining = applyStream(f.deps, f.id, "b");
  release();
  expect((await all).map((r) => r.stream)).toEqual(["a"]);
  expect((await joining).outcome).toBe("applied");
  expect(f.list).toHaveBeenCalledTimes(1);
  expect(f.read.mock.calls.filter(([s]) => s === b.scope)).toHaveLength(2);
});
async function appliedStreamB() {
  const f = await fixture();
  await f.head("a", [{ id: "a" }]);
  const b = await f.head("b", [{ id: "b" }]);
  await applyStream(f.deps, f.id, "b");
  // Stream a downloads on its first part blob; the hook fires once.
  const get = f.deps.blobs.get.bind(f.deps.blobs);
  const onDownloadOfA = (change: () => void | Promise<void>) => {
    let fired = false;
    f.deps.blobs.get = async (key) => {
      if (
        !fired &&
        key.startsWith(`${streamScope("fixture-source", "", "a")}/`) &&
        key.includes("/g1-p-")
      ) {
        fired = true;
        await change();
      }
      return get(key);
    };
  };
  return { ...f, b, onDownloadOfA };
}
it("a connection deleted while stream one commits still purges the already-applied stream two", async () => {
  const f = await appliedStreamB();
  const batch = f.db.batch.bind(f.db);
  vi.spyOn(f.db, "batch").mockImplementation(async (statements) => {
    const out = await batch(statements);
    if (
      statements.some(
        (s) =>
          s.sql.includes("INSERT OR REPLACE INTO stream_versions") &&
          s.params![1] === "a",
      )
    )
      f.setControl(2, true);
    return out;
  });
  const results = await applyConnection(f.deps, f.id);
  expect(results.map((r) => [r.stream, r.outcome])).toEqual([
    ["a", "applied"],
    ["b", "purged"],
  ]);
  expect(
    await f.db.query("SELECT stream FROM records WHERE stream='b'"),
  ).toEqual([]);
});
it("a stream replaced while stream one downloads is applied at its new version, not skipped as unchanged", async () => {
  const f = await appliedStreamB();
  f.onDownloadOfA(async () => {
    await f.head("b", [{ id: "b2" }], { version: 2 });
  });
  const results = await applyConnection(f.deps, f.id);
  expect(results.map((r) => [r.stream, r.outcome])).toEqual([
    ["a", "applied"],
    ["b", "applied"],
  ]);
  expect(
    await f.db.query("SELECT record_key FROM records WHERE stream='b'"),
  ).toHaveLength(1);
  expect(
    await f.db.query("SELECT head_version FROM stream_state WHERE stream='b'"),
  ).toEqual([{ head_version: 2 }]);
});
it("a stream tombstoned while stream one downloads is purged, not skipped as unchanged", async () => {
  const f = await appliedStreamB();
  f.onDownloadOfA(() => {
    f.reads.set(f.b.scope, {
      found: true,
      version: 2,
      dataHash: f.hashes.tombstoneData,
      metadataHash: f.hashes.tombstoneMetadata,
      deleted: true,
    });
  });
  const results = await applyConnection(f.deps, f.id);
  expect(results.map((r) => [r.stream, r.outcome])).toEqual([
    ["a", "applied"],
    ["b", "purged"],
  ]);
  expect(
    await f.db.query("SELECT stream FROM records WHERE stream='b'"),
  ).toEqual([]);
});
it("two unchanged streams cost one control read and no stream reads", async () => {
  const f = await fixture();
  const a = await f.head("a", [{ id: "a" }]),
    b = await f.head("b", [{ id: "b" }]);
  await applyConnection(f.deps, f.id);
  f.read.mockClear();
  expect((await applyConnection(f.deps, f.id)).map((r) => r.outcome)).toEqual([
    "noop",
    "noop",
  ]);
  expect(f.read.mock.calls.filter(([s]) => s === f.control)).toHaveLength(1);
  expect(
    f.read.mock.calls.filter(([s]) => s === a.scope || s === b.scope),
  ).toHaveLength(0);
});

async function bothApplied(path?: string) {
  const f = await fixture(path);
  const a = await f.head("a", [{ id: "a" }]);
  const b = await f.head("b", [{ id: "b" }]);
  await applyConnection(f.deps, f.id);
  f.read.mockClear();
  f.list.mockClear();
  const query = f.db.query.bind(f.db);
  /** Runs `change` once, just before the local query that starts stream a's work. */
  const beforeStreamA = (change: () => Promise<void>) => {
    let fired = false;
    vi.spyOn(f.db, "query").mockImplementation((async (
      sql: string,
      params?: unknown[],
    ) => {
      if (
        !fired &&
        sql.includes("FROM head_parts WHERE connection_id=? AND stream=?") &&
        params?.[1] === "a"
      ) {
        fired = true;
        await change();
      }
      return query(sql, params as never);
    }) as typeof f.db.query);
  };
  return { ...f, a, b, beforeStreamA };
}
it("a tombstone listed before a stream's turn is not purged once the registry holds a newer head", async () => {
  const f = await bothApplied();
  f.reads.set(f.b.scope, {
    found: true,
    version: 2,
    dataHash: f.hashes.tombstoneData,
    metadataHash: f.hashes.tombstoneMetadata,
    deleted: true,
  });
  f.beforeStreamA(async () => {
    await f.head("b", [{ id: "b3" }], { version: 3 });
  });
  const results = await applyConnection(f.deps, f.id);
  expect(results.map((r) => [r.stream, r.outcome])).toEqual([
    ["a", "noop"],
    ["b", "applied"],
  ]);
  expect(
    await f.db.query("SELECT head_version FROM stream_state WHERE stream='b'"),
  ).toEqual([{ head_version: 3 }]);
  expect(
    await f.db.query("SELECT stream FROM records WHERE stream='b'"),
  ).toHaveLength(1);
});
it("pins the contract: a change after the listing and before a stream's turn may be answered on the listing, and the next cycle applies it", async () => {
  // Every caller joined before the listing. The answer reflects reads taken
  // after those calls began, as the per-stream read at entry did before.
  const f = await bothApplied();
  f.beforeStreamA(async () => {
    await f.head("b", [{ id: "b2" }], { version: 2 });
  });
  expect((await applyConnection(f.deps, f.id)).map((r) => r.outcome)).toEqual([
    "noop",
    "noop",
  ]);
  expect(
    await f.db.query("SELECT head_version FROM stream_state WHERE stream='b'"),
  ).toEqual([{ head_version: 1 }]);
  expect((await applyConnection(f.deps, f.id)).map((r) => r.outcome)).toEqual([
    "noop",
    "applied",
  ]);
});
async function heldFlight(streams: string[]) {
  const f = await fixture();
  const heads: Record<string, Awaited<ReturnType<typeof f.head>>> = {};
  for (const s of streams) heads[s] = await f.head(s, [{ id: s }]);
  await applyConnection(f.deps, f.id);
  f.read.mockClear();
  f.list.mockClear();
  return { ...f, heads };
}
it("a stream joiner after the listing sees a registry change made before it joined", async () => {
  const f = await bothApplied();
  let release!: () => void, started!: () => void;
  const gate = new Promise<void>((r) => {
    release = r;
  });
  const entered = new Promise<void>((r) => {
    started = r;
  });
  f.beforeStreamA(async () => {
    started();
    await gate;
  });
  const all = applyConnection(f.deps, f.id);
  await entered;
  // The listing is taken (b v1) and no stream has downloaded. Now b changes,
  // then a caller asks for b.
  await f.head("b", [{ id: "b2" }], { version: 2 });
  const joining = applyStream(f.deps, f.id, "b");
  release();
  await all;
  expect((await joining).outcome).toBe("applied");
  expect(
    await f.db.query("SELECT head_version FROM stream_state WHERE stream='b'"),
  ).toEqual([{ head_version: 2 }]);
});
it("a connection joiner after the listing lists again and applies a stream published since", async () => {
  const f = await heldFlight(["a"]);
  await f.head("a", [{ id: "a2" }], { version: 2 });
  let release!: () => void, started!: () => void;
  const gate = new Promise<void>((r) => {
    release = r;
  });
  const entered = new Promise<void>((r) => {
    started = r;
  });
  const get = f.deps.blobs.get.bind(f.deps.blobs);
  let held = false;
  f.deps.blobs.get = async (key) => {
    if (!held) {
      held = true;
      started();
      await gate;
    }
    return get(key);
  };
  const first = applyConnection(f.deps, f.id);
  await entered;
  await f.head("c", [{ id: "c" }]);
  const second = applyConnection(f.deps, f.id);
  release();
  await first;
  expect((await second).map((r) => r.stream)).toEqual(["a", "c"]);
  expect(f.list).toHaveBeenCalledTimes(2);
});
it("a joiner for a stream the flight already answered gets a new answer", async () => {
  const f = await heldFlight(["a", "b"]);
  await f.head("a", [{ id: "a2" }], { version: 2 });
  await f.head("b", [{ id: "b2" }], { version: 2 });
  let release!: () => void, started!: () => void;
  const gate = new Promise<void>((r) => {
    release = r;
  });
  const entered = new Promise<void>((r) => {
    started = r;
  });
  const get = f.deps.blobs.get.bind(f.deps.blobs);
  let parts = 0;
  f.deps.blobs.get = async (key) => {
    if (key.includes("/g1-p-") && ++parts === 2) {
      started();
      await gate;
    }
    return get(key);
  };
  const all = applyConnection(f.deps, f.id);
  await entered;
  // Stream a is applied at v2. It changes again, then a caller asks for a.
  await f.head("a", [{ id: "a3" }], { version: 3 });
  const joining = applyStream(f.deps, f.id, "a");
  release();
  await all;
  expect((await joining).outcome).toBe("applied");
  expect(
    await f.db.query("SELECT head_version FROM stream_state WHERE stream='a'"),
  ).toEqual([{ head_version: 3 }]);
});

/** Holds each local query that starts a stream's work until the test releases it. */
function holdStreams(f: { db: SqlDriver }, streams: string[]) {
  const holds = new Map<string, Array<() => void>>(streams.map((s) => [s, []]));
  const query = f.db.query.bind(f.db);
  const spy = vi.spyOn(f.db, "query") as unknown as {
    mockImplementation: (fn: unknown) => void;
  };
  spy.mockImplementation(async (sql: string, params?: unknown[]) => {
    const mine = holds.get(String(params?.[1]));
    if (
      mine &&
      sql.includes("FROM head_parts WHERE connection_id=? AND stream=?")
    )
      await new Promise<void>((release) => mine.push(release));
    return query(sql, params as never);
  });
  return (stream: string) => ({
    held: (n: number) =>
      vi.waitFor(() => expect(holds.get(stream)!.length).toBe(n)),
    release: (n: number) => holds.get(stream)![n - 1]!(),
  });
}
function countFlights(f: { deps: LocalSyncDeps }) {
  const queue = f.deps.queue;
  let runs = 0;
  f.deps.queue = {
    run: (id, kind, work) => {
      if (kind === "apply") runs++;
      return queue.run(id, kind, work);
    },
  };
  return () => runs;
}
it("a caller resolves when its own flight ends, while a later caller's flight is still held", async () => {
  const f = await bothApplied();
  const holdAt = holdStreams(f, ["a", "b"]);
  const hold = holdAt("a");
  const holdB = holdAt("b");
  const c0 = applyStream(f.deps, f.id, "a");
  await hold.held(1);
  const c1 = applyStream(f.deps, f.id, "b");
  hold.release(1);
  const first = await Promise.race([
    c0.then(() => "c0"),
    holdB.held(1).then(() => "later caller's work"),
  ]);
  expect(first).toBe("c0");
  expect((await c0).outcome).toBe("noop");
  await holdB.held(1);
  holdB.release(1);
  expect((await c1).outcome).toBe("noop");
});
it("callers arriving during a flight make exactly one next flight, and that flight's arrivals one more", async () => {
  const f = await bothApplied();
  const runs = countFlights(f);
  const hold = holdStreams(f, ["a"])("a");
  const first = applyStream(f.deps, f.id, "a");
  await hold.held(1);
  const second = Array.from({ length: 5 }, () =>
    applyStream(f.deps, f.id, "a"),
  );
  expect(runs()).toBe(1);
  hold.release(1);
  await first;
  await hold.held(2);
  expect(runs()).toBe(2);
  const third = Array.from({ length: 5 }, () => applyStream(f.deps, f.id, "a"));
  hold.release(2);
  await Promise.all(second);
  await hold.held(3);
  expect(runs()).toBe(3);
  hold.release(3);
  await Promise.all(third);
  expect(runs()).toBe(3);
});
it("an absent control read held while the remote goes active does not answer a caller who called after", async () => {
  const f = await fixture();
  await f.head("a", [{ id: "a" }]);
  const absent = { found: false } as const;
  const read = f.deps.registry.read;
  let entered!: () => void, release!: () => void;
  const hasEntered = new Promise<void>((r) => {
    entered = r;
  });
  const gate = new Promise<void>((r) => {
    release = r;
  });
  let first = true;
  f.deps.registry = {
    ...f.deps.registry,
    read: async (scope) => {
      if (scope === f.control && first) {
        first = false;
        entered();
        await gate;
        return absent;
      }
      return read(scope);
    },
  };
  const c0 = applyStream(f.deps, f.id, "a");
  await hasEntered;
  const c1 = applyStream(f.deps, f.id, "a");
  release();
  expect((await c0).outcome).toBe("gone");
  expect((await c1).outcome).toBe("applied");
});
it("a failure in the next flight does not reject the callers of the flight before it", async () => {
  const f = await bothApplied();
  const hold = holdStreams(f, ["a"])("a");
  const c0 = applyStream(f.deps, f.id, "a");
  await hold.held(1);
  const c1 = applyStream(f.deps, f.id, "b");
  f.reads.set(f.b.scope, {
    found: true,
    version: 2,
    dataHash: "ab".repeat(32),
    metadataHash: f.hashes.activeMetadata,
    deleted: false,
  });
  const failed = expect(c1).rejects.toThrow("apply: missing head blob");
  hold.release(1);
  expect((await c0).outcome).toBe("noop");
  await failed;
});
it("five callers asking at once for unchanged streams share one flight: one control read, one listing, no stream reads", async () => {
  const f = await fixture();
  const a = await f.head("a", [{ id: "a" }]);
  const b = await f.head("b", [{ id: "b" }]);
  await applyConnection(f.deps, f.id);
  f.read.mockClear();
  f.list.mockClear();
  const runs = countFlights(f);
  const results = await Promise.all(
    Array.from({ length: 5 }, () => applyConnection(f.deps, f.id)),
  );
  expect(results.map((r) => r.map((x) => x.outcome))).toEqual(
    Array(5).fill(["noop", "noop"]),
  );
  expect(runs()).toBe(1);
  expect(f.list).toHaveBeenCalledTimes(1);
  expect(f.read.mock.calls.filter(([s]) => s === f.control)).toHaveLength(1);
  expect(
    f.read.mock.calls.filter(([s]) => s === a.scope || s === b.scope),
  ).toHaveLength(0);
});
it("bootstrap's apply sees a stream that advanced after bootstrap read the control row", async () => {
  const f = await bothApplied();
  const inner = f.deps.registry.read;
  let entered!: () => void, release!: () => void;
  const hasEntered = new Promise<void>((r) => {
    entered = r;
  });
  const gate = new Promise<void>((r) => {
    release = r;
  });
  let first = true;
  f.deps.registry = {
    ...f.deps.registry,
    read: async (scope) => {
      const read = await inner(scope);
      if (first) {
        first = false;
        entered();
        await gate;
      }
      return read;
    },
  };
  const running = syncBeforeBegin(f.deps, "fixture-source");
  await hasEntered;
  // Bootstrap's control read is taken and held; the remote advances before apply.
  await f.head("b", [{ id: "b2" }], { version: 2 });
  release();
  await running;
  expect(
    await f.db.query("SELECT head_version FROM stream_state WHERE stream='b'"),
  ).toEqual([{ head_version: 2 }]);
});
async function bootstrapFixture(path?: string) {
  const f = await bothApplied(path);
  f.read.mockClear();
  f.list.mockClear();
  return f;
}
it("an unchanged active bootstrap makes three registry calls: the control read twice and one listing", async () => {
  const f = await bootstrapFixture();
  const { unreachable } = await syncBeforeBegin(f.deps, "fixture-source");
  expect(unreachable).toBe(false);
  // Bootstrap's control read, apply's control read, apply's listing. No stream reads.
  expect(f.read.mock.calls.map(([scope]) => scope)).toEqual([
    f.control,
    f.control,
  ]);
  expect(f.list).toHaveBeenCalledTimes(1);
});
it("begin goes on offline when apply's own listing finds the registry unavailable", async () => {
  const f = await bootstrapFixture();
  f.deps.registry = {
    ...f.deps.registry,
    listStreamRows: async (key) => {
      // Fails only after bootstrap's own control read and apply's.
      if (f.read.mock.calls.length >= 2)
        throw new RegistryUnavailableError("registry listing failed: 503");
      return f.list(key);
    },
  };
  expect(await syncBeforeBegin(f.deps, "fixture-source")).toMatchObject({
    unreachable: true,
  });
});
it("begin goes on offline when apply's own control read finds the registry unavailable", async () => {
  const f = await bootstrapFixture();
  const read = f.deps.registry.read;
  let calls = 0;
  f.deps.registry = {
    ...f.deps.registry,
    read: async (scope) => {
      if (++calls === 2)
        throw new RegistryUnavailableError("registry read failed: 503");
      return read(scope);
    },
  };
  expect(await syncBeforeBegin(f.deps, "fixture-source")).toMatchObject({
    unreachable: true,
  });
});
it("begin still rejects when apply fails on integrity, on the database, or on a plain registry error", async () => {
  const integrity = await bootstrapFixture();
  // A corrupt head: the stream changes, and its part blob is gone.
  const b = await integrity.head("b", [{ id: "b2" }], { version: 2 });
  integrity.blobs.delete(`${b.scope}/g1-p-${b.parts[0]!.hash}`);
  await expect(
    syncBeforeBegin(integrity.deps, "fixture-source"),
  ).rejects.toThrow("apply: missing part blob");

  const database = await bootstrapFixture();
  await database.head("b", [{ id: "b2" }], { version: 2 });
  vi.spyOn(database.db, "batch").mockRejectedValue(
    new Error("SQLITE_IOERR: disk I/O error"),
  );
  await expect(
    syncBeforeBegin(database.deps, "fixture-source"),
  ).rejects.toThrow("SQLITE_IOERR");

  const refused = await bootstrapFixture();
  refused.deps.registry = {
    ...refused.deps.registry,
    listStreamRows: async () => {
      if (refused.read.mock.calls.length >= 2)
        throw new Error("registry listing failed: 403");
      return refused.list("fixture-source");
    },
  };
  await expect(syncBeforeBegin(refused.deps, "fixture-source")).rejects.toThrow(
    "403",
  );
});

// Apply has no rollback. An unavailable error after its first local write
// rejects begin, so a collector never starts on a half-applied connection.
// The writes already committed stay; these tests pin them as they are.
const beginRequest = {
  connector: "fixture-source",
  artifactDigest: "fixture-artifact",
  owner: { address: `0x${"12".repeat(20)}`, leaseId: null },
  observedAt: 40,
};
const beginDeclaration = {
  connector: "fixture-source",
  version: "1",
  streams: [{ name: "items", semantics: "mutable_state", primaryKey: ["id"] }],
} as const;
const unavailable = () =>
  new RegistryUnavailableError("registry read failed: 503");
async function rejectsBeginAfterAWrite(
  f: Awaited<ReturnType<typeof bootstrapFixture>>,
) {
  const error = await createRunIntakeStore({
    ...f.deps,
    ownerAddress: beginRequest.owner.address,
  })
    .begin("run", beginRequest, beginDeclaration)
    .catch((e: unknown) => e);
  expect(error).toBeInstanceOf(RegistryUnavailableError);
  expect(error).not.toBeInstanceOf(RegistryUnavailableBeforeWriteError);
  expect(await f.db.query("SELECT run_id FROM runs")).toEqual([]);
}
it.each([
  [
    "replaced",
    (f: Awaited<ReturnType<typeof bootstrapFixture>>) =>
      f.head("a", [{ id: "a2" }], { version: 2 }),
    // Stream a's replacement committed before stream b's read failed.
    async (f: Awaited<ReturnType<typeof bootstrapFixture>>) =>
      expect(
        await f.db.query(
          "SELECT head_version FROM stream_state WHERE stream='a'",
        ),
      ).toEqual([{ head_version: 2 }]),
  ],
  [
    "tombstoned",
    async (f: Awaited<ReturnType<typeof bootstrapFixture>>) => {
      // Stream b is tombstoned too: its purge is never decided on the
      // listing, so apply reads it again after stream a's purge committed.
      for (const stream of [f.a, f.b])
        f.reads.set(stream.scope, {
          found: true,
          version: 2,
          dataHash: f.hashes.tombstoneData,
          metadataHash: f.hashes.tombstoneMetadata,
          deleted: true,
        });
    },
    // Stream a's purge committed before stream b's read failed.
    async (f: Awaited<ReturnType<typeof bootstrapFixture>>) =>
      expect(
        await f.db.query("SELECT stream FROM records WHERE stream='a'"),
      ).toEqual([]),
  ],
])(
  "begin rejects and starts no run when stream a is %s and stream b's read is then unavailable",
  async (_name, change, committed) => {
    const f = await bootstrapFixture();
    await change(f);
    const read = f.deps.registry.read;
    f.deps.registry = {
      ...f.deps.registry,
      read: async (scope) => {
        if (scope === f.b.scope) throw unavailable();
        return read(scope);
      },
    };
    await rejectsBeginAfterAWrite(f);
    await committed(f);
  },
);
it("begin rejects and starts no run when a generation purge is followed by an unavailable listing", async () => {
  const f = await bootstrapFixture();
  f.setControl(2);
  f.deps.registry = {
    ...f.deps.registry,
    listStreamRows: async () => {
      throw unavailable();
    },
  };
  await rejectsBeginAfterAWrite(f);
  // The purge and reset committed before the listing failed.
  expect(await f.db.query("SELECT stream FROM records")).toEqual([]);
  expect(
    await f.db.query("SELECT head_version FROM stream_state ORDER BY stream"),
  ).toEqual([{ head_version: 0 }, { head_version: 0 }]);
});
it("an unavailable error before any write is typed as such, with the registry's error as its cause", async () => {
  const f = await bootstrapFixture();
  const cause = unavailable();
  f.deps.registry = {
    ...f.deps.registry,
    listStreamRows: async () => {
      throw cause;
    },
  };
  const error = await applyConnection(f.deps, f.id).catch((e: unknown) => e);
  expect(error).toBeInstanceOf(RegistryUnavailableBeforeWriteError);
  expect((error as Error).cause).toBe(cause);
  expect(await f.db.query("SELECT stream FROM records")).toHaveLength(2);
  // Nothing was written, so nothing is marked.
  expect(await f.db.query("SELECT apply_partial FROM connections")).toEqual([
    { apply_partial: 0 },
  ]);
});

// A rejected begin leaves the connection half applied. The mark in the
// database is what makes the next begin see that, in the same process and
// after a restart, whichever way the registry fails then.
type Half = Awaited<ReturnType<typeof bootstrapFixture>>;
type Registry = Half["deps"]["registry"];
const unavailableB =
  (f: Half) =>
  (base: Registry): Registry => ({
    ...base,
    read: async (scope) => {
      if (scope === f.b.scope) throw unavailable();
      return base.read(scope);
    },
  });
const heads = async (f: Half) =>
  f.db.query(
    "SELECT stream,head_version FROM stream_state WHERE stream IN ('a','b') ORDER BY stream",
  );
const recordStreams = async (f: Half) =>
  f.db.query("SELECT DISTINCT stream FROM records ORDER BY stream");
const tombstoneBoth = (f: Half) => {
  for (const stream of [f.a, f.b])
    f.reads.set(stream.scope, {
      found: true,
      version: 2,
      dataHash: f.hashes.tombstoneData,
      metadataHash: f.hashes.tombstoneMetadata,
      deleted: true,
    });
};
// What each scenario leaves after the rejected begin, and after the repair.
const scenarios: [
  string,
  (f: Half) => Promise<void> | void,
  (f: Half) => (base: Registry) => Registry,
  (f: Half) => Promise<unknown>,
  unknown,
  unknown,
][] = [
  [
    "stream a replaced, then stream b's read unavailable",
    async (f) => {
      await f.head("a", [{ id: "a2" }], { version: 2 });
    },
    unavailableB,
    heads,
    [
      { stream: "a", head_version: 2 },
      { stream: "b", head_version: 1 },
    ],
    [
      { stream: "a", head_version: 2 },
      { stream: "b", head_version: 1 },
    ],
  ],
  [
    "stream a tombstoned, then stream b's read unavailable",
    tombstoneBoth,
    unavailableB,
    recordStreams,
    [{ stream: "b" }],
    [],
  ],
  [
    "a generation purge, then the listing unavailable",
    (f) => f.setControl(2),
    () => (base) => ({
      ...base,
      listStreamRows: async () => {
        throw unavailable();
      },
    }),
    recordStreams,
    [],
    [],
  ],
];
const partial = async (f: Half) =>
  (
    await f.db.query<{ apply_partial: number }>(
      "SELECT apply_partial FROM connections",
    )
  ).map((r) => r.apply_partial);
const down = (base: Half["deps"]["registry"]) => ({
  ...base,
  read: async () => {
    throw unavailable();
  },
  listStreamRows: async () => {
    throw unavailable();
  },
});
/** The registry answers the control row but not the listing. */
const listingDown = (base: Half["deps"]["registry"]) => ({
  ...base,
  listStreamRows: async () => {
    throw unavailable();
  },
});
async function beginOn(deps: Half["deps"], run: string) {
  return createRunIntakeStore({
    ...deps,
    ownerAddress: beginRequest.owner.address,
  })
    .begin(run, beginRequest, beginDeclaration)
    .catch((e: unknown) => e);
}
/** A restart: a new queue and a new connection to the same file. */
async function restart<T extends { db: SqlDriver; deps: LocalSyncDeps }>(
  f: T,
  path: string,
): Promise<T> {
  await f.db.close();
  drivers.splice(drivers.indexOf(f.db), 1);
  const db = await openLocalDb(openBetterSqlite3(path), identity);
  drivers.push(db);
  return { ...f, db, deps: { ...f.deps, db, queue: connectionQueue() } };
}
it.each(scenarios)(
  "after %s, a later begin is not offline: same store, reopened database, then repaired",
  async (_name, change, failure, observe, afterFailure, afterRepair) => {
    const dir = mkdtempSync(join(tmpdir(), "apply-partial-"));
    dirs.push(dir);
    const path = join(dir, "local.db");
    const f = await bootstrapFixture(path);
    const working = f.deps.registry;
    await change(f);
    f.deps.registry = failure(f)(working);
    await rejectsBeginAfterAWrite(f);
    expect(await observe(f)).toEqual(afterFailure);
    expect(await partial(f)).toEqual([1]);

    // Same store: the registry is still down, whole or in part.
    for (const registry of [down(working), listingDown(working)]) {
      f.deps.registry = registry;
      const again = await beginOn(f.deps, "again");
      expect(again).toBeInstanceOf(RegistryUnavailableError);
      expect(await f.db.query("SELECT run_id FROM runs")).toEqual([]);
    }

    const reopened = await restart(f, path);
    expect(await partial(reopened)).toEqual([1]);
    for (const registry of [down(working), listingDown(working)]) {
      reopened.deps.registry = registry;
      const again = await beginOn(reopened.deps, "restarted");
      expect(again).toBeInstanceOf(RegistryUnavailableError);
      expect(await reopened.db.query("SELECT run_id FROM runs")).toEqual([]);
    }

    // The registry is back: apply repairs the connection and begin goes on.
    reopened.deps.registry = working;
    expect(await beginOn(reopened.deps, "repaired")).toMatchObject({
      status: "collecting",
    });
    expect(await partial(reopened)).toEqual([0]);
    expect(await observe(reopened)).toEqual(afterRepair);
  },
);
it("an apply of one stream does not clear the mark; only an apply of the whole connection does", async () => {
  const f = await bootstrapFixture();
  await f.head("a", [{ id: "a2" }], { version: 2 });
  const working = f.deps.registry;
  f.deps.registry = unavailableB(f)(working);
  await applyConnection(f.deps, f.id).catch(() => undefined);
  const marked = () => f.db.query("SELECT apply_partial FROM connections");
  expect(await marked()).toEqual([{ apply_partial: 1 }]);
  f.deps.registry = working;
  await applyStream(f.deps, f.id, "b");
  expect(await marked()).toEqual([{ apply_partial: 1 }]);
  await applyConnection(f.deps, f.id);
  expect(await marked()).toEqual([{ apply_partial: 0 }]);
});

// A whole apply that merged rows and then found the control row changed gives
// up on the stream ("gone"). The rows it merged stay, so the mark stays.
const lateControl = {
  absent: (f: Half) => f.reads.set(f.control, { found: false }),
  foreign: (f: Half) =>
    f.reads.set(f.control, {
      found: true,
      version: 2,
      dataHash: "0x" + "ab".repeat(32),
      metadataHash: f.hashes.activeMetadata,
      deleted: false,
    }),
  "in another generation": (f: Half) => f.setControl(2),
};
it.each(Object.entries(lateControl))(
  "a whole apply whose control is %s after a part merged keeps the mark: a later begin is not offline, same store or restarted, until repaired",
  async (name, change) => {
    const dir = mkdtempSync(join(tmpdir(), "apply-partial-"));
    dirs.push(dir);
    const path = join(dir, "local.db");
    const f = await bootstrapFixture(path);
    // Stream a changes, so its part downloads; the control row changes while
    // it does, after the first part's rows merge and before the final recheck.
    await f.head("a", [{ id: "a2" }], { version: 2 });
    const working = f.deps.registry;
    const get = f.deps.blobs.get.bind(f.deps.blobs);
    let merged = 0;
    f.deps.blobs.get = async (key) => {
      const out = await get(key);
      if (
        key.startsWith(`${f.a.scope}/`) &&
        key.includes("/g1-p-") &&
        !merged++
      )
        change(f);
      return out;
    };
    const results = await applyConnection(f.deps, f.id);
    f.deps.blobs.get = get;
    expect(results.find((r) => r.stream === "a")?.outcome).toBe("gone");
    expect(await partial(f)).toEqual([1]);

    // With the control row absent or foreign the registry answers a begin
    // online; only an unreadable control row is the offline case here.
    const outages = (base: Registry) =>
      name === "in another generation"
        ? [down(base), listingDown(base)]
        : [down(base)];
    for (const registry of outages(working)) {
      f.deps.registry = registry;
      expect(await beginOn(f.deps, "again")).toBeInstanceOf(
        RegistryUnavailableError,
      );
    }
    const reopened = await restart(f, path);
    expect(await partial(reopened)).toEqual([1]);
    for (const registry of outages(working)) {
      reopened.deps.registry = registry;
      expect(await beginOn(reopened.deps, "restarted")).toBeInstanceOf(
        RegistryUnavailableError,
      );
      expect(await reopened.db.query("SELECT run_id FROM runs")).toEqual([]);
    }

    // The control row is active again: a whole apply repairs, begin goes on.
    // A foreign row took version 2 and a generation change is generation 2:
    // the row that returns is newer than both.
    reopened.setControl(name === "absent" ? 1 : 3);
    reopened.deps.registry = working;
    expect(await beginOn(reopened.deps, "repaired")).toMatchObject({
      status: "collecting",
    });
    expect(await partial(reopened)).toEqual([0]);
  },
);
it("a control found deleted after a part merged purges the connection, which finishes: the mark clears", async () => {
  const f = await bootstrapFixture();
  await f.head("a", [{ id: "a2" }], { version: 2 });
  const get = f.deps.blobs.get.bind(f.deps.blobs);
  let fired = false;
  f.deps.blobs.get = async (key) => {
    const out = await get(key);
    if (!fired && key.startsWith(`${f.a.scope}/`) && key.includes("/g1-p-")) {
      fired = true;
      f.setControl(2, true);
    }
    return out;
  };
  await applyConnection(f.deps, f.id);
  expect(await f.db.query("SELECT stream FROM records")).toEqual([]);
  expect(await partial(f)).toEqual([0]);
});

// The mark clears only on proof of repair. A whole apply that ends on an early
// "gone" repaired nothing, whatever the stream count.
it("a whole single-stream apply that finds the head newer than the control keeps a standing mark: a later begin is not offline, same store or restarted", async () => {
  const dir = mkdtempSync(join(tmpdir(), "apply-partial-"));
  dirs.push(dir);
  const path = join(dir, "local.db");
  const f = await fixture(path);
  await f.head("a", [{ id: "a" }]);
  await applyConnection(f.deps, f.id);
  // An earlier failed apply merged generation-1 rows and left the mark.
  await f.db.batch([{ sql: "UPDATE connections SET apply_partial=1" }]);
  expect(await partial(f)).toEqual([1]);

  // Another publisher advances control and head to generation 2, after this
  // apply read the control at generation 1 and before it fetches the head.
  await f.head("a", [{ id: "a2" }], { generation: 2, version: 2 });
  f.setControl(1);
  const working = f.deps.registry;
  let flipped = false;
  f.deps.registry = {
    ...working,
    read: async (scope) => {
      const out = await working.read(scope);
      if (scope === f.control && !flipped) {
        flipped = true;
        f.setControl(2);
      }
      return out;
    },
  };
  const results = await applyConnection(f.deps, f.id);
  expect(results.map((r) => [r.stream, r.outcome])).toEqual([["a", "gone"]]);
  expect(await partial(f)).toEqual([1]);

  f.deps.registry = down(working);
  expect(await beginOn(f.deps, "again")).toBeInstanceOf(
    RegistryUnavailableError,
  );
  const reopened = await restart(f, path);
  expect(await partial(reopened)).toEqual([1]);
  reopened.deps.registry = down(working);
  expect(await beginOn(reopened.deps, "restarted")).toBeInstanceOf(
    RegistryUnavailableError,
  );
  expect(await reopened.db.query("SELECT run_id FROM runs")).toEqual([]);

  // Control and head agree on generation 2: a whole apply repairs.
  reopened.deps.registry = working;
  await applyConnection(reopened.deps, reopened.id);
  expect(await partial(reopened)).toEqual([0]);
});
