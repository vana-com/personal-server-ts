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
import { streamScope } from "@opendatalabs/personal-server-ts-stream-sync";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { remoteFixture } from "./apply-fixture.js";

const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
});
async function fixture() {
  const db = await openLocalDb(openBetterSqlite3(":memory:"), {
    owner: "0xabc",
    network: "test",
    deviceId: "pipeline",
  });
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
it("a late applyStream joins the existing connection flight and falls back to read when unlisted", async () => {
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
  expect((await all).map((r) => r.stream)).toEqual(["a", "b"]);
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

async function bothApplied() {
  const f = await fixture();
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
