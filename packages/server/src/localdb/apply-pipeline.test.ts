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
