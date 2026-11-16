// A head's parts are read ahead of the apply, within the store's memory
// budget: the GET of the next part runs while the commit of this one does.
import { afterEach, expect, it, vi } from "vitest";
import {
  connectionQueue,
  openLocalDb,
  type LocalSyncDeps,
  type SqlDriver,
} from "@opendatalabs/personal-server-ts-core/localdb";
import { applyConnection } from "../../../core/src/localdb/apply.js";
import {
  createStorageAccess,
  DEFAULT_STORAGE_ACCESS_POLICY,
} from "../../../core/src/stream-sync/storage-retry.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { remoteFixture } from "./apply-fixture.js";

const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
});

async function fixture(maxBytesInFlight?: number) {
  const db = await openLocalDb(openBetterSqlite3(":memory:"), {
    owner: "0xabc",
    network: "test",
    deviceId: "readahead",
  });
  drivers.push(db);
  const keys = {
    namespaceHmac: async () => new Uint8Array(32),
    encrypt: async (_s: string, b: Uint8Array) => b,
    encryptPart: async (_s: string, b: Uint8Array) => b,
    decrypt: async (_s: string, b: Uint8Array) => b,
  };
  const remote = await remoteFixture(keys);
  const blobs =
    maxBytesInFlight === undefined
      ? remote.storage
      : {
          ...remote.storage,
          governor: createStorageAccess({
            ...DEFAULT_STORAGE_ACCESS_POLICY,
            maxBytesInFlight,
          }),
        };
  let op = 0;
  const deps: LocalSyncDeps = {
    db,
    keys,
    blobs,
    registry: remote.registry,
    queue: connectionQueue(),
    ownerAddress: "0xabc",
    signer: { signAddData: async () => "0x00" },
    logger: { info: vi.fn(), warn: vi.fn() },
    now: () => 1000,
    newOp: () => `readahead-${++op}`,
  };
  await db.batch([
    {
      sql: "INSERT INTO connections(connection_id,connector,ns,generation,control_state,control_version) VALUES (?,'fixture-source','',1,'active',1)",
      params: [remote.control],
    },
  ]);
  return { ...remote, db, deps, id: remote.control };
}

/** The records each commit of an apply carries, in order. */
async function commitsOf(f: Awaited<ReturnType<typeof fixture>>) {
  const batch = f.db.batch.bind(f.db);
  const sizes: number[] = [];
  vi.spyOn(f.db, "batch").mockImplementation(async (statements) => {
    const staged = statements.filter((s) =>
      s.sql.includes("INSERT INTO temp.incoming"),
    ).length;
    if (staged > 0) sizes.push(staged);
    return batch(statements);
  });
  await applyConnection(f.deps, f.id);
  return sizes;
}

/** GETs of parts started when the first part's rows commit. */
async function getsAtFirstCommit(f: Awaited<ReturnType<typeof fixture>>) {
  const get = f.deps.blobs.get.bind(f.deps.blobs);
  let started = 0;
  let atFirstCommit: number | undefined;
  f.deps.blobs.get = async (key) => {
    if (key.includes("/g1-p-")) started++;
    return get(key);
  };
  const batch = f.db.batch.bind(f.db);
  vi.spyOn(f.db, "batch").mockImplementation(async (statements) => {
    if (
      atFirstCommit === undefined &&
      statements.some((s) => s.sql.includes("temp.incoming"))
    )
      atFirstCommit = started;
    return batch(statements);
  });
  await applyConnection(f.deps, f.id);
  return atFirstCommit;
}

const values = (n: number) =>
  Array.from({ length: n }, (_, i) => ({ id: `row-${i}` }));

it("fetches the parts that follow while the first part is applied", async () => {
  const f = await fixture();
  await f.head("a", values(6));
  expect(await getsAtFirstCommit(f)).toBe(6);
  expect(
    await f.db.query("SELECT 1 FROM records WHERE stream = 'a'"),
  ).toHaveLength(6);
});

it("reads no further ahead than the memory budget holds", async () => {
  const probe = await fixture();
  const { parts } = await probe.head("a", values(6));
  // A part is held as plain and as encrypted bytes: three parts fit.
  const f = await fixture(2 * 3 * parts[0]!.bytes);
  await f.head("a", values(6));
  expect(await getsAtFirstCommit(f)).toBe(3);
  expect(
    await f.db.query("SELECT 1 FROM records WHERE stream = 'a'"),
  ).toHaveLength(6);
});

it("gives its memory back when the apply fails", async () => {
  const f = await fixture();
  const h = await f.head("a", values(4));
  f.blobs.delete(`${h.scope}/g1-p-${h.parts[2]!.hash}`);
  await expect(applyConnection(f.deps, f.id)).rejects.toThrow(
    "apply: missing part blob",
  );
  // The budget is whole again: a reservation of all of it does not wait.
  const whole = f.deps.blobs.governor.reserve(
    DEFAULT_STORAGE_ACCESS_POLICY.maxBytesInFlight,
  );
  const outcome = await Promise.race([
    whole.then((release) => (release(), "granted")),
    new Promise((resolve) => setTimeout(() => resolve("waiting"), 100)),
  ]);
  expect(outcome).toBe("granted");
});

it("commits the first part alone, then the parts it has already fetched together", async () => {
  const f = await fixture();
  await f.head("a", values(6));
  const sizes = await commitsOf(f);
  expect(sizes[0]).toBe(1);
  expect(sizes.reduce((a, b) => a + b, 0)).toBe(6);
  expect(sizes.length).toBeLessThan(6);
});

it("never commits more parts at once than the memory budget holds", async () => {
  const probe = await fixture();
  const { parts } = await probe.head("a", values(12));
  const f = await fixture(2 * 3 * parts[0]!.bytes);
  await f.head("a", values(12));
  const sizes = await commitsOf(f);
  expect(sizes.reduce((a, b) => a + b, 0)).toBe(12);
  expect(Math.max(...sizes)).toBeLessThanOrEqual(3);
});
