// A head's parts are read ahead of the apply, within the store's memory
// budget: the GET of the next part runs while the commit of this one does.
import { afterEach, expect, it, vi } from "vitest";
import { sha256 } from "@noble/hashes/sha2";
import { pkHash } from "@opendatalabs/personal-server-ts-stream-sync";
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

async function fixture(
  maxBytesInFlight?: number,
  shared?: ReturnType<typeof createStorageAccess>,
) {
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
    shared !== undefined
      ? { ...remote.storage, governor: shared }
      : maxBytesInFlight === undefined
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

const deadline = <T>(work: Promise<T>, ms = 10_000) =>
  Promise.race([
    work,
    new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error("apply did not settle")), ms),
    ),
  ]);
const long = (id: string) => ({ id, pad: 'é"x'.repeat(1500) });

it("applies a record that spans more parts than the budget holds", async () => {
  // About 9,000 bytes in parts of 300, with room for three parts: a reservation
  // per part would wait for a fourth that only a commit could free.
  const f = await fixture(2 * 3 * 300);
  await f.head("a", [long("big"), { id: "after" }], { pieceBytes: 300 });
  await deadline(applyConnection(f.deps, f.id));
  const rows = await f.db.query<{ body: string }>(
    "SELECT body FROM records WHERE stream = 'a' ORDER BY pk_hash",
  );
  expect(rows.map((r) => JSON.parse(r.body).id).sort()).toEqual([
    "after",
    "big",
  ]);
  const whole = await f.deps.blobs.governor.reserve(2 * 3 * 300);
  whole();
});

it("settles connections that apply together under one budget", async () => {
  const governor = createStorageAccess({
    ...DEFAULT_STORAGE_ACCESS_POLICY,
    maxBytesInFlight: 2 * 3 * 300,
  });
  const fixtures = await Promise.all(
    [0, 1, 2].map(() => fixture(undefined, governor)),
  );
  for (const f of fixtures)
    await f.head("a", [long("one"), long("two"), { id: "end" }], {
      pieceBytes: 300,
    });
  await deadline(
    Promise.all(fixtures.map((f) => applyConnection(f.deps, f.id))),
  );
  for (const f of fixtures)
    expect(
      await f.db.query("SELECT 1 FROM records WHERE stream = 'a'"),
    ).toHaveLength(3);
  const whole = await governor.reserve(2 * 3 * 300);
  whole();
});

it("gives its memory back when a continuation part of a record is missing", async () => {
  const f = await fixture(2 * 3 * 300);
  const h = await f.head("a", [long("big")], { pieceBytes: 300 });
  f.blobs.delete(`${h.scope}/g1-p-${h.parts[7]!.hash}`);
  await expect(deadline(applyConnection(f.deps, f.id))).rejects.toThrow(
    "apply: missing part blob",
  );
  const whole = await Promise.race([
    f.deps.blobs.governor.reserve(2 * 3 * 300).then((r) => (r(), "granted")),
    new Promise((resolve) => setTimeout(() => resolve("waiting"), 100)),
  ]);
  expect(whole).toBe("granted");
});

// A head loaded progressively: each commit also writes the stream's partial
// row, so what a reader sees is what is durable.
const progressive = (
  f: Awaited<ReturnType<typeof fixture>>,
): LocalSyncDeps => ({
  ...f.deps,
  progressiveFirstLoad: true,
});

/** The ids of the records a head holds, in the order its parts hold them. */
async function idsInPartOrder(ids: readonly string[]) {
  const keyed = await Promise.all(
    ids.map(async (id) => ({ id, k: await pkHash(SHA, { id }, ["id"]) })),
  );
  return keyed.sort((a, b) => a.k.localeCompare(b.k)).map((r) => r.id);
}
const SHA = async (bytes: Uint8Array) => sha256(bytes);
const lettered = ["a", "b", "c", "d"].map((id) => ({ id }));

const partial = async (f: Awaited<ReturnType<typeof fixture>>) =>
  f.db.query<{ parts_applied: number; failed: number }>(
    "SELECT parts_applied, failed FROM stream_partial WHERE stream = 'a'",
  );
const storedIds = async (f: Awaited<ReturnType<typeof fixture>>) =>
  (
    await f.db.query<{ body: string }>(
      "SELECT body FROM records WHERE stream = 'a'",
    )
  )
    .map((r) => (JSON.parse(r.body) as { id: string }).id)
    .sort();

/** Holds the first commit until every part of the head has been fetched. */
function holdFirstCommit(
  f: Awaited<ReturnType<typeof fixture>>,
  fetchedParts: number,
) {
  let fetched = 0;
  const get = f.deps.blobs.get.bind(f.deps.blobs);
  f.deps.blobs.get = async (key) => {
    const bytes = await get(key);
    if (key.includes("/g1-p-")) fetched++;
    return bytes;
  };
  const batch = f.db.batch.bind(f.db);
  let held = false;
  vi.spyOn(f.db, "batch").mockImplementation(async (statements) => {
    if (!held && statements.some((s) => s.sql.includes("temp.incoming"))) {
      held = true;
      while (fetched < fetchedParts) await new Promise((r) => setTimeout(r, 5));
    }
    return batch(statements);
  });
}

it("commits the parts it has verified before it raises the error of the next one", async () => {
  const f = await fixture();
  const order = await idsInPartOrder(lettered.map((r) => r.id));
  const h = await f.head("a", lettered);
  // The third part's bytes do not match the hash the head declares for it.
  f.blobs.set(
    `${h.scope}/g1-p-${h.parts[2]!.hash}`,
    new Uint8Array(h.parts[2]!.bytes).fill(7),
  );
  holdFirstCommit(f, 4);
  await expect(deadline(applyConnection(progressive(f), f.id))).rejects.toThrow(
    /part SHA-256 does not match/,
  );
  // The first two parts were verified before the third failed: both are
  // durable and shown, the third and the fourth are not, and the stream is
  // not complete.
  expect(await storedIds(f)).toEqual([order[0], order[1]].sort());
  expect(await partial(f)).toEqual([{ parts_applied: 2, failed: 1 }]);
  expect(
    await f.db.query("SELECT 1 FROM stream_state WHERE complete = 1"),
  ).toHaveLength(0);
  expect(
    await f.db.query("SELECT 1 FROM temp.incoming WHERE op LIKE 'readahead-%'"),
  ).toHaveLength(0);
});

it("gives a fetch that is still running its memory when it ends, after the apply has failed", async () => {
  const f = await fixture();
  const h = await f.head("a", lettered);
  f.blobs.set(
    `${h.scope}/g1-p-${h.parts[2]!.hash}`,
    new Uint8Array(h.parts[2]!.bytes).fill(7),
  );
  // The fourth part's GET does not return until released.
  let release!: () => void;
  const stuck = new Promise<void>((r) => (release = r));
  const get = f.deps.blobs.get.bind(f.deps.blobs);
  let fetched = 0;
  f.deps.blobs.get = async (key) => {
    if (key.includes(h.parts[3]!.hash)) await stuck;
    const bytes = await get(key);
    if (key.includes("/g1-p-")) fetched++;
    return bytes;
  };
  const batch = f.db.batch.bind(f.db);
  let held = false;
  vi.spyOn(f.db, "batch").mockImplementation(async (statements) => {
    if (!held && statements.some((s) => s.sql.includes("temp.incoming"))) {
      held = true;
      while (fetched < 3) await new Promise((r) => setTimeout(r, 5));
    }
    return batch(statements);
  });
  await expect(deadline(applyConnection(progressive(f), f.id))).rejects.toThrow(
    /part SHA-256 does not match/,
  );
  const whole = DEFAULT_STORAGE_ACCESS_POLICY.maxBytesInFlight;
  const waiting = await Promise.race([
    f.deps.blobs.governor.reserve(whole).then((r) => (r(), "granted")),
    new Promise((resolve) => setTimeout(() => resolve("waiting"), 100)),
  ]);
  expect(waiting).toBe("waiting");
  release();
  // The fetch ends and the reader gives its part's memory back, exactly once.
  const after = await Promise.race([
    f.deps.blobs.governor.reserve(whole).then((r) => (r(), "granted")),
    new Promise((resolve) => setTimeout(() => resolve("waiting"), 2000)),
  ]);
  expect(after).toBe("granted");
});

it("leaves a committed first group durable when a later group fails before it is submitted, and a fresh apply finishes exactly", async () => {
  const f = await fixture();
  const records = Array.from({ length: 12 }, (_, i) => ({ id: `row-${i}` }));
  const h = await f.head("a", records);
  // The second data commit throws before the driver sees it, as a crash at
  // the transaction boundary would. The first commit (one part) is durable.
  const batch = f.db.batch.bind(f.db);
  const attempts: number[] = [];
  const sawOmission: string[] = [];
  vi.spyOn(f.db, "batch").mockImplementation(async (statements) => {
    for (const s of statements)
      if (s.sql.startsWith("DELETE FROM records")) sawOmission.push(s.sql);
    const staged = statements.filter((s) =>
      s.sql.includes("INSERT INTO temp.incoming"),
    ).length;
    if (staged > 0) {
      attempts.push(staged);
      if (attempts.length === 2) {
        expect(staged).toBeGreaterThan(1);
        throw new Error("crash before submit");
      }
    }
    return batch(statements);
  });
  await expect(deadline(applyConnection(progressive(f), f.id))).rejects.toThrow(
    "crash before submit",
  );
  expect(attempts[0]).toBe(1);
  expect(await storedIds(f)).toHaveLength(1);
  expect(await partial(f)).toEqual([{ parts_applied: 1, failed: 1 }]);
  expect(sawOmission).toEqual([]);
  expect(
    await f.db.query("SELECT 1 FROM stream_state WHERE complete = 1"),
  ).toHaveLength(0);
  // A new apply, with its own queue, from what is durable.
  vi.restoreAllMocks();
  const fresh: LocalSyncDeps = { ...progressive(f), queue: connectionQueue() };
  await deadline(applyConnection(fresh, f.id));
  expect(await storedIds(f)).toEqual(records.map((r) => r.id).sort());
  expect(
    (
      await f.db.query<{ part_hash: string }>(
        "SELECT part_hash FROM head_parts WHERE stream = 'a' ORDER BY seq",
      )
    ).map((r) => r.part_hash),
  ).toEqual(h.parts.map((p) => p.hash));
  expect(
    await f.db.query(
      "SELECT 1 FROM stream_state WHERE stream = 'a' AND complete = 1 AND head_data_hash = ?",
      [h.dataHash],
    ),
  ).toHaveLength(1);
  expect(await partial(f)).toEqual([]);
});
