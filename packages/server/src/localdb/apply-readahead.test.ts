// A head's parts are read ahead of the apply, within the store's memory
// budget: the GET of the next part runs while the commit of this one does.
import { afterEach, expect, it, vi } from "vitest";
import { sha256 } from "@noble/hashes/sha2";
import { pkHash } from "@opendatalabs/personal-server-ts-stream-sync";
import * as streamSync from "@opendatalabs/personal-server-ts-stream-sync";
import * as partReadahead from "../../../core/src/localdb/part-readahead.js";
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

// Keep the package exports spyable even when the workspace resolves it as ESM.
vi.mock(
  "@opendatalabs/personal-server-ts-stream-sync",
  async (importOriginal) => ({
    ...(await importOriginal<typeof streamSync>()),
  }),
);

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
  await reacquire(f, DEFAULT_STORAGE_ACCESS_POLICY.maxBytesInFlight);
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
  await reacquire(f, 2 * 3 * 300);
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

/** One deadline per scenario; every gate wait shares it, and it is cleared. */
async function acknowledgedScenario(
  run: (wait: <T>(work: Promise<T>) => Promise<T>) => Promise<void>,
) {
  let timer!: ReturnType<typeof setTimeout>;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(
      () => reject(new Error("apply scenario did not settle")),
      10_000,
    );
  });
  const wait = <T>(work: Promise<T>): Promise<T> =>
    Promise.race([work, timeout]);
  try {
    await run(wait);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * The whole budget can be reserved again: the reservation is acknowledged, and
 * no timing threshold decides it. A hang ends at the scenario deadline.
 */
async function reacquire(
  f: Awaited<ReturnType<typeof fixture>>,
  bytes: number,
) {
  await acknowledgedScenario(async (wait) => {
    const release = await wait(f.deps.blobs.governor.reserve(bytes));
    release();
  });
}

/**
 * Records every reservation and release at the governor, the boundary the
 * reader reserves through. Reservation `n` is the n-th the governor granted.
 */
function watchGovernor(
  governor: Awaited<ReturnType<typeof fixture>>["deps"]["blobs"]["governor"],
) {
  const events: string[] = [];
  const released: ReturnType<typeof acknowledgement>[] = [];
  const real = governor.reserve.bind(governor);
  const spy = vi
    .spyOn(governor, "reserve")
    .mockImplementation(async (bytes, objectBytes) => {
      const release = await real(bytes, objectBytes);
      const n = released.push(acknowledgement()) - 1;
      events.push(`reserved ${n}`);
      return () => {
        events.push(`released ${n}`);
        released[n]!.resolve();
        release();
      };
    });
  return { events, released, restore: () => spy.mockRestore() };
}

function acknowledgement<T = void>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

it("commits the parts it has verified before it raises the error of the next one", async () => {
  const f = await fixture();
  const order = await idsInPartOrder(lettered.map((r) => r.id));
  const h = await f.head("a", lettered);
  f.blobs.set(
    `${h.scope}/g1-p-${h.parts[2]!.hash}`,
    new Uint8Array(h.parts[2]!.bytes).fill(7),
  );
  const thirdReady = acknowledgement<boolean>();
  const firstSubmitted = acknowledgement();
  const releaseFirst = acknowledgement();
  const secondSubmitted = acknowledgement();
  const releaseSecond = acknowledgement();
  const validationFailed = acknowledgement<unknown>();
  const events: string[] = [];
  const realAhead = partReadahead.readPartsAhead;
  const aheadSpy = vi
    .spyOn(partReadahead, "readPartsAhead")
    .mockImplementation(function <
      P extends partReadahead.SizedPart,
      T = Uint8Array,
    >(
      blobs: Parameters<typeof realAhead>[0],
      parts: readonly P[],
      fetch: (part: P) => Promise<T>,
    ): partReadahead.PartReader<P, T> {
      const reader = realAhead(blobs, parts, fetch, (_first, last) => {
        if (last === 2) thirdReady.resolve(reader.ready(2));
      });
      return {
        ...reader,
        ready(index) {
          const ready = reader.ready(index);
          // apply.ts asks about part 3 only after validating/staging part 2.
          // A true result keeps that verified part pending instead of submitting it.
          if (index === 2 && ready) events.push("second pending");
          return ready;
        },
      };
    });
  const realFrames = streamSync.framesOfParts;
  const framesSpy = vi
    .spyOn(streamSync, "framesOfParts")
    .mockImplementation(async function* (
      ...args: Parameters<typeof realFrames>
    ) {
      try {
        yield* realFrames(...args);
      } catch (error) {
        events.push("third validation failed");
        validationFailed.resolve(error);
        throw error;
      }
    });
  const batch = f.db.batch.bind(f.db);
  let submissions = 0;
  const batchSpy = vi
    .spyOn(f.db, "batch")
    .mockImplementation(async (statements) => {
      if (statements.some((s) => s.sql.includes("INSERT INTO temp.incoming"))) {
        const rows = statements.filter((s) =>
          s.sql.includes("INSERT INTO temp.incoming"),
        );
        expect(rows).toHaveLength(1);
        submissions++;
        if (submissions === 1) {
          events.push("first submitted");
          firstSubmitted.resolve();
          await releaseFirst.promise;
        } else if (submissions === 2) {
          events.push("second submitted");
          secondSubmitted.resolve();
          await releaseSecond.promise;
        }
      }
      return batch(statements);
    });
  const outcome = applyConnection(progressive(f), f.id).then(
    () => ({ error: undefined }),
    (error: unknown) => ({ error }),
  );
  try {
    await acknowledgedScenario(async (wait) => {
      try {
        await wait(firstSubmitted.promise);
        expect(await wait(thirdReady.promise)).toBe(true);
        releaseFirst.resolve();
        const failure = await wait(validationFailed.promise);
        expect(failure).toBeInstanceOf(Error);
        expect((failure as Error).message).toMatch(
          /part SHA-256 does not match/,
        );
        expect(events.slice(0, 3)).toEqual([
          "first submitted",
          "second pending",
          "third validation failed",
        ]);
        // If the catch flush is removed, outcome settles without a second
        // submission; do not hang waiting for an event the mutant cannot emit.
        await wait(
          Promise.race([
            secondSubmitted.promise,
            outcome.then(() => undefined),
          ]),
        );
        expect(await wait(storedIds(f))).toEqual([order[0]]);
        releaseSecond.resolve();
        expect((await wait(outcome)).error).toBe(failure);
        // Mutation oracle: removing apply.ts's catch flush leaves only the
        // first part durable and fails these two-part durability assertions.
        expect(await wait(storedIds(f))).toEqual([order[0], order[1]].sort());
        expect(await wait(partial(f))).toEqual([
          { parts_applied: 2, failed: 1 },
        ]);
        expect(submissions).toBe(2);
        expect(events).toEqual([
          "first submitted",
          "second pending",
          "third validation failed",
          "second submitted",
        ]);
        await wait(
          f.deps.blobs.governor
            .reserve(DEFAULT_STORAGE_ACCESS_POLICY.maxBytesInFlight)
            .then((release) => release()),
        );
        expect(
          await wait(
            f.db.query("SELECT 1 FROM stream_state WHERE complete = 1"),
          ),
        ).toHaveLength(0);
        expect(
          await wait(
            f.db.query(
              "SELECT 1 FROM temp.incoming WHERE op LIKE 'readahead-%'",
            ),
          ),
        ).toHaveLength(0);
      } finally {
        releaseFirst.resolve();
        releaseSecond.resolve();
        await wait(outcome).catch(() => undefined);
      }
    });
  } finally {
    releaseFirst.resolve();
    releaseSecond.resolve();
    aheadSpy.mockRestore();
    framesSpy.mockRestore();
    batchSpy.mockRestore();
  }
});

it("gives a fetch that is still running its memory when it ends, after the apply has failed", async () => {
  const f = await fixture();
  const h = await f.head("a", lettered);
  f.blobs.set(
    `${h.scope}/g1-p-${h.parts[2]!.hash}`,
    new Uint8Array(h.parts[2]!.bytes).fill(7),
  );
  const releaseFourth = acknowledgement();
  const fourthStarted = acknowledgement();
  const fourthReturned = acknowledgement();
  const thirdReady = acknowledgement();
  const governor = watchGovernor(f.deps.blobs.governor);
  const get = f.deps.blobs.get.bind(f.deps.blobs);
  f.deps.blobs.get = async (key) => {
    if (!key.endsWith(h.parts[3]!.hash)) return get(key);
    fourthStarted.resolve();
    await releaseFourth.promise;
    try {
      return await get(key);
    } finally {
      governor.events.push("fourth fetch settled");
      fourthReturned.resolve();
    }
  };
  const realAhead = partReadahead.readPartsAhead;
  const aheadSpy = vi
    .spyOn(partReadahead, "readPartsAhead")
    .mockImplementation(function <
      P extends partReadahead.SizedPart,
      T = Uint8Array,
    >(
      blobs: Parameters<typeof realAhead>[0],
      parts: readonly P[],
      fetch: (part: P) => Promise<T>,
    ): partReadahead.PartReader<P, T> {
      return realAhead(blobs, parts, fetch, (_first, last) => {
        if (last === 2) thirdReady.resolve();
      });
    });
  const batch = f.db.batch.bind(f.db);
  let held = false;
  const batchSpy = vi
    .spyOn(f.db, "batch")
    .mockImplementation(async (statements) => {
      if (
        !held &&
        statements.some((s) => s.sql.includes("INSERT INTO temp.incoming"))
      ) {
        held = true;
        await thirdReady.promise;
        await fourthStarted.promise;
      }
      return batch(statements);
    });
  const outcome = applyConnection(progressive(f), f.id).then(
    () => undefined,
    (error: unknown) => error,
  );
  try {
    await acknowledgedScenario(async (wait) => {
      try {
        const error = await wait(outcome);
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toMatch(/part SHA-256 does not match/);
        // The apply has failed and closed its reader while the fourth GET is
        // still held: that unit's reservation must still be held.
        expect(governor.events).toContain("reserved 3");
        expect(governor.events).not.toContain("released 3");
        releaseFourth.resolve();
        await wait(fourthReturned.promise);
        // It is released only after its fetch settles.
        await wait(governor.released[3]!.promise);
        expect(governor.events.indexOf("fourth fetch settled")).toBeLessThan(
          governor.events.indexOf("released 3"),
        );
        // And the whole budget can then be reserved again.
        await reacquire(f, DEFAULT_STORAGE_ACCESS_POLICY.maxBytesInFlight);
      } finally {
        releaseFourth.resolve();
        await wait(outcome).catch(() => undefined);
      }
    });
  } finally {
    releaseFourth.resolve();
    f.deps.blobs.get = get;
    governor.restore();
    aheadSpy.mockRestore();
    batchSpy.mockRestore();
  }
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

it("rejects a head that splits a long record in its metadata, without waiting for another reservation", async () => {
  // Room for one part. The counts still add up to the record count, but the
  // second part is said to open a record while the first part's record runs on
  // into it, and the last part is said to continue one. Were the apply to read
  // the second part, its reservation would wait for the first part's commit,
  // which waits for the record: the old cycle.
  const f = await fixture(2 * 300);
  const bigKey = await pkHash(SHA, { id: "big" }, ["id"]);
  let after = "after-0";
  for (let i = 0; i < 64; i++) {
    after = `after-${i}`;
    if ((await pkHash(SHA, { id: after }, ["id"])) > bigKey) break;
  }
  const h = await f.head("a", [long("big"), { id: after }], {
    pieceBytes: 300,
    entry: (p, i, all) =>
      i === 1 ? { ...p, count: 1 } : i === all - 1 ? { ...p, count: 0 } : p,
  });
  expect(h.parts[1]!.count).toBe(0);
  let gets = 0;
  const get = f.deps.blobs.get.bind(f.deps.blobs);
  f.deps.blobs.get = async (key) => {
    if (key.includes("/g1-p-")) gets++;
    return get(key);
  };
  await expect(deadline(applyConnection(progressive(f), f.id))).rejects.toThrow(
    "long frame runs past its parts",
  );
  // Only the first part ever held a reservation: the second waited behind it
  // and the apply never waited for the second.
  expect(gets).toBe(1);
  expect(await f.db.query("SELECT 1 FROM records")).toHaveLength(0);
  expect(await partial(f)).toEqual([]);
  await reacquire(f, 2 * 300);
});

it("rejects a head that joins the next record to this one in its metadata, without waiting for another reservation", async () => {
  // The first part is said to hold two records and the second to continue
  // them. It is read as one unit of two parts, larger than the budget and
  // admitted alone; the decoder rejects the first part's count before it loads
  // the second.
  const f = await fixture(2 * 150);
  await f.head("a", [{ id: "one" }, { id: "two" }], {
    entry: (p, i) => ({ ...p, count: i === 0 ? 2 : 0 }),
  });
  await expect(deadline(applyConnection(progressive(f), f.id))).rejects.toThrow(
    "part has 1 frames, head says 2",
  );
  expect(await partial(f)).toEqual([]);
  await reacquire(f, 2 * 150);
});

it("commits only what precedes a part that fails, when the parts after it arrive first", async () => {
  const f = await fixture();
  const records = Array.from({ length: 5 }, (_, i) => ({ id: `row-${i}` }));
  const h = await f.head("a", records);
  const order = await idsInPartOrder(records.map((r) => r.id));
  const gates = h.parts.map(() => acknowledgement());
  const started = h.parts.map(() => acknowledgement());
  const returned = h.parts.map(() => acknowledgement());
  const arrivals: number[] = [];
  const get = f.deps.blobs.get.bind(f.deps.blobs);
  f.deps.blobs.get = async (key) => {
    const at = h.parts.findIndex((p) => key.endsWith(p.hash));
    if (at === -1) return get(key);
    started[at]!.resolve();
    await gates[at]!.promise;
    try {
      if (at === 1) throw new Error("storage failure on part 1");
      return await get(key);
    } finally {
      arrivals.push(at);
      returned[at]!.resolve();
    }
  };
  const outcome = applyConnection(progressive(f), f.id).then(
    () => "applied",
    (error: Error) => error.message,
  );
  try {
    await acknowledgedScenario(async (wait) => {
      try {
        await wait(Promise.all(started.map((s) => s.promise)));
        for (const at of [4, 3, 2, 1, 0]) {
          gates[at]!.resolve();
          await wait(returned[at]!.promise);
        }
        expect(arrivals).toEqual([4, 3, 2, 1, 0]);
        expect(await wait(outcome)).toBe("storage failure on part 1");
        expect(await wait(storedIds(f))).toEqual([order[0]]);
        expect(await wait(partial(f))).toEqual([
          { parts_applied: 1, failed: 1 },
        ]);
        await wait(
          f.deps.blobs.governor
            .reserve(DEFAULT_STORAGE_ACCESS_POLICY.maxBytesInFlight)
            .then((release) => release()),
        );
      } finally {
        for (const gate of gates) gate.resolve();
        await wait(outcome).catch(() => undefined);
      }
    });
  } finally {
    for (const gate of gates) gate.resolve();
    f.deps.blobs.get = get;
  }
});

it("commits no record of a head whose long record is missing a part, and finishes once the part is back", async () => {
  const f = await fixture(2 * 3 * 300);
  const bigKey = await pkHash(SHA, { id: "big" }, ["id"]);
  // A record that sorts after the long one: it would follow it in the parts.
  let after = "after-0";
  for (let i = 0; i < 64; i++) {
    after = `after-${i}`;
    if ((await pkHash(SHA, { id: after }, ["id"])) > bigKey) break;
  }
  const h = await f.head("a", [long("big"), { id: after }], {
    pieceBytes: 300,
  });
  const missing = `${h.scope}/g1-p-${h.parts[7]!.hash}`;
  const blob = f.blobs.get(missing)!;
  f.blobs.delete(missing);
  await expect(deadline(applyConnection(progressive(f), f.id))).rejects.toThrow(
    "apply: missing part blob",
  );
  // Neither the long record nor the one after it is committed, and no state
  // says part of the head is applied or the head complete.
  expect(await f.db.query("SELECT 1 FROM records")).toHaveLength(0);
  expect(await partial(f)).toEqual([]);
  expect(
    await f.db.query("SELECT 1 FROM stream_state WHERE complete = 1"),
  ).toHaveLength(0);
  expect(await f.db.query("SELECT 1 FROM head_parts")).toHaveLength(0);
  await reacquire(f, 2 * 3 * 300);
  // The part is back: a new apply finishes exactly.
  f.blobs.set(missing, blob);
  await deadline(applyConnection(progressive(f), f.id));
  expect(await storedIds(f)).toEqual(["big", after].sort());
  expect(await partial(f)).toEqual([]);
});

it("resumes a first load after the second group commit crashes", async () => {
  const f = await fixture();
  const h = await f.head("a", values(6));
  const deps = { ...f.deps, progressiveFirstLoad: true };
  const order = await idsInPartOrder(values(6).map((r) => r.id));
  const snapshot = async () => ({
    records: await f.db.query<{ pk_hash: string; body: string }>(
      "SELECT pk_hash,body FROM records WHERE connection_id=? AND stream='a' ORDER BY pk_hash",
      [f.id],
    ),
    head: await f.db.query<Record<string, unknown>>(
      "SELECT * FROM stream_state WHERE connection_id=? AND stream='a'",
      [f.id],
    ),
    partial: await f.db.query<Record<string, unknown>>(
      "SELECT * FROM stream_partial WHERE connection_id=? AND stream='a'",
      [f.id],
    ),
    versions: await f.db.query<Record<string, unknown>>(
      "SELECT * FROM stream_versions WHERE connection_id=? AND stream='a' ORDER BY version,generation",
      [f.id],
    ),
    parts: await f.db.query<Record<string, unknown>>(
      "SELECT * FROM head_parts WHERE connection_id=? AND stream='a' ORDER BY prefix,seq",
      [f.id],
    ),
  });
  const batch = f.db.batch.bind(f.db);
  const crash = new Error("simulated second group commit crash");
  let groups = 0;
  let crashed = false;
  let omissionDeletes = 0;
  let committed: Awaited<ReturnType<typeof snapshot>> | undefined;
  const spy = vi.spyOn(f.db, "batch").mockImplementation(async (statements) => {
    if (statements.some((s) => /DELETE\s+FROM\s+records\b/i.test(s.sql)))
      omissionDeletes++;
    // A dead process cannot persist a failed marker or run finally cleanup.
    // Refuse every write after the crash until the fresh apply below.
    if (crashed) throw crash;
    const rows = statements.filter((s) =>
      s.sql.includes("INSERT INTO temp.incoming"),
    ).length;
    if (rows > 0 && ++groups === 2) {
      crashed = true;
      throw crash;
    }
    const result = await batch(statements);
    if (rows > 0 && groups === 1) committed = await snapshot();
    return result;
  });
  const bounded = async <T>(work: Promise<T>): Promise<T> => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        work,
        new Promise<never>((_, reject) => {
          timer = setTimeout(
            () => reject(new Error("crash/resume did not settle")),
            10_000,
          );
        }),
      ]);
    } finally {
      clearTimeout(timer);
    }
  };
  try {
    await expect(bounded(applyConnection(deps, f.id))).rejects.toBe(crash);
    expect(groups).toBe(2);
    expect(omissionDeletes).toBe(0);
    if (committed === undefined) throw new Error("first group never committed");
    expect(committed.records.map((r) => JSON.parse(r.body).id)).toEqual([
      order[0],
    ]);
    expect(committed.head).toHaveLength(1);
    expect(committed.head[0]?.complete).toBe(0);
    // Column names and progress semantics come from partial-load.ts.
    // Dropping partialRowStatement from the group commit must fail here.
    expect(committed.partial).toHaveLength(1);
    expect(committed.partial[0]).toMatchObject({
      version: 1,
      generation: 1,
      data_hash: h.dataHash,
      head_blob: h.blobName,
      observed_at: 100,
      parts_applied: 1,
      parts_total: h.parts.length,
      records_total: 6,
      failed: 0,
    });
    expect(committed.versions).toEqual([]);
    expect(committed.parts).toEqual([]);
    // Exact persisted state is the first commit, not the attempted second one.
    expect(await snapshot()).toEqual(committed);
    expect(
      await f.db.query(
        "SELECT apply_partial FROM connections WHERE connection_id=?",
        [f.id],
      ),
    ).toEqual([{ apply_partial: 1 }]);

    // Fresh queue, read-ahead and operation IDs; only persisted data is reused.
    // Keep the same DB handle solely because this fixture is in-memory.
    spy.mockRestore();
    let finalBatches = 0;
    vi.spyOn(f.db, "batch").mockImplementation(async (statements) => {
      const final = statements.some((s) =>
        s.sql.includes("INSERT OR REPLACE INTO stream_versions"),
      );
      const omits = statements.some((s) =>
        /DELETE\s+FROM\s+records\b/i.test(s.sql),
      );
      if (final) finalBatches++;
      if (omits) {
        omissionDeletes++;
        // An omission may run only alongside installation of the final head,
        // never in a row-group commit or in an independent cleanup batch.
        expect(final).toBe(true);
        expect(
          statements.some((s) =>
            s.sql.includes("UPDATE stream_state SET primary_key="),
          ),
        ).toBe(true);
        expect(
          statements.some((s) => s.sql.includes("DELETE FROM stream_partial")),
        ).toBe(true);
      }
      const result = await batch(statements);
      if (final) {
        const installed = await snapshot();
        expect(installed.partial).toEqual([]);
        expect(installed.head[0]?.complete).toBe(1);
        expect(installed.versions).toHaveLength(1);
        expect(installed.parts).toHaveLength(h.parts.length);
      }
      return result;
    });
    let op = 0;
    await bounded(
      applyConnection(
        {
          ...deps,
          queue: connectionQueue(),
          newOp: () => `resumed-${++op}`,
        },
        f.id,
      ),
    );
    const resumed = await snapshot();
    expect(resumed.records.map((r) => JSON.parse(r.body).id).sort()).toEqual(
      values(6)
        .map((r) => r.id)
        .sort(),
    );
    expect(new Set(resumed.records.map((r) => r.pk_hash)).size).toBe(6);
    expect(resumed.records).toHaveLength(6);
    expect(resumed.partial).toEqual([]);
    expect(
      resumed.parts.map((p) => ({
        prefix: p.prefix,
        seq: p.seq,
        part_hash: p.part_hash,
        bytes: p.bytes,
        count: p.count,
      })),
    ).toEqual(
      h.parts.map((p, seq) => ({
        prefix: p.prefix,
        seq,
        part_hash: p.hash,
        bytes: p.bytes,
        count: p.count,
      })),
    );
    expect(resumed.versions).toHaveLength(1);
    expect(resumed.versions[0]).toMatchObject({
      version: 1,
      generation: 1,
      head_blob: h.blobName,
      head_format: 4,
      record_count: 6,
      observed_at: 100,
      complete: 1,
      kind: "applied",
    });
    expect(resumed.head[0]).toMatchObject({
      complete: 1,
      head_version: committed.partial[0]!.version,
      head_generation: committed.partial[0]!.generation,
      head_data_hash: h.dataHash,
      head_blob: h.blobName,
      consumed_version: 1,
      consumed_generation: 1,
      consumed_data_hash: h.dataHash,
    });
    expect(
      await f.db.query(
        "SELECT apply_partial FROM connections WHERE connection_id=?",
        [f.id],
      ),
    ).toEqual([{ apply_partial: 0 }]);
    // Proves the SQL observer recognizes the final-only omission deletion.
    expect(omissionDeletes).toBe(1);
    expect(finalBatches).toBe(1);
  } finally {
    vi.mocked(f.db.batch).mockRestore();
  }
});
