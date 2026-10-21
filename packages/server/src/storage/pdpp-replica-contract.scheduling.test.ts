/**
 * Contract suite, section B (cases 15-34): scheduling, budgets, dependencies and
 * finality, proven end to end on the real transport worker + receiver.
 *
 * Red-first: the coordinator does not exist yet. These tests describe the target
 * behaviour (CONTRACT-API.md) and fail today for the reasons named in each case.
 * Report items come from worker.step(budget); durable logical fields come from
 * workRecords(db) and from raw SQL on pdpp_transport_import_work.
 */
import { afterEach, expect, it, vi } from "vitest";
import type { ProgressReport } from "@opendatalabs/personal-server-ts-core/replication/coordinator";
import {
  CrashController,
  clock,
  cleanupHarness,
  cycles,
  durableSnapshot,
  expected,
  network,
  sourceId,
  transportDevice,
  transportInvariantViolations,
  workRecords,
  type Network,
  type TransportDevice,
  type WorkRecord,
} from "./pdpp-replica-contract.test-utils.js";

afterEach(() => {
  vi.restoreAllMocks();
  cleanupHarness();
});

// ------------------------------------------------------------------ constants

/** Fixture backoff B(1). Waits reset attempts, so the first genuine error is B(1). */
const B1 = 1000;
/** Bounded fallback rescan for non-finality waits (CONTRACT-API section 6). */
const FALLBACK = 60_000;

// ------------------------------------------------------------------- helpers

type Budget = { units: number; bytes?: number };

async function step(d: TransportDevice, budget: Budget = { units: 50 }) {
  return (await d.step(budget)) as ProgressReport | undefined;
}

/** n steps; the clock advances `ms` before each one. */
async function steps(
  d: TransportDevice,
  n: number,
  ms = 0,
  budget: Budget = { units: 50 },
) {
  const reports: (ProgressReport | undefined)[] = [];
  for (let i = 0; i < n; i++) {
    clock.advance(ms);
    reports.push(await step(d, budget));
  }
  return reports;
}

/** Step until `done()`; the clock advances `ms` before each step. Fails if never reached. */
async function stepUntil(
  d: TransportDevice,
  done: () => boolean,
  max: number,
  ms = 0,
  budget: Budget = { units: 50 },
) {
  for (let i = 0; i < max; i++) {
    if (done()) return;
    clock.advance(ms);
    await step(d, budget);
  }
  expect(done(), "condition not reached within the step bound").toBe(true);
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

async function within<T>(ms: number, work: Promise<T>, label: string) {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(
      () => reject(new Error(`${label}: no settlement within ${ms} ms`)),
      ms,
    );
  });
  try {
    return await Promise.race([work, timeout]);
  } finally {
    clearTimeout(timer);
  }
}

async function waitFor(done: () => boolean, ms: number, label: string) {
  const deadline = Date.now() + ms;
  while (!done()) {
    if (Date.now() > deadline)
      throw new Error(`timed out waiting for ${label}`);
    await sleep(5);
  }
}

const num = (d: TransportDevice, sql: string, ...params: unknown[]) =>
  (d.db.prepare(sql).get(...params) as { n: number }).n;
const outboxScopes = (d: TransportDevice) =>
  (
    d.db
      .prepare("SELECT scope FROM pdpp_transport_outbox ORDER BY rowid")
      .all() as { scope: string }[]
  ).map((r) => r.scope);
const outboxCount = (d: TransportDevice) =>
  num(d, "SELECT count(*) AS n FROM pdpp_transport_outbox");
const unpublished = (d: TransportDevice) =>
  num(
    d,
    "SELECT count(*) AS n FROM pdpp_transport_outbox WHERE state<>'published'",
  );
const batchCount = (d: TransportDevice) =>
  num(d, "SELECT count(*) AS n FROM pdpp_transport_batches");
const unpreparedBatches = (d: TransportDevice) =>
  num(d, "SELECT count(*) AS n FROM pdpp_transport_batches WHERE prepared<>1");
const retained = (d: TransportDevice) =>
  num(
    d,
    "SELECT count(*) AS n FROM pdpp_transport_inbox WHERE fragment_json IS NOT NULL",
  );
const importedReceipts = (d: TransportDevice) =>
  num(d, "SELECT count(*) AS n FROM pdpp_transport_imported");
const recordChanges = (d: TransportDevice) =>
  num(d, "SELECT count(*) AS n FROM pdpp_record_changes");
const journalOperations = (d: TransportDevice) =>
  num(d, "SELECT count(*) AS n FROM pdpp_replica_operations");
const writerOf = (d: TransportDevice) =>
  (
    d.db
      .prepare("SELECT writer FROM pdpp_transport_state WHERE id=1")
      .get() as { writer: string }
  ).writer;
const isFrom = (scope: string, writer: string) => scope.includes(`.${writer}_`);
const evidenceReads = (net: Network, scope: string) =>
  net.calls.evidence.filter((s) => s === scope).length;

interface ImportWork {
  writer: string;
  batch: string;
  sequence: number;
  outcome: string | null;
  reason: string | null;
  dependency: string | null;
  attempts: number;
  next_attempt: number;
}
/** Rows of pdpp_transport_import_work. [] until the table exists (red). */
function importWork(d: TransportDevice): ImportWork[] {
  const present = d.db
    .prepare(
      "SELECT 1 AS n FROM sqlite_master WHERE type='table' AND name='pdpp_transport_import_work'",
    )
    .get();
  if (!present) return [];
  return d.db
    .prepare(
      "SELECT writer,batch,sequence,outcome,reason,dependency,attempts,next_attempt FROM pdpp_transport_import_work ORDER BY rowid",
    )
    .all() as ImportWork[];
}
const importWorkFor = (d: TransportDevice, batch: string) =>
  importWork(d).filter((r) => r.batch === batch);

const records = (d: TransportDevice, table: string) =>
  workRecords(d.db).filter((r) => r.table === table);
const record = (d: TransportDevice, table: string, id: string) =>
  records(d, table).find((r) => r.id === id);
const OUTBOX = "pdpp_transport_outbox";
const INBOX = "pdpp_transport_inbox";
const BATCHES = "pdpp_transport_batches";

/** Registration that never reaches finalized evidence until finalizeAll(). */
function holdPending(
  net: Network,
  when: (scope: string) => boolean = () => true,
) {
  const put = net.port.put;
  net.port.put = async (part) => {
    if (when(part.scope)) net.pending.add(part.scope);
    return put(part);
  };
}

/** Wrap the verified block height the evidence port reports. */
function verifiedHeight(net: Network, initial: bigint) {
  const state = { height: initial };
  const evidence = net.port.evidence;
  net.port.evidence = async (scope) => {
    const e = await evidence(scope);
    return {
      ...e,
      chain: e.chain && { ...e.chain, blockNumber: state.height },
    };
  };
  return state;
}

// Narrow accessors for the missing coordinator surface.
type Wakeable = { onDependencyChanged?: (key: string) => unknown };
type Steppable = {
  step?: (input: {
    budget?: Budget;
    signal?: AbortSignal;
  }) => Promise<ProgressReport>;
};
/** Asserts the surface exists, then delivers the dependency notification. */
function wake(d: TransportDevice, key: string) {
  const fn = (d.worker as Wakeable).onDependencyChanged;
  expect(typeof fn, "worker.onDependencyChanged is missing").toBe("function");
  return fn!.call(d.worker, key);
}
/** Delivers the notification when the surface exists; never asserts it. */
function notify(d: TransportDevice, key: string) {
  const fn = (d.worker as Wakeable).onDependencyChanged;
  if (typeof fn === "function") fn.call(d.worker, key);
}
const hasWake = (d: TransportDevice) =>
  typeof (d.worker as Wakeable).onDependencyChanged === "function";

// Receiver instrumentation: counts calls on the very object the worker calls.
interface Tally {
  stage: { writer: string; batch: string }[];
  promote: { writer: string; batch: string }[];
  retry: number;
}
const newTally = (): Tally => ({ stage: [], promote: [], retry: 0 });
const idParts = (id: string) => {
  const [writer, batch] = JSON.parse(id) as [string, string];
  return { writer, batch };
};
const countFor = (calls: { writer: string }[], writer: string) =>
  calls.filter((c) => c.writer === writer).length;
interface Hooks {
  beforeStage?: (call: { writer: string; batch: string }) => void;
  /** May throw to inject a transient failure. */
  beforePromote?: (call: { writer: string; batch: string }) => void;
}
/** Call again after every reopen(): the receiver object is rebuilt. */
function instrument(d: TransportDevice, tally: Tally, hooks: Hooks = {}) {
  const receiver = d.receiver;
  const stage = receiver.stage.bind(receiver);
  const promote = receiver.promote.bind(receiver);
  const retry = receiver.retry.bind(receiver);
  vi.spyOn(receiver, "stage").mockImplementation((input) => {
    const call = idParts(input.id);
    tally.stage.push(call);
    hooks.beforeStage?.(call);
    return stage(input);
  });
  vi.spyOn(receiver, "promote").mockImplementation((input) => {
    const call = idParts(input.id);
    tally.promote.push(call);
    hooks.beforePromote?.(call);
    return promote(input);
  });
  vi.spyOn(receiver, "retry").mockImplementation((input) => {
    tally.retry++;
    return retry(input);
  });
}

const minDeadline = (rows: WorkRecord[]) =>
  Math.min(...rows.map((r) => r.nextEligible ?? Infinity));

/** A finalized single-record writer. Returns once every fragment is published. */
async function publishedWriter(
  net: Network,
  fill: (d: TransportDevice) => void,
  opts: { chunk?: number; pageSize?: number } = {},
) {
  const d = transportDevice(net, opts);
  fill(d);
  await stepUntil(
    d,
    () =>
      outboxCount(d) > 0 && unpublished(d) === 0 && unpreparedBatches(d) === 0,
    20,
    10_000,
  );
  return d;
}

/**
 * Writer with two batches (sequence 1 and 2). The importer sees only batch 2
 * until reveal(); its import must Wait(predecessor:<writer>:1).
 */
async function twoBatchRemote(opts: { crash?: CrashController } = {}) {
  const net = network();
  const a = transportDevice(net, { pageSize: 1 });
  a.put("one", "a");
  a.put("two", "b");
  await stepUntil(
    a,
    () =>
      batchCount(a) >= 2 && unpreparedBatches(a) === 0 && unpublished(a) === 0,
    30,
    10_000,
  );
  const batches = a.db
    .prepare(
      "SELECT batch,sequence FROM pdpp_transport_batches ORDER BY sequence",
    )
    .all() as { batch: string; sequence: number }[];
  expect(batches).toHaveLength(2);
  const writer = writerOf(a);
  const list = net.port.list;
  net.port.list = async (cursor) => {
    const page = await list(cursor);
    return {
      ...page,
      scopes: page.scopes.filter((s) => !s.includes(`_${batches[0]!.batch}.`)),
    };
  };
  const b = transportDevice(net, { crash: opts.crash });
  return {
    net,
    a,
    b,
    writer,
    first: batches[0]!.batch,
    second: batches[1]!.batch,
    reveal() {
      net.port.list = list;
    },
    /** Discover, download, confirm and evaluate the successor. */
    start: () => steps(b, 4, 0),
  };
}

const both = (d: TransportDevice) =>
  d.get("a") !== undefined && d.get("b") !== undefined;

// ===================================================================== 15, 16

/** Two writers: A (whose first import fails once) and C (unrelated). */
async function failedOnceImport(withUnrelatedWriter: boolean) {
  const net = network();
  const a = transportDevice(net);
  a.put("from A", "a");
  await cycles([a], 3);
  expect(unpublished(a)).toBe(0);
  const writerA = writerOf(a);
  let c: TransportDevice | undefined;
  if (withUnrelatedWriter) {
    c = transportDevice(net);
    c.put("from C", "c");
    await cycles([c], 3);
  }
  const b = transportDevice(net);
  const tally = newTally();
  let failuresLeft = 1;
  const hooks: Hooks = {
    beforePromote: ({ writer }) => {
      if (writer === writerA && failuresLeft-- > 0)
        throw new Error("transient import failure");
    },
  };
  instrument(b, tally, hooks);
  await stepUntil(b, () => countFor(tally.promote, writerA) >= 1, 12);
  return { net, a, b, c, writerA, tally, hooks, failedAt: clock.now() };
}

it("15 complete batch import fails transiently: no decode/stage/promote before B(1), deadline survives reopen, one import at the deadline", async () => {
  const { b, a, writerA, tally, hooks, failedAt } =
    await failedOnceImport(false);
  expect(countFor(tally.promote, writerA)).toBe(1);
  expect(countFor(tally.stage, writerA)).toBe(1);

  // 20 cycles inside the backoff window (20 x 40 ms = 800 ms < B(1)).
  for (let i = 0; i < 20; i++) {
    clock.advance(40);
    await step(b);
  }
  expect(
    countFor(tally.stage, writerA),
    "stage re-ran inside the backoff",
  ).toBe(1);
  expect(
    countFor(tally.promote, writerA),
    "promote re-ran inside the backoff",
  ).toBe(1);
  expect(importedReceipts(b)).toBe(0);
  expect(b.get("a")).toBeUndefined();

  const rows = importWork(b);
  expect(rows).toHaveLength(1);
  expect(rows[0]).toMatchObject({
    writer: writerA,
    outcome: "retry",
    attempts: 1,
    next_attempt: failedAt + B1,
  });

  // Survives restart: same row, same deadline, still no early attempt.
  b.reopen();
  instrument(b, tally, hooks);
  for (let i = 0; i < 3; i++) {
    clock.advance(30);
    await step(b);
  }
  expect(importWork(b)).toEqual(rows);
  expect(countFor(tally.promote, writerA)).toBe(1);
  expect(importedReceipts(b)).toBe(0);

  // At the deadline the batch imports once.
  clock.advance(failedAt + B1 - clock.now());
  await stepUntil(b, () => importedReceipts(b) === 1, 6);
  expect(countFor(tally.promote, writerA)).toBe(2);
  expect(b.get("a")).toEqual(a.get("a"));
  expect(importWork(b).every((r) => r.outcome !== "retry")).toBe(true);
});

it("16 discovery duplicates and unrelated dependency wakes before the deadline keep one work row and deadline; an unrelated writer still imports", async () => {
  const { b, net, c, writerA, tally, failedAt } = await failedOnceImport(true);
  expect(c).toBeDefined();
  const list = net.port.list;
  // The feed lists every scope twice on every page.
  net.port.list = async (cursor) => {
    const page = await list(cursor);
    return { ...page, scopes: [...page.scopes, ...page.scopes] };
  };
  const rowsOf = () => importWork(b).filter((r) => r.writer === writerA);
  const before = rowsOf();
  expect(before).toHaveLength(1);
  expect(before[0]).toMatchObject({
    outcome: "retry",
    attempts: 1,
    next_attempt: failedAt + B1,
  });
  for (let i = 0; i < 12; i++) {
    clock.advance(50);
    notify(b, `mapping:conn-${i}`);
    notify(b, `declaration:${sourceId}:other-${i}`);
    notify(b, "blob:unrelated");
    notify(b, `predecessor:${writerA}:99`);
    await step(b);
  }
  expect(countFor(tally.promote, writerA), "wake bypassed the backoff").toBe(1);
  expect(rowsOf()).toEqual(before);
  expect(b.get("a")).toBeUndefined();
  expect(b.get("c")).toEqual({ id: "c", text: "from C" });
  expect(hasWake(b), "worker.onDependencyChanged is missing").toBe(true);
});

// ========================================================================= 17

it("17a confirmation of many retained ready fragments is budgeted: evidence reads grow by at most k per step", async () => {
  const net = network();
  holdPending(net);
  const a = transportDevice(net, {
    preexisting: "x".repeat(15000),
    chunk: 500,
  });
  await stepUntil(
    a,
    () => outboxCount(a) > 0 && net.head.size === outboxCount(a),
    12,
    10_000,
  );
  const total = outboxCount(a);
  expect(total).toBeGreaterThan(20);
  const b = transportDevice(net);
  await stepUntil(b, () => retained(b) === total, 20, 10_000);
  expect(b.get("a")).toBeUndefined(); // pending, so nothing is confirmed yet
  net.finalizeAll();

  const k = 3;
  for (let i = 0; i < 40 && b.get("a") === undefined; i++) {
    clock.advance(10_000);
    const before = net.calls.evidence.length;
    await step(b, { units: k });
    const used = net.calls.evidence.length - before;
    expect(
      used,
      `step ${i} read evidence ${used} times with k=${k}`,
    ).toBeLessThanOrEqual(k);
  }
  expect(b.get("a")).toEqual(a.get("a"));
});

it("17b revalidation of many imported fragments is budgeted: evidence reads grow by at most k per step", async () => {
  const net = network();
  const a = await publishedWriter(net, (d) => d.put("x".repeat(15000), "a"), {
    chunk: 500,
  });
  const b = transportDevice(net);
  await stepUntil(b, () => b.get("a") !== undefined, 20, 10_000);
  const imported = num(
    b,
    "SELECT count(*) AS n FROM pdpp_transport_inbox WHERE state='imported'",
  );
  expect(imported).toBeGreaterThan(20);
  expect(b.get("a")).toEqual(a.get("a"));

  const k = 3;
  for (let i = 0; i < 6; i++) {
    clock.advance(10_000);
    const before = net.calls.evidence.length;
    await step(b, { units: k });
    const used = net.calls.evidence.length - before;
    expect(
      used,
      `step ${i} revalidated ${used} fragments with k=${k}`,
    ).toBeLessThanOrEqual(k);
  }
});

it("17c receiver.retry runs at most once per step and not on an idle step without a dependency change or due fallback", async () => {
  const net = network();
  const a = await publishedWriter(net, (d) => d.put("reconcile me", "a"));
  const b = transportDevice(net);
  const tally = newTally();
  instrument(b, tally);
  await stepUntil(b, () => b.get("a") !== undefined, 12, 10_000);
  expect(b.get("a")).toEqual(a.get("a"));
  await steps(b, 3, 10_000); // settle everything that is genuinely due

  const base = tally.retry;
  for (let i = 0; i < 5; i++) {
    clock.advance(10);
    await step(b);
  }
  expect(tally.retry - base, "idle steps ran receiver.retry").toBe(0);

  // The bounded fallback still runs it, never more than once per step.
  for (let i = 0; i < 20; i++) {
    clock.advance(30_000);
    const before = tally.retry;
    await step(b);
    expect(tally.retry - before).toBeLessThanOrEqual(1);
  }
  expect(
    tally.retry,
    "no fallback reconciliation within 10 minutes",
  ).toBeGreaterThan(base);
});

// ========================================================================= 18

it("18 per-phase isolation: a preparation backlog does not stop an independent remote batch from importing in one step", async () => {
  const net = network();
  const a = transportDevice(net);
  a.put("remote", "a");
  await cycles([a], 3);
  const writerA = writerOf(a);

  const b = transportDevice(net, { pageSize: 1 });
  const tally = newTally();
  let failImportOnce = 1;
  instrument(b, tally, {
    beforePromote: ({ writer }) => {
      if (writer === writerA && failImportOnce-- > 0)
        throw new Error("transient import failure");
    },
  });
  await stepUntil(b, () => countFor(tally.promote, writerA) >= 1, 12);

  // Sixteen local batches whose encryption is down: a preparation backlog.
  net.faults.encrypt = () => new Error("encryption down");
  for (let i = 0; i < 16; i++) b.put(`local ${i}`, `l${i}`);
  await stepUntil(b, () => batchCount(b) >= 12, 80, 5);

  // Everything is due now: the whole backlog and the retained remote import.
  net.faults.encrypt = undefined;
  clock.advance(2 * 3_600_000);
  const report = await step(b, { units: 8 });
  expect(b.get("a"), "remote batch starved by the preparation backlog").toEqual(
    a.get("a"),
  );
  expect(
    unpreparedBatches(b),
    "the backlog was not a real backlog",
  ).toBeGreaterThan(0);
  expect(report?.receipts.some((r) => r.phase === "import")).toBe(true);
});

// ===================================================================== 19, 21

async function fairnessFixture() {
  const net = network();
  const a = await publishedWriter(net, (d) => d.put("x".repeat(30000), "a"), {
    chunk: 500,
  });
  expect(outboxCount(a)).toBeGreaterThan(50);
  const c = await publishedWriter(net, (d) => d.put("from B", "b"));
  const b = transportDevice(net);
  return { net, a, c, b, writerA: writerOf(a) };
}

it("19 per-writer fairness: writer B's single batch imports within a bounded number of steps despite writer A's backlog, also after reopen", async () => {
  const { net, b } = await fairnessFixture();
  const units = 4;
  let i = 0;
  for (; i < 12 && b.get("b") === undefined; i++) {
    clock.advance(10_000);
    const gets = net.calls.gets.length;
    await step(b, { units });
    expect(
      net.calls.gets.length - gets,
      "downloads exceeded the step budget",
    ).toBeLessThanOrEqual(units);
    if (i === 1) b.reopen();
  }
  expect(b.get("b"), `B starved after ${i} steps`).toEqual({
    id: "b",
    text: "from B",
  });
});

it("21 repeated due failures of writer A cannot monopolize rounds: B is served, A keeps structured retry state", async () => {
  const { net, b, writerA } = await fairnessFixture();
  net.faults.get = (scope) =>
    isFrom(scope, writerA) ? new Error("blob store unavailable") : undefined;
  const units = 4;
  let i = 0;
  for (; i < 12 && b.get("b") === undefined; i++) {
    clock.advance(10_000); // A's failed rows are due again every round
    await step(b, { units });
    if (i === 3) b.reopen();
  }
  expect(b.get("b"), `B starved after ${i} steps`).toEqual({
    id: "b",
    text: "from B",
  });
  const aRows = records(b, INBOX).filter((r) => isFrom(r.id, writerA));
  const failed = aRows.filter((r) => r.outcome === "retry");
  expect(failed.length).toBeGreaterThan(0);
  for (const row of failed) {
    expect(row.reason).toBe("download_failed");
    expect(row.cause).toMatchObject({ name: "Error" });
    expect(row.attempts).toBeGreaterThanOrEqual(1);
    expect(row.nextEligible).toBeGreaterThan(0);
  }
  expect(b.get("a")).toBeUndefined();
});

// ========================================================================= 20

it("20 parked finality waits are filtered before the runnable quota: a due item progresses with phase quota 1 and parked items are not charged", async () => {
  const net = network();
  const hold = { on: true };
  holdPending(net, () => hold.on);
  net.port.list = async () => ({ scopes: [], cursor: null }); // the writer must not read itself
  const a = transportDevice(net, {
    preexisting: "x".repeat(60000),
    chunk: 500,
    worker: { quantum: { publish: 1 } },
  });
  await stepUntil(
    a,
    () => outboxCount(a) > 0 && net.head.size === outboxCount(a),
    20,
  );
  const parked = outboxScopes(a);
  expect(parked.length).toBeGreaterThanOrEqual(100);
  expect(
    num(
      a,
      "SELECT count(*) AS n FROM pdpp_transport_outbox WHERE state='ready'",
    ),
  ).toBe(parked.length);
  const parkedReads = () =>
    net.calls.evidence.filter((s) => parked.includes(s)).length;
  const readsBefore = parkedReads();

  hold.on = false;
  a.put("fresh", "f");
  for (let i = 0; i < 12; i++) {
    clock.advance(10);
    await step(a, { units: 3 });
  }
  const fresh = outboxScopes(a).filter((s) => !parked.includes(s));
  expect(fresh.length, "the due item never reached the outbox").toBeGreaterThan(
    0,
  );
  expect(
    num(
      a,
      `SELECT count(*) AS n FROM pdpp_transport_outbox WHERE state='published'`,
    ),
    "the due item was not published",
  ).toBe(fresh.length);
  expect(parkedReads(), "parked waits were re-read").toBe(readsBefore);
  const parkedRows = records(a, OUTBOX).filter((r) => parked.includes(r.id));
  expect(parkedRows).toHaveLength(parked.length);
  for (const row of parkedRows) {
    expect(row.attempts).toBe(0);
    expect(row.outcome).toBe("wait");
    expect(row.dependency).toBe(`finality:${row.id}`);
  }
});

// ========================================================================= 22

const SNAPSHOT_TABLES = [
  "pdpp_transport_state",
  "pdpp_transport_batches",
  "pdpp_transport_outbox",
  "pdpp_transport_inbox",
  "pdpp_transport_imported",
  "pdpp_transport_import_work",
  "pdpp_transport_preparing",
  "pdpp_binary_manifests",
  "pdpp_binary_chunks",
  "pdpp_replica_operations",
  "pdpp_replica_received",
  "pdpp_record_changes",
];
const netCounts = (net: Network) => ({
  puts: net.calls.puts.length,
  gets: net.calls.gets.length,
  registrations: net.calls.registrations.length,
  evidence: net.calls.evidence.length,
  lists: net.calls.lists,
  encrypts: net.calls.encrypts,
});

it("22a zero-unit step on a device with local work performs no evidence/put/get/encrypt call, changes nothing durable, and reports nextWake = now", async () => {
  const net = network();
  const a = transportDevice(net);
  await step(a); // initialize writer state
  a.put("more local work", "b");
  const before = durableSnapshot(a.db, SNAPSHOT_TABLES);
  const counts = netCounts(net);
  const report = await step(a, { units: 0 });
  expect(netCounts(net)).toEqual(counts);
  expect(durableSnapshot(a.db, SNAPSHOT_TABLES)).toEqual(before);
  expect(report, "step returned no report").toBeDefined();
  expect(report?.nextWake).toBe(clock.now());
});

it("22b zero-unit step on a device with remote work performs no network call, changes nothing durable, and reports nextWake = now", async () => {
  const net = network();
  const a = await publishedWriter(net, (d) => d.put("remote", "a"));
  const b = transportDevice(net);
  await step(b, { units: 0 }); // must not even initialize anything
  const before = durableSnapshot(b.db, SNAPSHOT_TABLES);
  const counts = netCounts(net);
  const report = await step(b, { units: 0 });
  expect(netCounts(net)).toEqual(counts);
  expect(durableSnapshot(b.db, SNAPSHOT_TABLES)).toEqual(before);
  expect(report, "step returned no report").toBeDefined();
  expect(report?.nextWake).toBe(clock.now());
  expect(a.get("a")).toBeDefined();
});

// ========================================================================= 23

it("23 a unit larger than budget.bytes is deferred: nothing is uploaded, no partial receipt, and a sufficient budget later completes it", async () => {
  const net = network();
  const a = transportDevice(net, {
    preexisting: "x".repeat(20000),
    chunk: 2000,
  });
  const report = await step(a, { units: 50, bytes: 300 });
  expect(report, "step returned no report").toBeDefined();
  expect(net.calls.puts).toHaveLength(0);
  expect(net.calls.registrations).toHaveLength(0);
  expect(report?.receipts.filter((r) => r.phase === "publish")).toEqual([]);
  expect(transportInvariantViolations(a)).toEqual([]);
  expect(
    num(
      a,
      "SELECT count(*) AS n FROM pdpp_transport_batches WHERE prepared=-1",
    ),
  ).toBe(0);
  // Resumable: a sufficient budget completes the same work, no truncation.
  await stepUntil(
    a,
    () => outboxCount(a) > 0 && unpublished(a) === 0,
    12,
    10_000,
    {
      units: 50,
      bytes: 10_000_000,
    },
  );
  expect(net.calls.puts).toHaveLength(outboxCount(a));
  expect(transportInvariantViolations(a)).toEqual([]);
});

// ========================================================================= 24

it("24 a publication whose put never resolves becomes Retry(deadline_exceeded); unrelated import progresses; the stalled publication is never reported published", async () => {
  const net = network();
  const r = await publishedWriter(net, (d) => d.put("remote", "r"));
  const d = transportDevice(net, { worker: { deadlineMs: 50 } });
  d.put("stalled", "l");
  const put = net.port.put;
  net.port.put = (part) => {
    const stalled = isFrom(part.scope, writerOf(d));
    return stalled ? new Promise<never>(() => undefined) : put(part);
  };
  const reports: (ProgressReport | undefined)[] = [];
  for (let i = 0; i < 12 && d.get("r") === undefined; i++) {
    clock.advance(10);
    reports.push(
      await within(
        3000,
        step(d, { units: 20 }),
        "step with a never-resolving put",
      ),
    );
  }
  expect(d.get("r")).toEqual(r.get("r"));
  const stalledRows = records(d, OUTBOX);
  expect(stalledRows.length).toBeGreaterThan(0);
  for (const row of stalledRows) {
    expect(row).toMatchObject({
      outcome: "retry",
      reason: "deadline_exceeded",
      attempts: 1,
    });
  }
  expect(unpublished(d)).toBe(outboxCount(d));
  expect(
    reports
      .flatMap((x) => x?.problems ?? [])
      .some((p) => p.phase === "publish" && p.problem === "deadline_exceeded"),
  ).toBe(true);
  expect(
    reports
      .flatMap((x) => x?.receipts ?? [])
      .filter((x) => x.phase === "publish"),
  ).toEqual([]);
  expect(net.head.size).toBe(outboxCount(r));
});

// ========================================================================= 25

it("25 host cancellation mid-step leaves only committed state; the cancelled run cannot overwrite it later; resume reuses the same bytes", async () => {
  const net = network();
  const a = transportDevice(net, { preexisting: "abort me" });
  let release!: () => void;
  const gate = new Promise<void>((resolve) => (release = resolve));
  let started = false;
  const put = net.port.put;
  net.port.put = async (part) => {
    started = true;
    await gate;
    return put(part);
  };
  const stepper = (a.worker as Steppable).step;
  expect(typeof stepper, "worker.step is missing").toBe("function");
  const controller = new AbortController();
  const running = stepper!
    .call(a.worker, { budget: { units: 50 }, signal: controller.signal })
    .then(
      (report) => ({ report }),
      (error: unknown) => ({ error }),
    );
  await waitFor(() => started, 3000, "the publish call to start");
  controller.abort();
  await within(3000, running, "aborted step");

  const tables = [
    "pdpp_transport_batches",
    "pdpp_transport_outbox",
    "pdpp_transport_state",
  ];
  const frozen = durableSnapshot(a.db, tables);
  expect(transportInvariantViolations(a)).toEqual([]);
  expect(unpublished(a)).toBe(outboxCount(a));
  expect(
    workRecords(a.db).every(
      (r) => r.outcome !== "quarantine" && r.outcome !== "unsupported",
    ),
  ).toBe(true);
  expect(
    num(
      a,
      "SELECT count(*) AS n FROM pdpp_transport_batches WHERE prepared=-1",
    ),
  ).toBe(0);
  const bytes = a.db
    .prepare("SELECT scope,encrypted FROM pdpp_transport_outbox ORDER BY rowid")
    .all();
  expect(bytes.length).toBeGreaterThan(0);

  release(); // the cancelled call finally returns
  await sleep(50);
  expect(
    durableSnapshot(a.db, tables),
    "a cancelled run overwrote state",
  ).toEqual(frozen);

  a.reopen();
  net.port.put = put;
  await stepUntil(a, () => unpublished(a) === 0, 6, 10_000);
  expect(
    a.db
      .prepare(
        "SELECT scope,encrypted FROM pdpp_transport_outbox ORDER BY rowid",
      )
      .all(),
  ).toEqual(bytes);
});

// ================================================================== 26, 27, 28

it("26 dependency events wake only matching waits: unrelated and duplicate events change nothing, a matching event re-evaluates the wait", async () => {
  const fx = await twoBatchRemote();
  const tally = newTally();
  instrument(fx.b, tally);
  await fx.start();
  const rows = () => importWorkFor(fx.b, fx.second);
  const dependency = `predecessor:${fx.writer}:1`;
  expect(rows()).toHaveLength(1);
  expect(rows()[0]).toMatchObject({
    writer: fx.writer,
    outcome: "wait",
    dependency,
    attempts: 0,
    next_attempt: clock.now() + FALLBACK,
  });
  const initial = rows();
  const staged = tally.stage.length;

  const unrelated = [
    `declaration:${sourceId}:messages`,
    `declaration:${sourceId}:messages`, // duplicate
    `declaration:${sourceId}:other`,
    "mapping:other",
    "blob:unrelated",
    "finality:pdpp_replica_v1.nobody_nothing.0",
    `predecessor:${fx.writer}:7`,
  ];
  for (const key of unrelated) wake(fx.b, key);
  clock.advance(1000);
  await steps(fx.b, 2, 0);
  expect(rows(), "an unrelated event changed the wait").toEqual(initial);
  expect(tally.stage.length, "an unrelated event re-evaluated the wait").toBe(
    staged,
  );

  // The matching event makes it due now. The predecessor is still absent:
  // it re-evaluates and Waits again from the new time.
  wake(fx.b, dependency);
  wake(fx.b, dependency);
  clock.advance(1000);
  await steps(fx.b, 2, 0);
  expect(rows()).toHaveLength(1);
  expect(rows()[0]).toMatchObject({
    outcome: "wait",
    dependency,
    attempts: 0,
    next_attempt: clock.now() + FALLBACK,
  });

  // Once the predecessor is reachable everything converges with no further event.
  fx.reveal();
  for (let i = 0; i < 30 && !both(fx.b); i++) {
    clock.advance(5000);
    await step(fx.b);
  }
  expect(both(fx.b)).toBe(true);
  expect(importedReceipts(fx.b)).toBe(2);
});

it("27a a notification delivered before the wait is registered is not lost: the wait becomes eligible within the bounded fallback", async () => {
  const fx = await twoBatchRemote();
  const tally = newTally();
  let fired = false;
  instrument(fx.b, tally, {
    // Fires while the successor is being evaluated, before its Wait can commit.
    beforeStage: ({ batch }) => {
      if (fired || batch !== fx.second) return;
      fired = true;
      fx.reveal();
      notify(fx.b, `predecessor:${fx.writer}:1`);
    },
  });
  await fx.start();
  for (let i = 0; i < 20 && !both(fx.b); i++) {
    clock.advance(5000); // <= 100 s, no further event of any kind
    await step(fx.b);
  }
  expect(both(fx.b), "wait lost the notification").toBe(true);
  expect(importedReceipts(fx.b)).toBe(2);
  expect(hasWake(fx.b), "worker.onDependencyChanged is missing").toBe(true);
});

/** Importer whose connection mapping is missing; the batch is retained and hidden. */
async function mappingFixture(crash?: CrashController) {
  const net = network();
  const a = await publishedWriter(net, (d) => d.put("needs mapping", "a"));
  const b = transportDevice(net, { crash });
  b.db.prepare("DELETE FROM pdpp_instance_binding WHERE instance='conn'").run();
  const reports = await steps(b, 4, 0);
  expect(b.get("a")).toBeUndefined();
  expect(
    importedReceipts(b),
    "custody is retained and receipted",
  ).toBeGreaterThan(0);
  return { net, a, b, reports };
}
const provision = (b: TransportDevice) =>
  b.store.registerConnection({
    instance: "conn",
    sourceId,
    method: "export",
    label: "C",
  });

it("27b a missing local mapping is reported as Wait(mapping), not as a failure", async () => {
  const { b, reports } = await mappingFixture();
  const waits = reports.flatMap((r) => r?.waits ?? []);
  expect(
    waits.some(
      (w) => w.dependency.kind === "mapping" && w.dependency.key === "conn",
    ),
    "no mapping wait was reported",
  ).toBe(true);
  expect(reports.flatMap((r) => r?.problems ?? [])).toEqual([]);
  expect(workRecords(b.db).every((r) => r.outcome !== "retry")).toBe(true);
});

it("27c mapping provisioned with no notification: the wait wakes within the bounded fallback", async () => {
  const { a, b } = await mappingFixture();
  b.reopen();
  provision(b);
  for (let i = 0; i < 24 && b.get("a") === undefined; i++) {
    clock.advance(5000); // <= 120 s
    await step(b);
  }
  expect(b.get("a")).toEqual(a.get("a"));
  expect(journalOperations(b), "import echoed into the local journal").toBe(0);
});

it("27d mapping provisioned and announced: the wait is eligible on the very next step", async () => {
  const { a, b } = await mappingFixture();
  b.reopen();
  provision(b);
  wake(b, "mapping:conn");
  clock.advance(10); // far below any fallback
  await steps(b, 2, 0);
  expect(b.get("a")).toEqual(a.get("a"));
});

/** Runs the two-batch scenario, optionally dying at one durable-write point. */
async function crashAfterPredecessorCommit(crashAt: number | undefined) {
  const crash = new CrashController();
  const fx = await twoBatchRemote({ crash });
  await fx.start();
  fx.reveal();
  crash.arm(crashAt);
  for (let i = 0; i < 12 && !crash.dead; i++) {
    clock.advance(10);
    await fx.b.step({ units: 50 }).catch(() => undefined);
  }
  return { fx, crash };
}

it("28a process death between the predecessor's commit and the successor's notification: reopen reconstructs the wake, one logical import each, no echo", async () => {
  // Rehearsal: enumerate the real write trace and complete the run for the control counts.
  const rehearsal = await crashAfterPredecessorCommit(undefined);
  for (let i = 0; i < 20 && !both(rehearsal.fx.b); i++) {
    clock.advance(5000);
    await step(rehearsal.fx.b);
  }
  expect(both(rehearsal.fx.b)).toBe(true);
  const control = {
    imported: importedReceipts(rehearsal.fx.b),
    changes: recordChanges(rehearsal.fx.b),
    journal: journalOperations(rehearsal.fx.b),
  };
  const trace = rehearsal.crash.trace;
  const insert = trace.findIndex((l) =>
    l.startsWith("after-insert:pdpp_transport_imported"),
  );
  expect(
    insert,
    "no import acknowledgement in the trace",
  ).toBeGreaterThanOrEqual(0);
  const commit = trace.findIndex((l, i) => i > insert && l === "commit");
  expect(commit).toBeGreaterThan(insert);
  rehearsal.fx.b.close();

  // Real run: the process dies right after the predecessor's import commit.
  const { fx, crash } = await crashAfterPredecessorCommit(commit);
  expect(crash.dead, "the crash point was never reached").toBe(true);
  fx.b.crashReopen();
  expect(importedReceipts(fx.b)).toBe(1); // exactly the committed predecessor
  expect(fx.b.get("a")).toBeDefined();
  for (let i = 0; i < 14 && !both(fx.b); i++) {
    clock.advance(5000); // no event is ever delivered: <= 70 s
    await step(fx.b);
  }
  expect(both(fx.b), "the successor's wake was lost with the process").toBe(
    true,
  );
  expect({
    imported: importedReceipts(fx.b),
    changes: recordChanges(fx.b),
    journal: journalOperations(fx.b),
  }).toEqual(control);
  expect(transportInvariantViolations(fx.b)).toEqual([]);
});

it("28b process death after the mapping commit, before any notification: the wait wakes by durable reconstruction", async () => {
  const crash = new CrashController();
  const { a, b } = await mappingFixture(crash);
  provision(b); // the dependency commit
  b.crashReopen(); // dies before the notification could be delivered
  for (let i = 0; i < 14 && b.get("a") === undefined; i++) {
    clock.advance(5000); // <= 70 s
    await step(b);
  }
  expect(b.get("a")).toEqual(a.get("a"));
  expect(journalOperations(b)).toBe(0);
});

// ========================================================================= 29

it("29 a wake flood on one shared declaration is bounded per step and every wait is eventually served", async () => {
  const net = network();
  const a = transportDevice(net, { pageSize: 1 });
  const total = 24;
  for (let i = 0; i < total; i++) a.put(`record ${i}`, `r${i}`);
  await stepUntil(
    a,
    () =>
      batchCount(a) >= total &&
      unpreparedBatches(a) === 0 &&
      unpublished(a) === 0,
    80,
    10_000,
  );
  const b = transportDevice(net);
  b.declarations([]); // no trusted declaration yet: nothing can materialize
  const tally = newTally();
  instrument(b, tally);
  await stepUntil(b, () => retained(b) >= total, 20, 10_000);
  expect(b.get("r0")).toBeUndefined();

  b.declarations(expected.declarations);
  for (let i = 0; i < 100; i++) notify(b, `declaration:${sourceId}:messages`);
  const units = 5;
  let rounds = 0;
  for (; rounds < 40 && importedReceipts(b) < total; rounds++) {
    clock.advance(10_000);
    const promoted = tally.promote.length;
    await step(b, { units });
    expect(
      tally.promote.length - promoted,
      `step ${rounds} imported more than its ${units} units`,
    ).toBeLessThanOrEqual(units);
  }
  expect(importedReceipts(b)).toBe(total);
  expect(b.get(`r${total - 1}`)).toBeDefined();
  expect(hasWake(b), "worker.onDependencyChanged is missing").toBe(true);
});

// ========================================================================== 30

it("30 finality hints are not evidence: verified height is monotone from verified reads only, a cooldown bounds checks, hidden until confirmed", async () => {
  const net = network();
  net.port.finality = { head: async () => 1000n };
  holdPending(net);
  const a = transportDevice(net, { preexisting: "pending" });
  await steps(a, 4, 0);
  const scope = [...net.head.keys()][0]!;
  expect(net.head.size).toBe(1);
  const verified = verifiedHeight(net, 123n);
  const b = transportDevice(net);
  await steps(b, 4, 0);
  expect(record(b, INBOX, scope)).toMatchObject({
    outcome: "wait",
    dependency: `finality:${scope}`,
    attempts: 0,
    checkedBlock: "123",
  });

  // First poll after the park sees an unchanged verified height: cooldown.
  await steps(b, 1, 2000);
  const afterPoll = evidenceReads(net, scope);
  const cooled = record(b, INBOX, scope)!;
  expect(cooled.nextEligible).toBe(clock.now() + 30_000);
  await steps(b, 13, 2000); // 26 s of an unchanged verified height and a very high hint
  expect(evidenceReads(net, scope)).toBe(afterPoll);
  expect(record(b, INBOX, scope)).toMatchObject({
    outcome: "wait",
    attempts: 0,
    checkedBlock: "123",
  });
  expect(b.get("a")).toBeUndefined();

  b.reopen();
  verified.height = 124n;
  clock.advance(cooled.nextEligible! - clock.now());
  await steps(b, 2, 0);
  expect(evidenceReads(net, scope)).toBeGreaterThan(afterPoll);
  expect(record(b, INBOX, scope)).toMatchObject({
    outcome: "wait",
    checkedBlock: "124",
  });

  verified.height = 120n; // a regressing read never lowers the verified height
  clock.advance(30_000);
  await steps(b, 2, 0);
  expect(record(b, INBOX, scope)).toMatchObject({ checkedBlock: "124" });
  expect(b.get("a")).toBeUndefined();
});

// ====================================================================== 30/32

/**
 * A finality Wait at verified height 123, then an RPC error (Retry, deadline
 * t + B(1)), then a very high finalized hint. Nothing may read evidence for the
 * scope before the deadline; the verified height is never replaced by the hint.
 */
async function retryIsNotBypassedByHint(kind: "publish" | "confirm") {
  const net = network();
  holdPending(net);
  let actor: TransportDevice;
  let table: string;
  if (kind === "publish") {
    net.port.list = async () => ({ scopes: [], cursor: null }); // no own inbox
    actor = transportDevice(net, { preexisting: "retry me" });
    await steps(actor, 4, 0);
    table = OUTBOX;
  } else {
    const writer = transportDevice(net, { preexisting: "retry me" });
    await steps(writer, 4, 0);
    actor = transportDevice(net);
    await steps(actor, 4, 0);
    table = INBOX;
  }
  expect(net.head.size).toBe(1);
  const scope = [...net.head.keys()][0]!;
  expect(record(actor, table, scope)).toMatchObject({
    outcome: "wait",
    attempts: 0,
    checkedBlock: "123",
  });

  // The RPC fails once the wait is due: Retry with deadline t + B(1).
  net.faults.evidence = (s) =>
    s === scope ? new Error("RPC unavailable") : undefined;
  clock.advance(2000);
  await steps(actor, 2, 0);
  const failedAt = clock.now();
  expect(record(actor, table, scope)).toMatchObject({
    outcome: "retry",
    attempts: 1,
    nextEligible: failedAt + B1,
    checkedBlock: "123", // provenance kept; never replaced by a hint
  });

  // The RPC recovers; a very high finalized hint and wakes arrive before the deadline.
  net.faults.evidence = undefined;
  net.port.finality = { head: async () => 10_000n };
  const reads = evidenceReads(net, scope);
  for (let i = 0; i < 8; i++) {
    clock.advance(100);
    notify(actor, `finality:${scope}`);
    await step(actor);
  }
  expect(evidenceReads(net, scope), "a hint bypassed the Retry deadline").toBe(
    reads,
  );
  expect(record(actor, table, scope)).toMatchObject({
    outcome: "retry",
    attempts: 1,
    nextEligible: failedAt + B1,
    checkedBlock: "123",
  });
  actor.reopen();
  clock.advance(100);
  await step(actor);
  expect(evidenceReads(net, scope)).toBe(reads);
  expect(record(actor, table, scope)).toMatchObject({
    outcome: "retry",
    nextEligible: failedAt + B1,
    checkedBlock: "123",
  });
  expect(hasWake(actor), "worker.onDependencyChanged is missing").toBe(true);

  // At the deadline the evidence is read again, and its verified height wins.
  clock.advance(failedAt + B1 - clock.now());
  await steps(actor, 2, 0);
  expect(evidenceReads(net, scope)).toBeGreaterThan(reads);
  expect(record(actor, table, scope)).toMatchObject({
    outcome: "wait",
    attempts: 0,
    checkedBlock: "123",
  });
}

it("32a hint never bypasses a Retry deadline in the publish (outbox) phase; verified checked_block is never replaced by the hint", () =>
  retryIsNotBypassedByHint("publish"));

it("32b hint never bypasses a Retry deadline in the confirm (retained inbox) phase; verified checked_block is never replaced by the hint", () =>
  retryIsNotBypassedByHint("confirm"));

// ========================================================================== 31

/** A: pending fragments (finality Wait). B: finalized batch. Y: local data. */
async function mixedFixture() {
  const net = network();
  const a = transportDevice(net);
  a.put("from A", "a");
  holdPending(net, (scope) => isFrom(scope, writerOf(a)));
  await steps(a, 4, 0);
  const c = transportDevice(net);
  c.put("from B", "b");
  await steps(c, 4, 0);
  const d = transportDevice(net);
  d.put("local Y", "y");
  return { net, a, c, d, writerA: writerOf(a) };
}

it("31a finality waits for A cannot block B's import or Y's preparation", async () => {
  const { net, d, writerA } = await mixedFixture();
  await steps(d, 8, 0);
  expect(d.get("b"), "B's batch was blocked by A's waits").toEqual({
    id: "b",
    text: "from B",
  });
  expect(outboxCount(d), "Y was never prepared").toBeGreaterThan(0);
  expect(unpublished(d), "Y was never published").toBe(0);
  const aRows = records(d, INBOX).filter((r) => isFrom(r.id, writerA));
  expect(aRows.length).toBeGreaterThan(0);
  for (const row of aRows) {
    expect(row).toMatchObject({
      outcome: "wait",
      dependency: `finality:${row.id}`,
      attempts: 0,
    });
  }
  const reads = () =>
    net.calls.evidence.filter((s) => isFrom(s, writerA)).length;
  const base = reads();
  await steps(d, 3, 100);
  expect(reads(), "parked A waits were re-read").toBe(base);
  expect(d.get("a")).toBeUndefined();
});

it("31b report.nextWake is the minimum relevant deadline, not A's wait deadline alone", async () => {
  const { net, d, writerA } = await mixedFixture();
  // Y's preparation fails with a shorter deadline than A's 2 s finality poll.
  net.faults.encrypt = (scope) =>
    isFrom(scope, writerOf(d)) ? new Error("encryption down") : undefined;
  await steps(d, 8, 0);
  const report = await step(d);
  const yBatch = records(d, BATCHES);
  expect(yBatch.length).toBeGreaterThan(0);
  expect(yBatch.every((r) => r.outcome === "retry" && r.attempts === 1)).toBe(
    true,
  );
  const tY = minDeadline(yBatch);
  const tA = minDeadline(
    records(d, INBOX).filter((r) => isFrom(r.id, writerA)),
  );
  expect(tY).toBe(clock.now() + B1);
  expect(tY).toBeLessThan(tA);
  expect(d.get("b")).toBeDefined(); // B is independent of both
  expect(report, "step returned no report").toBeDefined();
  expect(report?.nextWake).toBeDefined();
  expect(report!.nextWake!).toBeGreaterThanOrEqual(clock.now());
  expect(report!.nextWake!).toBeLessThanOrEqual(tY);
});

// ========================================================================== 33

it("33 a temporarily inactive registration is a Wait, not a conflict: no quarantine, no re-upload, and progress after reactivation", async () => {
  const net = network();
  const a = transportDevice(net, { preexisting: "retained" });
  net.faults.loseRegistrationResponse = true;
  await steps(a, 4, 0);
  expect(net.head.size).toBe(1);
  const scope = [...net.head.keys()][0]!;
  net.chain.set(scope, { ...net.chain.get(scope)!, status: "Unavailable" });
  const puts = net.calls.puts.filter((s) => s === scope).length;
  const b = transportDevice(net);
  for (let i = 0; i < 3; i++) {
    clock.advance(10_000);
    await step(a);
    await step(b);
  }
  expect(record(a, OUTBOX, scope)).toMatchObject({
    outcome: "wait",
    attempts: 0,
  });
  expect(record(b, INBOX, scope)).toMatchObject({
    outcome: "wait",
    attempts: 0,
  });
  expect(
    [...records(a, OUTBOX), ...records(b, INBOX)].every(
      (r) => r.outcome !== "quarantine" && r.outcome !== "retry",
    ),
  ).toBe(true);
  expect(
    num(
      b,
      "SELECT count(*) AS n FROM pdpp_transport_inbox WHERE state='quarantined'",
    ),
  ).toBe(0);
  expect(
    num(
      a,
      "SELECT count(*) AS n FROM pdpp_transport_outbox WHERE state='quarantined'",
    ),
  ).toBe(0);
  expect(net.calls.puts.filter((s) => s === scope)).toHaveLength(puts);
  expect(b.get("a")).toBeUndefined();

  net.chain.set(scope, { ...net.chain.get(scope)!, status: "Active" });
  for (let i = 0; i < 4; i++) {
    clock.advance(10_000);
    await step(a);
    await step(b);
  }
  expect(unpublished(a)).toBe(0);
  expect(b.get("a")).toEqual(a.get("a"));
  expect(net.calls.puts.filter((s) => s === scope)).toHaveLength(puts);
});

// ========================================================================== 34

/** Evidence port that reports an immutable-registration conflict for chosen scopes. */
function conflictOn(
  net: Network,
  which: (scope: string, first: string) => boolean,
) {
  let first: string | undefined;
  const evidence = net.port.evidence;
  net.port.evidence = async (scope) => {
    first ??= scope;
    const e = await evidence(scope);
    return which(scope, first)
      ? {
          ...e,
          chain: e.chain && {
            ...e.chain,
            currentVersion: "9",
            status: "Active" as const,
          },
        }
      : e;
  };
  return {
    conflicting: (scope: string) => first !== undefined && which(scope, first),
  };
}

it("34a report.nextWake comes from durable state: terminal work contributes nothing, and a reopened worker computes the same value", async () => {
  const net = network();
  const conflict = conflictOn(net, (scope, first) => scope === first);
  holdPending(net, (scope) => !conflict.conflicting(scope));
  net.port.list = async () => ({ scopes: [], cursor: null }); // keep the inbox out of it
  const a = transportDevice(net, { preexisting: "x".repeat(3000), chunk: 600 });
  const early = await steps(a, 6, 0);
  const rows = records(a, OUTBOX);
  expect(rows.length).toBeGreaterThan(2);
  const terminal = rows.filter((r) => r.outcome === "quarantine");
  const waiting = rows.filter((r) => r.outcome === "wait");
  expect(terminal, "the conflicting fragment is not terminal").toHaveLength(1);
  expect(waiting.length).toBe(rows.length - 1);
  const report = await step(a);
  expect(report, "step returned no report").toBeDefined();
  expect(report?.nextWake).toBe(minDeadline(waiting));
  expect(early.flatMap((r) => r?.quarantines ?? []).map((q) => q.id)).toEqual(
    terminal.map((r) => r.id),
  );

  a.reopen();
  const reopened = await step(a, { units: 0 });
  expect(reopened?.nextWake).toBe(report?.nextWake);
});

it("34b a device whose only work is terminal is idle: nextWake is undefined before and after reopen", async () => {
  const net = network();
  conflictOn(net, () => true);
  net.port.list = async () => ({ scopes: [], cursor: null });
  const a = transportDevice(net, { preexisting: "terminal" });
  await steps(a, 4, 0);
  const rows = records(a, OUTBOX);
  expect(rows).toHaveLength(1);
  expect(rows[0]?.outcome).toBe("quarantine");
  const report = await step(a);
  expect(report, "step returned no report").toBeDefined();
  expect(report?.nextWake).toBeUndefined();
  a.reopen();
  const reopened = await step(a, { units: 0 });
  expect(reopened, "step returned no report").toBeDefined();
  expect(reopened?.nextWake).toBeUndefined();
});
