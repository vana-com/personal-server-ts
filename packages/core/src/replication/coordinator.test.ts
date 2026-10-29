import { describe, expect, it } from "vitest";
import type {
  ProgressReport,
  ReplicaPhaseHandler,
  ReplicaWorkItem,
} from "./coordinator.js";
import { createReplicaCoordinator, REPLICA_STEP_BYTES } from "./coordinator.js";
import type {
  ReplicaDependency,
  ReplicaOutcome,
  ReplicaPhase,
  ReplicaPhaseOutcome,
} from "./outcome.js";
import {
  ReplicaFramingUnsupported,
  dependencyKey,
  replicaCause,
} from "./outcome.js";
import type { ReplicaBackoff, ReplicaWorkState } from "./schedule.js";
import {
  defaultReplicaBackoff,
  initialReplicaWorkState,
  settleReplicaWork,
} from "./schedule.js";

// ---------------------------------------------------------------------------
// Fixtures: fake clock values, injected backoffs, seeded PRNG
// ---------------------------------------------------------------------------

const T0 = 1_700_000_000_000;
const SECRET = "sk-live-SECRET-0123456789";
const expBackoff: ReplicaBackoff = (a) => 1000 * 2 ** (a - 1);
const sevenBackoff: ReplicaBackoff = (a) => a * 7;
const MAX_DATE_MS = 8.64e15;

function mulberry32(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

/** A run that never settles by itself but honours the abort signal. */
function untilAbort(signal: AbortSignal): Promise<never> {
  return new Promise<never>((_, reject) => {
    const abort = () => reject(new DOMException("aborted", "AbortError"));
    if (signal.aborted) abort();
    else signal.addEventListener("abort", abort, { once: true });
  });
}

// ---------------------------------------------------------------------------
// Fake in-memory phase handlers. `rows` is the durable store: rebuilding the
// coordinator from the same World is a process restart.
// ---------------------------------------------------------------------------

interface Row {
  id: string;
  phase: ReplicaPhase;
  writer: string;
  bytes?: number;
  state: ReplicaWorkState;
  done: boolean;
  terminal: "quarantine" | "unsupported" | null;
  lastOutcome: ReplicaOutcome | null;
  dependency: string | null;
}
interface SettleCall {
  id: string;
  phase: ReplicaPhase;
  at: number;
  outcome: ReplicaOutcome;
  state: ReplicaWorkState;
}
type Act =
  | ReplicaPhaseOutcome
  | Error
  | ((
      item: ReplicaWorkItem,
      signal: AbortSignal,
    ) => Promise<ReplicaPhaseOutcome>);
interface World {
  rows: Map<string, Row>;
  script: Map<string, Act[]>;
  runs: { id: string; phase: ReplicaPhase; at: number }[];
  events: string[];
  settles: SettleCall[];
  dueCalls: {
    phase: ReplicaPhase;
    now: number;
    total: number;
    perWriter: number;
  }[];
  wakeCalls: { phase: ReplicaPhase; key: string; now: number }[];
  failSettleOnce: Set<string>;
  noWake: Set<ReplicaPhase>;
  onSettle?: (call: SettleCall, world: World) => void;
  clock: { now: number };
}

function newWorld(): World {
  return {
    rows: new Map(),
    script: new Map(),
    runs: [],
    events: [],
    settles: [],
    dueCalls: [],
    wakeCalls: [],
    failSettleOnce: new Set(),
    noWake: new Set(),
    clock: { now: T0 },
  };
}

function addRow(
  world: World,
  id: string,
  phase: ReplicaPhase,
  writer: string,
  patch: { state?: Partial<ReplicaWorkState>; bytes?: number } = {},
): Row {
  const row: Row = {
    id,
    phase,
    writer,
    ...(patch.bytes === undefined ? {} : { bytes: patch.bytes }),
    state: { ...initialReplicaWorkState, ...patch.state },
    done: false,
    terminal: null,
    lastOutcome: null,
    dependency: null,
  };
  world.rows.set(id, row);
  return row;
}

function parkAsWait(
  world: World,
  id: string,
  dependency: ReplicaDependency,
  nextEligible: number,
) {
  const row = world.rows.get(id);
  if (!row) throw new Error(`no row ${id}`);
  row.state = { attempts: 0, nextEligible, waitSince: T0, checkedBlock: null };
  row.lastOutcome = { tag: "wait", dependency };
  row.dependency = dependencyKey(dependency);
}

function script(world: World, id: string, ...acts: Act[]) {
  world.script.set(id, acts);
}

function row(world: World, id: string): Row {
  const found = world.rows.get(id);
  if (!found) throw new Error(`no row ${id}`);
  return found;
}

/** A hint source that is configured but never knows a head. */
const silentHint = {
  head: () => Promise.reject(new Error("no finalized head")),
};

function handlerFor(world: World, phase: ReplicaPhase): ReplicaPhaseHandler {
  const mine = () => [...world.rows.values()].filter((r) => r.phase === phase);
  const handler: ReplicaPhaseHandler = {
    phase,
    // Due is a function of durable SCHEDULE STATE only (like next_attempt in
    // SQL): a terminal item is never due because the coordinator stored a
    // state that is never due, not because this fake special-cases it.
    due({ now }, limit) {
      world.dueCalls.push({ phase, now, ...limit });
      const sorted = mine()
        .filter((r) => !r.done && r.state.nextEligible <= now)
        .sort(
          (a, b) =>
            a.state.nextEligible - b.state.nextEligible ||
            (a.id < b.id ? -1 : a.id > b.id ? 1 : 0),
        );
      const perWriter = new Map<string, number>();
      const out: ReplicaWorkItem[] = [];
      for (const r of sorted) {
        if (out.length >= limit.total) break;
        const used = perWriter.get(r.writer) ?? 0;
        if (used >= limit.perWriter) continue;
        perWriter.set(r.writer, used + 1);
        out.push({
          id: r.id,
          phase: r.phase,
          writer: r.writer,
          state: structuredClone(r.state),
          ...(r.bytes === undefined ? {} : { bytes: r.bytes }),
        });
      }
      return out;
    },
    async run(item, signal) {
      world.runs.push({ id: item.id, phase, at: world.clock.now });
      world.events.push(`start:${item.id}`);
      const acts = world.script.get(item.id);
      const act = acts?.shift();
      try {
        if (act === undefined)
          return {
            outcome: { tag: "progress", receipt: { phase, key: item.id } },
          };
        if (act instanceof Error) throw act;
        if (typeof act === "function")
          return { outcome: await act(item, signal) };
        return { outcome: act };
      } finally {
        world.events.push(`end:${item.id}`);
      }
    },
    commit(item, attempt, settle) {
      world.events.push(`settle:${item.id}`);
      if (world.failSettleOnce.delete(item.id))
        throw new Error("simulated durable write failure");
      const { outcome, state } = settle(attempt.plan?.() ?? attempt.outcome);
      const target = row(world, item.id);
      const call: SettleCall = {
        id: item.id,
        phase,
        at: world.clock.now,
        outcome: structuredClone(outcome),
        state: structuredClone(state),
      };
      target.state = structuredClone(state);
      target.lastOutcome = structuredClone(outcome);
      if (outcome.tag === "progress") target.done = true;
      if (outcome.tag === "quarantine" || outcome.tag === "unsupported")
        target.terminal = outcome.tag;
      if (outcome.tag === "wait")
        target.dependency = dependencyKey(outcome.dependency);
      world.settles.push(call);
      world.onSettle?.(call, world);
      return outcome;
    },
    earliest() {
      let min: number | undefined;
      for (const r of mine()) {
        if (r.done || r.terminal) continue;
        if (min === undefined || r.state.nextEligible < min)
          min = r.state.nextEligible;
      }
      return min;
    },
  };
  if (world.noWake.has(phase)) return handler;
  return {
    ...handler,
    wake(key, now) {
      world.wakeCalls.push({ phase, key, now });
      let woken = 0;
      for (const r of mine()) {
        if (r.done || r.terminal) continue;
        if (r.lastOutcome?.tag !== "wait" || r.dependency !== key) continue;
        if (r.state.nextEligible > now) {
          r.state = { ...r.state, nextEligible: now };
          woken += 1;
        }
      }
      return woken;
    },
  };
}

type CoordinatorOptions = Omit<
  Parameters<typeof createReplicaCoordinator>[0],
  "phases"
> & { phases?: ReplicaPhase[] };

function build(world: World, options: CoordinatorOptions = {}) {
  const { phases, ...rest } = options;
  const order = phases ?? [
    ...new Set([...world.rows.values()].map((r) => r.phase)),
  ];
  return createReplicaCoordinator({
    phases: order.map((p) => handlerFor(world, p)),
    ...rest,
  });
}

type Coordinator = ReturnType<typeof build>;

function stepAt(
  world: World,
  co: Coordinator,
  now: number,
  budget: { units: number; bytes?: number } = { units: 1000 },
  signal?: AbortSignal,
): Promise<ProgressReport> {
  world.clock.now = now;
  return co.step({ now, signal, budget });
}

const runIds = (world: World) => world.runs.map((r) => r.id);
const runCount = (world: World, id: string) =>
  world.runs.filter((r) => r.id === id).length;
const retryOutcome = (
  problem:
    "publish_failed" | "download_failed" | "import_failed" = "publish_failed",
): ReplicaPhaseOutcome => ({ tag: "retry", problem });
const finalityWait = (
  checkedBlock: string,
  key = "scope-1",
): ReplicaPhaseOutcome => ({
  tag: "wait",
  dependency: { kind: "finality", key, checkedBlock },
});
const mappingWait = (key = "conn-1"): ReplicaPhaseOutcome => ({
  tag: "wait",
  dependency: { kind: "mapping", key },
});
const quarantineOutcome: ReplicaPhaseOutcome = {
  tag: "quarantine",
  proof: { reason: "immutable_registration_conflict", key: "scope-1:1" },
};
const unsupportedOutcome: ReplicaPhaseOutcome = {
  tag: "unsupported",
  admission: {
    reason: "replica_framing_unsupported",
    actual: 9,
    limit: 3,
    capability: "cap:3",
  },
};

const base: ReplicaWorkState = {
  attempts: 0,
  nextEligible: 0,
  waitSince: null,
  checkedBlock: null,
};

// ---------------------------------------------------------------------------
// Pure algebra: outcome.ts
// ---------------------------------------------------------------------------

describe("outcome.ts", () => {
  it("26 dependencyKey is `${kind}:${key}` and ignores the finality height", () => {
    expect(dependencyKey({ kind: "declaration", key: "src:stream" })).toBe(
      "declaration:src:stream",
    );
    expect(dependencyKey({ kind: "predecessor", key: "w:41" })).toBe(
      "predecessor:w:41",
    );
    expect(
      dependencyKey({ kind: "finality", key: "scope-1", checkedBlock: "10" }),
    ).toBe(
      dependencyKey({ kind: "finality", key: "scope-1", checkedBlock: "99" }),
    );
  });

  it("13 replicaCause of a RangeError with framing-imitating text is only its class name", () => {
    const cause = replicaCause(
      new RangeError(`encrypted fragment exceeds the cap ${SECRET}`),
    );
    expect(cause).toEqual({ name: "RangeError" });
    expect(JSON.stringify(cause)).not.toContain(SECRET);
    expect(JSON.stringify(cause)).not.toContain("exceeds");
  });

  it("14 replicaCause of a generic Error with imitation text is only its class name", () => {
    const cause = replicaCause(
      new Error(`replica framing unsupported: actual 9 limit 3 ${SECRET}`),
    );
    expect(cause).toEqual({ name: "Error" });
  });

  it("06 replicaCause keeps a string code and the nested cause chain as structure", () => {
    const inner = Object.assign(new TypeError(`socket ${SECRET}`), {
      code: "ECONNRESET",
    });
    const outer = new Error(`rpc failed ${SECRET}`, { cause: inner });
    const cause = replicaCause(outer);
    expect(cause).toEqual({
      name: "Error",
      cause: { name: "TypeError", code: "ECONNRESET" },
    });
    expect(JSON.stringify(cause)).not.toContain(SECRET);
  });

  it("06 replicaCause never reads .message", () => {
    let reads = 0;
    const error = new Error("seed");
    Object.defineProperty(error, "message", {
      get() {
        reads += 1;
        return SECRET;
      },
    });
    const cause = replicaCause(error);
    expect(reads).toBe(0);
    expect(JSON.stringify(cause)).not.toContain(SECRET);
  });

  it("06 replicaCause bounds a long chain to depth 4 and survives a cycle", () => {
    let chain: Error = new Error("leaf");
    for (let i = 0; i < 20; i += 1)
      chain = new Error(`link ${i}`, { cause: chain });
    const depth = (c: { cause?: unknown } | undefined): number =>
      c === undefined
        ? 0
        : 1 + depth(c.cause as { cause?: unknown } | undefined);
    expect(depth(replicaCause(chain))).toBeLessThanOrEqual(4);

    const loop = new Error("loop");
    (loop as Error & { cause?: unknown }).cause = loop;
    expect(depth(replicaCause(loop))).toBeLessThanOrEqual(4);
  });

  it("13 replicaCause of a non-Error throw never echoes the thrown value", () => {
    for (const thrown of [SECRET, { message: SECRET }, null, undefined, 42]) {
      const cause = replicaCause(thrown);
      expect(typeof cause.name).toBe("string");
      expect(JSON.stringify(cause)).not.toContain(SECRET);
    }
  });

  it("14 only ReplicaFramingUnsupported instances carry actual and limit", () => {
    const typed = new ReplicaFramingUnsupported(9, 3);
    expect(typed).toBeInstanceOf(Error);
    expect(typed).toBeInstanceOf(ReplicaFramingUnsupported);
    expect(typed.actual).toBe(9);
    expect(typed.limit).toBe(3);

    const imitation = Object.assign(
      new RangeError("encrypted fragment exceeds"),
      {
        actual: 9,
        limit: 3,
      },
    );
    expect(imitation).not.toBeInstanceOf(ReplicaFramingUnsupported);
    expect(new RangeError("x")).not.toBeInstanceOf(ReplicaFramingUnsupported);
    expect(new Error("x")).not.toBeInstanceOf(ReplicaFramingUnsupported);
    expect("actual" in new RangeError("x")).toBe(false);
    expect(replicaCause(typed)).toEqual({
      name: "ReplicaFramingUnsupported",
      code: "replica_framing_unsupported",
    });
  });
});

// ---------------------------------------------------------------------------
// Pure algebra: schedule.ts
// ---------------------------------------------------------------------------

describe("schedule.ts settleReplicaWork", () => {
  it("05 initial state is fresh and due at any real time", () => {
    expect(initialReplicaWorkState.attempts).toBe(0);
    expect(initialReplicaWorkState.waitSince).toBeNull();
    expect(initialReplicaWorkState.checkedBlock).toBeNull();
    expect(Number.isFinite(initialReplicaWorkState.nextEligible)).toBe(true);
    expect(initialReplicaWorkState.nextEligible).toBeLessThanOrEqual(T0);
  });

  it("06 default backoff doubles from one second and caps at 3_600_000", () => {
    expect([1, 2, 3, 4].map(defaultReplicaBackoff)).toEqual([
      1000, 2000, 4000, 8000,
    ]);
    expect(defaultReplicaBackoff(12)).toBe(2_048_000);
    expect(defaultReplicaBackoff(13)).toBe(3_600_000);
    expect(defaultReplicaBackoff(1000)).toBe(3_600_000);
  });

  it("05 retry charges one attempt and schedules now + B(attempts)", () => {
    const calls: number[] = [];
    const backoff: ReplicaBackoff = (a) => {
      calls.push(a);
      return a * 7;
    };
    const first = settleReplicaWork(base, retryOutcome(), T0, { backoff });
    expect(first.state.attempts).toBe(1);
    expect(first.state.nextEligible).toBe(T0 + 7);
    expect(first.outcome).toEqual({ ...retryOutcome(), nextEligible: T0 + 7 });

    const third = settleReplicaWork(
      { ...base, attempts: 2 },
      retryOutcome("download_failed"),
      T0,
      { backoff },
    );
    expect(third.state.attempts).toBe(3);
    expect(third.state.nextEligible).toBe(T0 + 21);
    expect(calls).toEqual([1, 3]);
  });

  it("06 retry keeps problem and structured cause and never moves with hints", () => {
    const outcome: ReplicaPhaseOutcome = {
      tag: "retry",
      problem: "import_failed",
      cause: { name: "Error", cause: { name: "TypeError", code: "E1" } },
    };
    const quiet = settleReplicaWork(base, outcome, T0, { backoff: expBackoff });
    const hinted = settleReplicaWork(base, outcome, T0, {
      backoff: expBackoff,
      hints: true,
    });
    expect(quiet.outcome).toEqual({ ...outcome, nextEligible: T0 + 1000 });
    expect(hinted).toEqual(quiet);
  });

  it("06 default backoff cap applies to a very high attempt count", () => {
    const { state } = settleReplicaWork(
      { ...base, attempts: 40 },
      retryOutcome(),
      T0,
    );
    expect(state.attempts).toBe(41);
    expect(state.nextEligible).toBe(T0 + 3_600_000);
  });

  it("07 a wait resets attempts and the next genuine error starts at B(1)", () => {
    const failing = settleReplicaWork(
      { ...base, attempts: 4 },
      retryOutcome(),
      T0,
      { backoff: expBackoff },
    ).state;
    expect(failing.attempts).toBe(5);
    const waiting = settleReplicaWork(failing, finalityWait("10"), T0 + 1, {
      backoff: expBackoff,
    }).state;
    expect(waiting.attempts).toBe(0);
    const again = settleReplicaWork(waiting, retryOutcome(), T0 + 5000, {
      backoff: expBackoff,
    }).state;
    expect(again.attempts).toBe(1);
    expect(again.nextEligible).toBe(T0 + 5000 + 1000);
  });

  it("07 a wait outcome is reported unchanged", () => {
    const wait = finalityWait("77");
    expect(settleReplicaWork(base, wait, T0).outcome).toEqual(wait);
  });

  it("30 first finality wait polls at 2s and records the verified height and wait start", () => {
    const { state } = settleReplicaWork(base, finalityWait("123"), T0);
    expect(state.nextEligible).toBe(T0 + 2000);
    expect(state.waitSince).toBe(T0);
    expect(state.checkedBlock).toBe("123");
    expect(state.attempts).toBe(0);
  });

  it("30 finality wait without hints grows its interval and keeps waitSince", () => {
    const first = settleReplicaWork(base, finalityWait("123"), T0).state;
    const second = settleReplicaWork(
      first,
      finalityWait("123"),
      T0 + 2000,
    ).state;
    expect(second.nextEligible).toBe(T0 + 2000 + 4000);
    expect(second.waitSince).toBe(T0);
  });

  it("P3 unchanged verified height without hints grows the finality poll", () => {
    let state = settleReplicaWork(base, finalityWait("123"), T0, {
      hints: false,
    }).state;
    expect(state.nextEligible).toBe(T0 + 2_000);

    state = settleReplicaWork(state, finalityWait("123"), T0 + 2_000, {
      hints: false,
    }).state;
    expect(state.nextEligible).toBe(T0 + 2_000 + 4_000);

    state = settleReplicaWork(state, finalityWait("123"), T0 + 6_000, {
      hints: false,
    }).state;
    expect(state.nextEligible).toBe(T0 + 6_000 + 8_000);

    state = settleReplicaWork(state, finalityWait("123"), T0 + 14_000, {
      hints: false,
    }).state;
    expect(state.nextEligible).toBe(T0 + 14_000 + 16_000);

    const long = settleReplicaWork(
      { ...state, waitSince: T0 },
      finalityWait("123"),
      T0 + 600_000,
      { hints: false },
    );
    expect(long.state.nextEligible).toBe(T0 + 600_000 + 30_000);
  });

  it("P1 registration waits without a checked block grow and enter long polling", () => {
    const registrationWait: ReplicaPhaseOutcome = {
      tag: "wait",
      dependency: {
        kind: "registration_pending",
        key: "scope/1",
        version: 1,
        since: T0,
      },
    };
    let state = settleReplicaWork(base, registrationWait, T0).state;
    expect(state.nextEligible).toBe(T0 + 2_000);
    state = settleReplicaWork(state, registrationWait, T0 + 2_000).state;
    expect(state.nextEligible).toBe(T0 + 2_000 + 4_000);
    state = settleReplicaWork(state, registrationWait, T0 + 6_000).state;
    expect(state.nextEligible).toBe(T0 + 6_000 + 8_000);
    state = settleReplicaWork(state, registrationWait, T0 + 14_000).state;
    expect(state.nextEligible).toBe(T0 + 14_000 + 16_000);

    const long = settleReplicaWork(
      { ...state, waitSince: T0 },
      registrationWait,
      T0 + 600_000,
    );
    expect(long.state.nextEligible).toBe(T0 + 600_000 + 30_000);
  });

  it("P2 a successor waits until its predecessor's next evidence check", () => {
    const successorWait: ReplicaPhaseOutcome = {
      tag: "wait",
      dependency: {
        kind: "registration_pending",
        key: "scope/1",
        version: 1,
        since: T0,
        nextCheckAt: T0 + 90_000,
      },
    };
    const { state } = settleReplicaWork(base, successorWait, T0);
    expect(state.nextEligible).toBe(T0 + 90_000);
  });

  it("30 with hints present and no verified advance the poll is 30s", () => {
    const first = settleReplicaWork(base, finalityWait("123"), T0, {
      hints: true,
    }).state;
    expect(first.nextEligible).toBe(T0 + 2000);
    const again = settleReplicaWork(first, finalityWait("123"), T0 + 2000, {
      hints: true,
    }).state;
    expect(again.nextEligible).toBe(T0 + 2000 + 30_000);
    expect(again.checkedBlock).toBe("123");
  });

  it("30 with hints present and the verified height advanced the poll stays 2s", () => {
    const first = settleReplicaWork(base, finalityWait("123"), T0, {
      hints: true,
    }).state;
    const advanced = settleReplicaWork(first, finalityWait("124"), T0 + 2000, {
      hints: true,
    }).state;
    expect(advanced.nextEligible).toBe(T0 + 2000 + 2000);
    expect(advanced.checkedBlock).toBe("124");
  });

  it("30 ten minutes of waiting slows the poll to 30s, with and without hints", () => {
    const wait = (since: number): ReplicaWorkState => ({
      ...base,
      waitSince: since,
      checkedBlock: "50",
    });
    const justUnder = settleReplicaWork(
      wait(T0 - 599_999),
      finalityWait("50"),
      T0,
    );
    expect(justUnder.state.nextEligible).toBe(T0 + 16_000);
    const exact = settleReplicaWork(wait(T0 - 600_000), finalityWait("50"), T0);
    expect(exact.state.nextEligible).toBe(T0 + 30_000);
    const advancedButOld = settleReplicaWork(
      wait(T0 - 600_000),
      finalityWait("51"),
      T0,
      { hints: true },
    );
    expect(advancedButOld.state.nextEligible).toBe(T0 + 30_000);
  });

  it("30 checkedBlock is monotone and compared as a number, not as text", () => {
    const at99 = settleReplicaWork(base, finalityWait("99"), T0).state;
    const at100 = settleReplicaWork(at99, finalityWait("100"), T0 + 1).state;
    expect(at100.checkedBlock).toBe("100");
    // "100" > "99" as a number: with hints present this still counts as an advance
    const advanced = settleReplicaWork(at99, finalityWait("100"), T0 + 1, {
      hints: true,
    }).state;
    expect(advanced.nextEligible).toBe(T0 + 1 + 2000);
    const stale = settleReplicaWork(at100, finalityWait("99"), T0 + 2).state;
    expect(stale.checkedBlock).toBe("100");
    const huge = settleReplicaWork(
      { ...base, checkedBlock: "9007199254740992" },
      finalityWait("9007199254740993"),
      T0,
    ).state;
    expect(huge.checkedBlock).toBe("9007199254740993");
    const hugeStale = settleReplicaWork(
      { ...base, checkedBlock: "9007199254740993" },
      finalityWait("9007199254740992"),
      T0,
    ).state;
    expect(hugeStale.checkedBlock).toBe("9007199254740993");
  });

  it("32 a retry after a finality wait keeps the verified height and ignores hints", () => {
    const waiting = settleReplicaWork(base, finalityWait("50"), T0, {
      hints: true,
    }).state;
    const retried = settleReplicaWork(waiting, retryOutcome(), T0 + 2000, {
      backoff: expBackoff,
      hints: true,
    }).state;
    expect(retried.attempts).toBe(1);
    expect(retried.nextEligible).toBe(T0 + 2000 + 1000);
    expect(retried.checkedBlock).toBe("50");
  });

  it("P3 non-finality waits grow the 60s fallback with a bounded long interval", () => {
    for (const hints of [false, true]) {
      for (const dependency of [
        { kind: "predecessor", key: "w:3" },
        { kind: "mapping", key: "conn-1" },
        { kind: "declaration", key: "src:stream" },
        { kind: "fragments", key: "w:b" },
        { kind: "blob", key: "w:b:0" },
        { kind: "reset", key: "w:reset" },
        { kind: "roster", key: "scope" },
        { kind: "owner", key: "batch" },
      ] as const) {
        const wait = { tag: "wait", dependency } as ReplicaPhaseOutcome;
        const first = settleReplicaWork({ ...base, attempts: 3 }, wait, T0, {
          hints,
        });
        expect(first.state.nextEligible).toBe(T0 + 60_000);
        const second = settleReplicaWork(first.state, wait, T0 + 60_000, {
          hints,
        });
        expect(second.state.nextEligible).toBe(T0 + 60_000 + 120_000);
        const long = settleReplicaWork(
          { ...second.state, waitSince: T0 - 600_000 },
          wait,
          T0,
          { hints },
        );
        expect(long.state.nextEligible).toBe(T0 + 600_000);
        expect(long.state.attempts).toBe(0);
        expect(long.state.checkedBlock).toBeNull();
      }
    }
  });

  it("05 progress clears failures and wait bookkeeping", () => {
    const outcome: ReplicaPhaseOutcome = {
      tag: "progress",
      receipt: { phase: "publish", key: "p1" },
    };
    const result = settleReplicaWork(
      { attempts: 3, nextEligible: T0, waitSince: T0 - 5, checkedBlock: "9" },
      outcome,
      T0,
    );
    expect(result.outcome).toEqual(outcome);
    expect(result.state.attempts).toBe(0);
    expect(result.state.waitSince).toBeNull();
  });

  it.each([
    ["09 quarantine", quarantineOutcome],
    ["10 unsupported", unsupportedOutcome],
  ] as const)(
    "%s is terminal: reported unchanged, not a failure, never due again",
    (_n, outcome) => {
      const previous: ReplicaWorkState = {
        attempts: 3,
        nextEligible: T0,
        waitSince: null,
        checkedBlock: null,
      };
      const result = settleReplicaWork(previous, outcome, T0, {
        backoff: expBackoff,
        hints: true,
      });
      expect(result.outcome).toEqual(outcome);
      expect(result.state.attempts).toBeLessThanOrEqual(previous.attempts);
      expect(Number.isFinite(result.state.nextEligible)).toBe(true);
      for (const now of [T0, T0 + 1e9, T0 + 1e12, MAX_DATE_MS]) {
        expect(result.state.nextEligible).toBeGreaterThan(now);
      }
    },
  );

  it("07 does not mutate its input state", () => {
    const frozen = Object.freeze({ ...base, attempts: 2 });
    expect(() =>
      settleReplicaWork(frozen, retryOutcome(), T0, { backoff: expBackoff }),
    ).not.toThrow();
    expect(frozen.attempts).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// Coordinator: transition timing and attempt accounting (05-08)
// ---------------------------------------------------------------------------

describe("coordinator transitions", () => {
  it.each([
    ["B(a)=1000*2^(a-1)", expBackoff, [1000, 2000]],
    ["B(a)=7a", sevenBackoff, [7, 14]],
  ] as const)(
    "05 Retry then Progress uses the injected backoff %s and replays across restart",
    async (_name, backoff, [d1]) => {
      const world = newWorld();
      addRow(world, "p1", "publish", "A");
      script(world, "p1", new Error(`PUT 503 ${SECRET}`));

      let co = build(world, { backoff });
      const failed = await stepAt(world, co, T0);
      expect(failed.problems).toEqual([
        {
          id: "p1",
          phase: "publish",
          problem: "unknown",
          cause: { name: "Error" },
          nextEligible: T0 + d1,
        },
      ]);
      expect(failed.receipts).toEqual([]);
      expect(failed.nextWake).toBe(T0 + d1);
      expect(row(world, "p1").state.attempts).toBe(1);
      expect(row(world, "p1").state.nextEligible).toBe(T0 + d1);

      co = build(world, { backoff }); // restart
      const early = await stepAt(world, co, T0 + d1 - 1);
      expect(runCount(world, "p1")).toBe(1);
      expect(early.receipts).toEqual([]);
      expect(early.nextWake).toBe(T0 + d1);

      const done = await stepAt(world, co, T0 + d1);
      expect(runCount(world, "p1")).toBe(2);
      expect(done.receipts).toEqual([{ phase: "publish", key: "p1" }]);
      expect(done.nextWake).toBeUndefined();
      const last = world.settles.at(-1);
      expect(last?.outcome.tag).toBe("progress");
      expect(last?.state.attempts).toBe(0);
      expect(world.settles).toHaveLength(2);
    },
  );

  it("05 without an injected backoff the coordinator uses defaultReplicaBackoff", async () => {
    const world = newWorld();
    addRow(world, "p1", "publish", "A");
    script(world, "p1", new Error("a"), new Error("b"));
    const co = build(world);
    await stepAt(world, co, T0);
    expect(row(world, "p1").state.nextEligible).toBe(
      T0 + defaultReplicaBackoff(1),
    );
    await stepAt(world, co, T0 + 1000);
    expect(row(world, "p1").state.nextEligible).toBe(
      T0 + 1000 + defaultReplicaBackoff(2),
    );
  });

  it("06 Retry to Retry increments attempts, uses B(2), keeps the structured cause and never the message", async () => {
    const world = newWorld();
    addRow(world, "d1", "download", "A");
    const nested = new Error(`rpc ${SECRET}`, {
      cause: Object.assign(new TypeError(`socket ${SECRET}`), {
        code: "ECONNRESET",
      }),
    });
    script(
      world,
      "d1",
      nested,
      Object.assign(new Error(`again ${SECRET}`), { code: "E_AGAIN" }),
    );
    let co = build(world, { backoff: expBackoff });
    const first = await stepAt(world, co, T0);
    expect(first.problems[0]?.cause).toEqual({
      name: "Error",
      cause: { name: "TypeError", code: "ECONNRESET" },
    });
    expect(first.problems[0]?.nextEligible).toBe(T0 + 1000);

    co = build(world, { backoff: expBackoff });
    const second = await stepAt(world, co, T0 + 1000);
    expect(second.problems).toEqual([
      {
        id: "d1",
        phase: "download",
        problem: "unknown",
        cause: { name: "Error", code: "E_AGAIN" },
        nextEligible: T0 + 1000 + 2000,
      },
    ]);
    expect(row(world, "d1").state.attempts).toBe(2);
    expect(runCount(world, "d1")).toBe(2);
    // the work item itself (checkpoint) is untouched by transient failures
    expect(row(world, "d1").done).toBe(false);
    expect(row(world, "d1").terminal).toBeNull();
    expect(
      JSON.stringify([first, second, world.settles, [...world.rows.values()]]),
    ).not.toContain(SECRET);
  });

  it("06 a retry returned by the phase keeps its problem and cause exactly", async () => {
    const world = newWorld();
    addRow(world, "i1", "import", "A");
    const cause = { name: "Error", cause: { name: "TypeError" } };
    script(world, "i1", { tag: "retry", problem: "import_failed", cause });
    const report = await stepAt(
      world,
      build(world, { backoff: sevenBackoff }),
      T0,
    );
    expect(report.problems).toEqual([
      {
        id: "i1",
        phase: "import",
        problem: "import_failed",
        cause,
        nextEligible: T0 + 7,
      },
    ]);
  });

  it("07 Retry then Wait then Retry: waits are not failures and the next error is B(1)", async () => {
    const world = newWorld();
    addRow(world, "c1", "fetch", "A");
    script(
      world,
      "c1",
      new Error("rpc"),
      finalityWait("10"),
      finalityWait("10"),
      finalityWait("10"),
      new Error("rpc again"),
    );
    let co = build(world, { backoff: expBackoff });
    await stepAt(world, co, T0);
    expect(row(world, "c1").state.attempts).toBe(1);

    const waited = await stepAt(world, co, T0 + 1000);
    expect(waited.waits).toEqual([
      {
        id: "c1",
        phase: "fetch",
        dependency: { kind: "finality", key: "scope-1", checkedBlock: "10" },
      },
    ]);
    expect(waited.problems).toEqual([]);
    expect(row(world, "c1").state).toEqual({
      attempts: 0,
      nextEligible: T0 + 1000 + 2000,
      waitSince: T0 + 1000,
      checkedBlock: "10",
    });

    co = build(world, { backoff: expBackoff });
    await stepAt(world, co, T0 + 3000);
    co = build(world, { backoff: expBackoff });
    await stepAt(world, co, T0 + 5000);
    expect(row(world, "c1").state.attempts).toBe(0);
    expect(row(world, "c1").state.waitSince).toBe(T0 + 1000);
    expect(row(world, "c1").state.nextEligible).toBe(T0 + 5000 + 2000);

    await stepAt(world, co, T0 + 7000);
    expect(row(world, "c1").state.attempts).toBe(0);
    expect(row(world, "c1").state.nextEligible).toBe(T0 + 15_000);
    await stepAt(world, co, T0 + 15_000);
    expect(row(world, "c1").state.attempts).toBe(1);
    expect(row(world, "c1").state.nextEligible).toBe(T0 + 15_000 + 1000);
    // no wait ever inflated the failure count
    expect(
      world.settles
        .filter((s) => s.outcome.tag === "wait")
        .map((s) => s.state.attempts),
    ).toEqual([0, 0, 0]);
  });

  it("08 Wait then Retry keeps the verified height and uses B(1); a hint-free wait then resumes polling", async () => {
    const world = newWorld();
    addRow(world, "c1", "fetch", "A");
    script(
      world,
      "c1",
      finalityWait("50"),
      new Error("evidence read failed"),
      finalityWait("50"),
    );
    const co = build(world, { backoff: expBackoff, hint: silentHint });
    await stepAt(world, co, T0);
    expect(row(world, "c1").state.checkedBlock).toBe("50");

    const failed = await stepAt(world, co, T0 + 2000);
    expect(failed.problems[0]?.nextEligible).toBe(T0 + 2000 + 1000);
    expect(row(world, "c1").state.attempts).toBe(1);
    expect(row(world, "c1").state.checkedBlock).toBe("50");

    await stepAt(world, co, T0 + 3000);
    expect(row(world, "c1").state.attempts).toBe(0);
    expect(row(world, "c1").state.checkedBlock).toBe("50");
    // verified height did not advance and hints exist: slow poll
    expect(row(world, "c1").state.nextEligible).toBe(T0 + 3000 + 30_000);
  });

  it("30 coordinator hints() decides the poll cadence and never lowers checkedBlock", async () => {
    const world = newWorld();
    addRow(world, "c1", "fetch", "A");
    script(
      world,
      "c1",
      finalityWait("123"),
      finalityWait("123"),
      finalityWait("99"),
      finalityWait("124"),
    );
    const co = build(world, { hint: silentHint });
    await stepAt(world, co, T0);
    expect(row(world, "c1").state.nextEligible).toBe(T0 + 2000);
    await stepAt(world, co, T0 + 2000);
    expect(row(world, "c1").state.nextEligible).toBe(T0 + 2000 + 30_000);
    await stepAt(world, co, T0 + 40_000);
    expect(row(world, "c1").state.checkedBlock).toBe("123");
    await stepAt(world, co, T0 + 80_000);
    expect(row(world, "c1").state.checkedBlock).toBe("124");
    expect(row(world, "c1").state.nextEligible).toBe(T0 + 80_000 + 2000);
  });

  it("32 a finality notification before the Retry deadline never runs the item or shortens its deadline", async () => {
    const world = newWorld();
    addRow(world, "c1", "fetch", "A");
    script(world, "c1", new Error("rpc"), finalityWait("5"));
    const co = build(world, { backoff: expBackoff, hint: silentHint });
    await stepAt(world, co, T0);
    const deadline = row(world, "c1").state.nextEligible;
    expect(deadline).toBe(T0 + 1000);

    const key = dependencyKey({
      kind: "finality",
      key: "scope-1",
      checkedBlock: "9999",
    });
    expect(co.onDependencyChanged(key, T0 + 10)).toBe(0);
    const before = await stepAt(world, co, T0 + 10);
    expect(runCount(world, "c1")).toBe(1);
    expect(before.nextWake).toBe(deadline);
    expect(row(world, "c1").state.nextEligible).toBe(deadline);

    expect(co.onDependencyChanged(key, deadline)).toBe(0);
    await stepAt(world, co, deadline);
    expect(runCount(world, "c1")).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// 09 / 10 / 11 / 12: terminal outcomes
// ---------------------------------------------------------------------------

describe("coordinator terminal outcomes", () => {
  const history: [string, Act[]][] = [
    ["fresh", []],
    ["after a wait", [mappingWait()]],
    ["after a retry", [new Error("transient")]],
  ];

  it.each(history)(
    "09 Quarantine from a %s item is reported once, terminal, and never run again",
    async (_name, before) => {
      const world = newWorld();
      addRow(world, "x1", "import", "A");
      addRow(world, "y1", "import", "B");
      script(world, "x1", ...before, quarantineOutcome);
      let co = build(world, { backoff: expBackoff });
      let now = T0;
      let report = await stepAt(world, co, now);
      for (let i = 0; i < before.length; i += 1) {
        now += 3_700_000;
        co = build(world, { backoff: expBackoff });
        report = await stepAt(world, co, now);
      }
      expect(row(world, "x1").terminal).toBe("quarantine");
      expect(report.quarantines).toEqual([
        {
          id: "x1",
          phase: "import",
          proof: {
            reason: "immutable_registration_conflict",
            key: "scope-1:1",
          },
        },
      ]);
      expect(report.problems).toEqual([]);
      const runsAtTerminal = runCount(world, "x1");
      expect(runsAtTerminal).toBe(before.length + 1);

      for (const later of [now + 1, now + 3_700_000, now + 1e12]) {
        co = build(world, { backoff: expBackoff }); // restart each time
        co.onDependencyChanged(
          dependencyKey({ kind: "mapping", key: "conn-1" }),
          later,
        );
        const idle = await stepAt(world, co, later);
        expect(idle.quarantines).toEqual([]);
        expect(idle.nextWake).toBeUndefined();
      }
      expect(runCount(world, "x1")).toBe(runsAtTerminal);
      // the unrelated writer's item was served normally
      expect(runCount(world, "y1")).toBe(1);
      expect(row(world, "y1").done).toBe(true);
    },
  );

  it("10 Unsupported is reported as admission data, not a failure or quarantine, and is inert", async () => {
    const world = newWorld();
    addRow(world, "b1", "prepare", "A", { state: { attempts: 0 } });
    script(world, "b1", unsupportedOutcome);
    let co = build(world, { backoff: expBackoff });
    const report = await stepAt(world, co, T0);
    expect(report.unsupported).toEqual([
      {
        id: "b1",
        phase: "prepare",
        admission: {
          reason: "replica_framing_unsupported",
          actual: 9,
          limit: 3,
          capability: "cap:3",
        },
      },
    ]);
    expect(report.problems).toEqual([]);
    expect(report.quarantines).toEqual([]);
    expect(report.nextWake).toBeUndefined();
    expect(world.settles).toHaveLength(1);
    expect(world.settles[0]?.outcome).toEqual(unsupportedOutcome);
    expect(world.settles[0]?.state.attempts).toBe(0);

    for (const later of [T0 + 60_000, T0 + 3_600_000, T0 + 1e12]) {
      co = build(world, { backoff: expBackoff });
      co.onDependencyChanged(
        dependencyKey({ kind: "reset", key: "conn:1" }),
        later,
      );
      const idle = await stepAt(world, co, later);
      expect(idle.unsupported).toEqual([]);
      expect(idle.nextWake).toBeUndefined();
    }
    expect(runCount(world, "b1")).toBe(1);
  });

  it("11 repeated steps, wake events and restarts never duplicate terminal or completed work", async () => {
    const world = newWorld();
    addRow(world, "done1", "publish", "A");
    addRow(world, "quar1", "import", "A");
    addRow(world, "unsup1", "prepare", "A");
    script(world, "quar1", quarantineOutcome);
    script(world, "unsup1", unsupportedOutcome);
    let co = build(world);
    await stepAt(world, co, T0);
    const settled = world.settles.length;
    expect(settled).toBe(3);
    const snapshot = JSON.stringify([...world.rows.values()]);
    for (let i = 1; i <= 5; i += 1) {
      co = build(world);
      for (const kind of [
        "mapping",
        "declaration",
        "predecessor",
        "reset",
      ] as const)
        co.onDependencyChanged(`${kind}:anything`, T0 + i * 1e9);
      const report = await stepAt(world, co, T0 + i * 1e9);
      expect(report).toEqual({
        receipts: [],
        waits: [],
        problems: [],
        quarantines: [],
        unsupported: [],
        nextWake: undefined,
      });
    }
    expect(world.settles).toHaveLength(settled);
    expect(JSON.stringify([...world.rows.values()])).toBe(snapshot);
  });

  it("12 the coordinator exposes no re-admission surface: only step and onDependencyChanged", () => {
    const co = build(newWorld(), { phases: ["prepare"] });
    expect(Object.keys(co).sort()).toEqual(["onDependencyChanged", "step"]);
  });
});

// ---------------------------------------------------------------------------
// 13 / 14: error classification inside a step
// ---------------------------------------------------------------------------

describe("coordinator error classification", () => {
  const imitations: [string, () => Error][] = [
    [
      "generic Error",
      () =>
        new Error(
          `encrypted fragment exceeds the cap; replica framing unsupported ${SECRET}`,
        ),
    ],
    [
      "RangeError",
      () => new RangeError(`encrypted fragment exceeds 1048576 ${SECRET}`),
    ],
    [
      "RangeError with actual/limit/capability fields",
      () =>
        Object.assign(new RangeError(`encrypted fragment exceeds ${SECRET}`), {
          actual: 9,
          limit: 3,
          capability: "cap:3",
        }),
    ],
  ];

  it.each(imitations)(
    "13 transient %s is Retry(unknown) with a structured cause, never Unsupported or Quarantine",
    async (_name, make) => {
      const error = make();
      const world = newWorld();
      addRow(world, "b1", "prepare", "A");
      addRow(world, "b2", "prepare", "A", { state: { nextEligible: T0 + 1 } });
      script(world, "b1", error);
      let co = build(world, { backoff: expBackoff });
      const report = await stepAt(world, co, T0);
      expect(report.problems).toEqual([
        {
          id: "b1",
          phase: "prepare",
          problem: "unknown",
          cause: { name: error.constructor.name },
          nextEligible: T0 + 1000,
        },
      ]);
      expect(report.unsupported).toEqual([]);
      expect(report.quarantines).toEqual([]);
      expect(row(world, "b1").terminal).toBeNull();
      expect(JSON.stringify([report, world.settles])).not.toContain(SECRET);

      co = build(world, { backoff: expBackoff });
      await stepAt(world, co, T0 + 999);
      expect(runCount(world, "b1")).toBe(1);
      // a later batch from the same writer still progresses
      expect(row(world, "b2").done).toBe(true);
      const recovered = await stepAt(world, co, T0 + 1000);
      expect(recovered.receipts).toEqual([{ phase: "prepare", key: "b1" }]);
      expect(row(world, "b1").done).toBe(true);
    },
  );

  it("14 a thrown non-Error value is Retry(unknown) and its text never reaches report or state", async () => {
    const world = newWorld();
    addRow(world, "b1", "prepare", "A");
    script(world, "b1", async () => {
      throw SECRET;
    });
    const report = await stepAt(world, build(world), T0);
    expect(report.problems).toHaveLength(1);
    expect(report.problems[0]?.problem).toBe("unknown");
    expect(report.unsupported).toEqual([]);
    expect(report.quarantines).toEqual([]);
    expect(
      JSON.stringify([report, world.settles, [...world.rows.values()]]),
    ).not.toContain(SECRET);
  });
});

// ---------------------------------------------------------------------------
// 17 / 18 / 22 / 23: budgets and per-phase quanta
// ---------------------------------------------------------------------------

describe("coordinator budgets", () => {
  it("17 units bound the runs per step across phases, with no trailing unmetered work", async () => {
    const world = newWorld();
    for (const phase of ["retain", "reconcile", "import"] as const)
      for (let i = 0; i < 5; i += 1)
        addRow(world, `${phase}-${i}`, phase, `w${i}`);
    const co = build(world);
    const report = await stepAt(world, co, T0, { units: 7 });
    expect(world.runs).toHaveLength(7);
    expect(world.settles).toHaveLength(7);
    expect(report.receipts).toHaveLength(7);
    expect(report.nextWake).toBe(T0);
  });

  it("17 k reconcile units per step, restart between steps, no unit repeated", async () => {
    const world = newWorld();
    for (let i = 0; i < 10; i += 1)
      addRow(world, `r${i}`, "reconcile", `w${i % 3}`);
    const k = 3;
    const seen: string[] = [];
    for (let step = 0; step < 4; step += 1) {
      const co = build(world); // restart
      const before = world.runs.length;
      const report = await stepAt(world, co, T0 + step, { units: k });
      const ran = world.runs.slice(before).map((r) => r.id);
      expect(ran.length).toBe(step < 3 ? k : 1);
      seen.push(...ran);
      expect(report.receipts).toHaveLength(ran.length);
      if (step < 3) expect(report.nextWake).toBe(T0 + step);
      else expect(report.nextWake).toBeUndefined();
    }
    expect(new Set(seen).size).toBe(10);
    expect(seen).toHaveLength(10);
  });

  it("18 default quantum is 50 runs per phase per step", async () => {
    const world = newWorld();
    for (let i = 0; i < 120; i += 1)
      addRow(world, `d${i}`, "download", `w${i % 7}`);
    const report = await stepAt(world, build(world), T0, { units: 10_000 });
    expect(world.runs).toHaveLength(50);
    expect(report.receipts).toHaveLength(50);
    expect(report.nextWake).toBe(T0);
  });

  it("18 exhausting one phase's quantum does not starve the others within a step", async () => {
    const world = newWorld();
    for (let i = 0; i < 100; i += 1)
      addRow(world, `prep-${i}`, "prepare", `w${i % 4}`);
    for (let i = 0; i < 100; i += 1)
      addRow(world, `pub-${i}`, "publish", `w${i % 4}`);
    for (let i = 0; i < 100; i += 1)
      addRow(world, `dis-${i}`, "discover", `w${i % 4}`);
    const co = build(world, {
      phases: ["prepare", "publish", "discover"],
      quantum: { prepare: 3, publish: 3, discover: 3 },
    });
    const report = await stepAt(world, co, T0, { units: 9 });
    const perPhase = (phase: ReplicaPhase) =>
      world.runs.filter((r) => r.phase === phase).length;
    expect(perPhase("prepare")).toBe(3);
    expect(perPhase("publish")).toBe(3);
    expect(perPhase("discover")).toBe(3);
    expect(report.receipts).toHaveLength(9);
  });

  it("18 a phase never exceeds its own quantum even when the budget has room", async () => {
    const world = newWorld();
    for (let i = 0; i < 20; i += 1)
      addRow(world, `prep-${i}`, "prepare", `w${i % 4}`);
    for (let i = 0; i < 20; i += 1)
      addRow(world, `pub-${i}`, "publish", `w${i % 4}`);
    const co = build(world, { quantum: { prepare: 2, publish: 7 } });
    await stepAt(world, co, T0, { units: 1000 });
    expect(world.runs.filter((r) => r.phase === "prepare")).toHaveLength(2);
    expect(world.runs.filter((r) => r.phase === "publish")).toHaveLength(7);
  });

  it("22 units: 0 is rejected before selection or settlement", async () => {
    const world = newWorld();
    addRow(world, "p1", "publish", "A");
    addRow(world, "i1", "import", "B", { state: { nextEligible: 12 } });
    const snapshot = JSON.stringify([...world.rows.values()]);
    await expect(stepAt(world, build(world), T0, { units: 0 })).rejects.toThrow(
      RangeError,
    );
    expect(world.runs).toEqual([]);
    expect(world.settles).toEqual([]);
    expect(JSON.stringify([...world.rows.values()])).toBe(snapshot);
  });

  it("22 positive finite budget reports the earliest deadline, and idle reports undefined", async () => {
    const world = newWorld();
    addRow(world, "p1", "publish", "A", { state: { nextEligible: T0 + 500 } });
    addRow(world, "i1", "import", "B", { state: { nextEligible: T0 + 300 } });
    const co = build(world);
    expect((await stepAt(world, co, T0, { units: 1 })).nextWake).toBe(T0 + 300);
    const empty = newWorld();
    expect(
      (
        await stepAt(empty, build(empty, { phases: ["publish"] }), T0, {
          units: 1,
        })
      ).nextWake,
    ).toBeUndefined();
  });

  it("22 budget exhausted mid-phase leaves the rest durable and nextWake === now", async () => {
    const world = newWorld();
    for (let i = 0; i < 5; i += 1)
      addRow(world, `i${i}`, "import", `w${i}`, { state: { nextEligible: i } });
    const co = build(world);
    const report = await stepAt(world, co, T0, { units: 2 });
    expect(runIds(world)).toEqual(["i0", "i1"]);
    expect(report.nextWake).toBe(T0);
    expect(["i2", "i3", "i4"].every((id) => !row(world, id).done)).toBe(true);
    expect(
      ["i2", "i3", "i4"].map((id) => row(world, id).state.nextEligible),
    ).toEqual([2, 3, 4]);
  });

  it("23 an item larger than the remaining byte budget is deferred: not run, not settled, state intact", async () => {
    const world = newWorld();
    addRow(world, "s1", "import", "B", {
      bytes: 30,
      state: { nextEligible: 1 },
    });
    addRow(world, "s2", "import", "C", {
      bytes: 30,
      state: { nextEligible: 2 },
    });
    // Fits the whole budget but not the 40 bytes left after s1 and s2.
    addRow(world, "big", "import", "A", {
      bytes: 90,
      state: { nextEligible: 3 },
    });
    const before = JSON.stringify(row(world, "big"));
    const report = await stepAt(world, build(world), T0, {
      units: 10,
      bytes: 100,
    });
    expect(runIds(world)).not.toContain("big");
    expect(world.settles.map((s) => s.id)).not.toContain("big");
    expect(JSON.stringify(row(world, "big"))).toBe(before);
    expect(runIds(world).sort()).toEqual(["s1", "s2"]);
    expect(report.receipts.map((r) => r.key).sort()).toEqual(["s1", "s2"]);
    expect(report.problems).toEqual([]);
    expect(report.unsupported).toEqual([]);
    expect(report.nextWake).toBe(T0);
  });

  it("23 under the default budget an item larger than the whole step runs alone, then spends the rest", async () => {
    const world = newWorld();
    addRow(world, "huge", "import", "A", {
      bytes: REPLICA_STEP_BYTES + 1,
      state: { nextEligible: 1 },
    });
    addRow(world, "s1", "import", "B", {
      bytes: 30,
      state: { nextEligible: 2 },
    });
    const first = await stepAt(world, build(world), T0, { units: 10 });
    expect(runIds(world)).toEqual(["huge"]);
    expect(first.nextWake).toBe(T0);
    await stepAt(world, build(world), T0, { units: 10 });
    expect(runIds(world)).toEqual(["huge", "s1"]);
  });

  it("23 under the default budget an oversized item waits for a step no other item charged", async () => {
    const world = newWorld();
    addRow(world, "s1", "import", "B", {
      bytes: 30,
      state: { nextEligible: 1 },
    });
    addRow(world, "huge", "import", "A", {
      bytes: REPLICA_STEP_BYTES + 1,
      state: { nextEligible: 2 },
    });
    await stepAt(world, build(world), T0, { units: 10 });
    expect(runIds(world)).toEqual(["s1"]);
    await stepAt(world, build(world), T0, { units: 10 });
    expect(runIds(world)).toEqual(["s1", "huge"]);
  });

  it("23 under an explicit budget an item larger than the whole budget stays deferred", async () => {
    const world = newWorld();
    addRow(world, "huge", "import", "A", {
      bytes: 500,
      state: { nextEligible: 1 },
    });
    for (let i = 0; i < 2; i++) {
      const report = await stepAt(world, build(world), T0, {
        units: 10,
        bytes: 100,
      });
      expect(runIds(world)).toEqual([]);
      expect(report.nextWake).toBe(T0);
    }
    await stepAt(world, build(world), T0, { units: 10, bytes: 500 });
    expect(runIds(world)).toEqual(["huge"]);
  });

  it("23 bytes are charged per run and an exact fit is admitted", async () => {
    const world = newWorld();
    addRow(world, "a", "import", "A", {
      bytes: 40,
      state: { nextEligible: 1 },
    });
    addRow(world, "b", "import", "B", {
      bytes: 60,
      state: { nextEligible: 2 },
    });
    addRow(world, "c", "import", "C", { bytes: 1, state: { nextEligible: 3 } });
    const report = await stepAt(world, build(world), T0, {
      units: 10,
      bytes: 100,
    });
    expect(runIds(world).sort()).toEqual(["a", "b"]);
    expect(report.nextWake).toBe(T0);
    expect(row(world, "c").done).toBe(false);
  });

  it("23 omitted byte budget uses a finite default large enough for admitted work", async () => {
    const world = newWorld();
    addRow(world, "big", "import", "A", { bytes: 10_000_000 });
    await stepAt(world, build(world), T0, { units: 1 });
    expect(runIds(world)).toEqual(["big"]);
  });
});

// ---------------------------------------------------------------------------
// 19 / 20 / 21: fairness
// ---------------------------------------------------------------------------

describe("coordinator fairness", () => {
  it("19 refilled rounds interleave writers: B's second item runs before A's third", async () => {
    const world = newWorld();
    for (let i = 1; i <= 100; i += 1)
      addRow(world, `a${String(i).padStart(3, "0")}`, "publish", "A", {
        state: { nextEligible: 0 },
      });
    addRow(world, "b1", "publish", "B", { state: { nextEligible: 5 } });
    addRow(world, "b2", "publish", "B", { state: { nextEligible: 6 } });
    await stepAt(world, build(world, { perWriter: 1 }), T0, { units: 10 });
    const order = runIds(world);
    expect(order).toHaveLength(10);
    expect(order.indexOf("b1")).toBeLessThan(order.indexOf("a003"));
    expect(order.indexOf("b2")).toBeLessThan(order.indexOf("a004"));
    expect(
      world.dueCalls.every((c) => c.perWriter === 1 && c.total <= 10),
    ).toBe(true);
  });

  it("19 the default per-writer limit is one per round: B is served despite A's older backlog", async () => {
    const world = newWorld();
    for (let i = 1; i <= 100; i += 1)
      addRow(world, `a${String(i).padStart(3, "0")}`, "publish", "A", {
        state: { nextEligible: 0 },
      });
    addRow(world, "b1", "publish", "B", { state: { nextEligible: T0 - 1 } });
    await stepAt(world, build(world), T0, { units: 2 });
    expect(runIds(world).sort()).toEqual(["a001", "b1"]);
  });

  it("19 writer A replenishing continuously cannot starve B across restarts", async () => {
    const world = newWorld();
    let seq = 0;
    const replenish = () =>
      addRow(world, `a${String(++seq).padStart(5, "0")}`, "publish", "A", {
        state: { nextEligible: 0 },
      });
    for (let i = 0; i < 3; i += 1) replenish();
    for (let i = 1; i <= 5; i += 1)
      addRow(world, `b${i}`, "publish", "B", {
        state: { nextEligible: T0 + i - 10 },
      });
    world.onSettle = (call, w) => {
      if (call.id.startsWith("a") && w.rows.get(call.id)?.writer === "A")
        replenish();
    };
    for (let step = 1; step <= 5; step += 1) {
      const co = build(world, { perWriter: 1 }); // restart every step
      await stepAt(world, co, T0 + step, { units: 2 });
      expect(row(world, `b${step}`).done).toBe(true);
    }
    expect([1, 2, 3, 4, 5].every((i) => row(world, `b${i}`).done)).toBe(true);
    expect(
      [...world.rows.values()].filter((r) => r.writer === "A" && !r.done)
        .length,
    ).toBeGreaterThan(0);
  });

  it("19 stable tie-breaking: a coordinator rebuilt every step serves the same order as a long-lived one", async () => {
    const make = () => {
      const world = newWorld();
      for (const [id, writer] of [
        ["a1", "A"],
        ["a2", "A"],
        ["b1", "B"],
        ["b2", "B"],
        ["c1", "C"],
      ] as const)
        addRow(world, id, "import", writer, { state: { nextEligible: T0 } });
      return world;
    };
    const continuous = make();
    const co = build(continuous);
    for (let i = 0; i < 5; i += 1)
      await stepAt(continuous, co, T0, { units: 1 });
    const restarted = make();
    for (let i = 0; i < 5; i += 1)
      await stepAt(restarted, build(restarted), T0, { units: 1 });
    expect(runIds(restarted)).toEqual(runIds(continuous));
    expect(runIds(restarted)).toHaveLength(5);
  });

  it.each([1, 2, 3, 4, 5, 6, 7, 8])(
    "19 randomized interleavings (seed %i): every writer with work runs in each step that has a unit per writer, and all work finishes",
    async (seed) => {
      const rand = mulberry32(seed);
      const world = newWorld();
      const writers = ["A", "B", "C", "D"];
      let total = 0;
      for (const w of writers) {
        const n = 1 + Math.floor(rand() * 12);
        for (let i = 0; i < n; i += 1) {
          addRow(world, `${w}-${i}`, "import", w, {
            state: { nextEligible: Math.floor(rand() * 5) },
          });
          total += 1;
        }
      }
      let steps = 0;
      while ([...world.rows.values()].some((r) => !r.done)) {
        steps += 1;
        expect(steps).toBeLessThan(200);
        const withWork = new Set(
          [...world.rows.values()].filter((r) => !r.done).map((r) => r.writer),
        );
        const units = withWork.size + Math.floor(rand() * 4);
        const before = world.runs.length;
        const co = build(world, { perWriter: 1 }); // restart every step
        await stepAt(world, co, T0, { units });
        const ran = new Set(
          world.runs.slice(before).map((r) => row(world, r.id).writer),
        );
        expect(world.runs.length - before).toBeLessThanOrEqual(units);
        for (const w of withWork) expect(ran).toContain(w);
      }
      expect(world.runs).toHaveLength(total);
    },
  );

  it("20 parked waits are never run or charged: the one due item runs on a one-unit budget", async () => {
    const world = newWorld();
    for (let i = 0; i < 100; i += 1) {
      addRow(world, `park${i}`, "fetch", "A");
      parkAsWait(
        world,
        `park${i}`,
        { kind: "finality", key: `s${i}`, checkedBlock: "1" },
        T0 + 2000 + i,
      );
    }
    addRow(world, "b1", "fetch", "B", { state: { nextEligible: T0 } });
    const report = await stepAt(
      world,
      build(world, { quantum: { fetch: 1 } }),
      T0,
      {
        units: 1,
      },
    );
    expect(runIds(world)).toEqual(["b1"]);
    expect(report.receipts).toEqual([{ phase: "fetch", key: "b1" }]);
    expect(report.nextWake).toBe(T0 + 2000);
    expect(world.dueCalls.length).toBeLessThanOrEqual(2);
  });

  it("21 an always-failing writer cannot monopolize rounds; its backoff accounting stays exact across restarts", async () => {
    const world = newWorld();
    for (let i = 1; i <= 20; i += 1) {
      const id = `a${String(i).padStart(2, "0")}`;
      addRow(world, id, "publish", "A", { state: { nextEligible: i } });
      script(
        world,
        id,
        ...Array.from({ length: 10 }, () => new Error(`down ${SECRET}`)),
      );
    }
    for (let i = 1; i <= 5; i += 1)
      addRow(world, `b${i}`, "publish", "B", {
        state: { nextEligible: 100 + i },
      });

    const stepTimes = [T0, T0 + 100_000, T0 + 200_000];
    for (const now of stepTimes) {
      await stepAt(
        world,
        build(world, { backoff: expBackoff, perWriter: 1 }),
        now,
        { units: 6 },
      );
      if (now === T0) expect(row(world, "b1").done).toBe(true);
    }
    expect([1, 2, 3, 4, 5].every((i) => row(world, `b${i}`).done)).toBe(true);
    // A1 failed in the first step at T0: attempts 1 and next = T0 + B(1)
    const firstFailure = world.settles.find((s) => s.id === "a01");
    expect(firstFailure?.state.attempts).toBe(1);
    expect(firstFailure?.state.nextEligible).toBe(T0 + 1000);
    expect(JSON.stringify(world.settles)).not.toContain(SECRET);
  });
});

// ---------------------------------------------------------------------------
// 24 / 25: deadlines and host cancellation
// ---------------------------------------------------------------------------

describe("coordinator cancellation", () => {
  it("24 a never-resolving run that honours abort becomes Retry(deadline_exceeded) and other phases are served", async () => {
    const world = newWorld();
    addRow(world, "p1", "publish", "A");
    addRow(world, "q1", "prepare", "B");
    let aborted = false;
    script(world, "p1", async (_item, signal) => {
      signal.addEventListener("abort", () => (aborted = true), { once: true });
      return untilAbort(signal);
    });
    const co = build(world, {
      phases: ["publish", "prepare"],
      deadlineMs: 25,
      backoff: expBackoff,
    });
    const started = Date.now();
    const report = await stepAt(world, co, T0);
    expect(Date.now() - started).toBeLessThan(2000);
    expect(aborted).toBe(true);
    expect(report.problems).toHaveLength(1);
    expect(report.problems[0]).toMatchObject({
      id: "p1",
      phase: "publish",
      problem: "deadline_exceeded",
      nextEligible: T0 + 1000,
    });
    expect(report.receipts).toEqual([{ phase: "prepare", key: "q1" }]);
    expect(row(world, "p1").state.attempts).toBe(1);
    expect(row(world, "p1").done).toBe(false);
    expect(row(world, "q1").done).toBe(true);
  });

  it.each([
    [
      "progress",
      { tag: "progress", receipt: { phase: "publish", key: "late" } },
    ],
    ["wait", mappingWait("late")],
    ["quarantine", quarantineOutcome],
    ["unsupported", unsupportedOutcome],
  ] as const)(
    "24 a late %s result after the deadline is discarded and cannot overwrite a newer settle",
    async (_name, late) => {
      const world = newWorld();
      addRow(world, "p1", "publish", "A");
      const first = deferred<ReplicaPhaseOutcome>();
      // run #1 ignores the abort and settles long after the deadline.
      script(world, "p1", () => first.promise);
      let co = build(world, { deadlineMs: 20, backoff: expBackoff });
      const report = await stepAt(world, co, T0);
      expect(report.problems[0]?.problem).toBe("deadline_exceeded");

      co = build(world, { deadlineMs: 20, backoff: expBackoff });
      const second = await stepAt(world, co, T0 + 1000);
      expect(second.receipts).toEqual([{ phase: "publish", key: "p1" }]);
      expect(row(world, "p1").done).toBe(true);
      const settled = world.settles.length;
      const snapshot = JSON.stringify(row(world, "p1"));

      first.resolve(late);
      await sleep(30);
      expect(world.settles).toHaveLength(settled);
      expect(JSON.stringify(row(world, "p1"))).toBe(snapshot);
      const after = await stepAt(world, co, T0 + 10_000);
      expect(after.receipts).toEqual([]);
      expect(after.quarantines).toEqual([]);
      expect(after.unsupported).toEqual([]);
      expect(runCount(world, "p1")).toBe(2);
    },
  );

  it("24 a late rejection after the deadline is discarded too", async () => {
    const world = newWorld();
    addRow(world, "p1", "publish", "A");
    const first = deferred<ReplicaPhaseOutcome>();
    script(world, "p1", () => first.promise);
    const co = build(world, { deadlineMs: 20, backoff: expBackoff });
    await stepAt(world, co, T0);
    const before = JSON.stringify(row(world, "p1"));
    const settled = world.settles.length;
    first.reject(new Error(`late ${SECRET}`));
    await sleep(30);
    expect(world.settles).toHaveLength(settled);
    expect(JSON.stringify(row(world, "p1"))).toBe(before);
  });

  it("25 host abort stops admitting work, settles nothing unfinished and invents no outcome", async () => {
    const world = newWorld();
    addRow(world, "p1", "publish", "A", { state: { nextEligible: T0 - 3 } });
    addRow(world, "p2", "publish", "A", { state: { nextEligible: T0 - 2 } });
    addRow(world, "p3", "publish", "A", { state: { nextEligible: T0 - 1 } });
    const started = deferred<void>();
    script(world, "p2", async (_item, signal) => {
      started.resolve();
      return untilAbort(signal);
    });
    const controller = new AbortController();
    const co = build(world, { backoff: expBackoff });
    const pending = stepAt(world, co, T0, { units: 10 }, controller.signal);
    await started.promise;
    controller.abort();
    const report = await pending;

    expect(runIds(world)).toEqual(["p1", "p2"]);
    expect(world.settles.map((s) => s.id)).toEqual(["p1"]);
    expect(report.receipts).toEqual([{ phase: "publish", key: "p1" }]);
    expect(report.problems).toEqual([]);
    expect(report.quarantines).toEqual([]);
    expect(report.unsupported).toEqual([]);
    expect(report.waits).toEqual([]);
    expect(row(world, "p2").state.attempts).toBe(0);
    expect(row(world, "p2").state.nextEligible).toBe(T0 - 2);
    expect(row(world, "p2").done).toBe(false);
    expect(row(world, "p3").done).toBe(false);
    expect(report.nextWake).toBe(T0);

    // resume after restart: the interrupted item and its successor run from scratch.
    const resumed = await stepAt(
      world,
      build(world, { backoff: expBackoff }),
      T0 + 1,
    );
    expect(resumed.receipts.map((r) => r.key)).toEqual(["p2", "p3"]);
    expect(row(world, "p2").state.attempts).toBe(0);
  });

  it("25 a step given an already-aborted signal runs and settles nothing", async () => {
    const world = newWorld();
    addRow(world, "p1", "publish", "A");
    const controller = new AbortController();
    controller.abort();
    const report = await stepAt(
      world,
      build(world),
      T0,
      { units: 10 },
      controller.signal,
    );
    expect(world.runs).toEqual([]);
    expect(world.settles).toEqual([]);
    expect(report.receipts).toEqual([]);
    expect(report.problems).toEqual([]);
    expect(report.nextWake).toBe(T0);
  });

  it("25 the step returns promptly on host abort even if a run ignores the signal, and discards its late result", async () => {
    const world = newWorld();
    addRow(world, "p1", "publish", "A");
    const never = deferred<ReplicaPhaseOutcome>();
    const started = deferred<void>();
    script(world, "p1", () => {
      started.resolve();
      return never.promise;
    });
    const controller = new AbortController();
    const co = build(world);
    const pending = stepAt(world, co, T0, { units: 10 }, controller.signal);
    await started.promise;
    controller.abort();
    const outcome = await Promise.race([
      pending,
      sleep(500).then(() => "hung" as const),
    ]);
    expect(outcome).not.toBe("hung");
    never.resolve({
      tag: "progress",
      receipt: { phase: "publish", key: "p1" },
    });
    await sleep(20);
    expect(world.settles).toEqual([]);
    expect(row(world, "p1").done).toBe(false);
    expect(row(world, "p1").state.attempts).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// 26 / 29: dependency wakes
// ---------------------------------------------------------------------------

describe("coordinator dependency wakes", () => {
  function waitingWorld() {
    const world = newWorld();
    const far = T0 + 60_000;
    const rows: [string, ReplicaPhase, ReplicaDependency][] = [
      ["map-x", "import", { kind: "mapping", key: "X" }],
      ["decl-d", "import", { kind: "declaration", key: "D" }],
      ["pred-p", "import", { kind: "predecessor", key: "w:1" }],
      ["blob-b", "download", { kind: "blob", key: "B" }],
      ["fin-s", "fetch", { kind: "finality", key: "S", checkedBlock: "1" }],
    ];
    for (const [id, phase, dependency] of rows) {
      addRow(world, id, phase, "A");
      parkAsWait(world, id, dependency, far);
    }
    const retrying = addRow(world, "retry-d", "import", "B");
    retrying.state = {
      attempts: 2,
      nextEligible: T0 + 30_000,
      waitSince: null,
      checkedBlock: null,
    };
    retrying.dependency = "declaration:D";
    retrying.lastOutcome = {
      tag: "retry",
      problem: "import_failed",
      nextEligible: T0 + 30_000,
    };
    return world;
  }

  it("26 wakes only the matching wait; duplicates are idempotent; unrelated keys wake nothing; Retry deadlines never move", async () => {
    const world = waitingWorld();
    const co = build(world);
    const key = dependencyKey({ kind: "declaration", key: "D" });
    const first = co.onDependencyChanged(key, T0);
    const second = co.onDependencyChanged(key, T0);
    expect(first).toBe(1);
    expect(second).toBe(0);
    expect(
      co.onDependencyChanged(
        dependencyKey({ kind: "declaration", key: "D2" }),
        T0,
      ),
    ).toBe(0);
    expect(row(world, "retry-d").state.nextEligible).toBe(T0 + 30_000);

    const report = await stepAt(world, co, T0);
    expect(runIds(world)).toEqual(["decl-d"]);
    expect(report.receipts).toEqual([{ phase: "import", key: "decl-d" }]);
    expect(report.nextWake).toBe(T0 + 30_000);
    expect(row(world, "retry-d").state.nextEligible).toBe(T0 + 30_000);
    expect(
      ["map-x", "pred-p", "blob-b", "fin-s"].every(
        (id) => row(world, id).state.nextEligible === T0 + 60_000,
      ),
    ).toBe(true);
  });

  it("26 onDependencyChanged sums handler counts and tolerates handlers without wake()", () => {
    const world = waitingWorld();
    world.noWake.add("download");
    const co = build(world);
    expect(
      co.onDependencyChanged(dependencyKey({ kind: "blob", key: "B" }), T0),
    ).toBe(0);
    expect(
      co.onDependencyChanged(dependencyKey({ kind: "mapping", key: "X" }), T0),
    ).toBe(1);
    expect(
      co.onDependencyChanged(
        dependencyKey({ kind: "finality", key: "S", checkedBlock: "2" }),
        T0,
      ),
    ).toBe(1);
  });

  it("26 a woken wait survives a restart before it runs", async () => {
    const world = waitingWorld();
    build(world).onDependencyChanged(
      dependencyKey({ kind: "predecessor", key: "w:1" }),
      T0,
    );
    const report = await stepAt(world, build(world), T0);
    expect(runIds(world)).toEqual(["pred-p"]);
    expect(report.receipts).toEqual([{ phase: "import", key: "pred-p" }]);
  });

  it("29 1000 waits on one key and 100 notifications run at most the quantum per step and every wait is eventually served", async () => {
    const world = newWorld();
    const key: ReplicaDependency = { kind: "declaration", key: "src:stream" };
    for (let w = 0; w < 10; w += 1)
      for (let j = 0; j < 100; j += 1) {
        const id = `w${w}-${String(j).padStart(3, "0")}`;
        addRow(world, id, "reconcile", `w${w}`);
        parkAsWait(world, id, key, T0 + 60_000);
      }
    for (let i = 0; i < 10; i += 1) {
      addRow(world, `other-${i}`, "reconcile", "Z");
      parkAsWait(
        world,
        `other-${i}`,
        { kind: "declaration", key: "other" },
        T0 + 60_000,
      );
    }
    let co = build(world);
    let woken = 0;
    for (let i = 0; i < 100; i += 1)
      woken += co.onDependencyChanged(dependencyKey(key), T0);
    expect(woken).toBe(1000);

    let steps = 0;
    let lastReport: ProgressReport | undefined;
    for (;;) {
      steps += 1;
      expect(steps).toBeLessThanOrEqual(25);
      co = build(world);
      const before = world.runs.length;
      lastReport = await stepAt(world, co, T0, { units: 50 });
      const ran = world.runs.length - before;
      expect(ran).toBeLessThanOrEqual(50);
      if (steps === 1) {
        // fair rounds: 50 runs over 10 writers is 5 each
        const perWriter = new Map<string, number>();
        for (const r of world.runs) {
          const w = row(world, r.id).writer;
          perWriter.set(w, (perWriter.get(w) ?? 0) + 1);
        }
        expect([...perWriter.values()]).toEqual(
          Array.from({ length: 10 }, () => 5),
        );
      }
      if (lastReport.nextWake !== T0) break;
    }
    expect(world.runs).toHaveLength(1000);
    expect(new Set(runIds(world)).size).toBe(1000);
    expect(runIds(world).some((id) => id.startsWith("other-"))).toBe(false);
    expect(lastReport?.nextWake).toBe(T0 + 60_000);
  });
});

// ---------------------------------------------------------------------------
// 34: nextWake
// ---------------------------------------------------------------------------

describe("coordinator nextWake", () => {
  it("34 nextWake is the earliest non-terminal deadline across phases; terminal work contributes nothing; a rebuilt coordinator agrees", async () => {
    const world = newWorld();
    addRow(world, "r1", "publish", "A", {
      state: { nextEligible: T0 + 20_000, attempts: 1 },
    });
    addRow(world, "r2", "download", "A", {
      state: { nextEligible: T0 + 30_000, attempts: 1 },
    });
    addRow(world, "f1", "fetch", "B");
    parkAsWait(
      world,
      "f1",
      { kind: "finality", key: "S", checkedBlock: "4" },
      T0 + 25_000,
    );
    addRow(world, "t1", "import", "C");
    script(world, "t1", quarantineOutcome);
    addRow(world, "t2", "prepare", "C");
    script(world, "t2", unsupportedOutcome);

    const co = build(world);
    const report = await stepAt(world, co, T0);
    expect(runIds(world).sort()).toEqual(["t1", "t2"]);
    expect(report.nextWake).toBe(T0 + 20_000);

    const fresh = build(world);
    expect((await stepAt(world, fresh, T0, { units: 1 })).nextWake).toBe(
      T0 + 20_000,
    );

    // A satisfied dependency makes work due now. Pre-aborted steps observe
    // it without running (and so without draining) it.
    expect(
      fresh.onDependencyChanged(
        dependencyKey({ kind: "finality", key: "S", checkedBlock: "5" }),
        T0,
      ),
    ).toBe(1);
    const observe = AbortSignal.abort();
    expect(
      (await stepAt(world, fresh, T0, { units: 1 }, observe)).nextWake,
    ).toBe(T0);
    expect(
      (await stepAt(world, build(world), T0, { units: 1 }, observe)).nextWake,
    ).toBe(T0);
    expect(runIds(world)).not.toContain("f1");
  });

  it("34 only terminal work means idle (undefined), not a far-future wake", async () => {
    const world = newWorld();
    addRow(world, "t1", "import", "C");
    script(world, "t1", quarantineOutcome);
    addRow(world, "t2", "prepare", "C");
    script(world, "t2", unsupportedOutcome);
    const report = await stepAt(world, build(world), T0);
    expect(report.nextWake).toBeUndefined();
  });

  it("34 a non-finality wait yields the bounded 60s fallback as nextWake", async () => {
    const world = newWorld();
    addRow(world, "i1", "import", "A");
    script(world, "i1", mappingWait("conn-1"));
    const report = await stepAt(world, build(world), T0);
    expect(report.waits).toEqual([
      {
        id: "i1",
        phase: "import",
        dependency: { kind: "mapping", key: "conn-1" },
      },
    ]);
    expect(report.nextWake).toBe(T0 + 60_000);
  });
});

// ---------------------------------------------------------------------------
// 45: outcome and state are settled together, once
// ---------------------------------------------------------------------------

describe("coordinator settle", () => {
  it("45 settle gets exactly the pure outcome and state for each run, once, after the run resolves", async () => {
    const world = newWorld();
    addRow(world, "r1", "publish", "A", { state: { nextEligible: 1 } });
    addRow(world, "w1", "fetch", "B", { state: { nextEligible: 2 } });
    addRow(world, "p1", "prepare", "C", { state: { nextEligible: 3 } });
    addRow(world, "q1", "import", "D", { state: { nextEligible: 4 } });
    const retry: ReplicaPhaseOutcome = {
      tag: "retry",
      problem: "publish_failed",
      cause: { name: "Error" },
    };
    script(world, "r1", retry);
    script(world, "w1", finalityWait("7"));
    script(world, "q1", quarantineOutcome);
    const before = new Map(
      [...world.rows].map(([id, r]) => [id, structuredClone(r.state)]),
    );
    const co = build(world, { backoff: sevenBackoff, hint: silentHint });
    const phaseOutcomes: Record<string, ReplicaPhaseOutcome> = {
      r1: retry,
      w1: finalityWait("7"),
      p1: { tag: "progress", receipt: { phase: "prepare", key: "p1" } },
      q1: quarantineOutcome,
    };
    await stepAt(world, co, T0);
    expect(world.settles.map((s) => s.id).sort()).toEqual([
      "p1",
      "q1",
      "r1",
      "w1",
    ]);
    for (const call of world.settles) {
      const expected = settleReplicaWork(
        before.get(call.id) ?? base,
        phaseOutcomes[call.id] ?? retry,
        T0,
        { backoff: sevenBackoff, hints: true },
      );
      expect(call.outcome).toEqual(expected.outcome);
      expect(call.state).toEqual(expected.state);
      const i = (tag: string) => world.events.indexOf(`${tag}:${call.id}`);
      expect(i("start")).toBeGreaterThanOrEqual(0);
      expect(i("start")).toBeLessThan(i("end"));
      expect(i("end")).toBeLessThan(i("settle"));
      expect(
        world.events.filter((e) => e === `settle:${call.id}`),
      ).toHaveLength(1);
    }
    const retried = world.settles.find((s) => s.id === "r1");
    expect(retried?.outcome).toEqual({ ...retry, nextEligible: T0 + 7 });
    expect(retried?.state.nextEligible).toBe(T0 + 7);
  });

  it("45 a throwing settle leaves the previous state intact, is not reported as an outcome, and the item runs again", async () => {
    const world = newWorld();
    addRow(world, "p1", "publish", "A", { state: { nextEligible: T0 - 10 } });
    const prior = JSON.stringify(row(world, "p1"));
    world.failSettleOnce.add("p1");
    let co = build(world, { backoff: expBackoff });
    const result = await stepAt(world, co, T0).then(
      (report) => ({ report }),
      (error: unknown) => ({ error }),
    );
    expect(JSON.stringify(row(world, "p1"))).toBe(prior);
    expect(row(world, "p1").state.attempts).toBe(0);
    expect(world.settles).toEqual([]);
    if ("report" in result) {
      expect(result.report.receipts).toEqual([]);
      expect(result.report.problems).toEqual([]);
      expect(result.report.quarantines).toEqual([]);
      expect(result.report.unsupported).toEqual([]);
      expect(result.report.waits).toEqual([]);
    }

    co = build(world, { backoff: expBackoff }); // restart
    const retried = await stepAt(world, co, T0 + 1);
    expect(runCount(world, "p1")).toBe(2);
    expect(retried.receipts).toEqual([{ phase: "publish", key: "p1" }]);
    expect(row(world, "p1").done).toBe(true);
    expect(world.settles).toHaveLength(1);
  });
});
