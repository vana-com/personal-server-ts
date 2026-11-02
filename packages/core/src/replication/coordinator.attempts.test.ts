import { describe, expect, it } from "vitest";
import {
  abortable,
  createReplicaCoordinator,
  type ReplicaAttempt,
  type ReplicaPhaseHandler,
  type ReplicaWorkItem,
} from "./coordinator.js";
import type { ReplicaOutcome, ReplicaPhaseOutcome } from "./outcome.js";
import {
  initialReplicaWorkState,
  replicaEligibleAt,
  type ReplicaEligibility,
  type ReplicaWorkState,
} from "./schedule.js";

const T0 = 1_000_000;
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/** One durable item in memory; `commit` mimics a transactional repository. */
function single(run: (signal: AbortSignal) => Promise<ReplicaAttempt>) {
  const store = {
    state: { ...initialReplicaWorkState } as ReplicaWorkState,
    outcome: undefined as ReplicaOutcome | undefined,
    commits: 0,
  };
  const handler: ReplicaPhaseHandler = {
    phase: "download",
    due({ now }) {
      const at = replicaEligibleAt(
        {
          finalityWait:
            store.outcome?.tag === "wait" &&
            store.outcome.dependency.kind === "finality",
          nextEligible: store.state.nextEligible,
          waitSince: store.state.waitSince,
          checkedBlock: store.state.checkedBlock,
        },
        { now, head: undefined, hintRefreshAt: undefined },
      );
      return store.outcome?.tag === "progress" || at === undefined || at > now
        ? []
        : [
            {
              id: "x",
              phase: "download",
              writer: "w",
              state: { ...store.state },
            } satisfies ReplicaWorkItem,
          ];
    },
    run: (_item, signal) => run(signal),
    commitProblem: "download_failed",
    commit(_item, attempt, settle) {
      store.commits++;
      // A throwing plan aborts the commit before anything is stored.
      const verdict = attempt.plan?.() ?? attempt.outcome;
      const settled = settle(verdict);
      store.state = settled.state;
      store.outcome = settled.outcome;
      return settled.outcome;
    },
    earliest(eligibility) {
      if (store.outcome?.tag === "progress") return undefined;
      return replicaEligibleAt(
        {
          finalityWait:
            store.outcome?.tag === "wait" &&
            store.outcome.dependency.kind === "finality",
          nextEligible: store.state.nextEligible,
          waitSince: store.state.waitSince,
          checkedBlock: store.state.checkedBlock,
        },
        eligibility,
      );
    },
  };
  return { store, handler };
}
const progress: ReplicaPhaseOutcome = {
  tag: "progress",
  receipt: { phase: "download", key: "x" },
};

describe("S2b attempt-scoped results", () => {
  it("a timed-out attempt's late plan never runs, even after a later Retry", async () => {
    let release = () => undefined as void;
    let calls = 0;
    const effects: string[] = [];
    const { store, handler } = single(async () => {
      calls++;
      if (calls === 1) {
        await new Promise<void>((r) => (release = r));
        return { outcome: progress, plan: () => void effects.push("late") };
      }
      return { outcome: { tag: "retry", problem: "download_failed" } };
    });
    const co = createReplicaCoordinator({ phases: [handler], deadlineMs: 20 });
    const first = await co.step({ now: T0, budget: { units: 10 } });
    expect(first.problems[0]?.problem).toBe("deadline_exceeded");
    release();
    await sleep(10);
    await co.step({ now: T0 + 10_000, budget: { units: 10 } });
    expect(effects).toEqual([]);
    expect(store.outcome).toMatchObject({
      tag: "retry",
      problem: "download_failed",
    });
    expect(store.state.attempts).toBe(2);
  });

  it("an aborted host signal ends the attempt and persists nothing", async () => {
    const { store, handler } = single((signal) =>
      abortable(signal, () => new Promise<ReplicaAttempt>(() => undefined)),
    );
    const co = createReplicaCoordinator({ phases: [handler] });
    const controller = new AbortController();
    const step = co.step({
      now: T0,
      signal: controller.signal,
      budget: { units: 10 },
    });
    controller.abort();
    const report = await step;
    expect(report.receipts).toEqual([]);
    expect(store.commits).toBe(0);
  });

  it("releases a successful fetch discarded by an immediate abort", async () => {
    const controller = new AbortController();
    let releases = 0;
    const { store, handler } = single(async () => {
      controller.abort();
      return {
        outcome: progress,
        release: () => releases++,
      };
    });
    const co = createReplicaCoordinator({ phases: [handler] });

    const report = await co.step({
      now: T0,
      signal: controller.signal,
      budget: { units: 10 },
    });
    await sleep(0);

    expect(report.receipts).toEqual([]);
    expect(store.commits).toBe(0);
    expect(releases).toBe(1);
  });

  it("a plan whose transaction fails persists the commit problem's Retry, without the plan", async () => {
    const { store, handler } = single(async () => ({
      outcome: progress,
      plan() {
        throw new Error("constraint failed");
      },
    }));
    const co = createReplicaCoordinator({ phases: [handler] });
    const report = await co.step({ now: T0, budget: { units: 10 } });
    expect(report.receipts).toEqual([]);
    expect(report.problems).toMatchObject([
      { problem: "download_failed", nextEligible: T0 + 1000 },
    ]);
    expect(store.commits).toBe(2);
    expect(store.outcome).toMatchObject({
      tag: "retry",
      problem: "download_failed",
    });
  });

  it("a plan may refine the verdict from what it committed", async () => {
    const { store, handler } = single(async () => ({
      outcome: progress,
      plan: () => ({
        tag: "wait",
        dependency: { kind: "mapping", key: "conn" },
      }),
    }));
    const co = createReplicaCoordinator({ phases: [handler] });
    const report = await co.step({ now: T0, budget: { units: 10 } });
    expect(report.waits).toMatchObject([{ dependency: { kind: "mapping" } }]);
    expect(store.outcome?.tag).toBe("wait");
  });
});

describe("S2b the coordinator's clock", () => {
  it("settles at the time the attempt ended, so a slow failure keeps its full backoff", async () => {
    const clock = { now: T0 };
    const { store, handler } = single(async () => {
      clock.now += 5_000;
      return { outcome: { tag: "retry", problem: "download_failed" } };
    });
    const co = createReplicaCoordinator({
      phases: [handler],
      clock: () => clock.now,
    });
    const report = await co.step({ now: T0, budget: { units: 10 } });
    expect(store.state.nextEligible).toBe(T0 + 5_000 + 1_000);
    expect(report.nextWake).toBe(T0 + 6_000);
  });
});

describe("S2b hints are bounded and optional", () => {
  it("a hint read that never settles costs at most the deadline once, and is not awaited again", async () => {
    let reads = 0;
    const { store, handler } = single(async () => ({ outcome: progress }));
    const co = createReplicaCoordinator({
      phases: [handler],
      deadlineMs: 30,
      hint: {
        head: () => {
          reads++;
          return new Promise<bigint>(() => undefined);
        },
      },
    });
    const started = Date.now();
    await co.step({ now: T0, budget: { units: 10 } });
    await co.step({ now: T0 + 10_000, budget: { units: 10 } });
    expect(Date.now() - started).toBeLessThan(1_000);
    expect(reads).toBe(1);
    expect(store.outcome?.tag).toBe("progress");
  });
});

describe("S2b eligibility is one policy for selection and nextWake", () => {
  const wait = {
    finalityWait: true,
    nextEligible: T0,
    waitSince: T0 - 1_000,
    checkedBlock: "123",
  };
  const at = (e: Partial<ReplicaEligibility>) =>
    replicaEligibleAt(wait, {
      now: T0 + 5_000,
      head: undefined,
      hintRefreshAt: undefined,
      ...e,
    });
  it("without a hint a wait is eligible at its deadline", () => {
    expect(at({})).toBe(T0);
  });
  it("a hint at or below the verified height parks it until the next hint refresh", () => {
    expect(at({ head: 123n, hintRefreshAt: T0 + 7_000 })).toBe(T0 + 7_000);
    expect(at({ head: 50n, hintRefreshAt: T0 + 7_000 })).toBe(T0 + 7_000);
  });
  it("an advanced hint, a non-finality wait or a ten-minute wait is not parked", () => {
    expect(at({ head: 124n, hintRefreshAt: T0 + 7_000 })).toBe(T0);
    expect(
      replicaEligibleAt(
        { ...wait, finalityWait: false },
        { now: T0 + 5_000, head: 1n, hintRefreshAt: T0 + 7_000 },
      ),
    ).toBe(T0);
    expect(
      replicaEligibleAt(
        { ...wait, waitSince: T0 - 600_000 },
        { now: T0 + 5_000, head: 1n, hintRefreshAt: T0 + 7_000 },
      ),
    ).toBe(T0);
  });
  it("a parked wait never wakes later than its ten-minute bound", () => {
    expect(at({ head: 123n, hintRefreshAt: T0 + 10_000_000 })).toBe(
      T0 - 1_000 + 600_000,
    );
  });
});
