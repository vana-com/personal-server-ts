import { describe, expect, it, vi } from "vitest";
import { createRecomputeScheduler, type SchedulerTimers } from "./scheduler.js";
import type { ComputeOutcome } from "./compute.js";
import { createInMemoryQuestionStore } from "./store.js";
import { computeDataPointId } from "../sync/data-point-id.js";
import type { QuestionRegistration } from "./types.js";

function registration(
  overrides: Partial<QuestionRegistration> = {},
): QuestionRegistration {
  return {
    questionId: "q-1",
    derivedScope: "coach.weekly",
    sourceScopes: ["oura.sleep"],
    question: "q",
    model: null,
    recompute: "on-change",
    registeredBy: { kind: "owner" },
    status: "ready",
    error: null,
    errorCode: null,
    createdAt: "2026-08-27T00:00:00.000Z",
    updatedAt: "2026-08-27T00:00:00.000Z",
    lastComputedAt: "2026-08-27T00:00:00.000Z",
    derivedVersion: 1,
    derivedCollectedAt: "2026-08-27T00:00:00Z",
    ...overrides,
  };
}

/** Manual timers: nothing fires until the test says so. */
function manualTimers() {
  const timers = new Map<number, { callback: () => void; ms: number }>();
  let next = 1;
  const api: SchedulerTimers = {
    setTimeout(callback, ms) {
      const id = next++;
      timers.set(id, { callback, ms });
      return id;
    },
    clearTimeout(handle) {
      timers.delete(handle as number);
    },
  };
  return {
    api,
    pending: () => [...timers.values()],
    fireAll() {
      const due = [...timers.entries()];
      timers.clear();
      for (const [, timer] of due) timer.callback();
    },
  };
}

async function flush() {
  await new Promise((resolve) => setTimeout(resolve, 0));
}

describe("createRecomputeScheduler", () => {
  it("marks registrations that read a changed scope stale and debounces the recompute", async () => {
    const store = createInMemoryQuestionStore({
      initial: [
        registration({ questionId: "q-1", sourceScopes: ["oura.sleep"] }),
        registration({
          questionId: "q-2",
          sourceScopes: ["chatgpt.conversations"],
        }),
        registration({
          questionId: "q-3",
          sourceScopes: ["oura.sleep"],
          status: "pending",
        }),
      ],
    });
    const timers = manualTimers();
    const compute = vi.fn(async () => undefined);
    const scheduler = createRecomputeScheduler({
      store,
      compute,
      debounceMs: 5_000,
      timers: timers.api,
    });

    scheduler.markSourceChanged("oura.sleep");
    await scheduler.whenIdle();

    expect((await store.get("q-1"))!.status).toBe("stale");
    expect((await store.get("q-2"))!.status).toBe("ready");
    // Never computed: stays pending (still scheduled).
    expect((await store.get("q-3"))!.status).toBe("pending");
    expect(timers.pending().map((t) => t.ms)).toEqual([5_000, 5_000]);
    expect(compute).not.toHaveBeenCalled();

    // A second change inside the quiet period resets the timer, no extra run.
    scheduler.markSourceChanged("oura.sleep");
    await scheduler.whenIdle();
    expect(timers.pending()).toHaveLength(2);

    timers.fireAll();
    await scheduler.whenIdle();
    expect(compute.mock.calls.map((call) => call[0]).sort()).toEqual([
      "q-1",
      "q-3",
    ]);
  });

  it("markSourceChanged skips snapshot questions; an explicit recompute still runs them", async () => {
    const store = createInMemoryQuestionStore({
      initial: [
        registration({ questionId: "q-snap", recompute: "snapshot" }),
        registration({ questionId: "q-live", recompute: "on-change" }),
      ],
    });
    const timers = manualTimers();
    const compute = vi.fn(async () => undefined);
    const scheduler = createRecomputeScheduler({
      store,
      compute,
      debounceMs: 0,
      timers: timers.api,
    });

    scheduler.markSourceChanged("oura.sleep");
    await scheduler.whenIdle();
    expect((await store.get("q-snap"))!.status).toBe("ready");
    expect((await store.get("q-live"))!.status).toBe("stale");
    timers.fireAll();
    await scheduler.whenIdle();
    expect(compute.mock.calls.map((call) => call[0])).toEqual(["q-live"]);

    // POST /questions/:id/recompute goes through requestRecompute, which
    // ignores the policy: the owner (or builder) asked for this run.
    scheduler.requestRecompute("q-snap", { immediate: true });
    await scheduler.whenIdle();
    timers.fireAll();
    await scheduler.whenIdle();
    expect(compute.mock.calls.map((call) => call[0])).toEqual([
      "q-live",
      "q-snap",
    ]);
  });

  it("runs one compute per question at a time and reruns once after a change during the run", async () => {
    const store = createInMemoryQuestionStore({ initial: [registration()] });
    const timers = manualTimers();
    let release: () => void = () => undefined;
    const compute = vi.fn(
      () =>
        new Promise<void>((resolve) => {
          release = resolve;
        }),
    );
    const scheduler = createRecomputeScheduler({
      store,
      compute,
      debounceMs: 0,
      timers: timers.api,
    });

    scheduler.requestRecompute("q-1", { immediate: true });
    await flush();
    timers.fireAll();
    await flush();
    expect(compute).toHaveBeenCalledTimes(1);

    // Two changes while in flight coalesce into a single rerun.
    scheduler.markSourceChanged("oura.sleep");
    scheduler.markSourceChanged("oura.sleep");
    await flush();
    timers.fireAll();
    await flush();
    expect(compute).toHaveBeenCalledTimes(1);

    release();
    await flush();
    await flush();
    // The rerun was scheduled (timer) after the first run finished.
    timers.fireAll();
    await flush();
    expect(compute).toHaveBeenCalledTimes(2);
    release();
    await scheduler.whenIdle();
  });

  it("skips a question whose own output the new version descends from", async () => {
    const OWNER = "0x1111111111111111111111111111111111111111" as const;
    const store = createInMemoryQuestionStore({
      initial: [
        registration({
          questionId: "q-1",
          derivedScope: "coach.weekly",
          sourceScopes: ["spine.summary"],
        }),
        registration({
          questionId: "q-2",
          derivedScope: "other.view",
          sourceScopes: ["spine.summary"],
        }),
      ],
    });
    const timers = manualTimers();
    const compute = vi.fn(async () => undefined);
    const scheduler = createRecomputeScheduler({
      store,
      compute,
      debounceMs: 0,
      serverOwner: OWNER,
      timers: timers.api,
    });
    // spine.summary (synced from another replica) was computed FROM
    // coach.weekly: q-1 must not chase its own tail; q-2 still runs.
    scheduler.markSourceChanged("spine.summary", {
      lineageSources: [computeDataPointId(OWNER, "coach.weekly").toUpperCase()],
    });
    await scheduler.whenIdle();
    expect((await store.get("q-1"))!.status).toBe("ready");
    expect((await store.get("q-2"))!.status).toBe("stale");
    timers.fireAll();
    await scheduler.whenIdle();
    expect(compute.mock.calls.map((call) => call[0])).toEqual(["q-2"]);
  });

  it("the first start() reschedules questions a previous process left pending or stale", async () => {
    const store = createInMemoryQuestionStore({
      initial: [
        registration({ questionId: "q-ready", status: "ready" }),
        registration({ questionId: "q-pending", status: "pending" }),
        registration({ questionId: "q-stale", status: "stale" }),
      ],
    });
    const timers = manualTimers();
    const compute = vi.fn(async () => undefined);
    const scheduler = createRecomputeScheduler({
      store,
      compute,
      debounceMs: 0,
      timers: timers.api,
    });
    // Boot: no stop() ever happened, the store simply came back populated.
    scheduler.start();
    await scheduler.whenIdle();
    expect(timers.pending()).toHaveLength(2);
    timers.fireAll();
    await scheduler.whenIdle();
    expect(compute.mock.calls.map((call) => call[0]).sort()).toEqual([
      "q-pending",
      "q-stale",
    ]);
    // While running, another start() must not replay anything.
    scheduler.start();
    await scheduler.whenIdle();
    expect(timers.pending()).toHaveLength(0);
    expect(compute).toHaveBeenCalledTimes(2);
  });

  it("start() after stop() reschedules pending and stale questions", async () => {
    const store = createInMemoryQuestionStore({
      initial: [
        registration({ questionId: "q-ready", status: "ready" }),
        registration({ questionId: "q-pending", status: "pending" }),
        registration({ questionId: "q-stale", status: "stale" }),
        registration({ questionId: "q-failed", status: "failed" }),
      ],
    });
    const timers = manualTimers();
    const compute = vi.fn(async () => undefined);
    const scheduler = createRecomputeScheduler({
      store,
      compute,
      debounceMs: 0,
      timers: timers.api,
    });
    scheduler.stop();
    scheduler.start();
    scheduler.start();
    await scheduler.whenIdle();
    expect(timers.pending()).toHaveLength(2);
    timers.fireAll();
    await scheduler.whenIdle();
    expect(compute.mock.calls.map((call) => call[0]).sort()).toEqual([
      "q-pending",
      "q-stale",
    ]);
  });

  it("stop cancels pending timers", async () => {
    const store = createInMemoryQuestionStore({ initial: [registration()] });
    const timers = manualTimers();
    const compute = vi.fn(async () => undefined);
    const scheduler = createRecomputeScheduler({
      store,
      compute,
      debounceMs: 1_000,
      timers: timers.api,
    });
    scheduler.requestRecompute("q-1");
    await scheduler.whenIdle();
    expect(timers.pending()).toHaveLength(1);
    scheduler.stop();
    expect(timers.pending()).toHaveLength(0);
    scheduler.markSourceChanged("oura.sleep");
    await scheduler.whenIdle();
    expect(compute).not.toHaveBeenCalled();
  });
});

describe("automatic retry of transient failures", () => {
  const NOW = new Date("2026-08-27T10:00:00.000Z");

  function failedOutcome(errorCode: "inference_unavailable" | "internal") {
    return {
      status: "failed" as const,
      registration: registration({ status: "failed", errorCode }),
      error: "upstream down",
    };
  }

  function readyOutcome() {
    return { status: "ready" as const, registration: registration() };
  }

  function retryScheduler(outcomes: unknown[]) {
    const store = createInMemoryQuestionStore({
      initial: [registration({ status: "pending" })],
    });
    const timers = manualTimers();
    const compute = vi.fn(
      async () => outcomes.shift() as ComputeOutcome | undefined,
    );
    const scheduler = createRecomputeScheduler({
      store,
      compute,
      debounceMs: 5_000,
      retryDelaysMs: [60_000, 300_000],
      timers: timers.api,
      now: () => NOW,
    });
    return { scheduler, timers, compute, store };
  }

  it("retries an inference_unavailable failure on a backoff schedule and then gives up", async () => {
    const { scheduler, timers, compute } = retryScheduler([
      failedOutcome("inference_unavailable"),
      failedOutcome("inference_unavailable"),
      failedOutcome("inference_unavailable"),
    ]);
    scheduler.requestRecompute("q-1", { immediate: true });
    await scheduler.whenIdle();
    timers.fireAll();
    await scheduler.whenIdle();
    expect(compute).toHaveBeenCalledTimes(1);
    // First retry after the first backoff step.
    expect(timers.pending().map((t) => t.ms)).toEqual([60_000]);
    expect(scheduler.nextRetryAt("q-1")).toBe("2026-08-27T10:01:00.000Z");

    timers.fireAll();
    await scheduler.whenIdle();
    expect(compute).toHaveBeenCalledTimes(2);
    expect(timers.pending().map((t) => t.ms)).toEqual([300_000]);
    expect(scheduler.nextRetryAt("q-1")).toBe("2026-08-27T10:05:00.000Z");

    timers.fireAll();
    await scheduler.whenIdle();
    expect(compute).toHaveBeenCalledTimes(3);
    // Backoff exhausted: no further timer, nothing promised.
    expect(timers.pending()).toEqual([]);
    expect(scheduler.nextRetryAt("q-1")).toBeNull();
  });

  it("does not retry a non-transient failure", async () => {
    const { scheduler, timers, compute } = retryScheduler([
      failedOutcome("internal"),
    ]);
    scheduler.requestRecompute("q-1", { immediate: true });
    await scheduler.whenIdle();
    timers.fireAll();
    await scheduler.whenIdle();
    expect(compute).toHaveBeenCalledTimes(1);
    expect(timers.pending()).toEqual([]);
    expect(scheduler.nextRetryAt("q-1")).toBeNull();
  });

  it("a success resets the backoff chain", async () => {
    const { scheduler, timers, compute } = retryScheduler([
      failedOutcome("inference_unavailable"),
      readyOutcome(),
      failedOutcome("inference_unavailable"),
    ]);
    scheduler.requestRecompute("q-1", { immediate: true });
    await scheduler.whenIdle();
    timers.fireAll();
    await scheduler.whenIdle();
    timers.fireAll(); // retry 1 -> success
    await scheduler.whenIdle();
    expect(compute).toHaveBeenCalledTimes(2);
    expect(timers.pending()).toEqual([]);
    expect(scheduler.nextRetryAt("q-1")).toBeNull();

    // A fresh failure starts from the FIRST step again.
    scheduler.requestRecompute("q-1", { immediate: true });
    await scheduler.whenIdle();
    timers.fireAll();
    await scheduler.whenIdle();
    expect(compute).toHaveBeenCalledTimes(3);
    expect(timers.pending().map((t) => t.ms)).toEqual([60_000]);
  });

  it("a source change during the retry window supersedes the retry and resets the chain", async () => {
    const { scheduler, timers, compute } = retryScheduler([
      failedOutcome("inference_unavailable"),
      failedOutcome("inference_unavailable"),
      failedOutcome("inference_unavailable"),
    ]);
    scheduler.requestRecompute("q-1", { immediate: true });
    await scheduler.whenIdle();
    timers.fireAll();
    await scheduler.whenIdle();
    timers.fireAll(); // retry 1 -> fails again, next step 300s
    await scheduler.whenIdle();
    expect(timers.pending().map((t) => t.ms)).toEqual([300_000]);

    scheduler.markSourceChanged("oura.sleep");
    await scheduler.whenIdle();
    // The retry timer is replaced by the debounce timer; the chain restarts.
    expect(timers.pending().map((t) => t.ms)).toEqual([5_000]);
    expect(scheduler.nextRetryAt("q-1")).toBeNull();
    timers.fireAll();
    await scheduler.whenIdle();
    expect(compute).toHaveBeenCalledTimes(3);
    expect(timers.pending().map((t) => t.ms)).toEqual([60_000]);
  });

  it("reports no retry for an unknown question", async () => {
    const { scheduler } = retryScheduler([]);
    expect(scheduler.nextRetryAt("nope")).toBeNull();
  });

  it("stop() clears any scheduled retry", async () => {
    const { scheduler, timers } = retryScheduler([
      failedOutcome("inference_unavailable"),
    ]);
    scheduler.requestRecompute("q-1", { immediate: true });
    await scheduler.whenIdle();
    timers.fireAll();
    await scheduler.whenIdle();
    expect(scheduler.nextRetryAt("q-1")).not.toBeNull();
    scheduler.stop();
    expect(timers.pending()).toEqual([]);
    expect(scheduler.nextRetryAt("q-1")).toBeNull();
  });
});

describe("retry interleavings (review findings)", () => {
  const NOW = new Date("2026-08-27T10:00:00.000Z");

  function reg(overrides: Partial<QuestionRegistration> = {}) {
    return registration({ status: "pending", ...overrides });
  }

  function failedOutcome() {
    return {
      status: "failed" as const,
      registration: reg({
        status: "failed",
        errorCode: "inference_unavailable",
      }),
      error: "upstream down",
    };
  }

  it("a source change during the in-flight compute keeps the 5s debounce; the retry branch must not clobber it", async () => {
    const store = createInMemoryQuestionStore({ initial: [reg()] });
    const timers = manualTimers();
    let settle!: (value: unknown) => void;
    let calls = 0;
    const compute = vi.fn(() => {
      calls += 1;
      if (calls === 1) {
        return new Promise((resolve) => {
          settle = resolve;
        });
      }
      return Promise.resolve(undefined);
    });
    const scheduler = createRecomputeScheduler({
      store,
      compute: compute as (
        questionId: string,
      ) => Promise<ComputeOutcome | void>,
      debounceMs: 5_000,
      retryDelaysMs: [60_000, 300_000],
      timers: timers.api,
      now: () => NOW,
    });

    scheduler.requestRecompute("q-1", { immediate: true });
    await scheduler.whenIdle();
    timers.fireAll(); // compute 1 starts and hangs
    await Promise.resolve();
    expect(calls).toBe(1);

    // Fresh data lands while the compute is in flight: debounce scheduled.
    scheduler.markSourceChanged("oura.sleep");
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(timers.pending().map((t) => t.ms)).toEqual([5_000]);

    // The in-flight compute now settles with a transient failure. The
    // pending debounce must survive; no 60s retry may replace it.
    settle(failedOutcome());
    await scheduler.whenIdle();
    expect(timers.pending().map((t) => t.ms)).toEqual([5_000]);
    expect(scheduler.nextRetryAt("q-1")).toBeNull();
  });

  it("a transient failure that settles after stop() leaves no phantom retry promise", async () => {
    const store = createInMemoryQuestionStore({ initial: [reg()] });
    const timers = manualTimers();
    let settle!: (value: unknown) => void;
    const compute = vi.fn(
      () =>
        new Promise((resolve) => {
          settle = resolve;
        }),
    );
    const scheduler = createRecomputeScheduler({
      store,
      compute: compute as (
        questionId: string,
      ) => Promise<ComputeOutcome | void>,
      debounceMs: 5_000,
      retryDelaysMs: [60_000],
      timers: timers.api,
      now: () => NOW,
    });
    scheduler.requestRecompute("q-1", { immediate: true });
    await scheduler.whenIdle();
    timers.fireAll(); // compute starts and hangs
    await Promise.resolve();
    scheduler.stop();
    settle(failedOutcome());
    await scheduler.whenIdle();
    expect(timers.pending()).toEqual([]);
    expect(scheduler.nextRetryAt("q-1")).toBeNull();
  });

  it("while the retry compute is in flight, no retry is promised (retryAt cleared when the timer fires)", async () => {
    const store = createInMemoryQuestionStore({ initial: [reg()] });
    const timers = manualTimers();
    let calls = 0;
    let settle!: (value: unknown) => void;
    const compute = vi.fn(() => {
      calls += 1;
      if (calls === 1) return Promise.resolve(failedOutcome());
      return new Promise((resolve) => {
        settle = resolve;
      });
    });
    const scheduler = createRecomputeScheduler({
      store,
      compute: compute as (
        questionId: string,
      ) => Promise<ComputeOutcome | void>,
      debounceMs: 5_000,
      retryDelaysMs: [60_000],
      timers: timers.api,
      now: () => NOW,
    });
    scheduler.requestRecompute("q-1", { immediate: true });
    await scheduler.whenIdle();
    timers.fireAll(); // compute 1 -> transient failure -> retry in 60s
    await scheduler.whenIdle();
    expect(scheduler.nextRetryAt("q-1")).toBe("2026-08-27T10:01:00.000Z");

    timers.fireAll(); // retry fires; compute 2 hangs
    await Promise.resolve();
    expect(calls).toBe(2);
    // No pending retry while it runs: a past timestamp would pin the
    // status route's retryAfterSeconds at 0 and invite a tight poll loop.
    expect(scheduler.nextRetryAt("q-1")).toBeNull();
    // But the retry is RUNNING, not abandoned: without this signal the
    // status route would serve the terminal failed-with-no-retry signature
    // for the whole in-flight window.
    expect(scheduler.retryInFlight("q-1")).toBe(true);
    settle(undefined);
    await scheduler.whenIdle();
    expect(scheduler.retryInFlight("q-1")).toBe(false);
  });

  it("a debounce run is not reported as a retry in flight", async () => {
    const store = createInMemoryQuestionStore({ initial: [reg()] });
    const timers = manualTimers();
    let settle!: (value: unknown) => void;
    const compute = vi.fn(
      () =>
        new Promise((resolve) => {
          settle = resolve;
        }),
    );
    const scheduler = createRecomputeScheduler({
      store,
      compute: compute as (
        questionId: string,
      ) => Promise<ComputeOutcome | void>,
      debounceMs: 5_000,
      retryDelaysMs: [60_000],
      timers: timers.api,
      now: () => NOW,
    });
    scheduler.markSourceChanged("oura.sleep");
    await scheduler.whenIdle();
    timers.fireAll(); // debounce fires; compute hangs
    await Promise.resolve();
    expect(scheduler.retryInFlight("q-1")).toBe(false);
    settle(undefined);
    await scheduler.whenIdle();
  });

  it("a runtime-unavailable skip mid-chain reschedules the retry instead of dropping the chain", async () => {
    const store = createInMemoryQuestionStore({ initial: [reg()] });
    const timers = manualTimers();
    const outcomes: Array<ComputeOutcome | undefined> = [
      failedOutcome(),
      { status: "skipped", reason: "runtime-unavailable" },
      failedOutcome(),
    ];
    const compute = vi.fn(
      async () => outcomes.shift() as ComputeOutcome | undefined,
    );
    const scheduler = createRecomputeScheduler({
      store,
      compute: compute as (
        questionId: string,
      ) => Promise<ComputeOutcome | void>,
      debounceMs: 5_000,
      retryDelaysMs: [60_000, 300_000, 1_800_000],
      timers: timers.api,
      now: () => NOW,
    });
    scheduler.requestRecompute("q-1", { immediate: true });
    await scheduler.whenIdle();
    timers.fireAll(); // failure -> retry in 60s
    await scheduler.whenIdle();
    expect(timers.pending().map((t) => t.ms)).toEqual([60_000]);

    timers.fireAll(); // retry fires but the runtime is unavailable
    await scheduler.whenIdle();
    // The chain continues instead of ending with a failed question that
    // nothing will ever recompute.
    expect(timers.pending().map((t) => t.ms)).toEqual([300_000]);
    expect(scheduler.nextRetryAt("q-1")).not.toBeNull();
  });

  it("marking a failed question stale clears its errorCode", async () => {
    const store = createInMemoryQuestionStore({
      initial: [
        reg({
          status: "failed",
          error: "upstream down",
          errorCode: "inference_unavailable",
        }),
      ],
    });
    const timers = manualTimers();
    const scheduler = createRecomputeScheduler({
      store,
      compute: vi.fn(async () => undefined),
      debounceMs: 5_000,
      timers: timers.api,
    });
    scheduler.markSourceChanged("oura.sleep");
    await scheduler.whenIdle();
    const stored = (await store.get("q-1"))!;
    expect(stored.status).toBe("stale");
    expect(stored.errorCode).toBeNull();
  });
});
