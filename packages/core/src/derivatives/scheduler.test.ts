import { describe, expect, it, vi } from "vitest";
import { createRecomputeScheduler, type SchedulerTimers } from "./scheduler.js";
import { createInMemoryQuestionStore } from "./store.js";
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
    registeredBy: { kind: "owner" },
    status: "ready",
    error: null,
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
