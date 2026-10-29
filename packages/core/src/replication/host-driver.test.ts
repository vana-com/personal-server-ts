import { describe, expect, it } from "vitest";
import type { ProgressReport } from "./coordinator.js";
import {
  createReplicationDriver,
  REPLICA_STEP_ERROR_DELAY_MS,
  REPLICA_WAKE_MAX_MS,
  REPLICA_WAKE_MIN_MS,
  replicaWakeDelay,
  type ReplicationStepper,
  type ReplicationTimers,
} from "./host-driver.js";

const T0 = 1_700_000_000_000;

function fakeTimers() {
  let now = T0;
  let next = 1;
  const pending = new Map<number, { at: number; run: () => void }>();
  const timers: ReplicationTimers = {
    now: () => now,
    setTimeout(run, ms) {
      const id = next++;
      pending.set(id, { at: now + ms, run });
      return id;
    },
    clearTimeout(handle) {
      pending.delete(handle as number);
    },
  };
  return {
    timers,
    pending,
    /** Delays of the armed timers, soonest first. */
    armed: () => [...pending.values()].map((t) => t.at - now).sort(),
    /** Advance the clock and run every timer now due. */
    advance(ms: number) {
      now += ms;
      for (const [id, timer] of [...pending])
        if (timer.at <= now) {
          pending.delete(id);
          timer.run();
        }
    },
  };
}

const report = (nextWake?: number): ProgressReport => ({
  receipts: [],
  waits: [],
  problems: [],
  quarantines: [],
  unsupported: [],
  nextWake,
});

function gate<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((a, b) => {
    resolve = a;
    reject = b;
  });
  return { promise, resolve, reject };
}

/** A stepper whose steps finish only when the test settles them. */
function manualStepper() {
  const steps: {
    signal: AbortSignal;
    done: ReturnType<typeof gate<ProgressReport>>;
  }[] = [];
  const keys: string[] = [];
  const stepper: ReplicationStepper = {
    step({ signal }) {
      const done = gate<ProgressReport>();
      steps.push({ signal, done });
      return done.promise;
    },
    onDependencyChanged: (key) => keys.push(key),
  };
  return { stepper, steps, keys };
}

const flush = () => new Promise((resolve) => setImmediate(resolve));
const budget = { units: 20, bytes: 8 * 1024 * 1024 };

describe("replicaWakeDelay", () => {
  it("clamps nextWake to [1 s, 15 min] and idles at 15 min", () => {
    expect(replicaWakeDelay(undefined, T0)).toBe(REPLICA_WAKE_MAX_MS);
    expect(replicaWakeDelay(T0, T0)).toBe(REPLICA_WAKE_MIN_MS);
    expect(replicaWakeDelay(T0 - 5_000, T0)).toBe(REPLICA_WAKE_MIN_MS);
    expect(replicaWakeDelay(T0 + 42_000, T0)).toBe(42_000);
    expect(replicaWakeDelay(T0 + 3_600_000, T0)).toBe(REPLICA_WAKE_MAX_MS);
  });
});

describe("createReplicationDriver", () => {
  it("rejects an invalid budget before any step", () => {
    const { stepper, steps } = manualStepper();
    for (const bad of [
      { units: 0 },
      { units: 1.5 },
      { units: Infinity },
      { units: 1, bytes: 0 },
    ])
      expect(() => createReplicationDriver({ stepper, budget: bad })).toThrow(
        RangeError,
      );
    expect(steps).toHaveLength(0);
  });

  it("does nothing until started, then steps once and arms one timer at nextWake", async () => {
    const clock = fakeTimers();
    const { stepper, steps } = manualStepper();
    const driver = createReplicationDriver({
      stepper,
      budget,
      timers: clock.timers,
    });
    expect(await driver.trigger()).toBeUndefined();
    expect(steps).toHaveLength(0);
    driver.start();
    driver.start();
    expect(steps).toHaveLength(1);
    expect(driver.status()).toMatchObject({ state: "running", stepping: true });
    steps[0]!.done.resolve(report(T0 + 30_000));
    await flush();
    expect(clock.armed()).toEqual([30_000]);
    expect(driver.status()).toMatchObject({
      stepping: false,
      nextWakeAt: T0 + 30_000,
      last: { receipts: 0, problems: 0 },
    });
    clock.advance(30_000);
    expect(steps).toHaveLength(2);
    steps[1]!.done.resolve(report(undefined));
    await flush();
    expect(clock.armed()).toEqual([REPLICA_WAKE_MAX_MS]);
  });

  it("is single-flight: a trigger during a step joins it and runs one more step after", async () => {
    const clock = fakeTimers();
    const { stepper, steps } = manualStepper();
    const driver = createReplicationDriver({
      stepper,
      budget,
      timers: clock.timers,
    });
    driver.start();
    const joined = [driver.trigger(), driver.trigger(), driver.trigger()];
    expect(steps).toHaveLength(1);
    const first = report(T0 + 60_000);
    steps[0]!.done.resolve(first);
    for (const result of await Promise.all(joined)) expect(result).toBe(first);
    await flush();
    // Three triggers during the step collapse into one follow-up step.
    expect(steps).toHaveLength(2);
    expect(clock.armed()).toEqual([]);
    steps[1]!.done.resolve(report(T0 + 60_000));
    await flush();
    expect(steps).toHaveLength(2);
    expect(clock.armed()).toEqual([60_000]);
  });

  it("a trigger replaces the armed timer instead of adding one", async () => {
    const clock = fakeTimers();
    const { stepper, steps } = manualStepper();
    const driver = createReplicationDriver({
      stepper,
      budget,
      timers: clock.timers,
    });
    driver.start();
    steps[0]!.done.resolve(report(undefined));
    await flush();
    expect(clock.armed()).toEqual([REPLICA_WAKE_MAX_MS]);
    void driver.trigger();
    expect(clock.armed()).toEqual([]);
    expect(steps).toHaveLength(2);
    steps[1]!.done.resolve(report(T0 + 5_000));
    await flush();
    expect(clock.armed()).toEqual([5_000]);
  });

  it("wake forwards the dependency to the stepper, then steps", async () => {
    const clock = fakeTimers();
    const { stepper, steps, keys } = manualStepper();
    const driver = createReplicationDriver({
      stepper,
      budget,
      timers: clock.timers,
    });
    driver.start();
    steps[0]!.done.resolve(report(undefined));
    await flush();
    driver.wake("mapping:conn");
    expect(keys).toEqual(["mapping:conn"]);
    expect(steps).toHaveLength(2);
  });

  it("a step that throws is reported and retried after the error delay", async () => {
    const clock = fakeTimers();
    const { stepper, steps } = manualStepper();
    const errors: unknown[] = [];
    const driver = createReplicationDriver({
      stepper,
      budget,
      timers: clock.timers,
      onError: (error) => errors.push(error),
    });
    driver.start();
    steps[0]!.done.reject(new Error("store closed"));
    await flush();
    expect(errors).toHaveLength(1);
    expect(driver.status().lastError).toBe("store closed");
    expect(clock.armed()).toEqual([REPLICA_STEP_ERROR_DELAY_MS]);
    clock.advance(REPLICA_STEP_ERROR_DELAY_MS);
    expect(steps).toHaveLength(2);
    steps[1]!.done.resolve(report(undefined));
    await flush();
    expect(driver.status().lastError).toBeUndefined();
  });

  it("a step that throws synchronously is retried after the error delay", async () => {
    const clock = fakeTimers();
    let calls = 0;
    const driver = createReplicationDriver({
      stepper: {
        step() {
          calls += 1;
          if (calls === 1) throw new Error("store closed");
          return Promise.resolve(report(undefined));
        },
      },
      budget,
      timers: clock.timers,
    });
    driver.start();
    await flush();
    expect(calls).toBe(1);
    expect(driver.status().stepping).toBe(false);
    expect(driver.status().lastError).toBe("store closed");
    expect(clock.armed()).toEqual([REPLICA_STEP_ERROR_DELAY_MS]);
    clock.advance(REPLICA_STEP_ERROR_DELAY_MS);
    await flush();
    expect(calls).toBe(2);
    expect(driver.status().stepping).toBe(false);
    expect(driver.status().lastError).toBeUndefined();
  });

  it("aborts a step that passes its deadline and clears the deadline after a step", async () => {
    const clock = fakeTimers();
    const { stepper, steps } = manualStepper();
    expect(() =>
      createReplicationDriver({ stepper, budget, deadlineMs: 0 }),
    ).toThrow(RangeError);
    const driver = createReplicationDriver({
      stepper,
      budget,
      deadlineMs: 30_000,
      timers: clock.timers,
    });
    driver.start();
    expect(clock.armed()).toEqual([30_000]);
    clock.advance(30_000);
    expect(steps[0]!.signal.aborted).toBe(true);
    expect((steps[0]!.signal.reason as DOMException).name).toBe("TimeoutError");
    steps[0]!.done.resolve(report(undefined));
    await flush();
    // Only the idle wake remains; the spent deadline is gone.
    expect(clock.armed()).toEqual([REPLICA_WAKE_MAX_MS]);
    void driver.trigger();
    steps[1]!.done.resolve(report(undefined));
    await flush();
    expect(steps[1]!.signal.aborted).toBe(false);
    expect(clock.armed()).toEqual([REPLICA_WAKE_MAX_MS]);
  });

  it("stop aborts the running step, waits for it to settle and arms nothing", async () => {
    const clock = fakeTimers();
    const { stepper, steps } = manualStepper();
    const driver = createReplicationDriver({
      stepper,
      budget,
      timers: clock.timers,
    });
    driver.start();
    void driver.trigger(); // a follow-up that stop must cancel
    const stopping = driver.stop(5_000);
    expect(steps[0]!.signal.aborted).toBe(true);
    expect(driver.status().state).toBe("stopping");
    steps[0]!.done.resolve(report(T0 + 1_000));
    expect(await stopping).toBe(true);
    await flush();
    expect(steps).toHaveLength(1);
    expect(clock.armed()).toEqual([]);
    expect(driver.status()).toMatchObject({
      state: "stopped",
      stepping: false,
    });
    expect(await driver.trigger()).toBeUndefined();
  });

  it("stop gives up after the grace period when a step ignores its abort", async () => {
    const clock = fakeTimers();
    const { stepper, steps } = manualStepper();
    const driver = createReplicationDriver({
      stepper,
      budget,
      timers: clock.timers,
    });
    driver.start();
    const stopping = driver.stop(5_000);
    clock.advance(5_000);
    expect(await stopping).toBe(false);
    expect(driver.status().state).toBe("stopped");
    // The late step settles without arming a timer.
    steps[0]!.done.resolve(report(T0));
    await flush();
    expect(clock.armed()).toEqual([]);
  });

  it("stop while idle clears the timer", async () => {
    const clock = fakeTimers();
    const { stepper, steps } = manualStepper();
    const driver = createReplicationDriver({
      stepper,
      budget,
      timers: clock.timers,
    });
    driver.start();
    steps[0]!.done.resolve(report(undefined));
    await flush();
    expect(clock.armed()).toHaveLength(1);
    expect(await driver.stop(0)).toBe(true);
    expect(clock.armed()).toEqual([]);
    await expect(driver.stop(-1)).rejects.toThrow(RangeError);
  });
});
