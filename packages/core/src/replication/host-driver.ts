/**
 * The host side of replication scheduling (host contract §4.4).
 *
 * A host owns only *when* to step: one timer at the coordinator's `nextWake`
 * and explicit triggers (foreground, local write, network back, "Sync now").
 * Retries, backoff, deadlines and phase order stay in the coordinator. This
 * driver adds no semantic scheduling; it only turns `nextWake` into one timer,
 * keeps steps single-flight and drains the running step on stop.
 *
 * Browser-safe: Node (`packages/server`) and PS-Lite use the same driver.
 */
import {
  validateReplicaStep,
  type ProgressReport,
  type ReplicaBudget,
} from "./coordinator.js";

/** Never step more often than this from the timer alone. */
export const REPLICA_WAKE_MIN_MS = 1_000;
/** Idle cadence: also the delay when the coordinator reports no deadline. */
export const REPLICA_WAKE_MAX_MS = 15 * 60_000;
/** Delay after a step that threw (a bug or a closed store, never a verdict). */
export const REPLICA_STEP_ERROR_DELAY_MS = 60_000;

/** One finite step. Node's transport worker and PS-Lite's runtime implement it. */
export interface ReplicationStepper {
  step(input: {
    budget: ReplicaBudget;
    signal: AbortSignal;
  }): Promise<ProgressReport>;
  /** Host-observed dependency change, e.g. `mapping:<connection>`. */
  onDependencyChanged?(key: string): unknown;
}

export interface ReplicationTimers {
  now(): number;
  setTimeout(run: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
}

export interface ReplicationDriverStatus {
  state: "stopped" | "running" | "stopping";
  stepping: boolean;
  lastStepAt?: number;
  nextWakeAt?: number;
  /** Counts from the last finished step; full entries go to `onReport`. */
  last?: {
    receipts: number;
    waits: number;
    problems: number;
    quarantines: number;
    unsupported: number;
  };
  lastError?: string;
}

export interface ReplicationDriver {
  /** Idempotent. Steps once now, then follows `nextWake`. */
  start(): void;
  /**
   * Request a step now. Single-flight: while a step runs, this returns that
   * step's report and runs one more step after it, so a write committed
   * during the step is not left for the idle timer.
   */
  trigger(): Promise<ProgressReport | undefined>;
  /** Forward a dependency change to the stepper, then trigger. */
  wake(key: string): void;
  status(): ReplicationDriverStatus;
  /**
   * Stop scheduling, abort the running step and wait at most `graceMs` for
   * it to settle. Resolves true when nothing is still running.
   */
  stop(graceMs: number): Promise<boolean>;
}

const defaultTimers: ReplicationTimers = {
  now: () => Date.now(),
  setTimeout: (run, ms) => globalThis.setTimeout(run, ms),
  clearTimeout: (handle) =>
    globalThis.clearTimeout(handle as ReturnType<typeof setTimeout>),
};

/** The timer delay for a coordinator `nextWake`, clamped to [1 s, 15 min]. */
export function replicaWakeDelay(
  nextWake: number | undefined,
  now: number,
): number {
  if (nextWake === undefined) return REPLICA_WAKE_MAX_MS;
  return Math.min(
    REPLICA_WAKE_MAX_MS,
    Math.max(REPLICA_WAKE_MIN_MS, nextWake - now),
  );
}

export function createReplicationDriver(input: {
  stepper: ReplicationStepper;
  budget: ReplicaBudget;
  /**
   * Abort a step that runs longer than this. The coordinator settles the
   * running attempt as a retry; checkpoints already committed stay.
   */
  deadlineMs?: number;
  timers?: ReplicationTimers;
  onReport?: (report: ProgressReport) => void;
  onError?: (error: unknown) => void;
}): ReplicationDriver {
  const timers = input.timers ?? defaultTimers;
  // Reject an invalid host budget at construction, not on the first timer.
  validateReplicaStep({ now: 0, budget: input.budget });
  if (
    input.deadlineMs !== undefined &&
    (!Number.isSafeInteger(input.deadlineMs) || input.deadlineMs < 1)
  )
    throw new RangeError("invalid replication step deadline");
  let state: ReplicationDriverStatus["state"] = "stopped";
  let timer: unknown;
  let nextWakeAt: number | undefined;
  let running: Promise<ProgressReport | undefined> | undefined;
  let controller: AbortController | undefined;
  let deadline: unknown;
  let again = false;
  let lastStepAt: number | undefined;
  let last: ReplicationDriverStatus["last"];
  let lastError: string | undefined;
  /** The wake delay the running step chose; read by `settle`. */
  let nextDelay = REPLICA_WAKE_MAX_MS;

  function arm(delay: number) {
    if (timer !== undefined) timers.clearTimeout(timer);
    timer = undefined;
    nextWakeAt = undefined;
    if (state !== "running") return;
    nextWakeAt = timers.now() + delay;
    timer = timers.setTimeout(() => {
      timer = undefined;
      void trigger();
    }, delay);
  }

  async function run(): Promise<ProgressReport | undefined> {
    const step = (controller = new AbortController());
    deadline =
      input.deadlineMs === undefined
        ? undefined
        : timers.setTimeout(
            () =>
              step.abort(
                new DOMException("replication step deadline", "TimeoutError"),
              ),
            input.deadlineMs,
          );
    nextDelay = REPLICA_WAKE_MAX_MS;
    try {
      const report = await input.stepper.step({
        budget: input.budget,
        signal: step.signal,
      });
      lastStepAt = timers.now();
      lastError = undefined;
      last = {
        receipts: report.receipts.length,
        waits: report.waits.length,
        problems: report.problems.length,
        quarantines: report.quarantines.length,
        unsupported: report.unsupported.length,
      };
      nextDelay = replicaWakeDelay(report.nextWake, timers.now());
      input.onReport?.(report);
      return report;
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error);
      nextDelay = REPLICA_STEP_ERROR_DELAY_MS;
      input.onError?.(error);
      return undefined;
    }
  }

  /**
   * Runs after `trigger` has assigned `running`, so a stepper that throws
   * before its first await still clears it. Doing this inside `run` would
   * clear `running` first and then have `trigger` overwrite it with a settled
   * promise, leaving the driver stalled for good.
   */
  function settle() {
    if (deadline !== undefined) timers.clearTimeout(deadline);
    deadline = undefined;
    controller = undefined;
    running = undefined;
    if (state === "running") {
      if (again) {
        again = false;
        void trigger();
      } else arm(nextDelay);
    }
  }

  function trigger(): Promise<ProgressReport | undefined> {
    if (state !== "running") return Promise.resolve(undefined);
    if (running) {
      again = true;
      return running;
    }
    if (timer !== undefined) timers.clearTimeout(timer);
    timer = undefined;
    nextWakeAt = undefined;
    const current = run();
    running = current;
    void current.then(settle, settle);
    return current;
  }

  return {
    start() {
      if (state !== "stopped") return;
      state = "running";
      void trigger();
    },
    trigger,
    wake(key) {
      input.stepper.onDependencyChanged?.(key);
      void trigger();
    },
    status: () => ({
      state,
      stepping: running !== undefined,
      ...(lastStepAt !== undefined && { lastStepAt }),
      ...(nextWakeAt !== undefined && { nextWakeAt }),
      ...(last && { last }),
      ...(lastError !== undefined && { lastError }),
    }),
    async stop(graceMs) {
      if (!Number.isFinite(graceMs) || graceMs < 0)
        throw new RangeError("invalid replication stop grace");
      if (state === "stopped") return running === undefined;
      state = "stopping";
      again = false;
      if (timer !== undefined) timers.clearTimeout(timer);
      timer = undefined;
      nextWakeAt = undefined;
      const current = running;
      controller?.abort(new DOMException("replication stopped", "AbortError"));
      let settled = current === undefined;
      if (current) {
        let grace: unknown;
        settled = await Promise.race([
          current.then(() => true),
          new Promise<boolean>((resolve) => {
            grace = timers.setTimeout(() => resolve(false), graceMs);
          }),
        ]);
        timers.clearTimeout(grace);
      }
      state = "stopped";
      return settled;
    },
  };
}
