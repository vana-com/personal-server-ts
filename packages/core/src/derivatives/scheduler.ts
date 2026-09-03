/**
 * Recompute scheduler: marks registrations stale when one of their source
 * scopes changes and runs the compute when someone actually asks for the
 * answer, one in flight per question. Timers and the clock are injectable
 * so tests drive it deterministically.
 *
 * Compute is just-in-time, not preemptive. A source refresh only marks the
 * answer stale; the recompute happens on the next authorized demand (a read
 * of the derived scope, the reader-facing status route, or an explicit
 * `POST /questions/:id/recompute`). Otherwise the inference bill would
 * scale with how often the owner's sources refresh rather than with how
 * often anyone reads the answer.
 */

import { computeDataPointId } from "../sync/data-point-id.js";
import type { ComputeOutcome } from "./compute.js";
import type { QuestionStore } from "./types.js";

export interface SchedulerTimers {
  setTimeout(callback: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
}

export interface RecomputeSchedulerOptions {
  store: QuestionStore;
  /**
   * Runs one compute; must not throw for compute failures. The outcome is
   * what the retry logic classifies — a wrapper that swallows it (returns
   * void) silently disables automatic retries, so forward it.
   */
  compute(questionId: string): Promise<ComputeOutcome | void>;
  /**
   * Quiet period before a recompute that was requested without `immediate`
   * (default 5s). A source change schedules nothing at all, and demand runs
   * at once, so nothing on the default deployment waits on this.
   */
  debounceMs?: number;
  /**
   * Backoff steps for automatic retry of a compute that failed with the
   * transient class (`errorCode: "inference_unavailable"`). Default
   * 1m, 5m, 30m; empty disables retry. Non-transient failures never
   * retry — they wait for a source change or an explicit recompute.
   */
  retryDelaysMs?: readonly number[];
  /**
   * Lets `markSourceChanged` recognise a new version that was computed FROM
   * a question's own derived scope (its `$lineage` names the derived data
   * point id) and skip that question: a cross-replica cycle then settles
   * instead of ping-ponging through sync. Without it every change counts.
   */
  serverOwner?: `0x${string}`;
  timers?: SchedulerTimers;
  now?: () => Date;
  logger?: {
    warn?(payload: Record<string, unknown>, message: string): void;
  };
}

export interface RecomputeScheduler {
  /**
   * A scope got a new local version (ingest or sync). Every registration
   * that lists it as a source is marked `stale` (if it had a result) and
   * NOTHING is scheduled: the recompute waits for demand. Fire and forget;
   * failures are logged.
   */
  markSourceChanged(
    scope: string,
    options?: {
      /** `$lineage.sources` of the new version, when it is a derivative. */
      lineageSources?: readonly string[];
    },
  ): void;
  /**
   * An authorized caller asked for the answer behind `derivedScope` — a read
   * of the derived data, or the reader-facing status route. Every
   * `on-change` question on that scope that is waiting for a compute
   * (`stale` or `pending`) runs now; one already running or already
   * scheduled is left alone, so N concurrent readers cause one compute.
   *
   * Callers MUST authorize first: this spends an inference call, and the
   * whole point of running on demand is that the bill follows real reads.
   * A `failed` question is not woken (its backoff chain or an explicit
   * recompute owns it) so that polling a permanently failing question
   * cannot spend a call per poll. Fire and forget; failures are logged.
   */
  markDemand(derivedScope: string): void;
  /** Schedule one question; `immediate` skips the debounce (owner recompute). */
  requestRecompute(questionId: string, options?: { immediate?: boolean }): void;
  /**
   * Next scheduled automatic retry for a failed question (ISO time), or
   * null when none is pending. In-memory, like the rest of the scheduler:
   * a restart drops the chain and the question waits for a source change
   * or an explicit recompute.
   */
  nextRetryAt(questionId: string): string | null;
  /**
   * True while a retry compute is actually RUNNING (its timer fired, the
   * compute has not settled). `nextRetryAt` is null in that window; without
   * this signal a status reader would see the terminal
   * failed-with-no-retry signature during every in-flight retry.
   */
  retryInFlight(questionId: string): boolean;
  /** Resolves once no compute or store lookup is pending or timed. */
  whenIdle(): Promise<void>;
  /** Cancel pending timers. In-flight computes finish on their own. */
  stop(): void;
  /**
   * Schedule every question left `pending` (immediately). The first call is
   * the boot reschedule: a question that has never produced an answer is
   * owed the compute its registration asked for, and a restarted process
   * only holds what the store holds. A `stale` question is NOT swept — it
   * has an answer to serve and waits for demand, otherwise every restart
   * (and in PS-Lite every tab that opens) would pay for the recomputes this
   * scheduler exists to defer. Later calls resume after `stop()`;
   * idempotent while running.
   */
  start(): void;
}

interface QuestionState {
  timer: unknown | null;
  running: Promise<void> | null;
  rerun: boolean;
  /** Consecutive transient failures already retried. */
  retryAttempts: number;
  /** When the pending retry timer fires (epoch ms), if one is set. */
  retryAtMs: number | null;
  /** The pending timer is a retry (not a debounce). */
  retryScheduled: boolean;
  /** A retry compute is running right now. */
  retryRunning: boolean;
  /**
   * A source changed while the current compute was reading: the answer it
   * is about to write does not reflect that change, so the question goes
   * back to `stale` when it settles.
   */
  sourceChangedDuringRun: boolean;
}

const DEFAULT_RETRY_DELAYS_MS: readonly number[] = [60_000, 300_000, 1_800_000];

/**
 * Structural check on the compute callback's resolved value: retry is only
 * for a failed outcome whose stored class is the one transient kind. A
 * callback that resolves anything else (older wiring, tests) never retries.
 */
/**
 * A compute skipped because the runtime is unavailable (PS-Lite with the
 * hosting tab inactive). During a retry chain this must not end the chain:
 * nothing else would ever reschedule a failed question.
 */
function isRuntimeSkipOutcome(outcome: unknown): boolean {
  if (typeof outcome !== "object" || outcome === null) return false;
  const shaped = outcome as { status?: unknown; reason?: unknown };
  return shaped.status === "skipped" && shaped.reason === "runtime-unavailable";
}

function isTransientFailureOutcome(outcome: unknown): boolean {
  if (typeof outcome !== "object" || outcome === null) return false;
  const shaped = outcome as {
    status?: unknown;
    registration?: { errorCode?: unknown } | null;
  };
  return (
    shaped.status === "failed" &&
    shaped.registration?.errorCode === "inference_unavailable"
  );
}

const defaultTimers: SchedulerTimers = {
  setTimeout: (callback, ms) => setTimeout(callback, ms),
  clearTimeout: (handle) =>
    clearTimeout(handle as ReturnType<typeof setTimeout>),
};

export function createRecomputeScheduler(
  options: RecomputeSchedulerOptions,
): RecomputeScheduler {
  const debounceMs = options.debounceMs ?? 5_000;
  const retryDelaysMs = options.retryDelaysMs ?? DEFAULT_RETRY_DELAYS_MS;
  const timers = options.timers ?? defaultTimers;
  const now = options.now ?? (() => new Date());
  const states = new Map<string, QuestionState>();
  const pending = new Set<Promise<unknown>>();
  let stopped = false;
  // Distinguishes the first start() (which must reschedule) from a
  // redundant one while already running (which must not).
  let started = false;

  function track<T>(promise: Promise<T>): Promise<T> {
    pending.add(promise);
    const done = () => pending.delete(promise);
    promise.then(done, done);
    return promise;
  }

  function warn(payload: Record<string, unknown>, message: string): void {
    options.logger?.warn?.(payload, message);
  }

  function stateFor(questionId: string): QuestionState {
    let state = states.get(questionId);
    if (!state) {
      state = {
        timer: null,
        running: null,
        rerun: false,
        retryAttempts: 0,
        retryAtMs: null,
        retryScheduled: false,
        retryRunning: false,
        sourceChangedDuringRun: false,
      };
      states.set(questionId, state);
    }
    return state;
  }

  function run(questionId: string): void {
    if (stopped) return;
    const state = stateFor(questionId);
    if (state.running) {
      // One in flight per question; a change during the run means the
      // result is already stale, so run once more when it finishes.
      state.rerun = true;
      return;
    }
    state.running = track(
      Promise.resolve()
        .then(() => options.compute(questionId))
        .then(
          (outcome) => outcome,
          (err) => {
            warn(
              {
                questionId,
                error: err instanceof Error ? err.name : String(err),
              },
              "Derivative compute threw",
            );
            return undefined;
          },
        )
        .then(async (outcome) => {
          state.running = null;
          state.retryAtMs = null;
          state.retryRunning = false;
          // Consumed here whichever branch wins: a rerun and a retry both
          // recompute from current data, so only the branch that schedules
          // nothing has to put the question back to `stale`.
          const sourceChangedDuringRun = state.sourceChangedDuringRun;
          state.sourceChangedDuringRun = false;
          const retryable =
            isTransientFailureOutcome(outcome) ||
            // A runtime-unavailable skip DURING a chain consumes an attempt
            // instead of ending the chain; on a fresh compute it keeps the
            // pre-retry behavior (pending/stale, reswept by start()).
            (isRuntimeSkipOutcome(outcome) && state.retryAttempts > 0);
          if (state.rerun) {
            // A source changed during the run: that supersedes any retry.
            state.rerun = false;
            state.retryAttempts = 0;
            await markStale(questionId);
            schedule(questionId, 0);
          } else if (
            retryable &&
            // A pending timer means a source change or explicit recompute
            // arrived during the run and already scheduled a fresher run;
            // replacing its 5s debounce with a 60s retry would delay the
            // recompute of data this compute never saw.
            state.timer === null &&
            // After stop() nothing may be scheduled; without this a compute
            // that settles late would record a retryAtMs no timer backs.
            !stopped &&
            state.retryAttempts < retryDelaysMs.length
          ) {
            const delayMs = retryDelaysMs[state.retryAttempts]!;
            state.retryAttempts += 1;
            state.retryAtMs = now().getTime() + delayMs;
            schedule(questionId, delayMs);
            state.retryScheduled = true;
          } else {
            state.retryAttempts = 0;
            if (sourceChangedDuringRun) {
              // Fresh data landed while this compute was reading, so the
              // answer it just wrote is already behind. Say so — and
              // schedule nothing: the next reader triggers the recompute.
              await markStale(questionId);
            }
            if (!states.get(questionId)?.timer) {
              states.delete(questionId);
            }
          }
        }),
    );
  }

  function schedule(questionId: string, delayMs: number): void {
    if (stopped) return;
    const state = stateFor(questionId);
    if (state.timer !== null) timers.clearTimeout(state.timer);
    state.timer = timers.setTimeout(() => {
      state.timer = null;
      // Whatever this timer was (debounce or retry), any promised retry is
      // now being consumed: a past retryAtMs would pin the status route's
      // retryAfterSeconds at 0 for the whole in-flight compute. A firing
      // RETRY timer hands over to retryRunning so the in-flight window is
      // still distinguishable from a terminal failure.
      state.retryAtMs = null;
      state.retryRunning = state.retryScheduled;
      state.retryScheduled = false;
      run(questionId);
    }, delayMs);
  }

  /**
   * Run this question because someone asked for its answer. Idempotent by
   * design: a compute already in flight or already timed is the compute the
   * demand wants, so concurrent readers collapse into one run. A pending
   * RETRY timer is the exception — its backoff is a fallback for nobody
   * asking, and a reader is asking now — so demand pulls it forward,
   * keeping the attempt count (an exhausting chain stays bounded).
   */
  function scheduleDemand(questionId: string): void {
    const state = stateFor(questionId);
    if (state.running !== null) return;
    if (state.timer !== null && !state.retryScheduled) return;
    schedule(questionId, 0);
    state.retryScheduled = false;
  }

  async function markStale(questionId: string): Promise<void> {
    const registration = await options.store.get(questionId);
    if (!registration) return;
    if (registration.status === "ready" || registration.status === "failed") {
      await options.store.update(questionId, {
        status: "stale",
        // The reader contract says errorCode is null unless failed; a stale
        // question is a recompute in progress, not a terminal failure.
        errorCode: null,
        updatedAt: now().toISOString(),
      });
    }
  }

  function resetRetry(questionId: string): void {
    const state = states.get(questionId);
    if (!state) return;
    state.retryAttempts = 0;
    state.retryAtMs = null;
    state.retryScheduled = false;
  }

  return {
    nextRetryAt(questionId) {
      const retryAtMs = states.get(questionId)?.retryAtMs;
      return retryAtMs == null ? null : new Date(retryAtMs).toISOString();
    },
    retryInFlight(questionId) {
      return states.get(questionId)?.retryRunning ?? false;
    },
    markSourceChanged(scope, opts) {
      if (stopped) return;
      const lineage = new Set(
        (opts?.lineageSources ?? []).map((id) => id.toLowerCase()),
      );
      void track(
        (async () => {
          const affected = await options.store.list({ sourceScope: scope });
          for (const registration of affected) {
            if (registration.recompute === "snapshot") {
              // A snapshot question computes at registration and on an
              // explicit recompute only; source changes never touch it.
              continue;
            }
            if (
              options.serverOwner &&
              lineage.has(
                computeDataPointId(
                  options.serverOwner,
                  registration.derivedScope,
                ),
              )
            ) {
              // The new version descends from this question's own output.
              continue;
            }
            // A change lands on a question whose compute is in flight: that
            // compute never saw the new data, so its result must not settle
            // as `ready`. Read the flag before and after the store write —
            // the run can finish inside that await.
            const state = states.get(registration.questionId);
            const runningBefore = state?.running != null;
            await markStale(registration.questionId);
            if (state && (runningBefore || state.running !== null)) {
              state.sourceChangedDuringRun = true;
            }
            // Nothing is scheduled: the recompute is owed, not started. Any
            // retry timer the question already carries stays as it is; the
            // retry recomputes from current data anyway.
          }
        })().catch((err) =>
          warn(
            { scope, error: err instanceof Error ? err.name : String(err) },
            "Could not mark derivative questions stale",
          ),
        ),
      );
    },
    markDemand(derivedScope) {
      if (stopped) return;
      void track(
        (async () => {
          const affected = await options.store.list({ derivedScope });
          for (const registration of affected) {
            if (registration.recompute === "snapshot") {
              // A snapshot answers from the version it computed at
              // registration; only an explicit recompute replaces it.
              continue;
            }
            if (
              registration.status !== "stale" &&
              registration.status !== "pending"
            ) {
              // `ready` has nothing to compute, and `failed` belongs to its
              // backoff chain or to an explicit recompute: a reader polling
              // a question that keeps failing must not spend an inference
              // call per poll.
              continue;
            }
            scheduleDemand(registration.questionId);
          }
        })().catch((err) =>
          warn(
            {
              derivedScope,
              error: err instanceof Error ? err.name : String(err),
            },
            "Could not schedule derivative questions on demand",
          ),
        ),
      );
    },
    requestRecompute(questionId, opts) {
      if (stopped) return;
      void track(
        markStale(questionId)
          .catch((err) =>
            warn(
              {
                questionId,
                error: err instanceof Error ? err.name : String(err),
              },
              "Could not mark derivative question stale",
            ),
          )
          .then(() => {
            resetRetry(questionId);
            schedule(questionId, opts?.immediate ? 0 : debounceMs);
          }),
      );
    },
    async whenIdle() {
      // Waits for store lookups and in-flight computes. Real timers are
      // polled too; injected timers are the caller's to fire.
      const waitForTimers = !options.timers;
      for (;;) {
        while (pending.size > 0) {
          await Promise.allSettled([...pending]);
        }
        const busy = [...states.values()].some(
          (state) =>
            state.running !== null || (waitForTimers && state.timer !== null),
        );
        if (!busy) return;
        await new Promise((resolve) => setTimeout(resolve, 5));
      }
    },
    stop() {
      stopped = true;
      for (const state of states.values()) {
        if (state.timer !== null) timers.clearTimeout(state.timer);
        state.timer = null;
        state.retryAttempts = 0;
        state.retryAtMs = null;
        state.retryScheduled = false;
      }
    },
    start() {
      if (started && !stopped) return;
      started = true;
      stopped = false;
      void track(
        (async () => {
          for (const registration of await options.store.list()) {
            // Only never-answered questions. A `stale` one has a previous
            // version to serve and is recomputed on demand, so a restart
            // costs nothing.
            if (registration.status === "pending") {
              schedule(registration.questionId, 0);
            }
          }
        })().catch((err) =>
          warn(
            { error: err instanceof Error ? err.name : String(err) },
            "Could not reschedule derivative questions",
          ),
        ),
      );
    },
  };
}
