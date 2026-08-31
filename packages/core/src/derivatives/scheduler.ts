/**
 * Recompute scheduler: marks registrations stale when one of their source
 * scopes changes and runs the compute after a quiet period, one in flight
 * per question. Timers and the clock are injectable so tests drive it
 * deterministically.
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
  /** Quiet period after a source change (default 5s). */
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
   * scheduled. Fire and forget; failures are logged.
   */
  markSourceChanged(
    scope: string,
    options?: {
      /** `$lineage.sources` of the new version, when it is a derivative. */
      lineageSources?: readonly string[];
    },
  ): void;
  /** Schedule one question; `immediate` skips the debounce (owner recompute). */
  requestRecompute(questionId: string, options?: { immediate?: boolean }): void;
  /**
   * Next scheduled automatic retry for a failed question (ISO time), or
   * null when none is pending. In-memory, like the rest of the scheduler:
   * a restart drops the chain and the question waits for a source change
   * or an explicit recompute.
   */
  nextRetryAt(questionId: string): string | null;
  /** Resolves once no compute or store lookup is pending or timed. */
  whenIdle(): Promise<void>;
  /** Cancel pending timers. In-flight computes finish on their own. */
  stop(): void;
  /**
   * Schedule every question left `pending` or `stale` (immediately). The
   * first call is the boot reschedule: a restarted process only holds what
   * the store holds, and those questions have no other way back onto a
   * timer. Later calls resume after `stop()`; idempotent while running.
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
          } else {
            state.retryAttempts = 0;
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
      // retryAfterSeconds at 0 for the whole in-flight compute.
      state.retryAtMs = null;
      run(questionId);
    }, delayMs);
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
  }

  return {
    nextRetryAt(questionId) {
      const retryAtMs = states.get(questionId)?.retryAtMs;
      return retryAtMs == null ? null : new Date(retryAtMs).toISOString();
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
            await markStale(registration.questionId);
            resetRetry(registration.questionId);
            schedule(registration.questionId, debounceMs);
          }
        })().catch((err) =>
          warn(
            { scope, error: err instanceof Error ? err.name : String(err) },
            "Could not mark derivative questions stale",
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
      }
    },
    start() {
      if (started && !stopped) return;
      started = true;
      stopped = false;
      void track(
        (async () => {
          for (const registration of await options.store.list()) {
            if (
              registration.status === "pending" ||
              registration.status === "stale"
            ) {
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
