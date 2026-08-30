/**
 * Recompute scheduler: marks registrations stale when one of their source
 * scopes changes and runs the compute after a quiet period, one in flight
 * per question. Timers and the clock are injectable so tests drive it
 * deterministically.
 */

import { computeDataPointId } from "../sync/data-point-id.js";
import type { QuestionStore } from "./types.js";

export interface SchedulerTimers {
  setTimeout(callback: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
}

export interface RecomputeSchedulerOptions {
  store: QuestionStore;
  /** Runs one compute; must not throw for compute failures. */
  compute(questionId: string): Promise<unknown>;
  /** Quiet period after a source change (default 5s). */
  debounceMs?: number;
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
  /** Resolves once no compute or store lookup is pending or timed. */
  whenIdle(): Promise<void>;
  /** Cancel pending timers. In-flight computes finish on their own. */
  stop(): void;
  /**
   * Resume after `stop()`: questions left `pending` or `stale` are
   * scheduled again (immediately). Idempotent while running.
   */
  start(): void;
}

interface QuestionState {
  timer: unknown | null;
  running: Promise<void> | null;
  rerun: boolean;
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
  const timers = options.timers ?? defaultTimers;
  const now = options.now ?? (() => new Date());
  const states = new Map<string, QuestionState>();
  const pending = new Set<Promise<unknown>>();
  let stopped = false;

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
      state = { timer: null, running: null, rerun: false };
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
          () => undefined,
          (err) =>
            warn(
              {
                questionId,
                error: err instanceof Error ? err.name : String(err),
              },
              "Derivative compute threw",
            ),
        )
        .then(async () => {
          state.running = null;
          if (state.rerun) {
            state.rerun = false;
            await markStale(questionId);
            schedule(questionId, 0);
          } else if (!states.get(questionId)?.timer) {
            states.delete(questionId);
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
      run(questionId);
    }, delayMs);
  }

  async function markStale(questionId: string): Promise<void> {
    const registration = await options.store.get(questionId);
    if (!registration) return;
    if (registration.status === "ready" || registration.status === "failed") {
      await options.store.update(questionId, {
        status: "stale",
        updatedAt: now().toISOString(),
      });
    }
  }

  return {
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
          .then(() => schedule(questionId, opts?.immediate ? 0 : debounceMs)),
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
      }
    },
    start() {
      if (!stopped) return;
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
