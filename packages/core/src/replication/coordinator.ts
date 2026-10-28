import {
  retryFromError,
  type ReplicaAdmission,
  type ReplicaCause,
  type ReplicaDependency,
  type ReplicaOutcome,
  type ReplicaPhase,
  type ReplicaPhaseOutcome,
  type ReplicaProblem,
  type ReplicaQuarantineProof,
  type ReplicaReceipt,
} from "./outcome.js";
import {
  settleReplicaWork,
  type ReplicaBackoff,
  type ReplicaEligibility,
  type ReplicaWorkState,
} from "./schedule.js";

export interface ReplicaWorkItem {
  id: string;
  phase: ReplicaPhase;
  writer: string;
  state: ReplicaWorkState;
  /** Admission estimate for byte budgets. */
  bytes?: number;
}

/**
 * The result of one attempt. `plan` is this attempt's transactional effect
 * (checkpoint, receipt, custody). It runs only inside the commit of this very
 * attempt, so a discarded attempt (deadline, abort) leaves no trace. A plan
 * may refine the verdict from what it committed.
 */
export interface ReplicaAttempt {
  outcome: ReplicaPhaseOutcome;
  plan?: () => ReplicaPhaseOutcome | void;
  /** Release short-lived resources after this attempt is committed or discarded. */
  release?: () => void;
}

/** Turns a verdict into its durable outcome and state, at settlement time. */
export type ReplicaSettle = (verdict: ReplicaPhaseOutcome) => {
  outcome: ReplicaOutcome;
  state: ReplicaWorkState;
};

/**
 * One phase's durable work: a storage adapter. The coordinator owns the
 * clock, eligibility, budgets, deadlines and transitions; the adapter owns
 * selection SQL rendered from the shared eligibility policy and atomic
 * persistence.
 */
export interface ReplicaPhaseHandler<
  I extends ReplicaWorkItem = ReplicaWorkItem,
> {
  phase: ReplicaPhase;
  /**
   * Eligible items (see replicaEligibleAt): at most perWriter per writer,
   * every writer's first item before any writer's second, and writers in
   * cyclic order starting after `after` (the writer this phase served last).
   * Oldest first within a writer.
   */
  due(
    eligibility: ReplicaEligibility,
    limit: { total: number; perWriter: number; after?: string },
  ): I[];
  /** Must honour `signal`: after abort it performs no further effect. */
  run(item: I, signal: AbortSignal): Promise<ReplicaAttempt>;
  /**
   * In ONE transaction: run `attempt.plan` (if any), settle the verdict with
   * `settle`, persist outcome and state. Return the persisted outcome. A throw
   * persists nothing.
   */
  commit(
    item: I,
    attempt: ReplicaAttempt,
    settle: ReplicaSettle,
  ): ReplicaOutcome;
  /** Problem recorded when a plan's transaction fails. */
  commitProblem?: ReplicaProblem;
  /**
   * Earliest eligibility of this phase's durable deadlines (retries, waits),
   * by the same policy as `due`; undefined when none. Polling sources and
   * sweeps that run on the host's cadence report only their deadlines.
   */
  earliest(eligibility: ReplicaEligibility): number | undefined;
  /** Make waits on this dependency key due now. Idempotent. */
  wake?(key: string, now: number): number;
}

/** A finalized-head hint source. Optional: it can only park finality waits. */
export interface ReplicaHintPort {
  head(signal: AbortSignal): Promise<bigint>;
}

/**
 * Await `start()` unless `signal` aborts first. After abort the caller sees a
 * rejection at once, so it performs no further effect; the underlying call
 * may still finish, and its value is dropped.
 */
export function abortable<T>(
  signal: AbortSignal,
  start: () => Promise<T>,
): Promise<T> {
  if (signal.aborted)
    return Promise.reject(
      signal.reason ?? new DOMException("aborted", "AbortError"),
    );
  return new Promise<T>((resolve, reject) => {
    const onAbort = () =>
      reject(signal.reason ?? new DOMException("aborted", "AbortError"));
    signal.addEventListener("abort", onAbort, { once: true });
    start().then(
      (value) => {
        signal.removeEventListener("abort", onAbort);
        resolve(value);
      },
      (error: unknown) => {
        signal.removeEventListener("abort", onAbort);
        reject(error);
      },
    );
  });
}

export interface ReplicaBudget {
  units: number;
  bytes?: number;
}

export interface ProgressReport {
  receipts: ReplicaReceipt[];
  waits: {
    id: string;
    phase: ReplicaPhase;
    dependency: ReplicaDependency;
    ageMs?: number;
  }[];
  problems: {
    id: string;
    phase: ReplicaPhase;
    problem: ReplicaProblem;
    cause?: ReplicaCause;
    nextEligible: number;
  }[];
  quarantines: {
    id: string;
    phase: ReplicaPhase;
    proof: ReplicaQuarantineProof;
  }[];
  unsupported: {
    id: string;
    phase: ReplicaPhase;
    admission: ReplicaAdmission;
  }[];
  /** `now` when admitted work remains; else the earliest durable deadline. */
  nextWake: number | undefined;
}

const DEFAULT_QUANTUM = 50;
/** Bound on one hint read when no per-run deadline is configured. */
const HINT_TIMEOUT_MS = 2_000;

/**
 * Selects due work fairly and turns phase verdicts into durable transitions.
 * The host schedules step(); it never runs another semantic retry loop.
 */
export function createReplicaCoordinator(input: {
  phases: ReplicaPhaseHandler[];
  quantum?: Partial<Record<ReplicaPhase, number>>;
  /** Items per writer per phase per step. Defaults to the phase quantum. */
  perWriter?: number;
  backoff?: ReplicaBackoff;
  /** Settlement clock. Defaults to the step's `now`. */
  clock?: () => number;
  /** Optional finalized-head hint, read at most every `hintRefreshMs`. */
  hint?: ReplicaHintPort;
  hintRefreshMs?: number;
  /** Per-run deadline, also bounding a hint read. A late result is discarded. */
  deadlineMs?: number;
  /**
   * Sweeps that are never finished (e.g. revalidating imported slots). Under
   * a finite budget they keep their reserved share but take leftover units
   * only after every other phase, so a sweep cannot crowd out progress.
   */
  background?: readonly ReplicaPhase[];
}) {
  const quantum = (phase: ReplicaPhase) =>
    input.quantum?.[phase] ?? DEFAULT_QUANTUM;
  /** Items whose run has not settled. A timed-out run blocks redispatch until it ends. */
  const inflight = new Set<string>();
  /** Rotating start writer per phase, so a replenishing writer cannot keep first place. */
  const lastWriter = new Map<ReplicaPhase, string>();
  /**
   * Service cursor over phases for finite budgets. A step that runs out of
   * units resumes at the first phase it could not serve, so every phase is
   * reached within ceil(phases / units) steps however busy earlier phases are.
   */
  let startPhase = 0;

  function interleave<I extends ReplicaWorkItem>(
    phase: ReplicaPhase,
    items: I[],
  ) {
    const groups = new Map<string, I[]>();
    for (const item of items) {
      const group = groups.get(item.writer);
      if (group) group.push(item);
      else groups.set(item.writer, [item]);
    }
    const writers = [...groups.keys()];
    const last = lastWriter.get(phase);
    const offset = last === undefined ? 0 : writers.indexOf(last) + 1;
    const rotated = [...writers.slice(offset), ...writers.slice(0, offset)];
    const ordered: I[] = [];
    for (let round = 0; ordered.length < items.length; round++)
      for (const writer of rotated) {
        const item = groups.get(writer)![round];
        if (item) ordered.push(item);
      }
    return ordered;
  }

  /**
   * Race `start` against the per-run deadline and the host's signal. On
   * either, the inner signal aborts and the late result is dropped whole.
   */
  async function bounded<T>(
    start: (signal: AbortSignal) => Promise<T>,
    signal: AbortSignal | undefined,
    deadlineMs = input.deadlineMs,
  ): Promise<{ value: T } | "deadline" | "aborted"> {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    let onAbort: (() => void) | undefined;
    const racers: Promise<{ value: T } | "deadline" | "aborted">[] = [
      start(controller.signal).then((value) => ({ value })),
    ];
    if (deadlineMs !== undefined)
      racers.push(
        new Promise((resolve) => {
          timer = setTimeout(() => {
            controller.abort();
            resolve("deadline");
          }, deadlineMs);
        }),
      );
    if (signal)
      racers.push(
        new Promise((resolve) => {
          onAbort = () => {
            controller.abort(signal.reason);
            resolve("aborted");
          };
          if (signal.aborted) onAbort();
          else signal.addEventListener("abort", onAbort, { once: true });
        }),
      );
    try {
      return await Promise.race(racers);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
      if (onAbort) signal?.removeEventListener("abort", onAbort);
    }
  }

  /** `undefined`: the host aborted the step before this run settled. */
  async function execute(
    handler: ReplicaPhaseHandler,
    item: ReplicaWorkItem,
    signal: AbortSignal | undefined,
  ): Promise<ReplicaAttempt | undefined> {
    const key = `${handler.phase}\0${item.id}`;
    inflight.add(key);
    const result = await bounded(
      (inner) =>
        handler
          .run(item, inner)
          .catch((error: unknown): ReplicaAttempt => ({
            outcome: retryFromError(error, "unknown"),
          }))
          .finally(() => inflight.delete(key)),
      signal,
    );
    if (result === "aborted") return undefined;
    if (result === "deadline")
      return { outcome: { tag: "retry", problem: "deadline_exceeded" } };
    return result.value;
  }

  // ------------------------------------------------------------- hints
  let head: bigint | undefined;
  let hintReadAt = Number.NEGATIVE_INFINITY;
  let hintInFlight = false;
  const hintRefreshMs = input.hintRefreshMs ?? 2_000;
  /**
   * Refresh the hint at most every hintRefreshMs, bounded by the deadline and
   * the step signal. A failed, slow or hung read leaves no hint: waits then
   * poll on their durable schedule. A read still in flight is never awaited
   * again, so a hung hint cannot stall later steps.
   */
  async function refreshHint(now: number, signal: AbortSignal | undefined) {
    const hint = input.hint;
    if (!hint || hintInFlight || now - hintReadAt < hintRefreshMs) return;
    hintReadAt = now;
    hintInFlight = true;
    const read = await bounded(
      (inner) =>
        hint
          .head(inner)
          .then((value) =>
            typeof value === "bigint" && value >= 0n ? value : undefined,
          )
          .catch(() => undefined)
          .finally(() => (hintInFlight = false)),
      signal,
      // A hint is optional: it is always bounded, with or without a run deadline.
      input.deadlineMs ?? HINT_TIMEOUT_MS,
    );
    head = typeof read === "object" ? read.value : undefined;
  }
  const eligibility = (now: number): ReplicaEligibility => ({
    now,
    head,
    hintRefreshAt: input.hint ? hintReadAt + hintRefreshMs : undefined,
  });

  /**
   * Persist one attempt. If its plan's transaction fails, persist the Retry
   * that failure means instead (no plan). If even that fails, the step fails:
   * the report never states an outcome the repository does not hold.
   */
  function commit(
    handler: ReplicaPhaseHandler,
    item: ReplicaWorkItem,
    attempt: ReplicaAttempt,
  ): ReplicaOutcome {
    const settle: ReplicaSettle = (verdict) =>
      settleReplicaWork(item.state, verdict, input.clock?.() ?? stepNow, {
        backoff: input.backoff,
        hints: input.hint !== undefined,
      });
    try {
      return handler.commit(item, attempt, settle);
    } catch (error) {
      if (!attempt.plan) throw error;
      return handler.commit(
        item,
        {
          outcome: retryFromError(
            error,
            handler.commitProblem ?? "storage_failed",
          ),
        },
        settle,
      );
    }
  }
  let stepNow = 0;

  function record(
    report: ProgressReport,
    phase: ReplicaPhase,
    id: string,
    outcome: ReplicaOutcome,
  ) {
    if (outcome.tag === "progress") report.receipts.push(outcome.receipt);
    else if (outcome.tag === "wait")
      report.waits.push({
        id,
        phase,
        dependency: outcome.dependency,
        ...(outcome.dependency.kind === "registration_pending" && {
          ageMs: Math.max(0, stepNow - outcome.dependency.since),
        }),
      });
    else if (outcome.tag === "retry")
      report.problems.push({
        id,
        phase,
        problem: outcome.problem,
        ...(outcome.cause && { cause: outcome.cause }),
        nextEligible: outcome.nextEligible,
      });
    else if (outcome.tag === "quarantine")
      report.quarantines.push({ id, phase, proof: outcome.proof });
    else report.unsupported.push({ id, phase, admission: outcome.admission });
  }

  return {
    async step(
      now: number,
      signal: AbortSignal | undefined,
      budget: ReplicaBudget,
    ): Promise<ProgressReport> {
      const report: ProgressReport = {
        receipts: [],
        waits: [],
        problems: [],
        quarantines: [],
        unsupported: [],
        nextWake: undefined,
      };
      stepNow = now;
      let units = Math.max(0, budget.units);
      let bytes = budget.bytes ?? Number.POSITIVE_INFINITY;
      let deferred = false;
      const aborted = () => signal?.aborted === true;
      await refreshHint(now, signal);
      // Selection reads the clock when it selects, so work a phase finished
      // earlier in this step (settled at a later clock reading) is eligible.
      const selection = () =>
        eligibility(Math.max(now, input.clock?.() ?? now));
      // An unbounded step keeps pipeline order, so prepared work publishes in
      // the same step. A finite step starts at the service cursor.
      const finite = Number.isFinite(units);
      const first = finite ? startPhase % Math.max(1, input.phases.length) : 0;
      const phases = [
        ...input.phases.slice(first),
        ...input.phases.slice(0, first),
      ];
      // Default: the next step starts one phase later (stable tie-breaking).
      let unserved: number | undefined;
      // A finite budget reserves a fair share per phase before any phase may
      // spend leftovers, so an early phase cannot take every unit.
      const share = finite
        ? Math.max(1, Math.floor(units / Math.max(1, phases.length)))
        : Number.POSITIVE_INFINITY;
      const spent = new Map<ReplicaPhase, number>();
      const ran = new Set<string>();
      const background = new Set(input.background ?? []);
      const leftovers = [
        ...phases.filter((handler) => !background.has(handler.phase)),
        ...phases.filter((handler) => background.has(handler.phase)),
      ];
      for (const pass of [0, 1]) {
        for (const [position, handler] of (pass === 0
          ? phases
          : leftovers
        ).entries()) {
          if (pass === 0 && units <= 0 && unserved === undefined)
            unserved = position;
          const used = spent.get(handler.phase) ?? 0;
          const cap = Math.min(
            quantum(handler.phase) - used,
            pass === 0 ? share : units,
            units,
          );
          let count = 0;
          // Refilled rounds: each due() call admits at most perWriter items per
          // writer, so one writer's backlog cannot fill a phase's quantum.
          while (count < cap && units > 0 && !aborted()) {
            const items = interleave(
              handler.phase,
              handler
                .due(selection(), {
                  total: cap - count,
                  perWriter: input.perWriter ?? 1,
                  after: lastWriter.get(handler.phase),
                })
                .filter((item) => {
                  const key = `${handler.phase}\0${item.id}`;
                  return !inflight.has(key) && !ran.has(key);
                }),
            );
            let admitted = 0;
            for (const item of items) {
              if (count >= cap || units <= 0 || aborted()) break;
              const key = `${handler.phase}\0${item.id}`;
              ran.add(key);
              if (item.bytes !== undefined && item.bytes > bytes) {
                deferred = true;
                continue;
              }
              admitted++;
              count++;
              units--;
              if (item.bytes !== undefined) bytes -= item.bytes;
              lastWriter.set(handler.phase, item.writer);
              const attempt = await execute(handler, item, signal);
              if (attempt === undefined) break;
              record(
                report,
                handler.phase,
                item.id,
                commit(handler, item, attempt),
              );
            }
            if (!admitted) break;
          }
          spent.set(handler.phase, used + count);
        }
      }
      if (finite && input.phases.length)
        startPhase = (first + (unserved ?? 1)) % input.phases.length;
      // The same eligibility as selection, read after this step's commits.
      const after = eligibility(input.clock?.() ?? now);
      let wake: number | undefined;
      for (const handler of input.phases) {
        const next = handler.earliest(after);
        if (next !== undefined && (wake === undefined || next < wake))
          wake = next;
      }
      // Already due (e.g. the budget ran out) is reported as `now`.
      report.nextWake = deferred
        ? now
        : wake === undefined
          ? undefined
          : Math.max(wake, now);
      return report;
    },
    onDependencyChanged(key: string, now: number): number {
      let woken = 0;
      for (const handler of input.phases)
        woken += handler.wake?.(key, now) ?? 0;
      return woken;
    },
  };
}
