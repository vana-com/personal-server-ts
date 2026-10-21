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
 * One phase's durable work. The repository owns selection SQL and atomic
 * persistence; the coordinator owns ordering, budgets and transitions.
 */
export interface ReplicaPhaseHandler<
  I extends ReplicaWorkItem = ReplicaWorkItem,
> {
  phase: ReplicaPhase;
  /**
   * Due, unparked items: at most perWriter per writer, every writer's first
   * item before any writer's second, and writers in cyclic order starting
   * after `after` (the writer this phase served last). Oldest first within a
   * writer. The cyclic start is what keeps a small limit from always
   * selecting the same writer.
   */
  due(
    now: number,
    limit: { total: number; perWriter: number; after?: string },
  ): I[];
  run(item: I, signal: AbortSignal): Promise<ReplicaPhaseOutcome>;
  /**
   * Persist outcome and state atomically with the item's checkpoint or receipt.
   * May return the outcome it actually persisted (e.g. a Retry when the commit
   * itself failed); the report then states that outcome.
   */
  settle(
    item: I,
    outcome: ReplicaOutcome,
    state: ReplicaWorkState,
  ): ReplicaOutcome | void;
  /** Earliest nextEligible of a non-terminal item, or undefined when idle. */
  nextWake(now: number): number | undefined;
  /** Make waits on this dependency key due now. Idempotent. */
  wake?(key: string, now: number): number;
}

export interface ReplicaBudget {
  units: number;
  bytes?: number;
}

export interface ProgressReport {
  receipts: ReplicaReceipt[];
  waits: { id: string; phase: ReplicaPhase; dependency: ReplicaDependency }[];
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
  hints?: () => boolean;
  /** Per-run deadline. A late result after expiry is discarded. */
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

  /** `undefined`: the host aborted the step before this run settled. */
  async function execute(
    handler: ReplicaPhaseHandler,
    item: ReplicaWorkItem,
    signal: AbortSignal | undefined,
  ): Promise<ReplicaPhaseOutcome | undefined> {
    const controller = new AbortController();
    const key = `${handler.phase}\0${item.id}`;
    inflight.add(key);
    const running = handler
      .run(item, controller.signal)
      .catch((error: unknown) => retryFromError(error, "unknown"));
    void running.finally(() => inflight.delete(key));
    let timer: ReturnType<typeof setTimeout> | undefined;
    let onAbort: (() => void) | undefined;
    const racers: Promise<ReplicaPhaseOutcome | undefined>[] = [running];
    if (input.deadlineMs !== undefined)
      racers.push(
        new Promise((resolve) => {
          timer = setTimeout(() => {
            controller.abort();
            resolve({ tag: "retry", problem: "deadline_exceeded" });
          }, input.deadlineMs);
        }),
      );
    if (signal)
      racers.push(
        new Promise((resolve) => {
          onAbort = () => {
            controller.abort(signal.reason);
            resolve(undefined);
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

  function record(
    report: ProgressReport,
    phase: ReplicaPhase,
    id: string,
    outcome: ReplicaOutcome,
  ) {
    if (outcome.tag === "progress") report.receipts.push(outcome.receipt);
    else if (outcome.tag === "wait")
      report.waits.push({ id, phase, dependency: outcome.dependency });
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
      let units = Math.max(0, budget.units);
      let bytes = budget.bytes ?? Number.POSITIVE_INFINITY;
      let deferred = false;
      const aborted = () => signal?.aborted === true;
      // An unbounded step keeps pipeline order, so prepared work publishes in
      // the same step. A bounded step starts at the service cursor.
      const bounded = Number.isFinite(units);
      const first = bounded ? startPhase % Math.max(1, input.phases.length) : 0;
      const phases = [
        ...input.phases.slice(first),
        ...input.phases.slice(0, first),
      ];
      // Default: the next step starts one phase later (stable tie-breaking).
      let unserved: number | undefined;
      // A finite budget reserves a fair share per phase before any phase may
      // spend leftovers, so an early phase cannot take every unit.
      const share = bounded
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
                .due(now, {
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
              const verdict = await execute(handler, item, signal);
              if (verdict === undefined) break;
              const settled = settleReplicaWork(item.state, verdict, now, {
                backoff: input.backoff,
                hints: input.hints?.() === true,
              });
              // A settle that throws persisted nothing: the step fails rather
              // than report a verdict the repository does not hold.
              const persisted =
                handler.settle(item, settled.outcome, settled.state) ??
                settled.outcome;
              record(report, handler.phase, item.id, persisted);
            }
            if (!admitted) break;
          }
          spent.set(handler.phase, used + count);
        }
      }
      if (bounded && input.phases.length)
        startPhase = (first + (unserved ?? 1)) % input.phases.length;
      let wake: number | undefined;
      for (const handler of input.phases) {
        const next = handler.nextWake(now);
        if (next !== undefined && (wake === undefined || next < wake))
          wake = next;
      }
      report.nextWake =
        deferred || (wake !== undefined && wake <= now) ? now : wake;
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
