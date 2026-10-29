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

type MaybePromise<T> = T | Promise<T>;

const isPromiseLike = (value: unknown): value is PromiseLike<unknown> =>
  typeof value === "object" &&
  value !== null &&
  typeof (value as { then?: unknown }).then === "function";

/** Continue with `next` now when `value` is plain, after it when a promise. */
function then<T, R>(
  value: MaybePromise<T>,
  next: (value: T) => MaybePromise<R>,
): MaybePromise<R> {
  return isPromiseLike(value) ? (value as Promise<T>).then(next) : next(value);
}

/** `try`/`catch` over a computation that may or may not be asynchronous. */
function recover<T>(
  run: () => MaybePromise<T>,
  handle: (error: unknown) => MaybePromise<T>,
): MaybePromise<T> {
  let value: MaybePromise<T>;
  try {
    value = run();
  } catch (error) {
    return handle(error);
  }
  return isPromiseLike(value) ? (value as Promise<T>).catch(handle) : value;
}

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
export interface ReplicaAttempt<P = () => ReplicaPhaseOutcome | void> {
  outcome: ReplicaPhaseOutcome;
  /** Node plans are callbacks; shared-engine plans are storage effects. */
  plan?: P;
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

/**
 * A phase handler whose storage may answer asynchronously (PS-Lite's native
 * transaction). A handler that returns plain values runs exactly as a
 * synchronous one: the coordinator awaits only what is a promise.
 */
export interface AsyncReplicaPhaseHandler<
  I extends ReplicaWorkItem = ReplicaWorkItem,
  C = unknown,
  P = unknown,
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
  ): MaybePromise<I[]>;
  /** Must honour `signal`: after abort it performs no further effect. */
  run(item: I, signal: AbortSignal): Promise<ReplicaAttempt<P>>;
  /**
   * In ONE transaction: run `attempt.plan` (if any), settle the verdict with
   * `settle`, persist outcome and state. Return the persisted outcome. A throw
   * persists nothing. `context` is the durable state port's transaction,
   * so the attempt and the rotation commit together.
   */
  commit(
    item: I,
    attempt: ReplicaAttempt<P>,
    settle: ReplicaSettle,
    context: C,
  ): MaybePromise<ReplicaOutcome>;
  /** Problem recorded when a plan's transaction fails. */
  commitProblem?: ReplicaProblem;
  /**
   * Earliest eligibility of this phase's durable deadlines (retries, waits),
   * by the same policy as `due`; undefined when none. Polling sources and
   * sweeps that run on the host's cadence report only their deadlines.
   */
  earliest(eligibility: ReplicaEligibility): MaybePromise<number | undefined>;
  /** Make waits on this dependency key due now. Idempotent. */
  wake?(key: string, now: number): MaybePromise<number>;
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
  /** Positive safe integer. Counts admitted attempts, not all storage work. */
  units: number;
  /** Positive safe integer; omitted means the finite default below. */
  bytes?: number;
}

export const REPLICA_STEP_BYTES = 64 * 1024 * 1024;
export const REPLICA_REPORT_LIMIT = 256;
export const REPLICA_ATTEMPT_TIMEOUT_MS = 30_000;

export interface ReplicaStep {
  /** Nonnegative safe-integer milliseconds on the host's scheduling clock. */
  now: number;
  budget: ReplicaBudget;
  signal?: AbortSignal;
}

/** Validate before storage, hints, selection or any other effect. */
export function validateReplicaStep(context: ReplicaStep): void {
  if (
    !context ||
    typeof context !== "object" ||
    !context.budget ||
    typeof context.budget !== "object"
  )
    throw new RangeError("invalid replica step context");
  if (!Number.isSafeInteger(context.now) || context.now < 0)
    throw new RangeError("invalid replica step clock");
  for (const value of [
    context.budget.units,
    context.budget.bytes === undefined
      ? REPLICA_STEP_BYTES
      : context.budget.bytes,
  ])
    if (!Number.isSafeInteger(value) || value < 1)
      throw new RangeError("invalid replica step budget");
}

/** Stable phase names survive a reordered host construction across restart. */
export interface ReplicaRotation {
  nextPhase?: ReplicaPhase;
  writers: Partial<Record<ReplicaPhase, string>>;
}

export interface ReplicaCoordinatorState extends ReplicaRotation {
  /** Opaque exclusive-owner fence, never a PID or wall-clock lease in core. */
  owner: string;
  /** Monotonic compare-and-swap revision within this durable repository. */
  version: number;
}

export class ReplicaCoordinatorConflict extends Error {
  constructor() {
    super("replica coordinator ownership or revision changed");
    this.name = "ReplicaCoordinatorConflict";
  }
}

/**
 * A host adapter must use the SAME transaction for `checkpoint` and rotation.
 * Check current ownership and revision before calling checkpoint, and again
 * before commit. On any throw, neither the checkpoint nor cursor may persist.
 * The callback is synchronous and must not escape or run after commit returns.
 * Every adapter must pass `replicaCoordinatorStateContract`.
 */
export interface ReplicaCoordinatorStatePort {
  load(): ReplicaCoordinatorState;
  commit<T>(
    expected: ReplicaCoordinatorState,
    next: ReplicaRotation,
    checkpoint: () => T,
  ): { state: ReplicaCoordinatorState; result: T };
}

/**
 * The same port over an asynchronous transaction (PS-Lite's native one).
 * `checkpoint` receives that transaction and the port awaits it before the
 * rotation is written; the same ownership, revision and rollback rules
 * apply. The callback must not escape or run after commit settles.
 */
export interface AsyncReplicaCoordinatorStatePort<C> {
  readonly async: true;
  load(): Promise<ReplicaCoordinatorState>;
  commit<T>(
    expected: ReplicaCoordinatorState,
    next: ReplicaRotation,
    checkpoint: (context: C) => Promise<T>,
  ): Promise<{ state: ReplicaCoordinatorState; result: T }>;
}

/** Thrown when a synchronous port is handed an asynchronous checkpoint. */
export class ReplicaAsyncCheckpointError extends Error {
  constructor() {
    super("asynchronous replica checkpoint under a synchronous state port");
    this.name = "ReplicaAsyncCheckpointError";
  }
}

export interface ProgressReport {
  /** Diagnostics may be incomplete because the fixed entry cap was reached. */
  diagnosticsTruncated?: boolean;
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

/** Options shared by both coordinator factories. */
export interface ReplicaCoordinatorOptions {
  quantum?: Partial<Record<ReplicaPhase, number>>;
  /** Items per writer in one selection round. Defaults to one. */
  perWriter?: number;
  backoff?: ReplicaBackoff;
  /** Settlement clock. Defaults to the step's `now`. */
  clock?: () => number;
  /** Optional finalized-head hint, read at most every `hintRefreshMs`. */
  hint?: ReplicaHintPort;
  hintRefreshMs?: number;
  /** Positive integer per-run timeout in ms (default 30s); late results are discarded. */
  deadlineMs?: number;
  /**
   * Sweeps that are never finished (e.g. revalidating imported slots). Under
   * a finite budget they keep their reserved share but take leftover units
   * only after every other phase, so a sweep cannot crowd out progress.
   */
  background?: readonly ReplicaPhase[];
}

/**
 * Selects due work fairly and turns phase verdicts into durable transitions.
 * The host schedules step(); it never runs another semantic retry loop.
 */
export function createReplicaCoordinator(
  input: ReplicaCoordinatorOptions & {
    phases: ReplicaPhaseHandler[];
    /** Required for restart fairness; omission is an in-memory-only test seam. */
    state?: ReplicaCoordinatorStatePort;
  },
) {
  const coordinator = createAsyncReplicaCoordinator<undefined>(
    input as ReplicaCoordinatorOptions & {
      phases: AsyncReplicaPhaseHandler<ReplicaWorkItem, undefined>[];
      state?: ReplicaCoordinatorStatePort;
    },
  );
  return {
    step: coordinator.step,
    onDependencyChanged(key: string, now: number): number {
      const woken = coordinator.onDependencyChanged(key, now);
      if (isPromiseLike(woken)) throw new ReplicaAsyncCheckpointError();
      return woken;
    },
  };
}

/**
 * The coordinator over handlers and a state port that may answer
 * asynchronously. Plain values keep the synchronous path, so a synchronous
 * host (Node) behaves exactly as under `createReplicaCoordinator`. With a
 * synchronous port, an asynchronous checkpoint is refused inside its
 * transaction, never committed half-done.
 */
export function createAsyncReplicaCoordinator<C>(
  input: ReplicaCoordinatorOptions & {
    // Each handler names its own work item and plan types.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    phases: AsyncReplicaPhaseHandler<any, C, any>[];
    /** Required for restart fairness; omission is an in-memory-only test seam. */
    state?: ReplicaCoordinatorStatePort | AsyncReplicaCoordinatorStatePort<C>;
  },
) {
  for (const value of [
    input.perWriter ?? 1,
    input.deadlineMs ?? REPLICA_ATTEMPT_TIMEOUT_MS,
    input.hintRefreshMs ?? 2_000,
  ])
    if (value === undefined || !Number.isSafeInteger(value) || value < 1)
      throw new RangeError("invalid replica coordinator bound");
  // A zero quantum leaves its phase idle (as on main); it is still finite.
  for (const value of Object.values(input.quantum ?? {}))
    if (value === undefined || !Number.isSafeInteger(value) || value < 0)
      throw new RangeError("invalid replica coordinator bound");
  // setTimeout clamps larger delays to 1ms on Node; never silently accept that.
  if ((input.deadlineMs ?? REPLICA_ATTEMPT_TIMEOUT_MS) > 2_147_483_647)
    throw new RangeError("invalid replica attempt timeout");
  if (
    new Set(input.phases.map((phase) => phase.phase)).size !==
    input.phases.length
  )
    throw new RangeError("duplicate replica phase");
  type Handler = (typeof input.phases)[number];
  const quantum = (phase: ReplicaPhase) =>
    input.quantum?.[phase] ?? DEFAULT_QUANTUM;
  /** Items whose run has not settled. A timed-out run blocks redispatch until it ends. */
  const inflight = new Set<string>();
  let state: ReplicaCoordinatorState = {
    owner: "memory",
    version: 0,
    writers: {},
  };
  let stepping = false;

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
    const last = state.writers[phase];
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
    deadlineMs = input.deadlineMs ?? REPLICA_ATTEMPT_TIMEOUT_MS,
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
    handler: Handler,
    item: ReplicaWorkItem,
    signal: AbortSignal | undefined,
  ): Promise<ReplicaAttempt<unknown> | undefined> {
    const key = `${handler.phase}\0${item.id}`;
    inflight.add(key);
    let running: Promise<ReplicaAttempt<unknown>> | undefined;
    const result = await bounded((inner) => {
      running = handler
        .run(item, inner)
        .catch((error: unknown): ReplicaAttempt<unknown> => ({
          outcome: retryFromError(error, "unknown"),
        }))
        .finally(() => inflight.delete(key));
      return running;
    }, signal);
    if (result === "aborted") {
      void running?.then((attempt) => attempt.release?.());
      return undefined;
    }
    if (result === "deadline") {
      void running?.then((attempt) => attempt.release?.());
      return { outcome: { tag: "retry", problem: "deadline_exceeded" } };
    }
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
    handler: Handler,
    item: ReplicaWorkItem,
    attempt: ReplicaAttempt<unknown>,
    signal: AbortSignal | undefined,
  ): MaybePromise<ReplicaOutcome> {
    const settle: ReplicaSettle = (verdict) =>
      settleReplicaWork(item.state, verdict, input.clock?.() ?? stepNow, {
        backoff: input.backoff,
        hints: input.hint !== undefined,
      });
    const advance = (
      value: ReplicaAttempt<unknown>,
    ): MaybePromise<ReplicaOutcome> => {
      const position = input.phases.indexOf(handler);
      const next: ReplicaRotation = {
        nextPhase: input.phases[(position + 1) % input.phases.length]?.phase,
        writers: { ...state.writers, [handler.phase]: item.writer },
      };
      const checkpoint = (context: C) => {
        const assertNotAborted = () => {
          if (signal?.aborted)
            throw signal.reason ?? new DOMException("aborted", "AbortError");
        };
        assertNotAborted();
        return then(handler.commit(item, value, settle, context), (result) => {
          // Still inside the durable state port's outer transaction. A plan
          // may close the host lifetime; roll back its effects.
          assertNotAborted();
          return result;
        });
      };
      const port = input.state;
      if (port && "async" in port && port.async)
        return port
          .commit(state, next, async (context) => checkpoint(context))
          .then((committed) => {
            state = committed.state;
            return committed.result;
          });
      if (port) {
        const committed = (port as ReplicaCoordinatorStatePort).commit(
          state,
          next,
          () => {
            const result = checkpoint(undefined as C);
            if (isPromiseLike(result)) {
              // Never leave the refused checkpoint's rejection unobserved.
              (result as Promise<unknown>).catch(() => undefined);
              throw new ReplicaAsyncCheckpointError();
            }
            return result;
          },
        );
        state = committed.state;
        return committed.result;
      }
      return then(checkpoint(undefined as C), (result) => {
        state = { ...state, ...next, version: state.version + 1 };
        return result;
      });
    };
    return recover(
      () => advance(attempt),
      (error) => {
        if (
          signal?.aborted ||
          !attempt.plan ||
          error instanceof ReplicaCoordinatorConflict
        )
          throw error;
        return advance({
          outcome: retryFromError(
            error,
            handler.commitProblem ?? "storage_failed",
          ),
        });
      },
    );
  }
  let stepNow = 0;

  function record(
    report: ProgressReport,
    phase: ReplicaPhase,
    id: string,
    outcome: ReplicaOutcome,
  ) {
    if (
      report.receipts.length +
        report.waits.length +
        report.problems.length +
        report.quarantines.length +
        report.unsupported.length >=
      REPLICA_REPORT_LIMIT
    ) {
      report.diagnosticsTruncated = true;
      return;
    }
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
    async step(context: ReplicaStep): Promise<ProgressReport> {
      validateReplicaStep(context);
      if (stepping) throw new ReplicaCoordinatorConflict();
      stepping = true;
      try {
        const { now, signal, budget } = context;
        // No in-memory cursor from a prior instance is authoritative.
        if (input.state) {
          const loaded = input.state.load();
          state = isPromiseLike(loaded) ? await loaded : loaded;
        }
        const report: ProgressReport = {
          receipts: [],
          waits: [],
          problems: [],
          quarantines: [],
          unsupported: [],
          nextWake: undefined,
        };
        stepNow = now;
        let units = budget.units;
        const stepBytes = budget.bytes ?? REPLICA_STEP_BYTES;
        let bytes = stepBytes;
        let deferred = false;
        const aborted = () => signal?.aborted === true;
        if (!aborted()) await refreshHint(now, signal);
        // Selection reads the clock when it selects, so work a phase finished
        // earlier in this step (settled at a later clock reading) is eligible.
        const selection = () =>
          eligibility(Math.max(now, input.clock?.() ?? now));
        const first = Math.max(
          0,
          input.phases.findIndex((phase) => phase.phase === state.nextPhase),
        );
        const phases = [
          ...input.phases.slice(first),
          ...input.phases.slice(0, first),
        ];
        // A finite budget reserves a fair share per phase before any phase may
        // spend leftovers, so an early phase cannot take every unit.
        const share = Math.max(
          1,
          Math.floor(units / Math.max(1, phases.length)),
        );
        const spent = new Map<ReplicaPhase, number>();
        const ran = new Set<string>();
        const background = new Set(input.background ?? []);
        const leftovers = [
          ...phases.filter((handler) => !background.has(handler.phase)),
          ...phases.filter((handler) => background.has(handler.phase)),
        ];
        for (const pass of [0, 1]) {
          for (const handler of pass === 0 ? phases : leftovers) {
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
              const selected = handler.due(selection(), {
                total: cap - count,
                perWriter: input.perWriter ?? 1,
                after: state.writers[handler.phase],
              });
              const items = interleave(
                handler.phase,
                (isPromiseLike(selected) ? await selected : selected).filter(
                  (item: ReplicaWorkItem) => {
                    const key = `${handler.phase}\0${item.id}`;
                    return !inflight.has(key) && !ran.has(key);
                  },
                ),
              );
              let admitted = 0;
              for (const item of items) {
                if (count >= cap || units <= 0 || aborted()) break;
                const key = `${handler.phase}\0${item.id}`;
                ran.add(key);
                if (
                  item.bytes !== undefined &&
                  (!Number.isSafeInteger(item.bytes) || item.bytes < 0)
                )
                  throw new RangeError("invalid replica item byte estimate");
                // Under the omitted (default) budget an item larger than the
                // whole step can never fit. It runs when no other item has
                // charged bytes in this step, and spends the rest, as the
                // unbounded default on main ran it. An explicit budget defers
                // it until the host gives a budget it fits.
                const alone =
                  budget.bytes === undefined &&
                  item.bytes !== undefined &&
                  item.bytes > stepBytes &&
                  bytes === stepBytes;
                if (item.bytes !== undefined && item.bytes > bytes && !alone) {
                  deferred = true;
                  continue;
                }
                admitted++;
                count++;
                units--;
                if (alone) bytes = 0;
                else if (item.bytes !== undefined) bytes -= item.bytes;
                const attempt = await execute(handler, item, signal);
                if (attempt === undefined) break;
                try {
                  // Abort can arrive between the winning run promise and this
                  // continuation. Discard/release before entering a checkpoint.
                  if (aborted()) break;
                  const outcome = commit(handler, item, attempt, signal);
                  record(
                    report,
                    handler.phase,
                    item.id,
                    isPromiseLike(outcome) ? await outcome : outcome,
                  );
                } finally {
                  attempt.release?.();
                }
              }
              if (!admitted) break;
            }
            spent.set(handler.phase, used + count);
          }
        }
        // The same eligibility as selection, read after this step's commits.
        const after = eligibility(input.clock?.() ?? now);
        let wake: number | undefined;
        for (const handler of input.phases) {
          const earliest = handler.earliest(after);
          const next = isPromiseLike(earliest) ? await earliest : earliest;
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
      } finally {
        stepping = false;
      }
    },
    onDependencyChanged(key: string, now: number): MaybePromise<number> {
      const counts = input.phases.map((handler) => handler.wake?.(key, now));
      const sum = (values: (number | undefined)[]) =>
        values.reduce<number>((total, value) => total + (value ?? 0), 0);
      return counts.some(isPromiseLike)
        ? Promise.all(counts).then(sum)
        : sum(counts as (number | undefined)[]);
    },
  };
}
