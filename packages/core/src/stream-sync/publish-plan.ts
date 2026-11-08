/**
 * The writer's publish plan: for one stream, what each retained run will do to
 * the head, decided by the same step the writer executes when it publishes.
 *
 * The plan is a pure function of the stream's current head, the stream's
 * floor (the highest connector version that registered on it and the newest
 * commit), and the retained runs in commit order. The writer applies it one
 * step at a time against the head it reads from the registry
 * (`planStreamStep`); a reader asks for the whole plan from the head it has
 * imported (`planStream`) and shows what the plan publishes. Neither re-derives
 * the other's decision.
 *
 * Policies the step enforces:
 *
 * - **Version floor.** A run from a connector older than every version that
 *   registered on the stream is refused, whatever it changes (rows, key or
 *   profile, or nothing). A changed primary key is accepted only from a
 *   connector newer than that floor, not only newer than the last writer. The
 *   floor never goes down, and the published profile never goes back.
 * - **Commit order.** Runs commit in (observedAt, runId) order. A run older
 *   than the newest commit on the stream never commits; an unresolved run
 *   holds back every later run of the stream.
 * - **Re-projection.** A step that changes the primary key or the projector
 *   profile publishes, even when no row changes (`isNoop` with `next`).
 */

import {
  writerCompatibility,
  type HeadProfile,
  type VersionOrder,
} from "@opendatalabs/personal-server-ts-stream-sync";

/** Compare connector versions as dotted numbers (§2.5 compatible writer). */
export function compareConnectorVersions(a: string, b: string): VersionOrder {
  const pa = a
    .split(/[^0-9]+/)
    .filter(Boolean)
    .map(Number);
  const pb = b
    .split(/[^0-9]+/)
    .filter(Boolean)
    .map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i += 1) {
    const x = pa[i] ?? 0;
    const y = pb[i] ?? 0;
    if (x !== y) return x > y ? "higher" : "lower";
  }
  return "equal";
}

function higherVersion(a: string | null, b: string | null): string | null {
  if (a === null) return b;
  if (b === null) return a;
  return compareConnectorVersions(b, a) === "higher" ? b : a;
}

/** What the plan reads of a head. */
export interface PlanHead {
  /** null only in a prediction: a first run whose generation admission has not bound yet. */
  readonly generation: number | null;
  readonly primaryKey: readonly string[];
  readonly profile: HeadProfile;
  readonly complete: boolean;
}

/** The order commits follow on a stream. */
export interface CommitStamp {
  readonly observedAt: number;
  readonly runId: string;
}

export function stampBefore(a: CommitStamp, b: CommitStamp): boolean {
  return a.observedAt !== b.observedAt
    ? a.observedAt < b.observedAt
    : a.runId < b.runId;
}

/** What a stream remembers across publications on this writer. */
export interface StreamFloor {
  /** The highest connector version that registered on the stream; null = none. */
  readonly version: string | null;
  /** The newest run committed (or recorded as a no-op) on the stream. */
  readonly committed: CommitStamp | null;
}

export const NO_FLOOR: StreamFloor = Object.freeze({
  version: null,
  committed: null,
});

/**
 * The seed of one run's stream (§2.9): none, merged into this publish, or not
 * decided yet (the run is not admitted, so its target generation is unknown).
 */
export type PlanSeed = "none" | "merged" | "unresolved";

/** A step the writer already executed for this run's stream. */
export interface ExecutedStep {
  readonly kind: "publish" | "noop";
  readonly head: PlanHead;
  /** The head's earlier rows are not in the result. */
  readonly replacesBase: boolean;
}

/** What the writer knows of one retained run's stream. */
export interface PlanRun extends CommitStamp {
  /** The run's target generation; null while it is not bound. */
  readonly generation: number | null;
  readonly primaryKey: readonly string[];
  readonly profile: HeadProfile;
  /** The run read the stream whole (`full` or a non-incremental stream). */
  readonly full: boolean;
  /** The run resumed from another namespace's checkpoint (§2.12). */
  readonly foreignCheckpoint: boolean;
  /** The run holds no intake record for the stream (exact). */
  readonly empty: boolean;
  readonly seed: PlanSeed;
  /** Present once the writer committed or recorded a no-op for this stream. */
  readonly executed?: ExecutedStep;
  /** The writer persisted a signed request and has not recorded the registry's answer. */
  readonly inFlight?: boolean;
}

/** Which rows a head holds, relative to the head the plan started from. */
export interface PlanRows {
  /** The starting head's rows are kept (merged under the runs). */
  readonly fromHead: boolean;
  /** Run line sets merged over them, in commit order. */
  readonly runs: readonly string[];
  /** Seed rows (§2.9) are merged in; the overlay does not expose them. */
  readonly seed: boolean;
}

export type RefusedReason = "connector_update_required" | "out_of_order";

export type DeferredReason =
  /** The run is not admitted yet, so whether a seed merges is not known. */
  | "seed_unresolved"
  /** The run has no target generation yet. */
  | "generation_unbound"
  /** The stream holds a newer generation than the run's target. */
  | "stale_generation"
  /** An earlier run of the stream is not resolved; commits stay in order. */
  | "earlier_run_pending"
  /**
   * The writer sent a signed request for this run, or a later run, and the
   * registry's answer is not recorded. The request may have committed: until
   * it is reconciled, no run it would supersede or reorder has a known fate.
   */
  | "publication_in_flight";

export type StepDecision =
  /** The writer publishes `head`; the parts may turn out unchanged, then it records a no-op of the same head. */
  | {
      readonly kind: "publish";
      readonly head: PlanHead;
      readonly replacesBase: boolean;
      readonly seed: boolean;
      readonly floor: string;
    }
  /** Nothing changes: the head stays as it is. */
  | { readonly kind: "noop"; readonly head: PlanHead; readonly floor: string }
  | { readonly kind: "refused"; readonly reason: RefusedReason }
  | { readonly kind: "deferred"; readonly reason: DeferredReason };

export interface PlanState {
  /** The head the step meets; null when the stream has none. */
  readonly head: PlanHead | null;
  readonly floor: StreamFloor;
}

/**
 * One step: what the writer does with `run` over `state`. The writer calls
 * this with the head it read from the registry, after admission and seed
 * preparation; `planStream` calls it for every retained run in order.
 */
export function planStreamStep(state: PlanState, run: PlanRun): StepDecision {
  const { head, floor } = state;
  if (floor.committed && stampBefore(run, floor.committed)) {
    return { kind: "refused", reason: "out_of_order" };
  }
  // A run admission has not bound publishes over no head (a first run made
  // offline), or over the head earlier unbound runs leave; over a bound head,
  // which generation it will target is not known yet.
  if (run.generation === null && head !== null && head.generation !== null) {
    return { kind: "deferred", reason: "generation_unbound" };
  }
  if (
    head &&
    run.generation !== null &&
    head.generation !== null &&
    head.generation > run.generation
  ) {
    return { kind: "deferred", reason: "stale_generation" };
  }
  if (run.seed === "unresolved") {
    return { kind: "deferred", reason: "seed_unresolved" };
  }
  // chooseBase: a head of an older generation is no base (§2.7).
  const base = head && head.generation === run.generation ? head : null;
  const against = higherVersion(floor.version, base?.profile.version ?? null);
  const versus: VersionOrder =
    against === null
      ? "equal"
      : compareConnectorVersions(run.profile.version, against);
  // Policy B: a run below the stream's floor is refused whatever it changes,
  // so the published profile never goes back to an older version.
  if (versus === "lower") {
    return { kind: "refused", reason: "connector_update_required" };
  }
  const compat = writerCompatibility(base, run.primaryKey, versus);
  if (compat.kind === "connector_update_required") {
    return { kind: "refused", reason: "connector_update_required" };
  }
  const used = compat.kind === "empty_base" ? null : base;
  const seedMerged = run.seed === "merged";
  // §2.5 complete = full || base complete || seed merged; §2.12 a run resumed
  // from another namespace's checkpoint is incomplete even over a complete base.
  const complete =
    !run.foreignCheckpoint &&
    (run.full || (used?.complete ?? false) || seedMerged);
  const next: PlanHead = {
    generation: run.generation,
    primaryKey: run.primaryKey,
    profile: run.profile,
    complete,
  };
  const nextFloor = higherVersion(against, run.profile.version)!;
  if (used && run.empty && !seedMerged && sameHead(used, next)) {
    return { kind: "noop", head: used, floor: nextFloor };
  }
  return {
    kind: "publish",
    head: next,
    replacesBase: head !== null && used === null,
    seed: seedMerged,
    floor: nextFloor,
  };
}

export function sameHead(a: PlanHead, b: PlanHead): boolean {
  return (
    a.generation === b.generation &&
    a.complete === b.complete &&
    a.profile.key === b.profile.key &&
    a.profile.version === b.profile.version &&
    a.primaryKey.length === b.primaryKey.length &&
    a.primaryKey.every((field, i) => field === b.primaryKey[i])
  );
}

/** One run's step in a stream's plan. */
export interface PlanStep {
  readonly runId: string;
  readonly decision: StepDecision;
  /** The writer already executed this step; it waits for the reader to import it. */
  readonly executed: boolean;
  /** The head after this step, and the rows it holds; null when the stream has no head yet. */
  readonly head: PlanHead | null;
  readonly rows: PlanRows;
}

export function commitOrder(a: CommitStamp, b: CommitStamp): number {
  if (a.observedAt !== b.observedAt) return a.observedAt - b.observedAt;
  return a.runId < b.runId ? -1 : a.runId > b.runId ? 1 : 0;
}

/**
 * The whole plan of one stream from `head`: every retained run, in commit
 * order, with its decision and the head and rows it leaves. A run the writer
 * already executed keeps the decision it executed. Once a run is deferred,
 * every later run of the stream waits for it.
 */
export function planStream(
  head: PlanHead | null,
  floor: StreamFloor,
  runs: readonly PlanRun[],
): PlanStep[] {
  let state: PlanState = { head, floor };
  let rows: PlanRows = { fromHead: head !== null, runs: [], seed: false };
  let waiting = false;
  const steps: PlanStep[] = [];
  const ordered = [...runs].sort(commitOrder);
  // A signed request is never proof of success. The newest run in flight may
  // commit, which refuses every older run, or fail, which does not: neither
  // that run nor an older one has a known fate yet, and a later run waits.
  const barrier = ordered.filter((r) => r.inFlight && !r.executed).at(-1);
  for (const run of ordered) {
    let decision: StepDecision;
    if (!run.executed && barrier && commitOrder(run, barrier) <= 0) {
      decision = { kind: "deferred", reason: "publication_in_flight" };
    } else if (run.executed) {
      const { executed } = run;
      decision =
        executed.kind === "noop"
          ? {
              kind: "noop",
              head: executed.head,
              floor: higherVersion(state.floor.version, run.profile.version)!,
            }
          : {
              kind: "publish",
              head: executed.head,
              replacesBase: executed.replacesBase,
              seed: run.seed === "merged",
              floor: higherVersion(state.floor.version, run.profile.version)!,
            };
    } else if (waiting) {
      decision = { kind: "deferred", reason: "earlier_run_pending" };
    } else {
      decision = planStreamStep(state, run);
    }
    if (decision.kind === "deferred") waiting = true;
    if (decision.kind === "publish" || decision.kind === "noop") {
      if (decision.kind === "publish") {
        rows = decision.replacesBase
          ? { fromHead: false, runs: [run.runId], seed: decision.seed }
          : {
              fromHead: rows.fromHead,
              runs: [...rows.runs, run.runId],
              seed: rows.seed || decision.seed,
            };
      }
      const committed =
        state.floor.committed && stampBefore(run, state.floor.committed)
          ? state.floor.committed
          : { observedAt: run.observedAt, runId: run.runId };
      state = {
        head: decision.head,
        floor: { version: decision.floor, committed },
      };
    }
    steps.push({
      runId: run.runId,
      decision,
      executed: run.executed !== undefined,
      head: state.head,
      rows,
    });
  }
  return steps;
}
