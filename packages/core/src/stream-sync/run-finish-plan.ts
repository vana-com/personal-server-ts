/**
 * What a stream-sync run made, decided from what its host saw: the outcome,
 * the streams whose records count, the checkpoint candidate and the streams
 * it may replace whole. Pure: host observations and the run's declarations
 * in, a plan out. Run end applies the plan; hosts show its answer.
 *
 * This is Desktop's rule, moved here so every host gets the same one: the
 * runtime's `covered_streams_with(source_answers_cover = true)` and
 * `safe_checkpoints`, the session's `finish_plan`, and the withheld-record
 * rule of `finish_with_blobs` (`block_upward`, `prune_downward`). Vectors:
 * `contracts/run-finish-plan.json`.
 */
import type { JsonValue } from "@opendatalabs/personal-server-ts-stream-sync";
import type { EndOutcome } from "./host-contract.js";
import {
  RunIntakeError,
  type CoverageStrategy,
  type EndRequest,
  type RunFinish,
  type StreamObservation,
} from "./intake.js";

/** What run end knows of each declared stream from the run's START. */
export interface RunFinishStream {
  readonly mode: "full_refresh" | "incremental";
  readonly coverageStrategy?: CoverageStrategy | null;
  readonly stateParents?: readonly string[];
}

export interface RunFinishInput {
  readonly finish: RunFinish;
  readonly streams: Readonly<Record<string, StreamObservation>>;
  readonly checkpoints: Readonly<Record<string, JsonValue>>;
  readonly provenFullStreams?: readonly string[];
}

export interface RunFinishPlan {
  readonly streamStatus?: Readonly<Record<string, "succeeded" | "held">>;
  /** `failed`: nothing of the run counts; run end discards it. */
  readonly outcome: Exclude<EndOutcome, "cancelled">;
  /** Sorted. Upserts of other streams are dropped; deletes always count. */
  readonly covered: readonly string[];
  readonly provenFull: readonly string[];
  readonly candidate: Readonly<Record<string, JsonValue>>;
  /** No selected stream was confirmed (see `EndResponse.unconfirmed`). */
  readonly unconfirmed: boolean;
}

/** `(child, parents)`: a child's cursor depends on its parents' cursors. */
export type StreamDependencies = readonly (readonly [
  string,
  readonly string[],
])[];

/** A blocked child blocks its parents, transitively. */
export function blockUpward(
  blocked: Set<string>,
  dependencies: StreamDependencies,
): void {
  for (;;) {
    const before = blocked.size;
    for (const [child, parents] of dependencies)
      if (blocked.has(child)) for (const parent of parents) blocked.add(parent);
    if (blocked.size === before) return;
  }
}

/**
 * Against the surviving cursors, a child whose parent has none loses its own.
 * A child pruned here never blocks its other parents.
 */
export function pruneDownward(
  eligible: Set<string>,
  dependencies: StreamDependencies,
): void {
  for (;;) {
    const before = eligible.size;
    for (const [child, parents] of dependencies)
      if (parents.some((parent) => !eligible.has(parent)))
        eligible.delete(child);
    if (eligible.size === before) return;
  }
}

function isNonNegativeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function jsonEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (Array.isArray(a))
    return (
      Array.isArray(b) &&
      a.length === b.length &&
      a.every((item, i) => jsonEqual(item, b[i]))
    );
  if (a && b && typeof a === "object" && typeof b === "object") {
    const keys = Object.keys(a);
    return (
      !Array.isArray(b) &&
      keys.length === Object.keys(b).length &&
      keys.every(
        (key) =>
          Object.prototype.hasOwnProperty.call(b, key) &&
          jsonEqual(
            (a as Record<string, unknown>)[key],
            (b as Record<string, unknown>)[key],
          ),
      )
    );
  }
  return false;
}

function reportField(report: JsonValue | undefined, field: string): unknown {
  return isPlainObject(report) ? report[field] : undefined;
}

/** Every considered key covered and every required key hydrated. */
function reportComplete(report: JsonValue | undefined): boolean {
  if (report === undefined) return false;
  const considered = reportField(report, "considered");
  const covered = reportField(report, "covered");
  const required = reportField(report, "required_keys");
  const hydrated = reportField(report, "hydrated_keys");
  return (
    isNonNegativeInteger(considered) &&
    considered === covered &&
    Array.isArray(required) &&
    Array.isArray(hydrated) &&
    required.every((key) => hydrated.some((h) => jsonEqual(h, key)))
  );
}

/** No report, or one with every considered key covered and no gap keys. */
function reportShowsWhole(report: JsonValue | undefined): boolean {
  if (report === undefined) return true;
  const considered = reportField(report, "considered");
  const gapKeys = reportField(report, "gap_keys");
  return (
    isNonNegativeInteger(considered) &&
    considered === reportField(report, "covered") &&
    (gapKeys === undefined || (Array.isArray(gapKeys) && gapKeys.length === 0))
  );
}

interface Run {
  readonly selected: readonly string[];
  readonly obs: (stream: string) => StreamObservation;
  readonly declared: (stream: string) => RunFinishStream | undefined;
  readonly retry: boolean;
  readonly dependencies: StreamDependencies;
}

function skipped(o: StreamObservation): boolean {
  return o.retryableSkip || o.otherSkip || o.preflightExclusion;
}

function anyRecord(o: StreamObservation): boolean {
  return o.liveRecord || o.explicitDelete;
}

/**
 * Desktop's `safe_checkpoints`: the cursors of `published` streams that no
 * skip, exclusion, gap or dependency holds back. `heldInDone` adds a failed
 * DONE's failed streams to the skipped ones.
 */
function safeCheckpoints(
  run: Run,
  checkpoints: Readonly<Record<string, JsonValue>>,
  published: readonly string[],
  retry: boolean,
  heldInDone = false,
  held: readonly string[] = [],
): Record<string, JsonValue> {
  const blocked = new Set<string>(held);
  for (const stream of run.selected) {
    const o = run.obs(stream);
    const retryableSkip = retry && o.retryableSkip;
    if (
      o.otherSkip ||
      (!retryableSkip && (skipped(o) || (heldInDone && o.failedInDone))) ||
      o.preflightExclusion ||
      o.detailGap === "retryable" ||
      o.invalidDetailCoverage ||
      (retry && o.detailGap !== "none")
    )
      blocked.add(stream);
  }
  const dependencies: (readonly [string, readonly string[]])[] = [];
  for (const child of run.selected) {
    const declared = run.declared(child);
    let parents = declared?.stateParents ?? [];
    if (declared?.coverageStrategy === "parent_detail_accounting") {
      // The manifest is authoritative: a connector report cannot invent a
      // STATE parent.
      if (parents.length === 0) parents = [child];
      const report = run.obs(child).detailCoverage;
      const complete = reportComplete(report);
      for (const parent of parents)
        if (!complete || reportField(report, "state_stream") !== parent)
          blocked.add(parent);
    }
    if (parents.length > 0) dependencies.push([child, parents]);
  }
  for (const [, parents] of dependencies)
    for (const parent of parents) {
      const o = run.selected.includes(parent) ? run.obs(parent) : undefined;
      if (o && o.detailGap !== "none") blocked.add(parent);
    }
  blockUpward(blocked, dependencies);
  const eligible = new Set(
    Object.keys(checkpoints).filter(
      (stream) => published.includes(stream) && !blocked.has(stream),
    ),
  );
  pruneDownward(eligible, dependencies);
  return pick(checkpoints, eligible);
}

function pick(
  checkpoints: Readonly<Record<string, JsonValue>>,
  streams: Iterable<string>,
): Record<string, JsonValue> {
  const keep = new Set(streams);
  const out: Record<string, JsonValue> = Object.create(null);
  for (const stream of Object.keys(checkpoints).sort())
    if (keep.has(stream)) out[stream] = checkpoints[stream]!;
  return out;
}

const FAILED: RunFinishPlan = {
  outcome: "failed",
  covered: [],
  provenFull: [],
  candidate: {},
  unconfirmed: false,
};

/**
 * Plan a run's finish. `declared` holds the run's START per stream: every
 * declared stream, selected or not (a parent may be unselected).
 */
export function planRunFinish(
  input: RunFinishInput,
  declared: Readonly<Record<string, RunFinishStream>>,
  policy: "legacy" | "raw-v1" = "legacy",
): RunFinishPlan {
  const selected = Object.keys(input.streams).sort();
  const obs = (stream: string) => input.streams[stream]!;
  const declaredOf = (stream: string) =>
    Object.prototype.hasOwnProperty.call(declared, stream)
      ? declared[stream]
      : undefined;
  const dependencies: [string, readonly string[]][] = [];
  for (const child of selected) {
    const parents = declaredOf(child)?.stateParents ?? [];
    if (parents.length > 0) dependencies.push([child, parents]);
  }
  const run: Run = {
    selected,
    obs,
    declared: declaredOf,
    retry: selected.some((stream) => obs(stream).retryableSkip),
    dependencies,
  };
  const proven = new Set(input.provenFullStreams ?? []);
  const anyDelete = selected.some((stream) => obs(stream).explicitDelete);
  if (policy === "raw-v1") return planRawV1(input, run, proven, anyDelete);
  if (input.finish !== "completed")
    return planFailedDone(input, run, proven, anyDelete);

  // A silent stream counts unless this run would clear it; then it needs an
  // explicit answer from the source: a delete or a whole-stream proof.
  const answered = selected.filter((stream) => {
    const o = obs(stream);
    return (
      o.sourceAnswered !== false &&
      !skipped(o) &&
      (declaredOf(stream)?.mode !== "full_refresh" ||
        o.liveRecord ||
        o.explicitDelete ||
        proven.has(stream))
    );
  });
  const covered = answered.filter((stream) => obs(stream).detailGap === "none");
  if (run.retry) {
    // Finished streams publish independently. Unfinished streams retain the
    // retry rule: only record-free tokens with safe dependencies may move.
    const finished = safeCheckpoints(run, input.checkpoints, covered, false);
    const retryTokens = withheld(
      run,
      safeCheckpoints(run, input.checkpoints, selected, true),
    );
    return {
      outcome: covered.length > 0 ? "partial" : "retry_pending",
      covered,
      provenFull: covered.filter((stream) => proven.has(stream)),
      candidate: {
        ...pick(
          retryTokens,
          selected.filter((stream) => !covered.includes(stream)),
        ),
        ...pick(finished, covered),
      },
      unconfirmed: false,
    };
  }
  if (answered.length === 0 && selected.length > 0) {
    // Nothing confirmed. Explicit deletes still count, key by key; no cursor
    // moves. A run that selected no stream has nothing to confirm.
    return anyDelete
      ? {
          outcome: "retry_pending",
          covered: [],
          provenFull: [],
          candidate: {},
          unconfirmed: true,
        }
      : { ...FAILED, unconfirmed: true };
  }
  const safe = safeCheckpoints(run, input.checkpoints, answered, false);
  return {
    outcome: covered.length < selected.length ? "partial" : "succeeded",
    covered,
    provenFull: covered.filter((stream) => proven.has(stream)),
    candidate: pick(safe, covered),
    unconfirmed: false,
  };
}

/** V1 has no retry cursor-only exception: every held stream keeps its cursor. */
function planRawV1(
  input: RunFinishInput,
  run: Run,
  proven: ReadonlySet<string>,
  anyDelete: boolean,
): RunFinishPlan {
  const completed = input.finish === "completed";
  const covered = run.selected.filter((stream) => {
    const o = run.obs(stream);
    if (
      o.sourceAnswered === false ||
      skipped(o) ||
      o.detailGap !== "none" ||
      o.invalidDetailCoverage ||
      o.failedInDone
    )
      return false;
    if (!completed) return anyRecord(o);
    return (
      run.declared(stream)?.mode !== "full_refresh" ||
      anyRecord(o) ||
      proven.has(stream)
    );
  });
  const held = run.selected.filter((stream) => !covered.includes(stream));
  const retry = run.selected.some(
    (stream) =>
      run.obs(stream).retryableSkip ||
      run.obs(stream).detailGap === "retryable",
  );
  const noAnswer = covered.length === 0 && run.selected.length > 0;
  const certified =
    input.finish === "certified_failed_done" &&
    run.selected.some((stream) => run.obs(stream).failedInDone);
  return {
    outcome: noAnswer
      ? retry || anyDelete
        ? "retry_pending"
        : "failed"
      : !completed || held.length > 0
        ? "partial"
        : "succeeded",
    covered,
    provenFull:
      completed || certified
        ? covered.filter((stream) => proven.has(stream))
        : [],
    candidate: completed
      ? safeCheckpoints(run, input.checkpoints, covered, false, true, held)
      : {},
    unconfirmed: noAnswer && !retry,
    streamStatus: Object.fromEntries(
      run.selected.map((stream) => [
        stream,
        covered.includes(stream) ? "succeeded" : "held",
      ]),
    ),
  };
}

/** The retry rule: streams with unsent records, and their parents, keep their cursor. */
function withheld(
  run: Run,
  candidate: Record<string, JsonValue>,
): Record<string, JsonValue> {
  const blocked = new Set(
    run.selected.filter((stream) => anyRecord(run.obs(stream))),
  );
  if (blocked.size === 0) return candidate;
  blockUpward(blocked, run.dependencies);
  const eligible = new Set(
    Object.keys(candidate).filter((stream) => !blocked.has(stream)),
  );
  pruneDownward(eligible, run.dependencies);
  return pick(candidate, eligible);
}

/**
 * A failed DONE keeps the records of streams nothing held back and moves no
 * cursor. Certified, it also names whole the streams a succeeded run would
 * have covered.
 */
function planFailedDone(
  input: RunFinishInput,
  run: Run,
  proven: ReadonlySet<string>,
  anyDelete: boolean,
): RunFinishPlan {
  const certified =
    input.finish === "certified_failed_done" &&
    run.selected.some((stream) => run.obs(stream).failedInDone);
  // A stream named failed in DONE is never covered: its upserts are never
  // kept, while its explicit deletes still publish (end keeps every delete).
  const published = run.selected.filter(
    (stream) =>
      run.obs(stream).sourceAnswered !== false &&
      !skipped(run.obs(stream)) &&
      !run.obs(stream).failedInDone &&
      anyRecord(run.obs(stream)),
  );
  if (!certified) {
    if (published.length === 0 && !anyDelete) return FAILED;
    return {
      outcome: "partial",
      covered: published,
      provenFull: [],
      candidate: {},
      unconfirmed: false,
    };
  }
  const all = Object.fromEntries(
    run.selected.map((stream) => [stream, null as JsonValue]),
  );
  const unheld = Object.keys(
    safeCheckpoints(run, all, run.selected, false, true),
  );
  const covered = published.filter((stream) => unheld.includes(stream));
  const cursors = Object.keys(input.checkpoints).filter((stream) =>
    unheld.includes(stream),
  );
  if (covered.length === 0 && cursors.length === 0 && !anyDelete) return FAILED;
  const unblocked = Object.keys(safeCheckpoints(run, all, run.selected, false));
  const whole = covered.filter((stream) => {
    const o = run.obs(stream);
    return (
      proven.has(stream) ||
      (unblocked.includes(stream) &&
        o.detailGap === "none" &&
        !o.invalidDetailCoverage &&
        reportShowsWhole(o.detailCoverage))
    );
  });
  return {
    outcome: "partial",
    covered,
    provenFull: whole,
    candidate: {},
    unconfirmed: false,
  };
}

const OBSERVATION_FLAGS = [
  "liveRecord",
  "explicitDelete",
  "retryableSkip",
  "otherSkip",
  "preflightExclusion",
  "invalidDetailCoverage",
  "failedInDone",
] as const;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * Check an `end` body's shape. `run` names the streams the run declared; an
 * observation of another stream is refused.
 */
export function parseEndRequest(
  body: unknown,
  declaredStreams: readonly string[],
): EndRequest {
  const invalid = (why: string) =>
    new RunIntakeError("invalid_request", `end: ${why}`);
  if (!isPlainObject(body)) throw invalid("body must be an object");
  const { finish, streams, checkpoints, lastBatch, provenFullStreams } = body;
  if (
    finish !== "completed" &&
    finish !== "certified_failed_done" &&
    finish !== "failed_done_upsert_only"
  )
    throw invalid("unknown finish");
  if (!isPlainObject(streams)) throw invalid("streams must be an object");
  for (const [name, o] of Object.entries(streams)) {
    if (!declaredStreams.includes(name))
      throw invalid(`unknown stream ${name}`);
    if (
      !isPlainObject(o) ||
      (o.sourceAnswered !== undefined &&
        typeof o.sourceAnswered !== "boolean") ||
      OBSERVATION_FLAGS.some((flag) => typeof o[flag] !== "boolean") ||
      (o.detailGap !== "none" &&
        o.detailGap !== "retryable" &&
        o.detailGap !== "fatal")
    )
      throw invalid(`bad observation for ${name}`);
  }
  if (!isPlainObject(checkpoints))
    throw invalid("checkpoints must be an object");
  if (typeof lastBatch !== "number" || !Number.isInteger(lastBatch))
    throw invalid("lastBatch must be an integer");
  if (
    provenFullStreams !== undefined &&
    (!Array.isArray(provenFullStreams) ||
      provenFullStreams.some((s) => typeof s !== "string"))
  )
    throw invalid("provenFullStreams must be strings");
  return body as unknown as EndRequest;
}
