/**
 * The graded question set's contract.
 *
 * `QueryEvalCase` is the interface from implementation plan phase 1, verbatim,
 * plus two optional fields that are flagged as extensions in the phase report:
 * `referenceFacts` (ground truth a `judged` rubric needs in order to be
 * checkable) and `expectedCoverage` (an absence case's exact readable /
 * unreadable counts, which the plan's `{ kind: "absence" }` cannot express).
 */

export type QueryEvalClass =
  | "aggregation"
  | "exhaustive"
  | "synthesis"
  | "inference"
  | "relational"
  | "introspection";

export type QueryEvalExpectation =
  | { kind: "numeric"; value: number; tolerance: number; denominator?: number }
  | { kind: "set"; contains: string[]; excludes?: string[] }
  | { kind: "absence"; mustReportCoverage: true }
  | { kind: "judged"; rubric: string };

export interface QueryEvalCase {
  id: string; // "Q1"
  question: string;
  class: QueryEvalClass;
  scopes: string[]; // scopes a consumer must hold to ask it
  expect: QueryEvalExpectation;
  mustCite: boolean;
  mustReportCoverage: boolean;

  /* --- extensions beyond the plan's interface (flagged in the report) --- */

  /**
   * Ground truth computed by the reference path. A `judged` rubric is not
   * checkable without it — "did it get the trend right" needs the trend.
   */
  referenceFacts?: Record<string, number | string>;
  /** Exact coverage an absence answer must account for. */
  expectedCoverage?: { recordsScanned?: number; unreadable?: number };
  /** Why a case cannot be graded offline, if it cannot. */
  requiresJudge?: boolean;
  /** Free-text note carried into the report. */
  notes?: string;
}

/* ------------------------------------------------------------------ */
/* The pluggable answerer                                              */
/* ------------------------------------------------------------------ */

/**
 * Mirrors the `QueryRequest` / `QueryAnswer` pair from implementation plan
 * phase 5.
 *
 * HOISTED 2026-08-28 (4a/4b/5 integration). Phase 5's `agent/types.ts` now
 * holds the single canonical definition and these are aliases, so the harness
 * cannot drift from what the loop actually returns — a mismatch becomes a
 * compile error rather than a grading bug. In particular `stoppedBecause` was
 * `"budget" | "error"` here while the loop produces nine values, so the
 * harness silently lost the reason a run stopped.
 */
export type {
  QueryRequest as EvalQueryRequest,
  QueryCoverage as EvalCoverage,
  QueryAnswer as EvalQueryAnswer,
} from "../agent/types.js";

import type { QueryRequest, QueryAnswer } from "../agent/types.js";
import type { DefensibleReading, ResolutionOutcome } from "./readings.js";

export interface EvalAnswerer {
  readonly name: string;
  answer(request: QueryRequest): Promise<QueryAnswer>;
}

/* ------------------------------------------------------------------ */
/* Results                                                             */
/* ------------------------------------------------------------------ */

export type EvalOutcome = "pass" | "fail" | "skipped";

export interface EvalCaseResult {
  id: string;
  class: QueryEvalClass;
  outcome: EvalOutcome;
  reasons: string[];
  durationMs: number;
  cost: {
    toolCalls: number;
    inputTokens: number;
    outputTokens: number;
    usd?: number;
  };
  actual?: number;
  /**
   * The set the answer says it aggregated over, verbatim.
   *
   * Recorded whether or not the number was right, because the two come apart:
   * the measured failure mode is a correct computation over the wrong set, and
   * without this the two are the same failing row.
   */
  resolution?: string;
  /**
   * True when a model, not a computed comparison, decided this row.
   *
   * Set where the verdict is made rather than reconstructed downstream, so a
   * report cannot render a judge's opinion and an arithmetic check
   * identically. A judge's verdict is not a measurement.
   */
  modelGraded?: boolean;

  /* --- the two grading rules, recorded side by side --- */

  /**
   * Which rule produced `outcome`.
   *
   * Resolution-aware for a question with enumerated readings on the corpus
   * they were enumerated over; strict everywhere else. Both verdicts are
   * always recorded — `outcome` picks one, it does not discard the other.
   */
  gradedBy?: "strict" | "resolution-aware";
  /**
   * Verdict under the strict rule: the number must match the single reading
   * the eval encodes. Kept computable so the old scoreboard stays comparable
   * across the change. Unset for a skipped case, which neither rule graded.
   */
  strictPass?: boolean;
  /**
   * Verdict under the resolution-aware rule, in full — including *how* it
   * failed, which is the part worth reading. `null` when the rule does not
   * apply: one honest reading, or a corpus the readings were not computed for.
   */
  resolutionOutcome?: ResolutionOutcome | null;
  /**
   * The reading the declaration classified to, flattened.
   *
   * `resolutionOutcome` carries the whole `DefensibleReading`, whose `signals`
   * are `RegExp`s that JSON-serialise to `{}`. Dumps are read back by
   * `scripts/query-regrade.ts`, so the two fields it actually needs are
   * duplicated here in a form that survives the round trip.
   */
  readingId?: string;
  readingLabel?: string;
}

export interface EvalClassRollup {
  class: QueryEvalClass;
  pass: number;
  fail: number;
  skipped: number;
  /** The same class under the strict rule, so the two scoreboards line up. */
  strictPass: number;
}

export interface EvalReport {
  answerer: string;
  seed: number;
  profile: string;
  results: EvalCaseResult[];
  rollups: EvalClassRollup[];
  /**
   * Whether the resolution-aware rule was in force, and on which questions.
   *
   * Empty when the run is not on the corpus the readings were enumerated over
   * — in which case every case graded strictly, and the report says so rather
   * than leaving the reader to assume the generous rule applied.
   */
  resolutionAware: string[];
  totals: {
    pass: number;
    fail: number;
    skipped: number;
    /**
     * Passes under the strict rule alone. `pass` is the headline; this is the
     * scoreboard the corpus reported before the rule existed, kept computable
     * so a change in the headline can be attributed.
     */
    strictPass: number;
    wallClockMs: number;
    inputTokens: number;
    outputTokens: number;
    usd: number;
  };
}

/* ------------------------------------------------------------------ */
/* Results, as they survive a JSON round trip                          */
/* ------------------------------------------------------------------ */

/**
 * A `DefensibleReading` as it appears in a dump on disk.
 *
 * Identical to the live shape except for `signals`. Those are `RegExp`s, and
 * `JSON.stringify` renders a `RegExp` as `{}` — which does not merely lose
 * them, it asserts the reading has no signals at all. The regexes ARE the
 * classification rule, so a reader asking "why did this resolution classify as
 * `trailing30`" needs them: the first analysis of the N=3 sweep re-implemented
 * `classifyResolution`'s regexes by hand against each row's `resolution`
 * string for exactly that reason. Written as `RegExp.source` strings, which
 * `new RegExp(...)` reverses.
 */
export interface SerializedReading extends Omit<DefensibleReading, "signals"> {
  signals: { all?: string[]; none?: string[] };
}

/**
 * A `ResolutionOutcome` as it appears in a dump on disk.
 *
 * `value` is `number | null` rather than `number`, because the outcome's own
 * "no number was returned at all" case carries `Number.NaN`, and JSON has no
 * NaN — it becomes `null` whether or not anyone meant it to. Saying so in the
 * type is the deliberate handling; a reader must not read it as a returned 0.
 */
export type SerializedResolutionOutcome =
  | { kind: "pass"; reading: SerializedReading }
  | { kind: "undeclared" }
  | { kind: "unrecognised"; resolution: string }
  | {
      kind: "inconsistent";
      reading: SerializedReading;
      value: number | null;
      expected: number;
    };

/** Flatten one reading's `RegExp` signals to their sources. */
function serializeReading(reading: DefensibleReading): SerializedReading {
  const { signals, ...rest } = reading;
  return {
    ...rest,
    signals: {
      ...(signals.all ? { all: signals.all.map((re) => re.source) } : {}),
      ...(signals.none ? { none: signals.none.map((re) => re.source) } : {}),
    },
  };
}

/**
 * Render a resolution outcome so a dump carries it losslessly.
 *
 * Every writer of a dump that `scripts/query-regrade.ts` reads goes through
 * here, so the writer and the reader share one definition of the on-disk
 * shape. Two of those drifting apart is the failure the dual-rule work exists
 * to avoid.
 */
export function serializeResolutionOutcome(
  outcome: ResolutionOutcome,
): SerializedResolutionOutcome {
  switch (outcome.kind) {
    case "pass":
      return { kind: "pass", reading: serializeReading(outcome.reading) };
    case "inconsistent":
      return {
        kind: "inconsistent",
        reading: serializeReading(outcome.reading),
        value: Number.isNaN(outcome.value) ? null : outcome.value,
        expected: outcome.expected,
      };
    default:
      return outcome;
  }
}
