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
 * phase 5. Phase 5 owns the real definitions; these live here so the harness is
 * runnable before the agent loop exists. When phase 5 lands, hoist one
 * definition to `packages/core/src/query/types.ts` and have both import it.
 */
export interface EvalQueryRequest {
  question: string;
  grantedScopes: string[];
  budget?: { toolCalls?: number; wallClockMs?: number; usd?: number };
}

export interface EvalCoverage {
  scopesScanned: string[];
  recordsScanned: number;
  scopesSkipped: { scope: string; reason: string }[];
  complete: boolean;
  /** Records present but unreadable — what makes an absence answer honest. */
  unreadable?: number;
  /** "prefiltered" marks a semantically-narrowed pass (prompt doc §5, Q9/Q15). */
  method?: "full" | "prefiltered";
  stoppedBecause?: "budget" | "error";
}

export interface EvalQueryAnswer {
  answer: string;
  citations: { scope: string; recordId?: string; blockRef?: string }[];
  coverage: EvalCoverage;
  script?: string;
  determinism: "replayed" | "generated";
  cost: {
    toolCalls: number;
    inputTokens: number;
    outputTokens: number;
    usd?: number;
  };
  /**
   * Extension: the numeric result, when the answer has one. Grading falls back
   * to extracting a number from `answer` text, but an answerer that knows its
   * own figure should say so rather than make the grader guess.
   */
  value?: number;
}

export interface EvalAnswerer {
  readonly name: string;
  answer(request: EvalQueryRequest): Promise<EvalQueryAnswer>;
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
}

export interface EvalClassRollup {
  class: QueryEvalClass;
  pass: number;
  fail: number;
  skipped: number;
}

export interface EvalReport {
  answerer: string;
  seed: number;
  profile: string;
  results: EvalCaseResult[];
  rollups: EvalClassRollup[];
  totals: {
    pass: number;
    fail: number;
    skipped: number;
    wallClockMs: number;
    inputTokens: number;
    outputTokens: number;
    usd: number;
  };
}
