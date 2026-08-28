/**
 * The query layer's request/answer contract (implementation plan phase 5).
 *
 * `QueryAnswer.coverage` is assembled by the host from its own counters, never
 * from anything the model or its script says — the integrity rule in
 * `docs/260828-query-layer-prompt.md` §1. A script that scans 30 of 300 records
 * cannot report completeness, because it does not author that field.
 */

export interface QueryBudget {
  /** Maximum model turns. Also the only bound on relay call volume today. */
  toolCalls?: number;
  wallClockMs?: number;
  usd?: number;
}

export interface QueryRequest {
  question: string;
  grantedScopes: string[];
  budget?: QueryBudget;
}

export interface QueryCitation {
  scope: string;
  recordId?: string;
  blockRef?: string;
}

/**
 * Why a run stopped early. `budget` is a first-class outcome, not an error
 * (prompt doc §3): the run ends with a partial answer and `complete: false`.
 */
export type QueryStoppedBecause =
  | "budget"
  | "wallClock"
  | "cpu"
  | "memory"
  | "outputCap"
  | "policyDenied"
  | "sandboxUnavailable"
  | "contractViolation"
  | "error";

export interface QueryCoverage {
  scopesScanned: string[];
  recordsScanned: number;
  scopesSkipped: { scope: string; reason: string }[];
  /** False ⇒ the answer text must say so. Host-authored. */
  complete: boolean;
  /** Records present but unreadable — what makes an absence answer honest. */
  unreadable?: number;
  /** "prefiltered" marks a semantically-narrowed pass (prompt doc §5, Q9/Q15). */
  method?: "full" | "prefiltered";
  stoppedBecause?: QueryStoppedBecause;
  /**
   * Scopes reached with no T2 profile. Plan §3 risk 3: a source without a
   * profile is reduced-confidence and must be flagged, not answered as if it
   * were understood.
   */
  unprofiledScopes?: string[];
  /**
   * Set when profile prose was summarized to fit the prompt budget. Plan §4.3:
   * reduced capability must be visible.
   */
  profilesSummarized?: string[];
  /** OS-sandbox policy violations observed during the run. */
  violations?: string[];
}

export interface QueryCost {
  toolCalls: number;
  inputTokens: number;
  outputTokens: number;
  usd?: number;
}

export interface QueryAnswer {
  answer: string;
  citations: QueryCitation[];
  coverage: QueryCoverage;
  /** The code that produced the answer, when a script ran. */
  script?: string;
  determinism: "replayed" | "generated";
  cost: QueryCost;
  /** The numeric result when the answer has one. */
  value?: number;
  /** Relay receipt ids seen across the run (`x-receipt-id`). */
  receiptIds?: string[];
}

/** Model-declared confidence from a `vana:answer` block. Never coverage. */
export type QueryConfidence = "high" | "medium" | "low";

/**
 * Coverage for a run that produced none.
 *
 * Fails closed: nothing scanned, nothing complete. Used when no confined run
 * ever reported — a contract violation burned both attempts, or the coverage
 * frame never arrived. The alternative, defaulting to an empty-but-complete
 * shape, would let "we learned nothing" render as a confident total.
 */
export const EMPTY_COVERAGE: QueryCoverage = Object.freeze({
  scopesScanned: [],
  recordsScanned: 0,
  scopesSkipped: [],
  complete: false,
});
