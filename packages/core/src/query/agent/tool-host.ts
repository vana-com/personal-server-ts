/**
 * The seam between the agent loop (phase 5) and capability confinement
 * (phase 4b). Reconciled 2026-08-28.
 *
 * ## What changed, and why it matters
 *
 * This interface previously offered `prepare(modelCode) -> {script, spec}` and
 * left the loop to call `sandbox.run(script, spec)` itself. Phase 4b then
 * measured that handing model-authored JavaScript to Node inside the phase-4a
 * sandbox is unsound: the script read its granted file with `require('fs')`,
 * so no counter observed the read, and printed a forged coverage line on the
 * same stdout the runtime uses.
 *
 * The fix is structural rather than advisory. The loop no longer holds a
 * `Sandbox` and no longer sees a script string: it calls `execute(modelCode)`
 * and receives a host-authored outcome. Running model code bare is now
 * unreachable from the loop rather than merely discouraged.
 *
 * ## The invariant this seam protects (prompt doc §1)
 *
 * Coverage is produced by the host. `ExecutedRun.coverage` originates in the
 * `CoverageLedger` inside the confined runtime — which the model's code cannot
 * name — and crosses the process boundary in a base64 frame the model's code
 * cannot produce. The loop treats it as authoritative and never synthesizes
 * those fields itself.
 */

import type { QueryCitation, QueryCoverage } from "./types.js";
import type { QueryScopeInfo } from "./prompt.js";

/** What a script passed to `vana.result(...)`, if it called it. */
export interface QueryScriptResult {
  answer?: string;
  citations?: QueryCitation[];
  value?: number;
  [key: string]: unknown;
}

/** The outcome of one confined run, as the loop sees it. */
export interface ExecutedRun {
  /** Host-authored. Never parsed out of script output or model prose. */
  coverage: QueryCoverage;
  /** `vana.note` output and routed `console.log`, in order. */
  notes: string[];
  /** Present when the script called `vana.result`. */
  result?: QueryScriptResult;
  /**
   * A confinement denial, budget exhaustion or script error. Surfaced to the
   * model verbatim: 4b's evaluator covers a deliberate subset of JS, so a
   * model that writes a `class` gets `CONFINEMENT_VIOLATION`, and it can only
   * correct that if it is told.
   */
  error?: { code: string; message: string };
  /** Why the sandbox stopped. Maps onto `coverage.stoppedBecause`. */
  termination: string;
  /** Script output with host framing removed, for feeding back to the model. */
  stdout: string;
  stderr: string;
  violations: string[];
  truncated: boolean;
}

export interface QueryToolHost {
  /** Granted scopes only. Anything outside the grant is unnameable, not denied. */
  listScopes(): Promise<QueryScopeInfo[]>;

  /**
   * Run one model-authored script under both layers: the confined interpreter
   * inside the OS sandbox. The model's code is data throughout.
   */
  execute(modelCode: string): Promise<ExecutedRun>;

  /**
   * Coverage accumulated across every run in this request, not just the last.
   *
   * A question can take several turns — read one scope, then another — and
   * coverage is a claim about the whole request. Reporting only the final
   * run's counters would let a two-scope answer claim it had read one scope,
   * which is the Q8 failure in a different disguise. A request where no script
   * ever ran has read nothing, and says so.
   */
  coverage(): QueryCoverage;
}
