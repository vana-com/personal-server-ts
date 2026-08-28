/**
 * PROVISIONAL — the seam between the agent loop (phase 5) and capability
 * confinement (phase 4b).
 *
 * Phase 4b owns the real `vana.*` implementation under
 * `packages/core/src/query/tools/`. That module did not exist when this loop
 * was written, so this file declares the NARROWEST interface the loop actually
 * needs and nothing more. It deliberately does not implement a `vana` API —
 * duplicating 4b's surface would guarantee a merge conflict and two divergent
 * definitions of the one invariant that matters.
 *
 * RECONCILIATION: when 4b lands, either have its module satisfy
 * `QueryToolHost` directly or write a thin adapter. The loop only ever calls
 * the five methods below.
 *
 * THE INVARIANT THIS SEAM PROTECTS (prompt doc §1): coverage is produced by the
 * host as it serves reads. `coverage()` must return counters the tool layer
 * accumulated, never anything parsed out of script output or model prose. The
 * loop treats whatever `coverage()` returns as authoritative and never
 * synthesizes those fields itself.
 */

import type { SandboxSpec } from "../ports.js";
import type { QueryCitation, QueryCoverage } from "./types.js";
import type { QueryScopeInfo } from "./prompt.js";

/** What a script passed to `vana.result(...)`, if it called it. */
export interface QueryScriptResult {
  answer?: string;
  citations?: QueryCitation[];
  value?: number;
  [key: string]: unknown;
}

export interface PreparedScript {
  /**
   * The full program handed to the sandbox: 4b's `vana` bridge plus the
   * model-authored body. The model's code is never executed bare.
   */
  script: string;
  /** Read paths, scratch dir and limits for this run, derived from the grant. */
  spec: SandboxSpec;
}

export interface QueryToolHost {
  /** Granted scopes only. Anything outside the grant is unnameable, not denied. */
  listScopes(): Promise<QueryScopeInfo[]>;

  /** Wrap model-authored code so it runs with `vana` in scope and nothing else. */
  prepare(modelCode: string): Promise<PreparedScript>;

  /**
   * Host-authored coverage for the run so far. Authoritative: the loop copies
   * these counters into the answer and never overrides them from script output.
   */
  coverage(): QueryCoverage;

  /** The payload from `vana.result(...)`, if the script terminated with one. */
  takeResult(): QueryScriptResult | undefined;

  /** Messages from `vana.note(...)`, drained per turn. */
  takeNotes(): string[];
}
