/**
 * Adapts the agent loop to the phase 1 eval harness's `EvalAnswerer`.
 *
 * This is what lets `npm run eval --answerer agent` grade the real loop
 * against the same 18 cases the reference answerer is graded on — the
 * comparison plan §7 asks for (beat the tool loop, not just the truncation
 * heuristic).
 *
 * Since the 4a/4b/5 integration the harness's request/answer types are
 * *aliases* of the loop's own, hoisted into `agent/types.ts`, so this adapter
 * no longer translates anything. It previously narrowed `stoppedBecause` from
 * the loop's nine values down to the harness's `"budget" | "error"`, which
 * silently discarded the reason a run stopped — exactly the information a
 * grader needs to distinguish "ran out of budget" from "the sandbox denied
 * it". That narrowing is gone.
 */

import type { EvalAnswerer } from "./types.js";
import { runQueryLoop, type QueryLoopOptions } from "../agent/loop.js";
import type { QueryAnswer, QueryRequest } from "../agent/types.js";

export interface AgentAnswererOptions extends QueryLoopOptions {
  /** Reported in the eval output so a run's provenance is legible. */
  name?: string;
}

export function createAgentAnswerer(
  options: AgentAnswererOptions,
): EvalAnswerer {
  return {
    name: options.name ?? "agent-loop",
    async answer(request: QueryRequest): Promise<QueryAnswer> {
      return runQueryLoop(
        {
          question: request.question,
          grantedScopes: request.grantedScopes,
          ...(request.budget ? { budget: request.budget } : {}),
        },
        options,
      );
    },
  };
}
