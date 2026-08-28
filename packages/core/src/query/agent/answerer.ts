/**
 * Adapts the agent loop to the phase 1 eval harness's `EvalAnswerer`.
 *
 * This is what lets `npm run eval` grade the real loop against the same 18
 * cases the reference answerer is graded on — the comparison plan §7 asks for
 * (beat the tool loop, not just the truncation heuristic).
 *
 * The shapes are near-identical by construction: `evals/types.ts` says phase 5
 * owns the real definitions and that one should be hoisted when it lands. This
 * adapter is the seam until that hoist happens, and it is where any drift
 * between the two becomes a compile error rather than a silent mismatch.
 */

import type {
  EvalAnswerer,
  EvalQueryAnswer,
  EvalQueryRequest,
} from "../evals/types.js";
import { runQueryLoop, type QueryLoopOptions } from "./loop.js";

export interface AgentAnswererOptions extends QueryLoopOptions {
  /** Reported in the eval output so a run's provenance is legible. */
  name?: string;
}

export function createAgentAnswerer(
  options: AgentAnswererOptions,
): EvalAnswerer {
  return {
    name: options.name ?? "agent-loop",
    async answer(request: EvalQueryRequest): Promise<EvalQueryAnswer> {
      const result = await runQueryLoop(
        {
          question: request.question,
          grantedScopes: request.grantedScopes,
          ...(request.budget ? { budget: request.budget } : {}),
        },
        options,
      );

      // `stoppedBecause` is wider on the loop than the harness's union, which
      // only knows "budget" | "error". Narrow rather than cast: an unmapped
      // reason becomes "error", which is the honest reading for a grader.
      const stopped = result.coverage.stoppedBecause;
      const evalStopped: "budget" | "error" | undefined =
        stopped === undefined
          ? undefined
          : stopped === "budget"
            ? "budget"
            : "error";

      const answer: EvalQueryAnswer = {
        answer: result.answer,
        citations: result.citations,
        coverage: {
          scopesScanned: result.coverage.scopesScanned,
          recordsScanned: result.coverage.recordsScanned,
          scopesSkipped: result.coverage.scopesSkipped,
          complete: result.coverage.complete,
          ...(result.coverage.unreadable === undefined
            ? {}
            : { unreadable: result.coverage.unreadable }),
          ...(result.coverage.method === undefined
            ? {}
            : { method: result.coverage.method }),
          ...(evalStopped === undefined ? {} : { stoppedBecause: evalStopped }),
        },
        determinism: result.determinism,
        cost: result.cost,
      };
      if (result.script !== undefined) answer.script = result.script;
      if (result.value !== undefined) answer.value = result.value;
      return answer;
    },
  };
}
