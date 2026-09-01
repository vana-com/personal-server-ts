/**
 * An answerer that refuses to answer anything.
 *
 * The floor of the scale. Every case must fail against it — if any case passes
 * here, that case is not testing what it claims to test. Cheap insurance
 * against a grader that accepts empty answers.
 */

import type {
  EvalAnswerer,
  EvalQueryAnswer,
  EvalQueryRequest,
} from "../types.js";

export function createNullAnswerer(): EvalAnswerer {
  return {
    name: "null",
    async answer(request: EvalQueryRequest): Promise<EvalQueryAnswer> {
      return {
        answer: "",
        citations: [],
        coverage: {
          scopesScanned: [],
          recordsScanned: 0,
          scopesSkipped: request.grantedScopes.map((scope) => ({
            scope,
            reason: "null answerer",
          })),
        },
        determinism: "generated",
        cost: { toolCalls: 0, inputTokens: 0, outputTokens: 0, usd: 0 },
      };
    },
  };
}
