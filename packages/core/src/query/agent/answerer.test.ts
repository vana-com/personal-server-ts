import { describe, expect, it } from "vitest";

import { createFakeInferenceProvider } from "../../derivatives/inference.js";
import { runEval } from "../evals/runner.js";
import type { QueryEvalCase } from "../evals/types.js";
import { createAgentAnswerer } from "./answerer.js";
import type { QueryToolHost } from "./tool-host.js";

const fence = "```";

/**
 * A tool host that reads nothing. Phase 4b owns the real `vana.*`; this stub
 * exists only to prove that the LOOP satisfies the harness's `EvalAnswerer`
 * and that host-authored coverage flows through to grading. It deliberately
 * does not read the fixture corpus — that would be a second, divergent
 * implementation of 4b's surface.
 */
function stubTools(coverage: {
  recordsScanned: number;
  complete: boolean;
  unreadable?: number;
}): QueryToolHost {
  return {
    async listScopes() {
      return [{ scope: "oura.sleep", itemCount: coverage.recordsScanned }];
    },
    async execute() {
      return {
        coverage: {
          scopesScanned: ["oura.sleep"],
          recordsScanned: coverage.recordsScanned,
          scopesSkipped: [],
          complete: coverage.complete,
        },
        notes: [],
        termination: "completed",
        stdout: "",
        stderr: "",
        violations: [],
        truncated: false,
      };
    },
    coverage: () => ({
      scopesScanned: ["oura.sleep"],
      recordsScanned: coverage.recordsScanned,
      scopesSkipped: [],
      complete: coverage.complete,
      ...(coverage.unreadable === undefined
        ? {}
        : { unreadable: coverage.unreadable }),
    }),
  };
}

describe("createAgentAnswerer", () => {
  it("satisfies EvalAnswerer and grades a numeric case", async () => {
    const provider = createFakeInferenceProvider({
      respond: () => ({
        content: `${fence}vana:answer\n${JSON.stringify({
          answer:
            "6.52 hours over 1030 nights, main sleep only, naps excluded.",
          citations: [{ scope: "oura.sleep" }],
        })}\n${fence}`,
      }),
    });

    const answerer = createAgentAnswerer({
      provider,
      tools: stubTools({ recordsScanned: 1030, complete: true }),
      name: "agent-loop-test",
    });

    const cases: QueryEvalCase[] = [
      {
        id: "Q1",
        question: "How much did I sleep on average?",
        class: "aggregation",
        scopes: ["oura.sleep"],
        expect: { kind: "numeric", value: 6.52, tolerance: 0.05 },
        mustCite: true,
        mustReportCoverage: true,
      },
    ];

    const report = await runEval({
      cases,
      answerer,
      seed: 1,
      profile: "small",
    });

    expect(report.answerer).toBe("agent-loop-test");
    expect(report.totals.pass).toBe(1);
    expect(report.totals.fail).toBe(0);
  });

  it("fails a case honestly when the host's coverage is incomplete", async () => {
    // The model asserts a confident "never"; the host counted an unreadable
    // remainder. The graded outcome must reflect the host, not the model.
    const provider = createFakeInferenceProvider({
      respond: () => ({
        content: `${fence}vana:answer\n${JSON.stringify({
          answer: "No, you have never agreed to anything conflicting.",
          citations: [{ scope: "oura.sleep" }],
        })}\n${fence}`,
      }),
    });

    const answerer = createAgentAnswerer({
      provider,
      tools: stubTools({
        recordsScanned: 318,
        complete: false,
        unreadable: 22,
      }),
    });

    const result = await answerer.answer({
      question: "Have I ever agreed to anything that conflicts?",
      grantedScopes: ["oura.sleep"],
    });

    expect(result.coverage.complete).toBe(false);
    expect(result.coverage.unreadable).toBe(22);
    // The honesty rule: the caveat is in the prose, not just the metadata.
    expect(result.answer).toContain("22 record(s) could not be read");
  });

  it("preserves the loop's precise stoppedBecause for the grader", async () => {
    const provider = createFakeInferenceProvider({
      respond: () => ({ content: "prose with no block" }),
    });
    const answerer = createAgentAnswerer({
      provider,
      tools: stubTools({ recordsScanned: 0, complete: false }),
    });
    const result = await answerer.answer({
      question: "q",
      grantedScopes: ["oura.sleep"],
    });
    // Before the 4a/4b/5 integration this adapter narrowed the loop's nine
    // stop reasons onto the harness's `"budget" | "error"`, so a grader could
    // not tell "ran out of budget" from "the sandbox denied it" from "the
    // model never produced a valid script". The harness types are now aliases
    // of the loop's own, so the precise reason survives.
    expect(result.coverage.stoppedBecause).toBe("contractViolation");
  });
});
