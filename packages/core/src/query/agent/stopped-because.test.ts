import { describe, expect, it } from "vitest";

import { createFakeInferenceProvider } from "../../derivatives/inference.js";
import { runQueryLoop } from "./loop.js";
import type { ExecutedRun, QueryToolHost } from "./tool-host.js";
import type { QueryCoverage } from "./types.js";

const fence = "```";

function coverage(stoppedBecause?: QueryCoverage["stoppedBecause"]) {
  const base: QueryCoverage = {
    scopesScanned: ["oura.sleep"],
    recordsScanned: 10,
    bytesScanned: 100,
    scopesSkipped: [],
    complete: true,
  };
  return stoppedBecause ? { ...base, stoppedBecause } : base;
}

function erroredRun(): ExecutedRun {
  return {
    coverage: coverage("error"),
    notes: [],
    termination: "error",
    stdout: "",
    stderr: "boom",
    violations: [],
    truncated: false,
    error: { code: "SCRIPT_ERROR", message: "boom" },
  };
}

/**
 * `stoppedBecause` answers "why did this run stop", not "did anything go wrong
 * along the way".
 *
 * The host's per-request coverage merge keeps the FIRST abnormal termination it
 * ever saw (`prev.stoppedBecause ?? next.stoppedBecause`) and never lets a
 * later success supersede it, so a run that recovered from a bad script still
 * reported `error`. It fired on 24 of 54 benchmark runs *including passing
 * ones*, which made the failure-mode column unusable for anyone reading
 * coverage. Only the control-flow field is corrected here; every host-authored
 * counter is left exactly as the host wrote it.
 */
describe("stoppedBecause describes why the run ended", () => {
  it("is cleared when a script errored but the run went on to answer", async () => {
    // Host coverage stays sticky at "error" the way the real merge does.
    const host: QueryToolHost = {
      async listScopes() {
        return [{ scope: "oura.sleep", itemCount: 10 }];
      },
      async execute(): Promise<ExecutedRun> {
        return erroredRun();
      },
      coverage: () => coverage("error"),
    };

    let turn = 0;
    const provider = createFakeInferenceProvider({
      respond: () => {
        turn += 1;
        if (turn === 1) {
          return { content: `${fence}vana:run\nreadAll()\n${fence}` };
        }
        return {
          content: `${fence}vana:answer\n${JSON.stringify({
            answer: "6.5 hours.",
            citations: [{ scope: "oura.sleep" }],
            value: 6.5,
            resolution: "trailing 31 days, main sleep only",
          })}\n${fence}`,
        };
      },
    });

    const answer = await runQueryLoop(
      { question: "How much did I sleep?", grantedScopes: ["oura.sleep"] },
      { provider, tools: host },
    );

    expect(answer.value).toBe(6.5);
    expect(answer.resolution).toContain("trailing 31 days");
    expect(answer.coverage.stoppedBecause).toBeUndefined();
    // Counters are untouched — only the control-flow field was corrected.
    expect(answer.coverage.recordsScanned).toBe(10);
  });

  it("still reports the real reason when the run never answers", async () => {
    // Every turn produces a failing script. Falling back to "budget" would
    // misreport a broken run as an exhausted one.
    const host: QueryToolHost = {
      async listScopes() {
        return [{ scope: "oura.sleep", itemCount: 10 }];
      },
      async execute(): Promise<ExecutedRun> {
        return erroredRun();
      },
      coverage: () => coverage("error"),
    };

    const provider = createFakeInferenceProvider({
      respond: () => ({ content: `${fence}vana:run\nboom()\n${fence}` }),
    });

    const answer = await runQueryLoop(
      { question: "How much did I sleep?", grantedScopes: ["oura.sleep"] },
      { provider, tools: host, maxTurns: 2 },
    );

    expect(answer.coverage.stoppedBecause).toBe("error");
    expect(answer.coverage.complete).toBe(false);
  });

  it("reports budget when the run simply ran out of turns", async () => {
    const host: QueryToolHost = {
      async listScopes() {
        return [{ scope: "oura.sleep", itemCount: 10 }];
      },
      async execute(): Promise<ExecutedRun> {
        return {
          coverage: coverage(),
          notes: [],
          termination: "completed",
          stdout: "{}",
          stderr: "",
          violations: [],
          truncated: false,
        };
      },
      coverage: () => coverage(),
    };

    const provider = createFakeInferenceProvider({
      respond: () => ({ content: `${fence}vana:run\nreadAll()\n${fence}` }),
    });

    const answer = await runQueryLoop(
      { question: "How much did I sleep?", grantedScopes: ["oura.sleep"] },
      { provider, tools: host, maxTurns: 2 },
    );

    expect(answer.coverage.stoppedBecause).toBe("budget");
  });
});
