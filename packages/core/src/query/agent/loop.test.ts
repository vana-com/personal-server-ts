import { describe, expect, it } from "vitest";

import {
  createFakeInferenceProvider,
  type InferenceChatResult,
} from "../../derivatives/inference.js";
import { runQueryLoop } from "./loop.js";
import type {
  ExecutedRun,
  QueryScriptResult,
  QueryToolHost,
} from "./tool-host.js";

const fence = "```";

function runBlock(body: string): string {
  return `${fence}vana:run\n${body}\n${fence}`;
}
function answerBlock(payload: Record<string, unknown>): string {
  return `${fence}vana:answer\n${JSON.stringify(payload)}\n${fence}`;
}
function reply(content: string): InferenceChatResult {
  return {
    content,
    usage: { promptTokens: 10, completionTokens: 5 },
    receiptId: "r-1",
  };
}

/**
 * A tool host that runs nothing. Since the 4a/4b/5 integration the loop has no
 * `Sandbox` of its own — the host owns both layers and returns an already
 * host-authored outcome — so these fakes stand in for a confined run rather
 * than for a sandbox.
 */
function executed(over: Partial<ExecutedRun> = {}): ExecutedRun {
  return {
    coverage: {
      scopesScanned: ["oura.sleep"],
      recordsScanned: 1030,
      scopesSkipped: [],
      complete: true,
    },
    notes: [],
    termination: "completed",
    stdout: "",
    stderr: "",
    violations: [],
    truncated: false,
    ...over,
  };
}

function fakeTools(
  runs: ExecutedRun[] = [executed()],
  over: Partial<QueryToolHost> = {},
): QueryToolHost & { executed: string[] } {
  const seen: string[] = [];
  let i = 0;
  let last: ExecutedRun | undefined;
  return {
    executed: seen,
    async listScopes() {
      return [{ scope: "oura.sleep", itemCount: 1030 }];
    },
    async execute(modelCode: string) {
      seen.push(modelCode);
      last = runs[Math.min(i++, runs.length - 1)] ?? executed();
      return last;
    },
    // Stands in for the real host's accumulator. A request where no script
    // ran has read nothing, and must say so rather than inherit a default.
    coverage() {
      return (
        last?.coverage ?? {
          scopesScanned: [],
          recordsScanned: 0,
          scopesSkipped: [],
          complete: false,
        }
      );
    },
    ...over,
  } as QueryToolHost & { executed: string[] };
}

describe("runQueryLoop — happy path", () => {
  it("runs a script then returns the model's answer", async () => {
    const provider = createFakeInferenceProvider({
      respond: (_i, n) =>
        reply(
          n === 0
            ? runBlock("const s = await vana.readAll('oura.sleep');")
            : answerBlock({
                answer: "6.52 hours over 1030 nights, main sleep only.",
                citations: [{ scope: "oura.sleep" }],
              }),
        ),
    });
    const tools = fakeTools([executed({ stdout: "avg=6.52" })]);

    const out = await runQueryLoop(
      { question: "How much did I sleep?", grantedScopes: ["oura.sleep"] },
      { provider, tools },
    );

    expect(out.answer).toContain("6.52 hours");
    expect(out.coverage.complete).toBe(true);
    expect(out.coverage.recordsScanned).toBe(1030);
    expect(out.script).toContain("vana.readAll");
    expect(out.cost.toolCalls).toBe(2);
    expect(out.receiptIds).toEqual(["r-1", "r-1"]);
  });

  it("wraps the model's code before executing it — never runs it bare", async () => {
    const provider = createFakeInferenceProvider({
      respond: (_i, n) =>
        reply(n === 0 ? runBlock("evil()") : answerBlock({ answer: "done" })),
    });
    const tools = fakeTools();
    await runQueryLoop(
      { question: "q", grantedScopes: ["oura.sleep"] },
      { provider, tools },
    );
    // The loop hands RAW model code to the host and holds no sandbox of its
    // own. Since the 4a/4b/5 integration the host runs it as data inside the
    // confined interpreter, so "running it bare" is unreachable from here
    // rather than merely avoided by convention.
    expect(tools.executed[0]).toBe("evil()");
    expect("sandbox" in ({} as Record<string, unknown>)).toBe(false);
  });

  it("feeds script output back as the next message's content", async () => {
    const provider = createFakeInferenceProvider({
      respond: (_i, n) =>
        reply(n === 0 ? runBlock("x") : answerBlock({ answer: "done" })),
    });
    await runQueryLoop(
      { question: "q", grantedScopes: ["oura.sleep"] },
      {
        provider,
        tools: fakeTools([executed({ stdout: "SENTINEL_OUT" })]),
      },
    );
    const second = provider.calls[1];
    expect(second?.messages.at(-1)?.content).toContain("SENTINEL_OUT");
    expect(second?.messages.at(-1)?.role).toBe("user");
  });

  it("ends the run when the script calls vana.result", async () => {
    const provider = createFakeInferenceProvider({
      respond: () => reply(runBlock("vana.result({answer:'from script'})")),
    });
    const result: QueryScriptResult = {
      answer: "from script",
      citations: [{ scope: "oura.sleep" }],
      value: 6.52,
    };
    const out = await runQueryLoop(
      { question: "q", grantedScopes: ["oura.sleep"] },
      {
        provider,
        tools: fakeTools([executed({ result })]),
      },
    );
    expect(out.answer).toContain("from script");
    expect(out.value).toBe(6.52);
    expect(out.cost.toolCalls).toBe(1);
  });
});

describe("runQueryLoop — the response contract", () => {
  it("repairs once, then succeeds", async () => {
    const provider = createFakeInferenceProvider({
      respond: (_i, n) =>
        reply(
          n === 0
            ? "I think it's about 6 hours."
            : answerBlock({ answer: "6.52h" }),
        ),
    });
    const out = await runQueryLoop(
      { question: "q", grantedScopes: ["oura.sleep"] },
      {
        provider,
        tools: fakeTools([executed()], {
          coverage: () => ({
            scopesScanned: ["oura.sleep"],
            recordsScanned: 1030,
            scopesSkipped: [],
            complete: true,
          }),
        }),
      },
    );
    expect(out.answer).toContain("6.52h");
    expect(out.coverage.complete).toBe(true);
    // The repair message went back as a user turn.
    const repairTurn = provider.calls[1]?.messages.at(-1);
    expect(repairTurn?.content).toContain(
      "did not follow the response contract",
    );
  });

  it("gives up after a second violation, honestly", async () => {
    const provider = createFakeInferenceProvider({
      respond: () => reply("still just prose, no block at all"),
    });
    const out = await runQueryLoop(
      { question: "q", grantedScopes: ["oura.sleep"] },
      { provider, tools: fakeTools() },
    );
    expect(out.answer).toContain("could not produce a valid script");
    expect(out.coverage.complete).toBe(false);
    expect(out.coverage.stoppedBecause).toBe("contractViolation");
    // Exactly two model turns: the first attempt and the one repair.
    expect(out.cost.toolCalls).toBe(2);
  });
});

describe("runQueryLoop — honesty invariants", () => {
  it("an answer with no script run is never reported as complete", async () => {
    // A model that answers straight from its own prose has read nothing. The
    // host accumulator has no runs to report, so coverage is empty and
    // incomplete — and the answer text has to say so. Without this, a
    // hallucinated answer inherits a confident-looking default.
    const provider = createFakeInferenceProvider({
      respond: () => reply(answerBlock({ answer: "About six and a half." })),
    });
    const out = await runQueryLoop(
      { question: "how much did I sleep?", grantedScopes: ["oura.sleep"] },
      { provider, tools: fakeTools() },
    );
    expect(out.coverage.complete).toBe(false);
    expect(out.coverage.recordsScanned).toBe(0);
    expect(out.answer).toContain("incomplete");
  });

  it("surfaces incompleteness in the ANSWER TEXT, not only metadata", async () => {
    // plan phase 5: coverage.complete === false must be visible to a reader of
    // the answer. Metadata alone lets a caller render a confident wrong answer.
    const provider = createFakeInferenceProvider({
      respond: () =>
        reply(answerBlock({ answer: "You have never agreed to that." })),
    });
    const out = await runQueryLoop(
      { question: "have I ever?", grantedScopes: ["docs"] },
      {
        provider,
        tools: fakeTools([executed()], {
          coverage: () => ({
            scopesScanned: ["docs"],
            recordsScanned: 318,
            scopesSkipped: [{ scope: "email", reason: "not granted" }],
            complete: false,
            unreadable: 22,
          }),
        }),
      },
    );
    expect(out.answer).toContain("incomplete");
    expect(out.answer).toContain("22 record(s) could not be read");
    expect(out.answer).toContain("email (not granted)");
    expect(out.coverage.complete).toBe(false);
  });

  it("never lets the host report complete when the run stopped early", async () => {
    const provider = createFakeInferenceProvider({
      respond: () => reply(runBlock("forever()")),
    });
    const out = await runQueryLoop(
      { question: "q", grantedScopes: ["oura.sleep"] },
      {
        provider,
        // The host reports complete; the loop must still refuse it because
        // the run was cut short.
        tools: fakeTools([executed({ termination: "cpu" })]),
        maxTurns: 1,
      },
    );
    expect(out.coverage.complete).toBe(false);
    expect(out.coverage.stoppedBecause).toBe("cpu");
  });

  it("takes coverage from the host, ignoring what the model asserts", async () => {
    // The model claims a complete scan of 999999 records; the host counted 12.
    const provider = createFakeInferenceProvider({
      respond: () =>
        reply(
          answerBlock({
            answer: "Scanned all 999999 records, complete coverage.",
            coverage: { complete: true, recordsScanned: 999_999 },
          }),
        ),
    });
    const out = await runQueryLoop(
      { question: "q", grantedScopes: ["oura.sleep"] },
      {
        provider,
        tools: fakeTools([executed()], {
          coverage: () => ({
            scopesScanned: ["oura.sleep"],
            recordsScanned: 12,
            scopesSkipped: [],
            complete: false,
          }),
        }),
      },
    );
    expect(out.coverage.recordsScanned).toBe(12);
    expect(out.coverage.complete).toBe(false);
  });

  it("reports budget exhaustion as an outcome, not an error", async () => {
    const provider = createFakeInferenceProvider({
      respond: () => reply(runBlock("keep_going()")),
    });
    const out = await runQueryLoop(
      {
        question: "q",
        grantedScopes: ["oura.sleep"],
        budget: { toolCalls: 3 },
      },
      { provider, tools: fakeTools() },
    );
    expect(out.coverage.stoppedBecause).toBe("budget");
    expect(out.coverage.complete).toBe(false);
    expect(out.cost.toolCalls).toBe(3);
    expect(out.answer).toContain("budget");
  });

  it("carries sandbox violations into coverage", async () => {
    const provider = createFakeInferenceProvider({
      respond: (_i, n) =>
        reply(
          n === 0 ? runBlock("readSecret()") : answerBlock({ answer: "d" }),
        ),
    });
    const out = await runQueryLoop(
      { question: "q", grantedScopes: ["oura.sleep"] },
      {
        provider,
        tools: fakeTools([
          executed({ violations: ["denied read /etc/passwd"] }),
        ]),
      },
    );
    expect(out.coverage.violations).toContain("denied read /etc/passwd");
  });

  it("flags scopes with no T2 profile as reduced confidence", async () => {
    const provider = createFakeInferenceProvider({
      respond: () => reply(answerBlock({ answer: "done" })),
    });
    const out = await runQueryLoop(
      { question: "q", grantedScopes: ["mystery.source"] },
      {
        provider,
        tools: fakeTools([executed()], {
          async listScopes() {
            return [{ scope: "mystery.source" }];
          },
          coverage: () => ({
            scopesScanned: ["mystery.source"],
            recordsScanned: 5,
            scopesSkipped: [],
            complete: false,
          }),
        }),
      },
    );
    expect(out.coverage.unprofiledScopes).toContain("mystery.source");
    expect(out.answer).toContain("no source profile");
  });
});
