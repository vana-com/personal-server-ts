import { describe, expect, it } from "vitest";

import { runQueryLoop, DEFAULT_MAX_TOKENS } from "./loop.js";
import type { QueryToolHost, ExecutedRun } from "./tool-host.js";
import type { InferenceProvider } from "../../derivatives/inference.js";

/**
 * The two robustness failures the 18-question dogfood benchmark exposed.
 *
 * Between them they accounted for 8 of 18 questions: three died outright on a
 * null reply, five hit the turn ceiling and threw away everything they had
 * learned.
 */

const emptyReplyError = (): Error =>
  new Error("inference response carried no assistant content");

function host(): QueryToolHost {
  return {
    listScopes: async () => [{ scope: "oura.sleep", itemCount: 10 }],
    execute: async (): Promise<ExecutedRun> => ({
      coverage: {
        scopesScanned: ["oura.sleep"],
        recordsScanned: 10,
        scopesSkipped: [],
        complete: false,
      },
      notes: [],
      termination: "completed",
      stdout: "{}",
      stderr: "",
      violations: [],
      truncated: false,
    }),
    coverage: () => ({
      scopesScanned: ["oura.sleep"],
      recordsScanned: 10,
      scopesSkipped: [],
      complete: false,
    }),
  } as unknown as QueryToolHost;
}

describe("a null reply is retried, not fatal", () => {
  it("recovers when a later attempt returns content", async () => {
    const budgets: number[] = [];
    let calls = 0;
    const provider = {
      defaultModel: "m",
      chat: async (input: { maxTokens?: number }) => {
        budgets.push(input.maxTokens ?? 0);
        calls++;
        // Two empty replies, then a real answer.
        if (calls <= 2) throw emptyReplyError();
        return {
          content: '```vana:answer\n{"answer":"recovered","value":6.5}\n```',
          usage: { promptTokens: 10, completionTokens: 5 },
        };
      },
    } as unknown as InferenceProvider;

    const out = await runQueryLoop(
      { question: "q", grantedScopes: ["oura.sleep"] },
      { provider, tools: host() },
    );

    expect(out.answer).toContain("recovered");
    expect(out.value).toBe(6.5);
    // The budget ESCALATES. Re-asking an identical request that ran out of
    // reasoning room would mostly reproduce the failure.
    expect(budgets).toEqual([
      DEFAULT_MAX_TOKENS,
      DEFAULT_MAX_TOKENS * 2,
      DEFAULT_MAX_TOKENS * 4,
    ]);
  });

  it("ends with honest coverage rather than throwing when it never recovers", async () => {
    const provider = {
      defaultModel: "m",
      chat: async () => {
        throw emptyReplyError();
      },
    } as unknown as InferenceProvider;

    // The old behaviour propagated out of the answerer and lost the question.
    const out = await runQueryLoop(
      { question: "q", grantedScopes: ["oura.sleep"] },
      { provider, tools: host() },
    );

    expect(out.coverage.complete).toBe(false);
    expect(out.coverage.stoppedBecause).toBe("error");
    expect(out.answer).toMatch(/no content/i);
  });

  it("does not swallow an unrelated provider failure", async () => {
    const provider = {
      defaultModel: "m",
      chat: async () => {
        throw new Error("relay_signing_failed");
      },
    } as unknown as InferenceProvider;

    await expect(
      runQueryLoop(
        { question: "q", grantedScopes: ["oura.sleep"] },
        { provider, tools: host() },
      ),
    ).rejects.toThrow("relay_signing_failed");
  });
});

describe("budget exhaustion ends on a partial answer", () => {
  it("asks the model to conclude with what it has", async () => {
    let sawWrapUp = false;
    const provider = {
      defaultModel: "m",
      chat: async (input: { messages: { content: string }[] }) => {
        const last = input.messages.at(-1)?.content ?? "";
        if (last.includes("run out of")) {
          sawWrapUp = true;
          return {
            content:
              '```vana:answer\n{"answer":"partial: read 10 of 30 nights","value":6.1}\n```',
            usage: { promptTokens: 5, completionTokens: 5 },
          };
        }
        return {
          content: "```vana:run\nawait vana.readAll('oura.sleep');\n```",
          usage: { promptTokens: 5, completionTokens: 5 },
        };
      },
    } as unknown as InferenceProvider;

    const out = await runQueryLoop(
      {
        question: "q",
        grantedScopes: ["oura.sleep"],
        budget: { toolCalls: 2 },
      },
      { provider, tools: host() },
    );

    expect(sawWrapUp).toBe(true);
    expect(out.answer).toContain("partial");
    expect(out.value).toBe(6.1);
    // A partial answer must still be reported as partial.
    expect(out.coverage.complete).toBe(false);
    expect(out.coverage.stoppedBecause).toBe("budget");
  });

  it("counts script runs and model turns separately", async () => {
    const provider = {
      defaultModel: "m",
      chat: async (input: { messages: { content: string }[] }) => {
        const last = input.messages.at(-1)?.content ?? "";
        if (last.includes("run out of")) {
          return {
            content: '```vana:answer\n{"answer":"done"}\n```',
            usage: { promptTokens: 1, completionTokens: 1 },
          };
        }
        return {
          content: "```vana:run\nawait vana.readAll('oura.sleep');\n```",
          usage: { promptTokens: 1, completionTokens: 1 },
        };
      },
    } as unknown as InferenceProvider;

    const out = await runQueryLoop(
      {
        question: "q",
        grantedScopes: ["oura.sleep"],
        budget: { toolCalls: 3 },
      },
      { provider, tools: host() },
    );

    // 3 turns ran scripts; the wrap-up turn ran none.
    expect(out.cost.toolCalls).toBe(3);
    expect(out.cost.modelTurns).toBe(4);
  });

  it("still answers when the wrap-up turn itself fails", async () => {
    const provider = {
      defaultModel: "m",
      chat: async (input: { messages: { content: string }[] }) => {
        const last = input.messages.at(-1)?.content ?? "";
        if (last.includes("run out of")) throw new Error("boom");
        return {
          content: "```vana:run\nawait vana.readAll('oura.sleep');\n```",
          usage: { promptTokens: 1, completionTokens: 1 },
        };
      },
    } as unknown as InferenceProvider;

    const out = await runQueryLoop(
      {
        question: "q",
        grantedScopes: ["oura.sleep"],
        budget: { toolCalls: 1 },
      },
      { provider, tools: host() },
    );
    expect(out.answer).toMatch(/ran out of the budget/i);
    expect(out.coverage.stoppedBecause).toBe("budget");
  });
});
