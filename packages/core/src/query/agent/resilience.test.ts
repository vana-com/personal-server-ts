import { describe, expect, it } from "vitest";

import { runQueryLoop, DEFAULT_MAX_TOKENS } from "./loop.js";
import type { QueryToolHost, ExecutedRun } from "./tool-host.js";
import {
  InferenceRequestError,
  type InferenceProvider,
} from "../../derivatives/inference.js";

/**
 * The two robustness failures the 18-question dogfood benchmark exposed.
 *
 * Between them they accounted for 8 of 18 questions: three died outright on a
 * null reply, five hit the turn ceiling and threw away everything they had
 * learned.
 */

/**
 * A contentless reply from a provider that is NOT `InferenceRequestError`, so
 * it carries no code — the conservative fallback path, treated as
 * `emptyContent`.
 */
const emptyReplyError = (): Error =>
  new Error("inference response carried no assistant content");

/** The same outcome, coded, as `inference.ts` now throws it. */
const codedEmptyReply = (
  code: "emptyContent" | "malformedToolCall",
  finishReason: string | null = null,
): Error =>
  new InferenceRequestError(
    "inference response carried no assistant content",
    200,
    { code, finishReason },
  );

function host(): QueryToolHost {
  return {
    listScopes: async () => [{ scope: "oura.sleep", itemCount: 10 }],
    execute: async (): Promise<ExecutedRun> => ({
      coverage: {
        scopesScanned: ["oura.sleep"],
        recordsScanned: 10,
        scopesSkipped: [],
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

/**
 * The escalation ladder used to treat every contentless reply as a truncation.
 *
 * It is not one. All 20 contentless replies in the N=3 dogfood sweep were a 200
 * with `finish_reason: "function_call_filter: MALFORMED_FUNCTION_CALL"` — the
 * provider discarding a tool call it could not parse — and they fired at 8192,
 * 16384 and 32768 alike. Doubling the budget cannot fix a parse failure; it
 * just replays the whole prompt at twice the price.
 */
describe("a discarded tool call is not a truncation", () => {
  it("re-asks once at the SAME budget and recovers", async () => {
    const budgets: number[] = [];
    let calls = 0;
    const provider = {
      defaultModel: "m",
      chat: async (input: { maxTokens?: number }) => {
        budgets.push(input.maxTokens ?? 0);
        calls++;
        if (calls === 1) {
          throw codedEmptyReply(
            "malformedToolCall",
            "function_call_filter: MALFORMED_FUNCTION_CALL",
          );
        }
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
    // Flat, not doubled. This is the whole behavioural difference — measured,
    // a flat re-ask recovers as often as a doubled one.
    expect(budgets).toEqual([DEFAULT_MAX_TOKENS, DEFAULT_MAX_TOKENS]);
  });

  it("stops after its re-asks, saying so in coverage", async () => {
    const budgets: number[] = [];
    const provider = {
      defaultModel: "m",
      chat: async (input: { maxTokens?: number }) => {
        budgets.push(input.maxTokens ?? 0);
        throw codedEmptyReply(
          "malformedToolCall",
          "function_call_filter: MALFORMED_FUNCTION_CALL",
        );
      },
    } as unknown as InferenceProvider;

    const out = await runQueryLoop(
      { question: "q", grantedScopes: ["oura.sleep"] },
      { provider, tools: host() },
    );

    // Three calls at ONE budget, where the old ladder made three at three
    // different ones. The count is held at parity on purpose: the defect was
    // the escalation, not the number of chances, and cutting the count turned
    // 1 stopped run into 4 on a live sweep.
    expect(budgets).toEqual([
      DEFAULT_MAX_TOKENS,
      DEFAULT_MAX_TOKENS,
      DEFAULT_MAX_TOKENS,
    ]);
    // The run must stay diagnosable: the reason reaches `coverage`, under its
    // own name rather than the catch-all `error`.
    expect(out.coverage.stoppedBecause).toBe("malformedToolCall");
    expect(out.answer).toMatch(/could not parse/i);
    expect(out.answer).toMatch(/not a truncation/i);
  });

  it("still escalates a coded empty reply, which IS a possible truncation", async () => {
    /*
     * The negative control on the split: telling the two apart must not
     * quietly disable the escalation the other one needs. Same class, same
     * message, different code — and the ladder returns.
     */
    const budgets: number[] = [];
    const provider = {
      defaultModel: "m",
      chat: async (input: { maxTokens?: number }) => {
        budgets.push(input.maxTokens ?? 0);
        throw codedEmptyReply("emptyContent", "length");
      },
    } as unknown as InferenceProvider;

    const out = await runQueryLoop(
      { question: "q", grantedScopes: ["oura.sleep"] },
      { provider, tools: host() },
    );

    expect(budgets).toEqual([
      DEFAULT_MAX_TOKENS,
      DEFAULT_MAX_TOKENS * 2,
      DEFAULT_MAX_TOKENS * 4,
    ]);
    expect(out.coverage.stoppedBecause).toBe("error");
  });

  it("counts the two ladders separately when a run sees both", async () => {
    // Neither cause may consume the other's allowance: a discarded tool call
    // early must not spend the doublings a later truncation needs.
    const budgets: number[] = [];
    let calls = 0;
    const provider = {
      defaultModel: "m",
      chat: async (input: { maxTokens?: number }) => {
        budgets.push(input.maxTokens ?? 0);
        calls++;
        throw codedEmptyReply(
          calls === 1 ? "malformedToolCall" : "emptyContent",
        );
      },
    } as unknown as InferenceProvider;

    await runQueryLoop(
      { question: "q", grantedScopes: ["oura.sleep"] },
      { provider, tools: host() },
    );

    // Flat re-asks for the tool call, then the full doubling ladder — the
    // tool-call attempts must not consume the doublings a truncation needs.
    expect(budgets).toEqual([
      DEFAULT_MAX_TOKENS,
      DEFAULT_MAX_TOKENS,
      DEFAULT_MAX_TOKENS * 2,
      DEFAULT_MAX_TOKENS * 4,
    ]);
  });

  it("does not claim a provider error that merely has a code", async () => {
    // The negative control on `emptyReplyCause`: only the two contentless
    // codes are handled here. Anything else still propagates.
    const provider = {
      defaultModel: "m",
      chat: async () => {
        throw new InferenceRequestError("inference request failed", 429, {
          code: "httpError",
        });
      },
    } as unknown as InferenceProvider;

    await expect(
      runQueryLoop(
        { question: "q", grantedScopes: ["oura.sleep"] },
        { provider, tools: host() },
      ),
    ).rejects.toThrow("inference request failed");
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
