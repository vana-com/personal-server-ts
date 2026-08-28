import { describe, expect, it } from "vitest";
import {
  buildSearchCorpus,
  DEFAULT_MAX_TOOL_CALLS,
  runAgenticLoop,
} from "./agentic.js";
import {
  createFakeInferenceProvider,
  type InferenceChatResult,
  type InferenceToolCall,
} from "./inference.js";

const CONVERSATIONS = {
  conversations: [
    {
      id: "c-1",
      title: "Greenhouse plans",
      create_time: "2026-05-01T09:00:00Z",
      messages: [
        { role: "user", content: "Planning a greenhouse for tomatoes." },
        { role: "assistant", content: "South-facing spot works best." },
      ],
    },
    {
      id: "c-2",
      title: "Espresso dialing",
      messages: [{ role: "user", content: "My espresso shots run too fast." }],
    },
  ],
};

describe("buildSearchCorpus", () => {
  it("indexes top-level array items and finds them by keyword", () => {
    const corpus = buildSearchCorpus([
      { scope: "chatgpt.conversations", data: CONVERSATIONS },
    ]);
    expect(corpus.passageCount).toBeGreaterThan(0);
    const hits = corpus.search("greenhouse tomatoes");
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0]!.scope).toBe("chatgpt.conversations");
    expect(hits[0]!.snippet).toContain("greenhouse");
    // read returns the whole ITEM the hit belongs to.
    const text = corpus.read(hits[0]!.ref);
    expect(text).toContain("South-facing spot");
  });

  it("skips reserved envelope keys and bare timestamps", () => {
    const corpus = buildSearchCorpus([
      {
        scope: "a.b",
        data: {
          items: [{ note: "hello world", created_at: "2026-01-01T00:00:00Z" }],
          $lineage: { sources: ["0xdead"] },
        },
      },
    ]);
    expect(corpus.search("hello").length).toBe(1);
    expect(corpus.search("lineage").length).toBe(0);
    expect(corpus.search("0xdead").length).toBe(0);
  });

  it("indexes a record with no arrays as one item", () => {
    const corpus = buildSearchCorpus([
      { scope: "a.b", data: { summary: "quarterly report totals" } },
    ]);
    expect(corpus.search("quarterly").length).toBe(1);
  });

  it("returns null for an unknown ref", () => {
    const corpus = buildSearchCorpus([{ scope: "a.b", data: { x: "hi" } }]);
    expect(corpus.read("a.b#nope#0")).toBeNull();
  });
});

function toolCall(
  id: string,
  name: string,
  args: Record<string, unknown>,
): InferenceToolCall {
  return { id, name, arguments: JSON.stringify(args) };
}

const FINAL: InferenceChatResult = {
  content: JSON.stringify({ answer: "the answer", evidence: "c-1" }),
};

describe("runAgenticLoop", () => {
  it("executes a search, feeds the result back and returns the final text", async () => {
    const corpus = buildSearchCorpus([
      { scope: "chatgpt.conversations", data: CONVERSATIONS },
    ]);
    const provider = createFakeInferenceProvider({
      respond: (input, index) => {
        if (index === 0) {
          expect(input.tools?.map((tool) => tool.name)).toEqual([
            "search_data",
            "read_data",
          ]);
          return {
            content: "",
            toolCalls: [toolCall("t1", "search_data", { query: "greenhouse" })],
          };
        }
        // The tool result made it into the transcript.
        const toolMessage = input.messages.find((m) => m.role === "tool");
        expect(toolMessage?.toolCallId).toBe("t1");
        expect(toolMessage?.content).toContain("greenhouse");
        return FINAL;
      },
    });
    const result = await runAgenticLoop({
      provider,
      model: "fake-model",
      question: "What am I planning to grow?",
      corpus,
    });
    expect(result.toolCalls).toBe(1);
    expect(JSON.parse(result.content).answer).toBe("the answer");
  });

  it("answers tool errors inline instead of failing the loop", async () => {
    const corpus = buildSearchCorpus([{ scope: "a.b", data: { x: "hi" } }]);
    const provider = createFakeInferenceProvider({
      respond: (input, index) => {
        if (index === 0) {
          return {
            content: "",
            toolCalls: [toolCall("t1", "no_such_tool", {})],
          };
        }
        const toolMessage = input.messages.find((m) => m.role === "tool");
        expect(toolMessage?.content).toContain("unknown tool");
        return FINAL;
      },
    });
    const result = await runAgenticLoop({
      provider,
      model: "fake-model",
      question: "q",
      corpus,
    });
    expect(result.toolCalls).toBe(1);
  });

  it("stops at the budget: refuses further calls and bounds provider turns", async () => {
    const corpus = buildSearchCorpus([{ scope: "a.b", data: { x: "hi" } }]);
    let turns = 0;
    const provider = createFakeInferenceProvider({
      // Always ask for another tool; never volunteer a final answer.
      respond: (_input, index) => {
        turns += 1;
        return {
          content: "",
          toolCalls: [toolCall(`t${index}`, "search_data", { query: "hi" })],
        };
      },
    });
    const result = await runAgenticLoop({
      provider,
      model: "fake-model",
      question: "q",
      corpus,
      maxToolCalls: 2,
    });
    expect(result.toolCalls).toBe(2);
    expect(turns).toBeLessThanOrEqual(2 + 2);
    // The over-budget calls were answered with a refusal, not executed.
    const refusals = provider.calls
      .flatMap((call) => call.messages)
      .filter(
        (message) =>
          message.role === "tool" &&
          message.content.includes("tool budget exhausted"),
      );
    expect(refusals.length).toBeGreaterThan(0);
  });

  it("uses the default budget when none is given", () => {
    expect(DEFAULT_MAX_TOOL_CALLS).toBe(6);
  });
});
