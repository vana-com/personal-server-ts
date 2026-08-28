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
    // budget+2 tool-bearing turns plus the one forced answer turn
    expect(turns).toBeLessThanOrEqual(2 + 3);
    // The forced final turn offers no tools, and interim narration is never
    // returned as the answer: the fake kept requesting tools, so content is
    // empty and the caller fails the compute.
    expect(provider.calls[provider.calls.length - 1]!.tools).toBeUndefined();
    expect(result.content).toBe("");
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

describe("review fixes", () => {
  it("keeps date-prefixed prose but drops pure timestamps", () => {
    const corpus = buildSearchCorpus([
      {
        scope: "a.b",
        data: {
          items: [
            {
              note: "2026-05-01 met the cardiologist, follow-up in June",
              at: "2026-05-01T09:00:00Z",
            },
          ],
        },
      },
    ]);
    expect(corpus.search("cardiologist").length).toBe(1);
    const text = corpus.read(corpus.search("cardiologist")[0]!.ref);
    expect(text).toContain("2026-05-01 met the cardiologist");
    expect(text).not.toContain("09:00:00");
  });

  it("centers the snippet on the matched term for deep matches", () => {
    const filler = "lorem ipsum dolor sit amet ".repeat(30); // ~810 chars
    const corpus = buildSearchCorpus([
      {
        scope: "a.b",
        data: {
          items: [{ note: `${filler} the xylophone concert was great` }],
        },
      },
    ]);
    const hits = corpus.search("xylophone");
    expect(hits.length).toBe(1);
    expect(hits[0]!.snippet).toContain("xylophone");
  });

  it("when the model narrates past the cap, the forced turn's answer wins", async () => {
    const corpus = buildSearchCorpus([{ scope: "a.b", data: { x: "hello" } }]);
    const provider = createFakeInferenceProvider({
      respond: (input) => {
        if (input.tools && input.tools.length > 0) {
          // Interim narration plus another tool request, every tool turn.
          return {
            content: "Let me search for one more thing…",
            toolCalls: [toolCall("t", "search_data", { query: "hello" })],
          };
        }
        return FINAL; // the forced tools-free turn
      },
    });
    const result = await runAgenticLoop({
      provider,
      model: "fake-model",
      question: "q",
      corpus,
      maxToolCalls: 1,
    });
    expect(JSON.parse(result.content).answer).toBe("the answer");
    expect(result.content).not.toContain("one more thing");
  });

  it("retries a single provider call through the retry hook, not the loop", async () => {
    let searches = 0;
    const wrapped = buildSearchCorpus([{ scope: "a.b", data: { x: "hello" } }]);
    const countingCorpus: typeof wrapped = {
      ...wrapped,
      search: (q) => {
        searches += 1;
        return wrapped.search(q);
      },
      read: (r) => wrapped.read(r),
    };
    let failedOnce = false;
    const provider = createFakeInferenceProvider({
      respond: (input, index) => {
        if (index === 0) {
          return {
            content: "",
            toolCalls: [toolCall("t1", "search_data", { query: "hello" })],
          };
        }
        if (!failedOnce) {
          failedOnce = true;
          throw new Error("transient");
        }
        return FINAL;
      },
    });
    const result = await runAgenticLoop({
      provider,
      model: "fake-model",
      question: "q",
      corpus: countingCorpus,
      retry: async (attempt) => {
        try {
          return await attempt();
        } catch {
          return attempt();
        }
      },
    });
    expect(JSON.parse(result.content).answer).toBe("the answer");
    // The retry replayed one chat call; the tool was executed exactly once.
    expect(searches).toBe(1);
  });

  it("appends the context note to the question", async () => {
    const corpus = buildSearchCorpus([{ scope: "a.b", data: { x: "hello" } }]);
    const provider = createFakeInferenceProvider({
      respond: (input) => {
        expect(input.messages[1]!.content).toContain(
          "Note: photos.raw holds binary records",
        );
        return FINAL;
      },
    });
    await runAgenticLoop({
      provider,
      model: "fake-model",
      question: "q",
      corpus,
      contextNote: "photos.raw holds binary records",
    });
  });
});
