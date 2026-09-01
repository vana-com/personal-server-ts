/**
 * The naive control arm's two load-bearing properties.
 *
 * This answerer exists to anchor the scoreboard, so the only things that must
 * hold are the ones a comparison would be worthless without: it truncates
 * NEWEST-FIRST (plan §7's heuristic, not an arbitrary one), and its coverage
 * describes what it actually put in the prompt rather than what it was granted.
 * A baseline that quietly reported a full pass over a truncated slice would
 * make the agent arm look bad for being honest.
 */

import { describe, expect, it } from "vitest";

import { createFakeInferenceProvider } from "../../../derivatives/inference.js";
import type { CorpusManifest } from "../fixtures/generate.js";
import type { FixtureSource } from "../fixtures/sink.js";
import { createStuffedAnswerer, recordTimeMs } from "./stuffed-answerer.js";

/** One in-memory scope file, addressed the way the manifest addresses it. */
function sourceOf(files: Record<string, unknown[]>): FixtureSource {
  return {
    list: async () => Object.keys(files),
    read: async (name: string) => JSON.stringify(files[name] ?? []),
    size: async (name: string) => JSON.stringify(files[name] ?? []).length,
  };
}

const ANSWER =
  "```vana:answer\n" +
  JSON.stringify({
    answer: "an answer",
    citations: [{ scope: "notes.entries" }],
    value: 7,
    resolution: "everything I was shown",
  }) +
  "\n```";

/** `n` notes one day apart, newest last, each tagged with its index. */
function notes(n: number): unknown[] {
  return Array.from({ length: n }, (_, i) => ({
    id: `note${i}`,
    created: new Date(Date.UTC(2024, 0, 1) + i * 86_400_000).toISOString(),
    body: `body ${i}`,
  }));
}

function harness(rows: unknown[], corpusBudgetChars: number) {
  const provider = createFakeInferenceProvider({
    respond: () => ({ content: ANSWER }),
  });
  const manifest: CorpusManifest = {
    seed: 1,
    profile: "small",
    scopes: [
      { scope: "notes.entries", files: ["notes.json"], records: rows.length },
    ],
  };
  const answerer = createStuffedAnswerer({
    source: sourceOf({ "notes.json": rows }),
    manifest,
    provider,
    corpusBudgetChars,
  });
  return { answerer, provider };
}

describe("newest-first truncation", () => {
  it("keeps the most recent records and drops the oldest", async () => {
    const rows = notes(100);
    // Room for a handful of records, not for a hundred.
    const { answerer, provider } = harness(rows, 600);

    await answerer.answer({
      question: "what happened?",
      grantedScopes: ["notes.entries"],
    });

    const prompt = provider.calls[0]?.messages[1]?.content ?? "";
    expect(prompt, "the newest note must survive").toContain('"note99"');
    expect(prompt, "the oldest note must be dropped").not.toContain('"note0"');
  });

  it("includes everything when the whole grant fits", async () => {
    const rows = notes(20);
    const { answerer } = harness(rows, 1_000_000);

    const answer = await answerer.answer({
      question: "what happened?",
      grantedScopes: ["notes.entries"],
    });

    expect(answer.coverage.recordsScanned).toBe(20);
  });
});

describe("coverage describes the prompt, not the grant", () => {
  it("reports only the records it put in the prompt when truncating", async () => {
    const rows = notes(100);
    const { answerer } = harness(rows, 600);

    const answer = await answerer.answer({
      question: "have I ever done X?",
      grantedScopes: ["notes.entries"],
    });

    expect(
      answer.coverage.method,
      "a truncated slice is a prefiltered pass, not a full one",
    ).toBe("prefiltered");
    expect(answer.coverage.recordsScanned).toBeLessThan(rows.length);
    expect(answer.coverage.recordsScanned).toBeGreaterThan(0);
  });

  it("tells the model that records were withheld", async () => {
    const { answerer, provider } = harness(notes(100), 600);

    await answerer.answer({
      question: "have I ever done X?",
      grantedScopes: ["notes.entries"],
    });

    const prompt = provider.calls[0]?.messages[1]?.content ?? "";
    expect(prompt).toContain("truncated slice");
  });

  it("counts records that announce their own extraction failure", async () => {
    const rows = [
      { id: "d0", created: "2024-01-03", text_extracted: "readable" },
      {
        id: "d1",
        created: "2024-01-02",
        text_extracted: null,
        extraction_error: "scanned image, no text layer",
      },
      { id: "d2", created: "2024-01-01", text_extracted: "readable" },
    ];
    const { answerer } = harness(rows, 1_000_000);

    const answer = await answerer.answer({
      question: "have I ever done X?",
      grantedScopes: ["notes.entries"],
    });

    expect(answer.coverage.unreadable).toBe(1);
  });

  it("runs no scripts — the whole point of the arm", async () => {
    const { answerer } = harness(notes(5), 1_000_000);

    const answer = await answerer.answer({
      question: "what happened?",
      grantedScopes: ["notes.entries"],
    });

    expect(answer.cost.toolCalls).toBe(0);
    expect(answer.script).toBeUndefined();
  });
});

describe("the response contract is the agent's", () => {
  it("carries value and resolution through to the answer", async () => {
    const { answerer } = harness(notes(5), 1_000_000);

    const answer = await answerer.answer({
      question: "how many?",
      grantedScopes: ["notes.entries"],
    });

    expect(answer.value).toBe(7);
    expect(answer.resolution).toBe("everything I was shown");
    expect(answer.citations).toEqual([{ scope: "notes.entries" }]);
  });

  it("repairs once when the reply breaks the contract, then gives up", async () => {
    const provider = createFakeInferenceProvider({
      respond: () => ({ content: "no fenced block here at all" }),
    });
    const answerer = createStuffedAnswerer({
      source: sourceOf({ "notes.json": notes(5) }),
      manifest: {
        seed: 1,
        profile: "small",
        scopes: [{ scope: "notes.entries", files: ["notes.json"], records: 5 }],
      },
      provider,
      corpusBudgetChars: 1_000_000,
    });

    const answer = await answerer.answer({
      question: "how many?",
      grantedScopes: ["notes.entries"],
    });

    expect(provider.calls, "one attempt plus exactly one repair").toHaveLength(
      2,
    );
    expect(answer.coverage.stoppedBecause).toBe("contractViolation");
    expect(answer.value).toBeUndefined();
  });
});

describe("recordTimeMs", () => {
  it("reads the encodings this corpus actually uses", () => {
    // ISO instant, bare day, epoch seconds as a number, epoch seconds as a
    // string — Slack's `ts` is the last of these and is easy to misread as ms.
    expect(recordTimeMs({ date: "2024-01-02T03:04:05.000Z" })).toBe(
      Date.parse("2024-01-02T03:04:05.000Z"),
    );
    expect(recordTimeMs({ day: "2024-01-02" })).toBe(
      Date.parse("2024-01-02T00:00:00.000Z"),
    );
    expect(recordTimeMs({ create_time: 1_716_990_358.965 })).toBe(
      1_716_990_358_965,
    );
    expect(recordTimeMs({ ts: "1713451788.166000" })).toBe(1_713_451_788_166);
  });

  it("returns undefined for a record with no time at all", () => {
    expect(recordTimeMs({ merchant: "coffee" })).toBeUndefined();
    expect(recordTimeMs(null)).toBeUndefined();
  });
});
