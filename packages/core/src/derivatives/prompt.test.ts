import { describe, expect, it } from "vitest";
import { parseAnswerShapeInput } from "./answer-shape.js";
import {
  buildQuestionMessages,
  buildShapeRetryMessages,
  parseAnswer,
  parseShapedAnswer,
  sortNewestFirst,
  trimSourceData,
} from "./prompt.js";

const shape = parseAnswerShapeInput({
  fields: [
    { name: "score", type: "integer", min: 1, max: 5 },
    { name: "mood", type: "enum", values: ["up", "down"], required: false },
  ],
})!;

const source = {
  scope: "oura.sleep",
  collectedAt: "2026-08-01T00:00:00Z",
  version: 3,
  data: [{ score: 80 }],
  kept: 1,
  total: 5,
  truncated: false,
};

describe("sortNewestFirst", () => {
  it("orders timestamped items newest first and keeps undated items after them, reversed", () => {
    const items = [
      { id: "a", createdAt: "2026-01-01T00:00:00Z" },
      { id: "u1" },
      { id: "b", createdAt: "2026-03-01T00:00:00Z" },
      { id: "c", create_time: 1_770_000_000 },
      { id: "u2" },
    ];
    expect(sortNewestFirst(items).map((item) => item.id)).toEqual([
      "b",
      "c",
      "a",
      "u2",
      "u1",
    ]);
  });
});

describe("trimSourceData", () => {
  it("keeps the newest N items of an array record", () => {
    const items = Array.from({ length: 10 }, (_, i) => ({
      i,
      createdAt: new Date(Date.UTC(2026, 0, i + 1)).toISOString(),
    }));
    const result = trimSourceData(items, { maxItems: 3 });
    expect((result.data as Array<{ i: number }>).map((item) => item.i)).toEqual(
      [9, 8, 7],
    );
    expect(result).toMatchObject({ kept: 3, total: 10, truncated: false });
  });

  it("trims every top-level array of an object record and drops reserved keys", () => {
    const result = trimSourceData(
      {
        conversations: [{ n: 1 }, { n: 2 }, { n: 3 }],
        profile: { name: "x" },
        $lineage: { sources: [] },
        $writtenBy: { builder: "0x1" },
      },
      { maxItems: 2 },
    );
    expect(result.data).toEqual({
      conversations: [{ n: 3 }, { n: 2 }],
      profile: { name: "x" },
    });
    expect(result).toMatchObject({ kept: 2, total: 3 });
  });

  it("drops items until the char cap fits, then truncates the serialization", () => {
    const items = Array.from({ length: 8 }, (_, i) => ({
      i,
      pad: "x".repeat(40),
    }));
    const fitted = trimSourceData(items, { maxItems: 8, maxChars: 120 });
    expect(fitted.truncated).toBe(false);
    expect((fitted.data as unknown[]).length).toBeLessThan(8);
    expect(JSON.stringify(fitted.data).length).toBeLessThanOrEqual(120);

    const cut = trimSourceData({ blob: "y".repeat(500) }, { maxChars: 50 });
    expect(cut.truncated).toBe(true);
    expect(typeof cut.data).toBe("string");
    expect((cut.data as string).endsWith("...[truncated]")).toBe(true);
  });

  it("drops the consumed caller lineage field from a stamped derivative source", () => {
    const result = trimSourceData({
      summary: "seven hours",
      lineage: ["0xsource"],
      $lineage: { sources: ["0xsource"], writtenAt: "2026-06-05" },
      $writtenBy: { builder: "0xbeef" },
    });
    expect(result.data).toEqual({ summary: "seven hours" });
  });

  it("keeps a lineage field on an unstamped record", () => {
    const result = trimSourceData({
      summary: "root",
      lineage: ["user-data"],
    });
    expect(result.data).toEqual({ summary: "root", lineage: ["user-data"] });
  });
});

describe("buildQuestionMessages", () => {
  it("pins the model to the data and includes every source section", () => {
    const messages = buildQuestionMessages({
      question: "What did I do?",
      sources: [
        {
          scope: "oura.sleep",
          collectedAt: "2026-08-01T00:00:00Z",
          version: 3,
          data: [{ score: 80 }],
          kept: 1,
          total: 5,
          truncated: false,
        },
      ],
    });
    expect(messages).toHaveLength(2);
    expect(messages[0]).toMatchObject({ role: "system" });
    expect(messages[0]!.content).toContain("ONLY the user data");
    expect(messages[1]!.role).toBe("user");
    expect(messages[1]!.content).toContain("What did I do?");
    expect(messages[1]!.content).toContain(
      "### Scope: oura.sleep (newest 1 of 5 items)",
    );
    expect(messages[1]!.content).toContain('[{"score":80}]');
  });
});

describe("buildQuestionMessages with an answer shape", () => {
  it("asks for the declared object and names every field", () => {
    const messages = buildQuestionMessages({
      question: "How did I sleep?",
      sources: [source],
      answerShape: shape,
    });
    const system = messages[0]!.content;
    expect(system).toContain("ONLY the user data");
    expect(system).toContain('"answer": object');
    expect(system).toContain('"score": integer between 1 and 5 (required)');
    expect(system).toContain('"mood": exactly one of "up", "down" (optional)');
    expect(system).toContain("Do not add fields");
    expect(messages[1]!.content).toContain(
      "where answer holds exactly the declared fields",
    );
  });

  it("leaves the free-text prompt untouched without a shape", () => {
    const plain = buildQuestionMessages({
      question: "How did I sleep?",
      sources: [source],
    });
    expect(plain[0]!.content).toBe(
      buildQuestionMessages({
        question: "How did I sleep?",
        sources: [source],
        answerShape: null,
      })[0]!.content,
    );
    expect(plain[0]!.content).toContain('"answer": string');
    expect(plain[0]!.content).not.toContain("Do not add fields");
    expect(
      plain[1]!.content.endsWith(
        "Answer the question as a JSON object with the fields answer and evidence.",
      ),
    ).toBe(true);
  });
});

describe("buildShapeRetryMessages", () => {
  it("keeps the original turns, echoes the reply and states what was wrong", () => {
    const messages = buildQuestionMessages({
      question: "How did I sleep?",
      sources: [source],
      answerShape: shape,
    });
    const retry = buildShapeRetryMessages({
      messages,
      reply: '{"answer":{"score":"great"}}',
      issues: ["score: Invalid input: expected number, received string"],
      answerShape: shape,
    });
    expect(retry.slice(0, 2)).toEqual(messages);
    expect(retry[2]).toEqual({
      role: "assistant",
      content: '{"answer":{"score":"great"}}',
    });
    expect(retry[3]!.role).toBe("user");
    expect(retry[3]!.content).toContain("did not match the required answer");
    expect(retry[3]!.content).toContain(
      "- score: Invalid input: expected number, received string",
    );
    expect(retry[3]!.content).toContain('"score": integer between 1 and 5');
  });
});

describe("parseShapedAnswer", () => {
  it("offers the answer member first, then the whole envelope", () => {
    expect(
      parseShapedAnswer('{"answer":{"score":4},"evidence":"two nights"}'),
    ).toEqual([
      { answer: { score: 4 }, evidence: "two nights" },
      {
        answer: { answer: { score: 4 }, evidence: "two nights" },
        evidence: "two nights",
      },
    ]);
  });

  it("offers the top-level object for a model that skipped the envelope", () => {
    expect(parseShapedAnswer('{"score":4}')).toEqual([
      { answer: { score: 4 }, evidence: null },
    ]);
  });

  it("reads through a fenced block", () => {
    expect(
      parseShapedAnswer('```json\n{"answer":{"score":4}}\n```')[0],
    ).toEqual({ answer: { score: 4 }, evidence: null });
  });

  it("is empty when the reply holds no JSON object", () => {
    expect(parseShapedAnswer("I scored it a four out of five.")).toEqual([]);
  });
});

describe("parseAnswer", () => {
  it("reads a bare JSON object", () => {
    expect(parseAnswer('{"answer":"a","evidence":"e"}')).toEqual({
      answer: "a",
      evidence: "e",
    });
  });
  it("reads a fenced JSON block with prose around it", () => {
    expect(parseAnswer('Sure:\n```json\n{"answer":"a"}\n```\nDone.')).toEqual({
      answer: "a",
      evidence: null,
    });
  });
  it("falls back to the raw text when no object parses", () => {
    expect(parseAnswer("  plain text  ")).toEqual({
      answer: "plain text",
      evidence: null,
    });
  });
});
