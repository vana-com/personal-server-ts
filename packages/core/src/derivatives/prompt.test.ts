import { describe, expect, it } from "vitest";
import {
  buildQuestionMessages,
  parseAnswer,
  sortNewestFirst,
  trimSourceData,
} from "./prompt.js";

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
