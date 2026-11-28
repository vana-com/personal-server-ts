import { expect, it } from "vitest";
import { buildQuestionMessages, trimSourceData } from "./prompt.js";

it("keeps the actual serialized model input within the per-source cap after truncation", () => {
  const maxChars = 64;
  const trimmed = trimSourceData({ note: '"\\'.repeat(100) }, { maxChars });
  expect(trimmed.truncated).toBe(true);
  const wire = JSON.stringify(trimmed.data) ?? "";
  expect(wire.length).toBeLessThanOrEqual(maxChars);
  expect(wire).toContain("[truncated]");
  const messages = buildQuestionMessages({
    question: "Summarize the note.",
    sources: [
      {
        ...trimmed,
        scope: "fixture.notes",
        collectedAt: "2026-01-01T00:00:00.000Z",
        version: 1,
      },
    ],
  });
  expect(messages[1]?.content.split("\n")).toContain(wire);
});

it("omits the value when even an empty JSON string cannot fit", () => {
  const trimmed = trimSourceData({ note: "fixture" }, { maxChars: 1 });
  expect(trimmed.truncated).toBe(true);
  expect(JSON.stringify(trimmed.data) ?? "").toHaveLength(0);
});
