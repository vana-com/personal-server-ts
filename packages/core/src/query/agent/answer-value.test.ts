/**
 * `vana:answer` must be able to carry the number it computed.
 *
 * Without an explicit `value` the harness falls back to pulling the first
 * number out of the prose. On a live run that read "30" out of a sentence
 * about a 30-day window and graded a correct 6.16h answer as wrong, which
 * made every numeric case ungradeable.
 */

import { describe, expect, it } from "vitest";
import { parseTurn } from "./contract.js";

const block = (body: string) => "```vana:answer\n" + body + "\n```";

describe("vana:answer value", () => {
  it("carries an explicit numeric value", () => {
    const p = parseTurn(block('{"answer":"6.52 hours","value":6.52}'));
    expect(p.kind).toBe("answer");
    if (p.kind === "answer") expect(p.value).toBe(6.52);
  });

  it("accepts a numeric string rather than failing a near miss", () => {
    const p = parseTurn(block('{"answer":"a","value":"6.52"}'));
    if (p.kind === "answer") expect(p.value).toBe(6.52);
    else throw new Error("expected an answer");
  });

  it("leaves value unset when the answer is not a number", () => {
    const p = parseTurn(block('{"answer":"a list of people"}'));
    if (p.kind === "answer") expect(p.value).toBeUndefined();
    else throw new Error("expected an answer");
  });

  it("refuses a formatted value instead of silently dropping it", () => {
    const p = parseTurn(block('{"answer":"a","value":"6.52 hours"}'));
    expect(p.kind).toBe("violation");
    if (p.kind === "violation") {
      expect(p.violation).toBe("answer-bad-value");
      expect(p.detail).toContain("bare number");
    }
  });

  it("refuses a value that is an object", () => {
    const p = parseTurn(block('{"answer":"a","value":{"n":1}}'));
    expect(p.kind).toBe("violation");
  });

  it("keeps NaN and Infinity out", () => {
    // JSON has no NaN literal, so these arrive as strings if at all.
    const p = parseTurn(block('{"answer":"a","value":"NaN"}'));
    expect(p.kind).toBe("violation");
  });
});

describe("vana:answer confidence", () => {
  it("accepts the three words", () => {
    for (const c of ["high", "medium", "low"] as const) {
      const p = parseTurn(block(`{"answer":"a","confidence":"${c}"}`));
      if (p.kind === "answer") expect(p.confidence).toBe(c);
      else throw new Error("expected an answer");
    }
  });

  it("buckets a 0-1 number rather than dropping it", () => {
    // Gemini answered `"confidence": 1.0` and it was silently discarded.
    const cases: [number, string][] = [
      [1.0, "high"],
      [0.8, "high"],
      [0.5, "medium"],
      [0.1, "low"],
      [0, "low"],
    ];
    for (const [n, want] of cases) {
      const p = parseTurn(block(`{"answer":"a","confidence":${n}}`));
      if (p.kind === "answer") expect(p.confidence).toBe(want);
      else throw new Error(`expected an answer for ${n}`);
    }
  });

  it("refuses an out-of-range number rather than guessing", () => {
    const p = parseTurn(block('{"answer":"a","confidence":42}'));
    expect(p.kind).toBe("violation");
    if (p.kind === "violation")
      expect(p.violation).toBe("answer-bad-confidence");
  });

  it("refuses an unknown word", () => {
    const p = parseTurn(block('{"answer":"a","confidence":"pretty sure"}'));
    expect(p.kind).toBe("violation");
  });
});
