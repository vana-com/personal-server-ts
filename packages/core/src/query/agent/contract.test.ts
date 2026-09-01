import { describe, expect, it } from "vitest";

import {
  ANSWER_TAG,
  RUN_TAG,
  findFencedBlocks,
  parseTurn,
  repairMessage,
} from "./contract.js";

const fence = "```";

describe("findFencedBlocks", () => {
  it("reads a tagged block", () => {
    const blocks = findFencedBlocks(
      `${fence}${RUN_TAG}\nconst a = 1;\n${fence}`,
    );
    expect(blocks).toEqual([{ tag: RUN_TAG, body: "const a = 1;" }]);
  });

  it("supports tilde fences", () => {
    const blocks = findFencedBlocks(`~~~${RUN_TAG}\nx\n~~~`);
    expect(blocks).toEqual([{ tag: RUN_TAG, body: "x" }]);
  });

  it("lets a longer fence contain a nested triple-backtick string", () => {
    // A script that builds markdown is legal and must not truncate at the
    // inner fence.
    const text = [
      "````" + RUN_TAG,
      "const md = `" + fence + "js\\ncode\\n" + fence + "`;",
      "````",
    ].join("\n");
    const blocks = findFencedBlocks(text);
    expect(blocks).toHaveLength(1);
    expect(blocks[0]?.body).toContain("const md =");
  });

  it("keeps the body of an unclosed fence", () => {
    const blocks = findFencedBlocks(`${fence}${RUN_TAG}\nconst a = 1;`);
    expect(blocks[0]?.body).toBe("const a = 1;");
  });
});

describe("parseTurn — the contract", () => {
  it("parses a run block", () => {
    const r = parseTurn(
      `prose\n${fence}${RUN_TAG}\nawait vana.scopes();\n${fence}`,
    );
    expect(r).toEqual({ kind: "run", script: "await vana.scopes();" });
  });

  it("takes the LAST matching block, not the first", () => {
    const text = [
      "Here is a draft:",
      `${fence}${RUN_TAG}`,
      "const draft = 1;",
      fence,
      "On reflection:",
      `${fence}${RUN_TAG}`,
      "const final = 2;",
      fence,
    ].join("\n");
    const r = parseTurn(text);
    expect(r).toMatchObject({ kind: "run", script: "const final = 2;" });
  });

  it("takes a trailing answer block over an earlier run block", () => {
    const text = [
      `${fence}${RUN_TAG}`,
      "const a = 1;",
      fence,
      `${fence}${ANSWER_TAG}`,
      '{"answer":"done","citations":[{"scope":"oura.sleep"}]}',
      fence,
    ].join("\n");
    expect(parseTurn(text)).toMatchObject({ kind: "answer", answer: "done" });
  });

  it("ignores prose outside the block", () => {
    const r = parseTurn(
      `I will now compute the average.\n\n${fence}${RUN_TAG}\nrun();\n${fence}\n\nHope that helps!`,
    );
    expect(r).toMatchObject({ kind: "run", script: "run();" });
  });

  it("parses an answer block with citations and confidence", () => {
    const body = JSON.stringify({
      answer: "6.52 hours over 1030 nights, main sleep only.",
      citations: [{ scope: "oura.sleep", recordId: "s1" }],
      confidence: "high",
    });
    expect(parseTurn(`${fence}${ANSWER_TAG}\n${body}\n${fence}`)).toEqual({
      kind: "answer",
      answer: "6.52 hours over 1030 nights, main sleep only.",
      citations: [{ scope: "oura.sleep", recordId: "s1" }],
      confidence: "high",
    });
  });

  it("accepts citations given as bare scope strings", () => {
    const body = JSON.stringify({ answer: "x", citations: ["oura.sleep"] });
    expect(parseTurn(`${fence}${ANSWER_TAG}\n${body}\n${fence}`)).toMatchObject(
      {
        citations: [{ scope: "oura.sleep" }],
      },
    );
  });

  it("defaults citations to empty when absent", () => {
    const body = JSON.stringify({ answer: "x" });
    expect(parseTurn(`${fence}${ANSWER_TAG}\n${body}\n${fence}`)).toMatchObject(
      {
        citations: [],
      },
    );
  });
});

describe("parseTurn — violations", () => {
  it("reports no-block when the model wrote only prose", () => {
    expect(parseTurn("I think the answer is about 6 hours.")).toMatchObject({
      kind: "violation",
      violation: "no-block",
    });
  });

  it("reports unknown-tag when the model used a plain js fence", () => {
    const r = parseTurn(`${fence}js\nconst a = 1;\n${fence}`);
    expect(r).toMatchObject({ kind: "violation", violation: "unknown-tag" });
    expect((r as { detail: string }).detail).toContain("`js`");
  });

  it("reports empty-block", () => {
    expect(parseTurn(`${fence}${RUN_TAG}\n\n${fence}`)).toMatchObject({
      violation: "empty-block",
    });
  });

  it("reports answer-not-json", () => {
    expect(
      parseTurn(`${fence}${ANSWER_TAG}\nnot json\n${fence}`),
    ).toMatchObject({ violation: "answer-not-json" });
  });

  it("reports answer-not-object for a JSON array", () => {
    expect(parseTurn(`${fence}${ANSWER_TAG}\n[1,2]\n${fence}`)).toMatchObject({
      violation: "answer-not-object",
    });
  });

  it("reports a missing or empty answer field", () => {
    expect(
      parseTurn(`${fence}${ANSWER_TAG}\n{"citations":[]}\n${fence}`),
    ).toMatchObject({ violation: "answer-missing-answer-field" });
    expect(
      parseTurn(`${fence}${ANSWER_TAG}\n{"answer":"   "}\n${fence}`),
    ).toMatchObject({ violation: "answer-missing-answer-field" });
  });

  it("reports bad citations", () => {
    const body = '{"answer":"x","citations":[{"noScope":true}]}';
    expect(parseTurn(`${fence}${ANSWER_TAG}\n${body}\n${fence}`)).toMatchObject(
      {
        violation: "answer-bad-citations",
      },
    );
  });
});

describe("repairMessage", () => {
  it("names the violation and restates both tags", () => {
    const failure = parseTurn("just prose");
    const msg = repairMessage(failure as never);
    expect(msg).toContain("no fenced block");
    expect(msg).toContain(RUN_TAG);
    expect(msg).toContain(ANSWER_TAG);
  });
});
