import { describe, expect, it } from "vitest";

import type { InferenceMessage } from "../../derivatives/inference.js";
import {
  DEFAULT_TRANSCRIPT_BUDGET_BYTES,
  RELAY_MAX_BODY_BYTES,
  byteLength,
  fitTranscript,
  renderRunResult,
  transcriptBytes,
  truncateOutput,
} from "./transcript.js";

describe("truncateOutput", () => {
  it("passes short output through untouched", () => {
    const r = truncateOutput("hello", 1000);
    expect(r.text).toBe("hello");
    expect(r.truncation).toBeUndefined();
  });

  it("keeps both head and tail when it cuts", () => {
    // The head carries denominators a script printed first; the tail carries
    // the stack of whatever threw. Losing either loses the answer.
    const output = "HEAD_MARKER\n" + "x".repeat(50_000) + "\nTAIL_MARKER";
    const r = truncateOutput(output, 2_000);
    expect(r.text).toContain("HEAD_MARKER");
    expect(r.text).toContain("TAIL_MARKER");
    expect(r.text).toContain("omitted by the host");
    expect(r.truncation?.droppedBytes).toBeGreaterThan(40_000);
  });

  it("stays within the byte budget plus the marker", () => {
    const r = truncateOutput("y".repeat(100_000), 4_000);
    // Budget covers head+tail; the marker itself is small and additive.
    expect(byteLength(r.text)).toBeLessThan(4_000 + 200);
  });

  it("never splits a multi-byte character", () => {
    const r = truncateOutput("🌸".repeat(10_000), 1_000);
    expect(r.text).not.toContain("�");
    expect(() => JSON.parse(JSON.stringify(r.text))).not.toThrow();
  });
});

describe("renderRunResult", () => {
  it("includes notes, stdout and stderr", () => {
    const r = renderRunResult({
      stdout: "rows=1030",
      stderr: "warn: two devices",
      notes: ["excluded naps"],
      termination: "completed",
      truncatedByHost: false,
    });
    expect(r.content).toContain("excluded naps");
    expect(r.content).toContain("rows=1030");
    expect(r.content).toContain("warn: two devices");
  });

  it("tells the model when the run ended early", () => {
    const r = renderRunResult({
      stdout: "partial",
      stderr: "",
      notes: [],
      termination: "cpu",
      truncatedByHost: false,
    });
    expect(r.content).toContain("ended early: cpu");
    expect(r.content).toContain("must be reported as partial");
  });

  it("tells the model when the host capped its output", () => {
    const r = renderRunResult({
      stdout: "lots",
      stderr: "",
      notes: [],
      termination: "outputCap",
      truncatedByHost: true,
    });
    expect(r.content).toContain("output cap");
    expect(r.content).toContain("aggregate in code");
  });

  it("reports no output rather than an empty message", () => {
    const r = renderRunResult({
      stdout: "",
      stderr: "",
      notes: [],
      termination: "completed",
      truncatedByHost: false,
    });
    expect(r.content).toContain("(no output)");
  });
});

describe("fitTranscript — the relay's 2 MiB body cap", () => {
  const sys: InferenceMessage = { role: "system", content: "SYSTEM" };
  const question: InferenceMessage = { role: "user", content: "QUESTION" };

  it("leaves a small transcript alone", () => {
    const msgs = [sys, question, { role: "assistant", content: "hi" } as const];
    const r = fitTranscript(msgs);
    expect(r.droppedTurns).toBe(0);
    expect(r.messages).toHaveLength(3);
  });

  it("keeps the default budget under the relay cap", () => {
    expect(DEFAULT_TRANSCRIPT_BUDGET_BYTES).toBeLessThan(RELAY_MAX_BODY_BYTES);
  });

  it("drops oldest turns but always keeps the system prompt and question", () => {
    const big = "z".repeat(200_000);
    const msgs: InferenceMessage[] = [sys, question];
    for (let i = 0; i < 20; i += 1) {
      msgs.push({ role: "assistant", content: `${big}#${i}` });
    }
    const r = fitTranscript(msgs, 500_000);
    expect(r.droppedTurns).toBeGreaterThan(0);
    expect(r.messages[0]).toBe(sys);
    expect(r.messages[1]).toBe(question);
    expect(transcriptBytes(r.messages)).toBeLessThanOrEqual(500_000);
  });

  it("marks the gap rather than dropping history silently", () => {
    const big = "z".repeat(200_000);
    const msgs: InferenceMessage[] = [sys, question];
    for (let i = 0; i < 10; i += 1) {
      msgs.push({ role: "assistant", content: `${big}#${i}` });
    }
    const r = fitTranscript(msgs, 500_000);
    const marker = r.messages[2];
    expect(marker?.content).toContain("dropped by the host");
    expect(marker?.content).toContain("not seeing the full history");
  });

  it("keeps the most recent turn, not the oldest", () => {
    const big = "z".repeat(200_000);
    const msgs: InferenceMessage[] = [sys, question];
    for (let i = 0; i < 10; i += 1) {
      msgs.push({ role: "assistant", content: `${big}#${i}` });
    }
    const r = fitTranscript(msgs, 500_000);
    const last = r.messages[r.messages.length - 1];
    expect(last?.content).toContain("#9");
  });
});
