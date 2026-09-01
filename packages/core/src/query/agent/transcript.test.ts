import { describe, expect, it } from "vitest";

import type { InferenceMessage } from "../../derivatives/inference.js";
import {
  DEFAULT_TRANSCRIPT_BUDGET_BYTES,
  E2EE_CONTENT_EXPANSION,
  E2EE_MESSAGE_FRAMING_BYTES,
  RELAY_MAX_BODY_BYTES,
  REQUEST_OVERHEAD_RESERVE_BYTES,
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

describe("fitTranscript — the relay's 256 KiB body cap", () => {
  const sys: InferenceMessage = { role: "system", content: "SYSTEM" };
  const question: InferenceMessage = { role: "user", content: "QUESTION" };

  it("leaves a small transcript alone", () => {
    const msgs = [sys, question, { role: "assistant", content: "hi" } as const];
    const r = fitTranscript(msgs);
    expect(r.droppedTurns).toBe(0);
    expect(r.messages).toHaveLength(3);
  });

  it("matches the gateway's real body cap", () => {
    // data-gateway/lib/inference.ts:35 DEFAULT_INFERENCE_MAX_BODY_BYTES,
    // enforced as 413 BODY_TOO_LARGE. This was 2 MiB — 8x too large — and a
    // large question failed outright instead of being trimmed.
    expect(RELAY_MAX_BODY_BYTES).toBe(256 * 1024);
  });

  it("derives the budget from the cap rather than hard-coding a second number", () => {
    expect(DEFAULT_TRANSCRIPT_BUDGET_BYTES).toBe(
      Math.floor(
        (RELAY_MAX_BODY_BYTES - REQUEST_OVERHEAD_RESERVE_BYTES) /
          E2EE_CONTENT_EXPANSION,
      ),
    );
    expect(DEFAULT_TRANSCRIPT_BUDGET_BYTES).toBe(120 * 1024);
  });

  it("leaves room for the E2EE-encoded body, not just the plaintext", () => {
    // The old budget was 1 MiB of plaintext: 4x the gateway's ENTIRE body
    // limit before E2EE even doubles it. Halving the cap is not enough on its
    // own — the derivation has to survive the wire encoding.
    expect(
      DEFAULT_TRANSCRIPT_BUDGET_BYTES * E2EE_CONTENT_EXPANSION,
    ).toBeLessThan(RELAY_MAX_BODY_BYTES);
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

/**
 * What the gateway actually weighs: the serialized body AFTER encryption
 * (`readRequestBody`, measured against `DEFAULT_INFERENCE_MAX_BODY_BYTES`).
 * Mirrors how `createInferenceProvider` assembles it — E2EE encrypts each
 * `messages[i].content` to hex, then the whole object is JSON-stringified once
 * (`../../derivatives/inference.ts:375-393`).
 */
function e2eeEncodedBodyBytes(messages: InferenceMessage[]): number {
  // `{"provider":{"aci_verified":true,"zdr":true},"model":"z-ai/glm-5.2",
  //   "messages":[…],"max_tokens":2048}`
  let total = 110;
  for (const m of messages) {
    // `{"role":"assistant","content":"<hex>"},` — hex never needs escaping.
    total += 24 + m.role.length;
    total +=
      byteLength(m.content) * E2EE_CONTENT_EXPANSION +
      E2EE_MESSAGE_FRAMING_BYTES;
  }
  return total;
}

describe("the transcript budget against the gateway's 413", () => {
  const sys: InferenceMessage = { role: "system", content: "SYSTEM PROMPT" };
  const question: InferenceMessage = { role: "user", content: "QUESTION" };

  /** A run the old 1 MiB budget waved through and the gateway would refuse. */
  function oversizedTranscript(): InferenceMessage[] {
    const msgs: InferenceMessage[] = [sys, question];
    for (let i = 0; i < 20; i += 1) {
      msgs.push({ role: "assistant", content: `${"x".repeat(20_000)}#${i}` });
      msgs.push({ role: "user", content: `${"y".repeat(8_000)}#${i}` });
    }
    return msgs;
  }

  it("would 413 without fitting — the bug this budget exists to prevent", () => {
    // Guards the premise: if this ever stops being over the cap the test below
    // proves nothing.
    expect(e2eeEncodedBodyBytes(oversizedTranscript())).toBeGreaterThan(
      RELAY_MAX_BODY_BYTES,
    );
  });

  it("fits an over-cap transcript inside the body the gateway will accept", () => {
    const r = fitTranscript(oversizedTranscript());
    expect(r.droppedTurns).toBeGreaterThan(0);
    expect(e2eeEncodedBodyBytes(r.messages)).toBeLessThanOrEqual(
      RELAY_MAX_BODY_BYTES,
    );
  });

  it("trims rather than refusing, and says the history is partial", () => {
    const r = fitTranscript(oversizedTranscript());
    expect(r.messages[0]).toBe(sys);
    expect(r.messages[1]).toBe(question);
    // The most recent turn survives: trimming must not cost the model the
    // output it is about to reason from.
    expect(r.messages.at(-1)?.content).toContain("#19");
    expect(r.messages[2]?.content).toContain("dropped by the host");
  });

  it("a single message too large to fit is still sent rather than dropped", () => {
    // The tail-keeping walk keeps at least one message, so an enormous final
    // run result is not silently swallowed into an empty transcript. It may
    // still 413 — but `truncateOutput` caps run results long before this, so
    // the only way here is a caller passing its own oversized message.
    const huge: InferenceMessage = {
      role: "user",
      content: "z".repeat(DEFAULT_TRANSCRIPT_BUDGET_BYTES * 2),
    };
    const r = fitTranscript([sys, question, huge]);
    expect(r.messages).toContain(huge);
  });
});
