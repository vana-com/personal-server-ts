import { describe, expect, it } from "vitest";
import {
  RESULT_FRAME_BEGIN,
  RESULT_FRAME_END,
  decodeResultFrame,
  encodeResultFrame,
  stripResultFrames,
  type RunDocument,
} from "./protocol.js";
import type { CoverageCounters } from "./types.js";

const coverage: CoverageCounters = {
  scopesScanned: ["oura.sleep"],
  recordsScanned: 3,
  bytesScanned: 128,
  scopesSkipped: [],
  complete: true,
  method: "full",
  enforcementNotes: [],
};

function doc(over: Partial<RunDocument> = {}): RunDocument {
  return { v: 1, coverage, notes: [], toolCalls: 1, classifyUsd: 0, ...over };
}

describe("result frame", () => {
  it("round-trips a document", () => {
    const out = decodeResultFrame(`noise\n${encodeResultFrame(doc())}\nmore`);
    expect(out.ok).toBe(true);
    if (out.ok) expect(out.doc.coverage.recordsScanned).toBe(3);
  });

  it("round-trips non-ASCII payloads", () => {
    // Notes carry user data, which is not ASCII. A latin1 base64 would corrupt
    // it silently.
    const out = decodeResultFrame(
      encodeResultFrame(doc({ notes: ["日本旅行 — café ☕️"] })),
    );
    expect(out.ok).toBe(true);
    if (out.ok) expect(out.doc.notes[0]).toBe("日本旅行 — café ☕️");
  });

  it("cannot be forged by note text containing the sentinel", () => {
    // The whole safety argument: base64's alphabet has no underscore, so an
    // encoded payload can never reproduce the sentinel. A note that IS a
    // well-formed frame is just characters inside the real one.
    const forged = encodeResultFrame({
      ...doc(),
      coverage: { ...coverage, recordsScanned: 999_999 },
    });
    const out = decodeResultFrame(
      encodeResultFrame(doc({ notes: [forged, RESULT_FRAME_BEGIN] })),
    );
    expect(out.ok).toBe(true);
    if (out.ok) {
      expect(out.doc.coverage.recordsScanned).toBe(3);
      expect(out.doc.notes[0]).toContain(RESULT_FRAME_BEGIN);
    }
  });

  it("takes the last frame", () => {
    const first = encodeResultFrame(doc());
    const second = encodeResultFrame({
      ...doc(),
      coverage: { ...coverage, recordsScanned: 77 },
    });
    const out = decodeResultFrame(first + second);
    expect(out.ok).toBe(true);
    if (out.ok) expect(out.doc.coverage.recordsScanned).toBe(77);
  });

  it("fails closed when absent", () => {
    expect(decodeResultFrame("just output")).toEqual({
      ok: false,
      reason: "absent",
    });
  });

  it("fails closed when truncated mid-frame", () => {
    // What an output-cap kill looks like. Never salvage a partial payload.
    const full = encodeResultFrame(doc());
    const cut = full.slice(0, full.length - RESULT_FRAME_END.length - 10);
    expect(decodeResultFrame(cut)).toEqual({ ok: false, reason: "truncated" });
  });

  it("fails closed on a corrupt payload", () => {
    const bad = `${RESULT_FRAME_BEGIN}!!!not-base64!!!${RESULT_FRAME_END}`;
    expect(decodeResultFrame(bad).ok).toBe(false);
  });

  it("fails closed on a wrong version", () => {
    const wrong = encodeResultFrame({
      ...doc(),
      v: 2 as unknown as 1,
    });
    expect(decodeResultFrame(wrong)).toEqual({
      ok: false,
      reason: "malformed",
    });
  });

  it("strips frames from output shown to the model", () => {
    const stdout = `before\n${encodeResultFrame(doc())}\nafter`;
    const stripped = stripResultFrames(stdout);
    expect(stripped).toContain("before");
    expect(stripped).toContain("after");
    expect(stripped).not.toContain(RESULT_FRAME_BEGIN);
  });

  it("drops the tail of an unterminated frame when stripping", () => {
    const stdout = `visible\n${RESULT_FRAME_BEGIN}aGVsbG8`;
    expect(stripResultFrames(stdout)).toBe("visible");
  });
});
