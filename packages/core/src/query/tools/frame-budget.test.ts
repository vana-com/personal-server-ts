/**
 * The coverage frame must survive a chatty script.
 *
 * Notes are unbounded — `console.log` and `vana.note` both append — and they
 * travel inside the frame, so an unbounded note list makes an unbounded frame.
 * A frame past the sandbox's `maxOutputBytes` is killed mid-write, the host
 * correctly refuses to trust a truncated frame, and the run loses every
 * counter it had. Coverage is the load-bearing part; notes are not.
 */

import { describe, expect, it } from "vitest";
import {
  NOTES_TRIMMED,
  boundRunDocument,
  decodeResultFrame,
  encodeResultFrame,
  type RunDocument,
} from "./protocol.js";
import type { CoverageCounters } from "./types.js";

const coverage: CoverageCounters = {
  scopesScanned: ["oura.sleep", "chatgpt.conversations"],
  recordsScanned: 119_758,
  bytesScanned: 8_531_996,
  scopesSkipped: [{ scope: "documents.files", reason: "no text layer" }],
  complete: true,
  method: "full",
  enforcementNotes: ["RSS watchdog samples every 50ms"],
};

const doc = (notes: string[], result?: RunDocument["result"]): RunDocument => ({
  v: 1,
  coverage,
  notes,
  toolCalls: 3,
  classifyUsd: 0,
  ...(result ? { result } : {}),
});

const chatty = (n: number): string[] =>
  Array.from({ length: n }, (_, i) => `debugging row ${i} ${"pad".repeat(30)}`);

describe("frame budget", () => {
  it("leaves a document that already fits completely alone", () => {
    const d = doc(["one", "two"]);
    expect(boundRunDocument(d, 64_000)).toEqual(d);
  });

  it("keeps coverage intact when notes must be dropped", () => {
    const bounded = boundRunDocument(doc(chatty(5000)), 8_000);
    expect(encodeResultFrame(bounded).length).toBeLessThanOrEqual(8_000);
    // The whole point: every counter survives.
    expect(bounded.coverage).toEqual(coverage);
    expect(bounded.coverage.recordsScanned).toBe(119_758);
  });

  it("says what it dropped rather than dropping it silently", () => {
    const bounded = boundRunDocument(doc(chatty(5000)), 8_000);
    expect(bounded.notes.join("\n")).toContain(NOTES_TRIMMED);
    expect(bounded.notes.length).toBeLessThan(5000);
  });

  it("keeps both ends of the note list", () => {
    const notes = chatty(400);
    const bounded = boundRunDocument(doc(notes), 6_000);
    expect(bounded.notes[0]).toBe(notes[0]);
    expect(bounded.notes.at(-1)).toBe(notes.at(-1));
  });

  it("survives a single note larger than the whole budget", () => {
    const bounded = boundRunDocument(doc(["x".repeat(500_000)]), 4_000);
    expect(encodeResultFrame(bounded).length).toBeLessThanOrEqual(4_000);
    expect(bounded.coverage.recordsScanned).toBe(119_758);
  });

  it("drops an oversized result rather than the frame, and says so", () => {
    const bounded = boundRunDocument(
      doc([], { answer: "y".repeat(500_000) }),
      4_000,
    );
    expect(encodeResultFrame(bounded).length).toBeLessThanOrEqual(4_000);
    expect(bounded.result).toBeUndefined();
    expect(bounded.error?.code).toBe("RESULT_TOO_LARGE");
    expect(bounded.coverage).toEqual(coverage);
  });

  it("a bounded frame still decodes, and to trustworthy coverage", () => {
    const bounded = boundRunDocument(doc(chatty(5000)), 8_000);
    const out = decodeResultFrame(encodeResultFrame(bounded));
    expect(out.ok).toBe(true);
    if (out.ok) {
      expect(out.doc.coverage.recordsScanned).toBe(119_758);
      expect(out.doc.coverage.complete).toBe(true);
    }
  });

  it("trimming never invents coverage", () => {
    // Bounding must not be a route to a *better*-looking run than really
    // happened: an incomplete run stays incomplete however much is trimmed.
    const partial: CoverageCounters = { ...coverage, complete: false };
    const bounded = boundRunDocument(
      { ...doc(chatty(5000)), coverage: partial },
      8_000,
    );
    expect(bounded.coverage.complete).toBe(false);
  });
});
