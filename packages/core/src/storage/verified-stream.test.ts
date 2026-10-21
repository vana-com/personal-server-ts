import { describe, expect, it, vi } from "vitest";
import { boundedJsonBytes } from "./verified-stream.js";

describe("bounded projection serialization", () => {
  it("matches JSON bytes for escapes, Unicode, sparse arrays and toJSON", () => {
    const value = {
      text: '\u0000\b\t\n\f\r"\\é中😀\ud800x\udfff',
      array: [, undefined, null, false, 1, { toJSON: () => "😀" }],
      omitted: undefined,
    };
    const expected = new TextEncoder().encode(JSON.stringify(value));
    expect(boundedJsonBytes(value, expected.byteLength)).toEqual(expected);
    expect(() => boundedJsonBytes(value, expected.byteLength - 1)).toThrow(
      expect.objectContaining({ code: "too_large" }),
    );
  });

  it("refuses an escaped string before allocating its JSON serialization", () => {
    const value = { text: "\u0000".repeat(1024) };
    const stringify = JSON.stringify;
    let largest = 0;
    const spy = vi.spyOn(JSON, "stringify").mockImplementation((...args) => {
      const text = stringify(...args);
      largest = Math.max(largest, text?.length ?? 0);
      return text;
    });
    try {
      expect(() => boundedJsonBytes(value, 2048)).toThrow(
        expect.objectContaining({ code: "too_large" }),
      );
      expect(largest).toBeLessThanOrEqual(2048);
    } finally {
      spy.mockRestore();
    }
  });
});
