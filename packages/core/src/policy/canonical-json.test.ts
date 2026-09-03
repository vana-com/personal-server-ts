import { describe, expect, it } from "vitest";
import { canonicalJsonBytes } from "./canonical-json.js";

describe("canonicalJsonBytes", () => {
  it("sorts object keys recursively and preserves UTF-8 values", () => {
    const input = { b: 1, a: { d: [3, { z: 1, y: 2 }], c: "é" } };

    const bytes = canonicalJsonBytes(input);

    expect(new TextDecoder().decode(bytes)).toBe(
      '{"a":{"c":"é","d":[3,{"y":2,"z":1}]},"b":1}',
    );
  });

  it("keeps null, drops undefined properties, and adds no newline", () => {
    const bytes = canonicalJsonBytes({ z: undefined, b: null, a: 1 });
    const json = new TextDecoder().decode(bytes);

    expect(json).toBe('{"a":1,"b":null}');
    expect(json.endsWith("\n")).toBe(false);
    expect(new TextDecoder().decode(canonicalJsonBytes(Array(1)))).toBe(
      "[null]",
    );
  });
});
