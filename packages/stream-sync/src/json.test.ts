import { describe, expect, it } from "vitest";
import { canonicalJson } from "./json.js";
import { NonCanonicalValueError } from "./errors.js";

describe("canonicalJson", () => {
  it.each([
    ["undefined", undefined],
    ["undefined property", { a: undefined }],
    ["NaN", [Number.NaN]],
    ["Infinity", [Number.POSITIVE_INFINITY]],
    ["bigint", [1n]],
    ["function", [() => 1]],
    ["Date", [new Date(0)]],
    ["Map", new Map()],
    ["symbol", [Symbol("x")]],
    ["sparse array hole", [, 1]],
  ])("rejects %s", (_name, value) => {
    expect(() => canonicalJson(value)).toThrow(NonCanonicalValueError);
  });

  it("rejects cycles and over-deep nesting with a typed error", () => {
    const cyclic: Record<string, unknown> = {};
    cyclic["self"] = cyclic;
    expect(() => canonicalJson(cyclic)).toThrow(NonCanonicalValueError);
  });

  it("does not depend on key insertion order", () => {
    expect(canonicalJson({ a: 1, b: { d: 1, c: 2 } })).toBe(
      canonicalJson({ b: { c: 2, d: 1 }, a: 1 }),
    );
  });

  it("accepts null-prototype objects", () => {
    const o = Object.create(null) as Record<string, number>;
    o["x"] = 1;
    expect(canonicalJson(o)).toBe('{"x":1}');
  });

  it("never touches Object.prototype", () => {
    canonicalJson(
      JSON.parse(
        '{"__proto__":{"polluted":true},"constructor":{"prototype":{"p":1}}}',
      ),
    );
    expect(({} as Record<string, unknown>)["polluted"]).toBeUndefined();
    expect(({} as Record<string, unknown>)["p"]).toBeUndefined();
  });
});
