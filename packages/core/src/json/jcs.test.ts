import { describe, expect, it } from "vitest";
import { canonicalJsonBytes, canonicalizeJson } from "./jcs.js";

describe("canonicalizeJson (RFC 8785)", () => {
  it("sorts members by UTF-16 code units and emits no whitespace", () => {
    expect(canonicalizeJson({ b: 1, a: [2, { d: null, c: true }] })).toBe(
      '{"a":[2,{"c":true,"d":null}],"b":1}',
    );
    // A surrogate pair (d83d...) sorts before U+FF5E on code units, and
    // U+00E9 after every ASCII key.
    expect(
      Object.keys(
        JSON.parse(canonicalizeJson({ "～": 1, "\u{1f600}": 2, é: 3, z: 4 })),
      ),
    ).toEqual(["z", "é", "\u{1f600}", "～"]);
  });

  it("serializes numbers like ECMAScript and strings like JSON.stringify", () => {
    expect(
      canonicalizeJson([1, 1.0, -0, 0.1, 1e21, 123456789012345680000]),
    ).toBe("[1,1,0,0.1,1e+21,123456789012345680000]");
    expect(canonicalizeJson('\u20ac \n \u001f " \\')).toBe(
      '"\u20ac \\n \\u001f \\" \\\\"',
    );
  });

  it("refuses values that are not JSON instead of dropping them", () => {
    expect(() => canonicalizeJson({ a: undefined })).toThrow(TypeError);
    expect(() => canonicalizeJson(Number.NaN)).toThrow(TypeError);
    expect(() => canonicalizeJson(() => 1)).toThrow(TypeError);
    expect(() => canonicalizeJson(1n)).toThrow(TypeError);
  });

  it("sorts integer-like keys lexicographically, not numerically", () => {
    // `Object.keys` hoists integer-like keys to the front in ASCENDING
    // NUMERIC order, so the raw property order is ["0","1","2","10","100"].
    // RFC 8785 sorts on UTF-16 code units, where "10" < "2". Asserting on the
    // canonical STRING is load-bearing: round-tripping through JSON.parse to
    // read back Object.keys would re-hoist these and mask a real ordering bug.
    const intKeys = { 10: "a", 2: "b", 1: "c", 0: "d", 100: "e" };
    expect(Object.keys(intKeys)).toEqual(["0", "1", "2", "10", "100"]);
    expect(canonicalizeJson(intKeys)).toBe(
      '{"0":"d","1":"c","10":"a","100":"e","2":"b"}',
    );
    expect(canonicalizeJson({ b: 1, 2: 2, a: 3, 10: 4 })).toBe(
      '{"10":4,"2":2,"a":3,"b":1}',
    );
  });

  it("preserves array order while sorting object keys at every depth", () => {
    // Arrays are ordered values: canonicalization must never touch them.
    expect(canonicalizeJson([3, 1, 2, "b", "a"])).toBe('[3,1,2,"b","a"]');
    expect(
      canonicalizeJson([
        { b: 1, a: 2 },
        { d: 3, c: 4 },
      ]),
    ).toBe('[{"a":2,"b":1},{"c":4,"d":3}]');
    expect(canonicalizeJson({ z: { y: { x: 1, a: 2 }, b: 3 }, a: 4 })).toBe(
      '{"a":4,"z":{"b":3,"y":{"a":2,"x":1}}}',
    );
  });

  it("escapes only what RFC 8785 requires", () => {
    // Two-character forms where they exist, lowercase \u00xx for the rest of
    // C0, and NO escaping at or above U+0020 - U+0080 stays a raw character.
    expect(canonicalizeJson({ a: "\t\b\f\r\n" })).toBe(
      '{"a":"\\t\\b\\f\\r\\n"}',
    );
    expect(canonicalizeJson({ a: "\u001f" })).toBe('{"a":"\\u001f"}');
    expect(canonicalizeJson({ a: "\u0080" })).toBe('{"a":"\u0080"}');
    expect(canonicalizeJson({ a: "\u00e9\u{1f600}" })).toBe(
      '{"a":"\u00e9\u{1f600}"}',
    );
  });

  it("does NOT honour toJSON, unlike JSON.stringify", () => {
    // Documented deviation: a Date canonicalizes to {} rather than its ISO
    // string. Callers must pass plain JSON data (parsed JSON). Pinned here so
    // the behaviour is a decision on record rather than a latent surprise.
    const date = new Date("2026-01-01T00:00:00.000Z");
    expect(JSON.stringify({ d: date })).toBe(
      '{"d":"2026-01-01T00:00:00.000Z"}',
    );
    expect(canonicalizeJson({ d: date })).toBe('{"d":{}}');
  });

  it("encodes the canonical form as UTF-8", () => {
    expect(Array.from(canonicalJsonBytes({ a: "€" }))).toEqual([
      ...Array.from(new TextEncoder().encode('{"a":"€"}')),
    ]);
  });
});
