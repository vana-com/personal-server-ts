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

  it("encodes the canonical form as UTF-8", () => {
    expect(Array.from(canonicalJsonBytes({ a: "€" }))).toEqual([
      ...Array.from(new TextEncoder().encode('{"a":"€"}')),
    ]);
  });
});
