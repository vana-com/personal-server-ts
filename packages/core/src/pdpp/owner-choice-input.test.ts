import { describe, expect, it } from "vitest";
import { isWellFormedJson, ownValue } from "./named.js";
import { normalizeOwnerChoiceInput } from "./owner-choice-input.js";
import { parseDeclaration } from "./declaration.js";
import { validateSelectionRequest } from "./selection.js";
import {
  PDPP_DATA_ACCESS_TYPE_V02,
  type DeclarationSnapshot,
} from "./types.js";

describe("isWellFormedJson", () => {
  it("accepts text, astral characters and paired surrogates anywhere", () => {
    expect(
      isWellFormedJson({
        "key \u{1F600}": ["value", { nested: "\u{1F600}" }],
        n: 1,
        b: null,
      }),
    ).toBe(true);
  });

  it.each([
    ["a key", { "\ud800": 1 }],
    ["a nested key", { a: { "x\udc00": 1 } }],
    ["a string", "\ud83d"],
    ["a string in an array", [["ok", "\udc00y"]]],
    ["a reversed pair", "\ude00\ud83d"],
  ])("rejects a lone surrogate in %s", (_label, value) => {
    expect(isWellFormedJson(value)).toBe(false);
  });
});

describe("ownValue", () => {
  it.each([null, undefined, "text", 7])("finds nothing in %j", (map) => {
    expect(ownValue(map as never, "constructor")).toBeUndefined();
  });

  it("reads own properties only", () => {
    expect(ownValue({ a: 1 }, "a")).toBe(1);
    expect(ownValue({ a: 1 }, "toString")).toBeUndefined();
    expect(ownValue(JSON.parse('{"__proto__":2}'), "__proto__")).toBe(2);
  });
});

describe("normalizeOwnerChoiceInput", () => {
  it("returns prototype-free copies that keep __proto__ as a key", () => {
    const result = normalizeOwnerChoiceInput({
      ownerChoices: JSON.parse(
        '{"fields":{"__proto__":["a"]},"time_ranges":{"constructor":{"since":"2025-01-01T00:00:00Z"}}}',
      ),
      instanceChoices: JSON.parse('{"__proto__":["h"]}'),
    });
    if (!result.ok) throw new Error(result.message);
    expect(Object.getPrototypeOf(result.ownerChoices?.fields)).toBeNull();
    expect(Object.keys(result.ownerChoices?.fields ?? {})).toEqual([
      "__proto__",
    ]);
    expect(Object.keys(result.instanceChoices ?? {})).toEqual(["__proto__"]);
    expect(ownValue(result.ownerChoices?.fields, "toString")).toBeUndefined();
  });

  it("passes absent choices through", () => {
    expect(normalizeOwnerChoiceInput({})).toEqual({
      ok: true,
      ownerChoices: undefined,
      instanceChoices: undefined,
    });
  });

  it.each([
    ["null owner choices", { ownerChoices: null }],
    ["a list of owner choices", { ownerChoices: [] }],
    ["null instance choices", { instanceChoices: null }],
    ["a bare handle", { instanceChoices: { s: "h" } }],
    ["null fields", { ownerChoices: { fields: null } }],
    ["a bare field", { ownerChoices: { fields: { s: "f" } } }],
    ["null time_ranges", { ownerChoices: { time_ranges: null } }],
    [
      "a non-string bound",
      { ownerChoices: { time_ranges: { s: { since: 1 } } } },
    ],
    ["a stream list of numbers", { ownerChoices: { declined_streams: [1] } }],
    ["a lone surrogate key", { ownerChoices: { fields: { "\ud800": ["f"] } } }],
    ["a lone surrogate value", { instanceChoices: { s: ["\udc00"] } }],
  ])("refuses %s", (_label, input) => {
    expect(normalizeOwnerChoiceInput(input).ok).toBe(false);
  });
});

describe("one Unicode policy at every boundary that accepts names", () => {
  const name = "lone \ud800 surrogate";
  const snapshot: DeclarationSnapshot = {
    source_id: "https://data.example.com/names",
    source_kind: "provider_native",
    version: "1",
    digest: "a".repeat(64),
    streams: [{ name, fields: ["f"], required_fields: [], primary_key: ["f"] }],
  };

  it("refuses a selection request that names a declared stream with one", () => {
    const result = validateSelectionRequest(
      {
        type: PDPP_DATA_ACCESS_TYPE_V02,
        source: { id: snapshot.source_id },
        purpose_code: "https://apps.example.com/p",
        access_mode: "single_use",
        streams: [{ name, fields: ["f"] }],
      },
      snapshot,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.failure.code).toBe("invalid_request");
  });

  it("refuses a declaration document that declares one", () => {
    const body = JSON.stringify({
      source_id: snapshot.source_id,
      source_kind: "provider_native",
      version: "1",
      streams: [{ name, fields: ["f"], primary_key: ["f"] }],
    });
    const result = parseDeclaration(body, snapshot.source_id);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.failure.code).toBe("invalid_document");
  });
});
