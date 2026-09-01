import { describe, expect, it } from "vitest";

import { unwrapEnvelopeData as liteUnwrap } from "./lite-query-service.js";
import { unwrapEnvelopeData as nodeUnwrap } from "../../../server/src/query/query-service.js";

/**
 * The envelope unwrap, pinned against the Node implementation it duplicates.
 *
 * `lite-query-service.ts` reimplements `unwrapEnvelopeData` because the Node
 * original lives in a module bound to Node, and design §19.18 kept the Node arm
 * byte-for-byte the code its benchmark numbers were measured on. The duplicate
 * is only safe while something fails when the two diverge.
 *
 * Why this matters more than an ordinary duplicate: the function decides how
 * many *records* a scope contains. Handed a `DataFileEnvelope` directly a
 * runner counts the envelope as ONE record and every figure in `coverage`
 * reads `1`. If the two runtimes picked different keys they would report
 * different denominators for identical data, and every Lite-vs-Node comparison
 * in §19.18 — `recordsScanned` included — would be measuring the unwrap rather
 * than the runtime.
 *
 * So this suite does not merely assert Lite's outputs: it runs BOTH
 * implementations over the same table and asserts they agree, key and note
 * included. A change to one that is not made to the other fails here.
 *
 * The cross-package import mirrors the existing precedent in
 * `packages/core/src/signing/signer.test.ts` and
 * `packages/core/src/schemas/server-config.test.ts`. It is a test-only import;
 * `packages/lite/tsconfig.json` excludes `src/**\/*.test.ts` from the build, so
 * no Node module reaches the browser bundle.
 */
const cases: { name: string; input: unknown }[] = [
  { name: "a bare array is already a record list", input: [1, 2, 3] },
  { name: "an empty array", input: [] },
  { name: "null is a single unreadable record", input: null },
  { name: "a primitive is a single record", input: 42 },
  { name: "a string is a single record", input: "hello" },
  {
    name: "a DataFileEnvelope is unwrapped one level",
    input: { version: 1, scope: "documents.files", data: [{ a: 1 }, { a: 2 }] },
  },
  {
    name: "a DataFileEnvelope wrapping a keyed payload reports a dotted key",
    input: {
      version: "2",
      scope: "email.messages",
      data: { messages: [{ id: 1 }] },
    },
  },
  {
    name: "an envelope whose payload is a primitive carries the inner note",
    input: { version: 1, scope: "x.y", data: 7 },
  },
  {
    name: "a sole array-valued key is taken without a note",
    input: { rows: [{ r: 1 }], meta: "ignored" },
  },
  {
    name: "several array keys fall back to the known-key order",
    input: { items: [{ i: 1 }], extras: [{ e: 1 }] },
  },
  {
    name: "known-key order prefers items over results",
    input: { results: [{ r: 1 }], items: [{ i: 1 }], events: [{ v: 1 }] },
  },
  {
    name: "no array-valued key means one record",
    input: { a: 1, b: "two" },
  },
  {
    name: "array keys matching no known record key means one record",
    input: { alphas: [1], betas: [2] },
  },
  {
    name: "an object missing `scope` is not treated as an envelope",
    input: { version: 1, data: [{ a: 1 }] },
  },
  {
    name: "an object missing `version` is not treated as an envelope",
    input: { scope: "documents.files", data: [{ a: 1 }] },
  },
  {
    name: "a non-string `scope` is not treated as an envelope",
    input: { version: 1, scope: 5, data: [{ a: 1 }] },
  },
];

describe("Lite unwrapEnvelopeData agrees with the Node implementation", () => {
  for (const { name, input } of cases) {
    it(name, () => {
      const lite = liteUnwrap(input);
      const node = nodeUnwrap(input);
      // Deep-equal over the whole result: items, the chosen key, and the note.
      // The note is part of the contract — it is what stops a wrong key being
      // applied invisibly — so a divergence in wording is a divergence.
      expect(lite).toEqual(node);
    });
  }

  it("covers the envelope case both implementations single out", () => {
    // Guards the table above against being silently emptied of the case the
    // whole function exists for.
    const envelope = {
      version: 1,
      scope: "documents.files",
      data: [{ a: 1 }, { a: 2 }],
    };
    const lite = liteUnwrap(envelope);
    expect(lite.items).toHaveLength(2);
    expect(lite.key).toBe("data");
    expect(lite).toEqual(nodeUnwrap(envelope));
  });
});
