/**
 * §5.2: the embedded stream schema is meta-validated before acceptance.
 *
 * ── The clause ──────────────────────────────────────────────────────────────
 *
 * Core Section 5: "If `$schema` is present, it MUST equal
 * `https://json-schema.org/draft/2020-12/schema`. [...] The AS MUST
 * meta-validate each embedded stream schema before accepting the declaration.
 * Embedded `$ref` and `$dynamicRef` values MUST be local fragment references.
 * A declaration MUST NOT make consent interpretation depend on a mutable
 * remote schema."
 *
 * ── Why the remote-reference half is the one with teeth ─────────────────────
 *
 * The last sentence is the reason the whole clause exists. A `$ref` pointing
 * at a remote document is a schema the AS never fetched and never froze, so a
 * third party can change what the consent covers without the declaration
 * changing at all — and without the owner ever seeing a new document to
 * approve. Everything else in the clause is hygiene; this one moves the
 * consent boundary out from under the owner after the fact.
 *
 * The check is recursive rather than top-level. A `$ref` nested inside
 * `properties`, `items`, `$defs` or a combinator is exactly as remote as one
 * at the root, and a top-level-only check would be a formality: the suite's
 * own negative puts the reference under `properties`.
 *
 * `parseDeclaration` previously carried `schema` through verbatim with no
 * inspection at all.
 */

import { describe, expect, it } from "vitest";
import { parseDeclaration } from "./declaration.js";

const SOURCE_ID = "https://registry.pdpp.dev/connectors/conformance";
const DIALECT = "https://json-schema.org/draft/2020-12/schema";

function documentWithSchema(schema: Record<string, unknown>): string {
  return JSON.stringify({
    protocol_version: "0.1.0",
    source: { kind: "connector", id: SOURCE_ID },
    declaration_version: "2026-09-18",
    publisher: { id: "https://pdpp.dev/conformance-suite" },
    display: { name: "Conformance" },
    streams: [
      {
        name: "records",
        semantics: "mutable_state",
        schema,
        primary_key: ["id"],
        selection: { fields: true, resources: false },
      },
    ],
    extensions: {},
  });
}

const LOCAL_SCHEMA = {
  $schema: DIALECT,
  type: "object",
  properties: { id: { type: "string" } },
  additionalProperties: false,
};

describe("§5.2 embedded stream schema meta-validation", () => {
  it("accepts a purely local schema in the fixed dialect", () => {
    expect(
      parseDeclaration(documentWithSchema(LOCAL_SCHEMA), SOURCE_ID).ok,
    ).toBe(true);
  });

  it("accepts a schema that omits $schema", () => {
    // §5: "Each `streams[].schema` uses that dialect when `$schema` is
    // absent." Omission is not a violation, so it must not become a refusal.
    const { $schema: _omitted, ...withoutDialect } = LOCAL_SCHEMA;
    expect(
      parseDeclaration(documentWithSchema(withoutDialect), SOURCE_ID).ok,
    ).toBe(true);
  });

  it("accepts a local fragment $ref", () => {
    // Local fragments are expressly permitted — the clause forbids remote
    // references, not reuse.
    const parsed = parseDeclaration(
      documentWithSchema({
        $schema: DIALECT,
        type: "object",
        $defs: { idField: { type: "string" } },
        properties: { id: { $ref: "#/$defs/idField" } },
        additionalProperties: false,
      }),
      SOURCE_ID,
    );
    expect(parsed.ok).toBe(true);
  });

  it("refuses a $schema that is not the fixed dialect", () => {
    const parsed = parseDeclaration(
      documentWithSchema({
        ...LOCAL_SCHEMA,
        $schema: "http://json-schema.org/draft-07/schema#",
      }),
      SOURCE_ID,
    );

    expect(parsed.ok).toBe(false);
    if (parsed.ok) return;
    expect(parsed.failure.code).toBe("invalid_document");
    expect(parsed.failure.message).toContain("$schema");
  });

  it("refuses a $ref pointing at a remote document", () => {
    const parsed = parseDeclaration(
      documentWithSchema({
        $schema: DIALECT,
        type: "object",
        properties: {
          id: { $ref: "https://schemas.example/mutable/field.json" },
        },
        additionalProperties: false,
      }),
      SOURCE_ID,
    );

    expect(parsed.ok).toBe(false);
    if (parsed.ok) return;
    expect(parsed.failure.code).toBe("invalid_document");
    expect(parsed.failure.message).toContain("$ref");
    expect(parsed.failure.message).toContain("https://schemas.example");
  });

  it("refuses a remote $dynamicRef too", () => {
    // Named separately by the clause, and a server can miss one while
    // catching the other.
    const parsed = parseDeclaration(
      documentWithSchema({
        $schema: DIALECT,
        type: "object",
        properties: { id: { $dynamicRef: "https://schemas.example/dyn.json" } },
        additionalProperties: false,
      }),
      SOURCE_ID,
    );

    expect(parsed.ok).toBe(false);
    if (parsed.ok) return;
    expect(parsed.failure.code).toBe("invalid_document");
    expect(parsed.failure.message).toContain("$dynamicRef");
  });

  it("finds a remote reference nested below the top level", () => {
    // The whole point of recursing. A top-level-only check would pass this.
    const parsed = parseDeclaration(
      documentWithSchema({
        $schema: DIALECT,
        type: "object",
        properties: {
          id: { type: "string" },
          tags: {
            type: "array",
            items: { $ref: "https://schemas.example/tag.json" },
          },
        },
        additionalProperties: false,
      }),
      SOURCE_ID,
    );

    expect(parsed.ok).toBe(false);
    if (parsed.ok) return;
    expect(parsed.failure.message).toContain(
      "https://schemas.example/tag.json",
    );
  });

  it("refuses a schema that is not an object at all", () => {
    // The minimum meta-validation the clause implies: a `schema` member that
    // is not a schema cannot have been meta-validated against anything.
    const parsed = parseDeclaration(
      JSON.stringify({
        protocol_version: "0.1.0",
        source: { kind: "connector", id: SOURCE_ID },
        declaration_version: "2026-09-18",
        publisher: { id: "https://pdpp.dev/conformance-suite" },
        display: { name: "Conformance" },
        streams: [
          {
            name: "records",
            fields: ["id"],
            required_fields: [],
            primary_key: ["id"],
            schema: "not a schema",
          },
        ],
      }),
      SOURCE_ID,
    );

    expect(parsed.ok).toBe(false);
    if (parsed.ok) return;
    expect(parsed.failure.code).toBe("invalid_document");
  });
});
