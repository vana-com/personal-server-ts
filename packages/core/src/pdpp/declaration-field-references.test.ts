/**
 * §5.2: a stream's key and cursor references must name fields the stream
 * actually declares.
 *
 * ── The conformance gap this closes ─────────────────────────────────────────
 *
 * Core Section 5, `streams[].schema`: "`primary_key` and `cursor_field` MUST
 * reference fields declared here." `parseDeclaration` checked
 * `required_fields ⊆ fields` and that `primary_key` was a non-empty array, but
 * never checked that either `primary_key`'s entries or `cursor_field` named a
 * field the stream declares. A declaration promising record ordering over a
 * field that does not exist was retained, and the contradiction surfaced at
 * read time — after the owner had consented to the document.
 *
 * The check is written against the projected `fields` list rather than against
 * `schema.properties` directly, because that list IS the projection of
 * `schema.properties` for a normative document (see `normalizeNormativeDeclaration`)
 * and is the field list the internal flat shape carries. One check therefore
 * covers both shapes, and a private-shape fixture cannot slip past it.
 */

import { describe, expect, it } from "vitest";
import { parseDeclaration } from "./declaration.js";

const SOURCE_ID = "https://registry.pdpp.dev/connectors/conformance";

/** A normative §5 document over `properties`, with the references overridable. */
function normativeDocument(overrides: {
  properties: readonly string[];
  primaryKey?: readonly string[];
  cursorField?: string;
}): string {
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
        schema: {
          $schema: "https://json-schema.org/draft/2020-12/schema",
          type: "object",
          properties: Object.fromEntries(
            overrides.properties.map((p) => [p, { type: "string" }]),
          ),
          additionalProperties: false,
        },
        primary_key: overrides.primaryKey ?? ["id"],
        ...(overrides.cursorField === undefined
          ? {}
          : { cursor_field: overrides.cursorField }),
        selection: { fields: true, resources: false },
      },
    ],
    extensions: {},
  });
}

describe("§5.2 key and cursor references", () => {
  it("accepts a stream whose primary_key and cursor_field are declared", () => {
    // The positive control. Without it, a parser that refused every document
    // would satisfy the negatives below while onboarding nothing.
    const parsed = parseDeclaration(
      normativeDocument({
        properties: ["id", "updated_at"],
        primaryKey: ["id"],
        cursorField: "updated_at",
      }),
      SOURCE_ID,
    );
    expect(parsed.ok).toBe(true);
  });

  it("refuses a cursor_field the stream's schema does not declare", () => {
    const parsed = parseDeclaration(
      normativeDocument({
        properties: ["id", "updated_at"],
        cursorField: "field_the_schema_does_not_declare",
      }),
      SOURCE_ID,
    );

    expect(parsed.ok).toBe(false);
    if (parsed.ok) return;
    expect(parsed.failure.code).toBe("invalid_document");
    expect(parsed.failure.message).toContain("cursor_field");
    expect(parsed.failure.message).toContain(
      "field_the_schema_does_not_declare",
    );
  });

  it("refuses a primary_key naming a field the stream does not declare", () => {
    // The same clause sentence covers `primary_key`, and a server can get one
    // right while leaving the other unchecked — so it is asserted separately.
    const parsed = parseDeclaration(
      normativeDocument({
        properties: ["id", "updated_at"],
        primaryKey: ["id", "key_the_schema_does_not_declare"],
      }),
      SOURCE_ID,
    );

    expect(parsed.ok).toBe(false);
    if (parsed.ok) return;
    expect(parsed.failure.code).toBe("invalid_document");
    expect(parsed.failure.message).toContain("primary_key");
    expect(parsed.failure.message).toContain("key_the_schema_does_not_declare");
  });

  it("applies the same check to the internal flat shape", () => {
    // The flat shape carries `fields` with no `schema`. It is the shape every
    // existing private fixture uses, so a check that only looked at
    // `schema.properties` would leave that whole path unvalidated.
    const flat = JSON.stringify({
      source_id: SOURCE_ID,
      source_kind: "connector",
      version: "2026-09-18",
      streams: [
        {
          name: "records",
          fields: ["id"],
          required_fields: ["id"],
          primary_key: ["id"],
          cursor_field: "not_a_declared_field",
        },
      ],
    });

    const parsed = parseDeclaration(flat, SOURCE_ID);
    expect(parsed.ok).toBe(false);
    if (parsed.ok) return;
    expect(parsed.failure.code).toBe("invalid_document");
  });
});
