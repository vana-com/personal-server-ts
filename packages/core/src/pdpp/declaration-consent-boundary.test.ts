/**
 * §5.2: a stream's consent boundary must name a field the stream declares.
 *
 * ── The conformance gap this closes ─────────────────────────────────────────
 *
 * Core Section 5, `streams[].consent_time_field`: "The temporal consent
 * boundary: the field against which `time_range` is evaluated. [...] MUST
 * reference a field declared in the schema."
 *
 * ── Why this is its own commit and not folded into the key/cursor check ─────
 *
 * The two clauses are separate sentences about separate fields, and a server
 * can validate the sync-mechanics references while leaving the consent
 * boundary unchecked. That is the more dangerous of the two. `cursor_field`
 * governs read ordering; `consent_time_field` is the field a `time_range`
 * grant is evaluated against, and §6 makes its PRESENCE the authoritative
 * signal that a stream is time-range-capable.
 *
 * So an undeclared `consent_time_field` does not merely break ordering — it
 * makes the stream advertise time-range capability whose filter has no column
 * behind it. An owner who consents to "the last six months" gets their
 * boundary applied to nothing: either every record passes or none does, and
 * which one is an implementation accident of the resource server.
 */

import { describe, expect, it } from "vitest";
import { parseDeclaration } from "./declaration.js";

const SOURCE_ID = "https://registry.pdpp.dev/connectors/conformance";

function normativeDocument(consentTimeField?: string): string {
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
          properties: {
            id: { type: "string" },
            created_at: { type: "string" },
          },
          additionalProperties: false,
        },
        primary_key: ["id"],
        cursor_field: "created_at",
        ...(consentTimeField === undefined
          ? {}
          : { consent_time_field: consentTimeField }),
        selection: { fields: true, resources: false },
      },
    ],
    extensions: {},
  });
}

describe("§5.2 consent_time_field references", () => {
  it("accepts a consent_time_field the schema declares", () => {
    const parsed = parseDeclaration(normativeDocument("created_at"), SOURCE_ID);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.snapshot.streams[0].consent_time_field).toBe("created_at");
  });

  it("accepts a stream that declares no consent_time_field at all", () => {
    // Absence is normative — §5 "Streams that cannot define a stable
    // `consent_time_field` simply omit it" — so the new check must not turn
    // an omission into a refusal.
    const parsed = parseDeclaration(normativeDocument(), SOURCE_ID);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.snapshot.streams[0].consent_time_field).toBeUndefined();
  });

  it("refuses a consent_time_field the schema does not declare", () => {
    const parsed = parseDeclaration(
      normativeDocument("consent_field_the_schema_does_not_declare"),
      SOURCE_ID,
    );

    expect(parsed.ok).toBe(false);
    if (parsed.ok) return;
    expect(parsed.failure.code).toBe("invalid_document");
    expect(parsed.failure.message).toContain("consent_time_field");
    expect(parsed.failure.message).toContain(
      "consent_field_the_schema_does_not_declare",
    );
  });

  it("applies the same check to the internal flat shape", () => {
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
          consent_time_field: "not_a_declared_field",
        },
      ],
    });

    const parsed = parseDeclaration(flat, SOURCE_ID);
    expect(parsed.ok).toBe(false);
    if (parsed.ok) return;
    expect(parsed.failure.code).toBe("invalid_document");
  });
});
