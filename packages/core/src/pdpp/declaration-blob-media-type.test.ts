/**
 * §4.8: a declared `blob_ref` media type must be a media type.
 *
 * ── The clause ──────────────────────────────────────────────────────────────
 *
 * Core Section 4, "Binary data (blob_ref)": "`mime_type` MUST be a valid IANA
 * media type."
 *
 * `mime_type` is what every consumer uses to decide how to interpret fetched
 * bytes. Retaining one no registry defines means each client guesses
 * differently, and the guess is frozen into the document the owner's consent
 * is written against.
 *
 * ── Where a DECLARATION carries one ─────────────────────────────────────────
 *
 * Section 4 shows `mime_type` inside a RECORD's `blob_ref`. A declaration
 * describes record shape, so it can pin a media type in two places, and this
 * validates both rather than picking one:
 *
 *   - inside the stream's embedded JSON Schema, as a `const` or `enum` on a
 *     `blob_ref.mime_type` property — the spec-faithful location, since that
 *     is how a declaration constrains any record field;
 *   - in a `blob_fields` member listing the stream's blob-bearing fields with
 *     their media types.
 *
 * Neither is mandatory. A stream declaring no blob field at all is untouched,
 * which is the clause's own applicability condition ("the declaration declares
 * a `blob_ref` field").
 *
 * ── What "valid" is checked against ─────────────────────────────────────────
 *
 * The grammar, not a registry snapshot. IANA adds subtypes continuously and
 * without a spec revision, so refusing a well-formed subtype this server has
 * not heard of would reject conforming declarations and make the check a
 * freshness test rather than a validity one. The registered top-level types
 * are a closed set and are checked; the subtype is checked against RFC 6838's
 * token grammar.
 */

import { describe, expect, it } from "vitest";
import { parseDeclaration } from "./declaration.js";

const SOURCE_ID = "https://registry.pdpp.dev/connectors/conformance";
const DIALECT = "https://json-schema.org/draft/2020-12/schema";

function documentWithStream(extra: Record<string, unknown>): string {
  return JSON.stringify({
    protocol_version: "0.1.0",
    source: { kind: "connector", id: SOURCE_ID },
    declaration_version: "2026-09-18",
    publisher: { id: "https://pdpp.dev/conformance-suite" },
    display: { name: "Conformance" },
    streams: [
      {
        name: "media",
        semantics: "mutable_state",
        schema: {
          $schema: DIALECT,
          type: "object",
          properties: { id: { type: "string" } },
          additionalProperties: false,
        },
        primary_key: ["id"],
        selection: { fields: true, resources: false },
        ...extra,
      },
    ],
    extensions: {},
  });
}

describe("§4.8 declared blob_ref media types", () => {
  it("accepts a stream declaring no blob field", () => {
    // The clause applies only where a declaration declares a `blob_ref`
    // field, so the common case must stay untouched.
    expect(parseDeclaration(documentWithStream({}), SOURCE_ID).ok).toBe(true);
  });

  it("accepts a valid media type in blob_fields", () => {
    const parsed = parseDeclaration(
      documentWithStream({
        blob_fields: [{ name: "attachment", mime_type: "image/jpeg" }],
      }),
      SOURCE_ID,
    );
    expect(parsed.ok).toBe(true);
  });

  it("accepts a media type with parameters and a structured suffix", () => {
    // `application/vnd.api+json; charset=utf-8` is well-formed. Refusing it
    // would make the check stricter than the grammar.
    const parsed = parseDeclaration(
      documentWithStream({
        blob_fields: [
          { name: "doc", mime_type: "application/vnd.api+json; charset=utf-8" },
        ],
      }),
      SOURCE_ID,
    );
    expect(parsed.ok).toBe(true);
  });

  it("accepts a well-formed subtype this server has never heard of", () => {
    // The check is the grammar, not a registry snapshot. IANA adds subtypes
    // without a spec revision, so a registry-freshness check would refuse
    // conforming declarations.
    const parsed = parseDeclaration(
      documentWithStream({
        blob_fields: [
          { name: "blob", mime_type: "application/x-some-future-format" },
        ],
      }),
      SOURCE_ID,
    );
    expect(parsed.ok).toBe(true);
  });

  it("refuses a blob_fields media type that is not a media type", () => {
    const parsed = parseDeclaration(
      documentWithStream({
        blob_fields: [{ name: "attachment", mime_type: "not a media type" }],
      }),
      SOURCE_ID,
    );

    expect(parsed.ok).toBe(false);
    if (parsed.ok) return;
    expect(parsed.failure.code).toBe("invalid_document");
    expect(parsed.failure.message).toContain("attachment");
    expect(parsed.failure.message).toContain("not a media type");
  });

  it("refuses an unregistered top-level type", () => {
    // Top-level types ARE a closed set, unlike subtypes.
    const parsed = parseDeclaration(
      documentWithStream({
        blob_fields: [{ name: "attachment", mime_type: "nonsense/jpeg" }],
      }),
      SOURCE_ID,
    );

    expect(parsed.ok).toBe(false);
    if (parsed.ok) return;
    expect(parsed.failure.code).toBe("invalid_document");
  });

  it("refuses an invalid media type pinned in the embedded schema", () => {
    // The spec-faithful location: a declaration constrains a record field
    // through its schema, so a `const` on `blob_ref.mime_type` is how it pins
    // one without any non-normative member.
    const parsed = parseDeclaration(
      documentWithStream({
        schema: {
          $schema: DIALECT,
          type: "object",
          properties: {
            id: { type: "string" },
            blob_ref: {
              type: "object",
              properties: { mime_type: { const: "not a media type" } },
            },
          },
          additionalProperties: false,
        },
      }),
      SOURCE_ID,
    );

    expect(parsed.ok).toBe(false);
    if (parsed.ok) return;
    expect(parsed.failure.code).toBe("invalid_document");
    expect(parsed.failure.message).toContain("mime_type");
  });

  it("accepts a valid media type pinned in the embedded schema", () => {
    const parsed = parseDeclaration(
      documentWithStream({
        schema: {
          $schema: DIALECT,
          type: "object",
          properties: {
            id: { type: "string" },
            blob_ref: {
              type: "object",
              properties: {
                mime_type: { enum: ["image/jpeg", "image/png"] },
              },
            },
          },
          additionalProperties: false,
        },
      }),
      SOURCE_ID,
    );
    expect(parsed.ok).toBe(true);
  });
});
