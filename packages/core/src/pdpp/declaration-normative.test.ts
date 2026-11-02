/**
 * PS accepts the NORMATIVE §5 SourceDeclaration.
 *
 * ── The conformance gap this closes ─────────────────────────────────────────
 *
 * `parseDeclaration` historically required a PRIVATE shape — `source_id`,
 * `source_kind`, `version`, and flat `fields[]` / `required_fields[]`. That
 * shape is not the protocol. The published schema
 * (`https://pdpp.dev/schemas/source-declaration/0.1.0`, exported from
 * `@pdpp/reference-contract`) requires `protocol_version`, a nested
 * `source {kind, id}`, `declaration_version`, `publisher`, `display`, and a
 * real JSON-Schema `schema` per stream — and sets `additionalProperties:
 * false`, which makes the private shape affirmatively INVALID rather than
 * merely different.
 *
 * Before this change, PS rejected a real producer document with
 * `invalid_document: declaration is missing source_id`. Every declaration in
 * the 20-passing conformance run was a private-shape fixture, so no tested
 * requirement exercised this — which is exactly why it needed closing
 * separately rather than being assumed covered.
 *
 * ── Why these fixtures ──────────────────────────────────────────────────────
 *
 * `__fixtures__/*.source-declaration.json` are the ACTUAL documents emitted by
 * the Unity producer (PR #1098, `bccc682e`), copied byte-for-byte. Not
 * hand-written substitutes: a fixture I authored would only prove PS agrees
 * with me, whereas these prove PS agrees with the producer it must interop
 * with. Their digests are the ones the producer publishes.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { computeDeclarationDigest, parseDeclaration } from "./declaration.js";

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "__fixtures__");

const PRODUCER_DECLARATIONS = [
  {
    connector: "github",
    sourceId: "https://registry.pdpp.dev/connectors/github",
  },
  {
    connector: "instagram",
    sourceId: "https://registry.pdpp.dev/connectors/instagram",
  },
  {
    connector: "youtube",
    sourceId: "https://registry.pdpp.dev/connectors/youtube",
  },
] as const;

/** Exact bytes as the producer emits them — never re-serialized. */
function readDocument(connector: string): string {
  return readFileSync(
    join(FIXTURES, `${connector}.source-declaration.json`),
    "utf-8",
  );
}

describe("normative §5 SourceDeclaration is accepted", () => {
  for (const { connector, sourceId } of PRODUCER_DECLARATIONS) {
    it(`parses the real ${connector} producer declaration`, () => {
      const parsed = parseDeclaration(readDocument(connector), sourceId);

      expect(parsed.ok).toBe(true);
      if (!parsed.ok) return;

      // Nested `source` projected onto the internal identity.
      expect(parsed.snapshot.source_id).toBe(sourceId);
      expect(parsed.snapshot.source_kind).toBe("connector");
      // `declaration_version`, not `version`.
      expect(parsed.snapshot.version).toBeTruthy();
      expect(parsed.snapshot.streams.length).toBeGreaterThan(0);
    });

    it(`derives fields from ${connector}'s JSON Schema, not a flat list`, () => {
      const document = readDocument(connector);
      const parsed = parseDeclaration(document, sourceId);
      if (!parsed.ok) return;

      const raw = JSON.parse(document) as {
        streams: {
          name: string;
          schema: { properties: Record<string, unknown>; required?: string[] };
        }[];
      };

      for (const declared of raw.streams) {
        const projected = parsed.snapshot.streams.find(
          (s) => s.name === declared.name,
        );
        expect(projected).toBeDefined();
        // Field list is the schema's property names.
        expect(new Set(projected!.fields)).toEqual(
          new Set(Object.keys(declared.schema.properties)),
        );
        // The consent floor is the schema's `required`.
        expect(new Set(projected!.required_fields)).toEqual(
          new Set(declared.schema.required ?? []),
        );
      }
    });
  }

  it("digests the EXACT producer bytes, not a re-serialization", () => {
    // The property both sides must not compromise: the digest proves the
    // producer read the same bytes the owner consented against. Canonicalizing
    // or re-serializing would destroy exactly that proof.
    const document = readDocument("instagram");
    const parsed = parseDeclaration(
      document,
      "https://registry.pdpp.dev/connectors/instagram",
    );
    if (!parsed.ok) return;

    expect(parsed.snapshot.digest).toBe(computeDeclarationDigest(document));
    // And re-serializing the parsed snapshot does NOT reproduce it.
    expect(computeDeclarationDigest(JSON.stringify(parsed.snapshot))).not.toBe(
      parsed.snapshot.digest,
    );
  });

  it("carries normative per-stream semantics through", () => {
    const parsed = parseDeclaration(
      readDocument("instagram"),
      "https://registry.pdpp.dev/connectors/instagram",
    );
    if (!parsed.ok) return;
    // `semantics` is normative and per-stream; it is no longer hardcoded.
    expect(parsed.snapshot.streams[0].semantics).toBe("mutable_state");
  });

  it("still enforces source identity on a normative document", () => {
    // Normalization must not weaken the check that a trusted host cannot
    // serve an authority for a source it does not own.
    const parsed = parseDeclaration(
      readDocument("github"),
      "https://registry.pdpp.dev/connectors/instagram",
    );
    expect(parsed.ok).toBe(false);
    if (parsed.ok) return;
    expect(parsed.failure.code).toBe("source_id_mismatch");
  });
});

describe("the private shape still parses", () => {
  it("accepts an internal-shaped declaration unchanged", () => {
    // This is a compatibility adapter, not a replacement: existing private
    // fixtures — including every declaration in the current conformance run —
    // must keep working.
    const privateShape = JSON.stringify({
      source_id: "https://registry.pdpp.dev/connectors/spotify",
      source_kind: "connector",
      version: "2026-08-11",
      streams: [
        {
          name: "top_artists",
          fields: ["id", "name"],
          required_fields: ["id"],
          primary_key: ["id"],
        },
      ],
    });

    const parsed = parseDeclaration(
      privateShape,
      "https://registry.pdpp.dev/connectors/spotify",
    );
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.snapshot.streams[0].fields).toEqual(["id", "name"]);
  });
});
