import { describe, expect, it } from "vitest";
import { DataFileEnvelopeSchema } from "@opendatalabs/vana-sdk/browser";
import { redactEnvelopeForGrantee } from "./index.js";
import { redactJsonEnvelopeBytesForGrantee } from "./raw-envelope.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function expectLegacyEquivalent(value: unknown): void {
  const stored = encoder.encode(JSON.stringify(value, null, 2));
  const legacy = JSON.stringify(
    redactEnvelopeForGrantee(DataFileEnvelopeSchema.parse(value)),
  );

  expect(decoder.decode(redactJsonEnvelopeBytesForGrantee(stored))).toBe(
    legacy,
  );
}

describe("redactJsonEnvelopeBytesForGrantee", () => {
  it("matches the legacy parse, redact, and stringify output", () => {
    expectLegacyEquivalent({
      $schema: "https://schema.vana.org/data-file-envelope-v1.json",
      schemaId: "profile-v1",
      version: "1.0",
      scope: "instagram.profile",
      collectedAt: "2026-09-03T11:00:00.000Z",
      data: {
        name: "Jos\u00e9 \ud83c\udf0e",
        nested: { spaced: "kept", values: [1, true, null] },
        lineage: ["private-source"],
        $lineage: { sources: ["0x1234"], writtenAt: "2026-09-03" },
        $writtenBy: { builder: "0xabcd", signature: "secret" },
      },
    });
  });

  it("removes lineage from binary metadata while preserving other metadata", () => {
    expectLegacyEquivalent({
      version: "1.0",
      scope: "binary.file",
      collectedAt: "2026-09-03T11:00:00.000Z",
      data: {
        $binary: true,
        contentType: "application/octet-stream",
        content: "AAEC",
        metadata: { lineage: ["private-source"], caption: "kept" },
        $lineage: { sources: ["0x1234"], writtenAt: "2026-09-03" },
      },
    });
  });

  it("omits empty binary metadata like the legacy path", () => {
    expectLegacyEquivalent({
      version: "1.0",
      scope: "binary.file",
      collectedAt: "2026-09-03T11:00:00.000Z",
      data: {
        $binary: true,
        contentType: "application/octet-stream",
        content: "AAEC",
        metadata: { lineage: ["private-source"] },
        $lineage: { sources: ["0x1234"], writtenAt: "2026-09-03" },
      },
    });
  });
});
