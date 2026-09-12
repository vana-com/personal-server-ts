import { describe, expect, it } from "vitest";
import { DataFileEnvelopeSchema } from "@opendatalabs/vana-sdk/browser";
import { redactEnvelopeForGrantee } from "@opendatalabs/personal-server-ts-core/api";
import { openRedactedEnvelopeStream } from "./raw-envelope-stream.js";

const encoder = new TextEncoder();

describe("openRedactedEnvelopeStream", () => {
  it.each([
    {
      $schema: "https://schema.vana.org/data-file-envelope-v1.json",
      schemaId: "profile-v1",
      version: "1.0",
      scope: "profile.test",
      collectedAt: "2026-09-03T11:00:00.000Z",
      data: {
        name: "José 🌎",
        nested: { values: [1, true, null] },
        lineage: ["private-source"],
        $lineage: { sources: ["0x1234"] },
        $writtenBy: { signature: "secret" },
      },
    },
    {
      version: "1.0",
      scope: "binary.test",
      collectedAt: "2026-09-03T11:00:00.000Z",
      data: {
        $binary: true,
        contentType: "application/octet-stream",
        content: "AAEC",
        metadata: { lineage: ["private-source"], caption: "kept" },
        $lineage: { sources: ["0x1234"] },
      },
    },
    {
      version: "1.0",
      scope: "binary.test",
      collectedAt: "2026-09-03T11:00:00.000Z",
      data: {
        $binary: true,
        contentType: "application/octet-stream",
        content: "AAEC",
        metadata: { lineage: ["private-source"] },
        $lineage: { sources: ["0x1234"] },
      },
    },
  ])("matches the buffered grantee representation", async (value) => {
    await expectStreamingParity(value);
  });

  it("matches the buffered redactor across metadata and lineage shapes", async () => {
    const metadataShapes: Array<[string, unknown, boolean]> = [
      ["object-only-lineage", { lineage: ["metadata-source"] }, true],
      ["object-lineage-extra", { lineage: -2.5, caption: "visible" }, true],
      ["object-without-lineage", { caption: "visible" }, true],
      ["string", "just a note", true],
      ["array", ["a"], true],
      ["number", 42, true],
      ["missing", undefined, false],
    ];
    const lineageShapes: Array<[string, unknown, boolean]> = [
      ["array", ["caller-source"], true],
      ["number", -2.5, true],
      ["absent", undefined, false],
    ];
    const payloads = [null, true, -7, "text", [1, 2], { nested: "value" }];
    let cases = 0;

    for (const binary of [false, true]) {
      for (const storedLineage of [false, true]) {
        for (const [metadataName, metadata, hasMetadata] of metadataShapes) {
          for (const [lineageName, lineage, hasLineage] of lineageShapes) {
            for (const [index, marker] of payloads.entries()) {
              const data: Record<string, unknown> = {
                marker,
                ...(binary
                  ? {
                      $binary: true,
                      contentType: "application/octet-stream",
                      content: "AAEC",
                    }
                  : {}),
                ...(hasMetadata ? { metadata } : {}),
                ...(hasLineage ? { lineage } : {}),
                ...(storedLineage
                  ? { $lineage: { sources: [`source-${index}`] } }
                  : {}),
              };
              await expectStreamingParity({
                version: "1.0",
                scope: `parity.${metadataName}.${lineageName}`,
                collectedAt: "2026-09-03T11:00:00.000Z",
                data,
              });
              cases += 1;
            }
          }
        }
      }
    }

    expect(cases).toBe(504);
  });
});

async function expectStreamingParity(value: unknown): Promise<void> {
  const stored = encoder.encode(JSON.stringify(value, null, 2));
  const open = async () => chunkedStream(stored, 7);
  const stream = await openRedactedEnvelopeStream(open);
  const actual = await new Response(stream).text();
  const expected = JSON.stringify(
    redactEnvelopeForGrantee(DataFileEnvelopeSchema.parse(value)),
  );

  expect(actual).toBe(expected);
}

function chunkedStream(
  bytes: Uint8Array,
  chunkBytes: number,
): ReadableStream<Uint8Array> {
  let offset = 0;
  return new ReadableStream({
    pull(controller) {
      if (offset === bytes.length) {
        controller.close();
        return;
      }
      const end = Math.min(bytes.length, offset + chunkBytes);
      controller.enqueue(bytes.subarray(offset, end));
      offset = end;
    },
  });
}
