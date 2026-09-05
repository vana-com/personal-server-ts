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
    const stored = encoder.encode(JSON.stringify(value, null, 2));
    const open = async () => chunkedStream(stored, 7);
    const stream = await openRedactedEnvelopeStream(open);
    const actual = await new Response(stream).text();
    const expected = JSON.stringify(
      redactEnvelopeForGrantee(DataFileEnvelopeSchema.parse(value)),
    );

    expect(actual).toBe(expected);
  });
});

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
