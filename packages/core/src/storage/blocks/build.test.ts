import { describe, expect, it } from "vitest";
import { buildBinaryEnvelopeData } from "../../contracts/binary.js";
import { buildDataBlocks, type DataBlockPayload } from "./build.js";

describe("buildDataBlocks", () => {
  it("classifies Vana envelopes and emits metadata plus complete data blocks", () => {
    const envelope = {
      scope: "test.scope",
      collectedAt: "2026-06-05T00:00:00.000Z",
      schemaId: "schema-1",
      data: {
        items: Array.from({ length: 120 }, (_, index) => ({
          id: index,
          value: `item-${index}`,
        })),
      },
    };

    const result = buildDataBlocks({
      scope: envelope.scope,
      collectedAt: envelope.collectedAt,
      content: envelope,
      blockTargetBytes: 450,
      maxBlockBytes: 900,
    });

    expect(result.manifest.contentKind).toBe("vana-envelope");
    expect(result.blocks[0]?.path).toBe("$.__envelope");
    expect(result.blocks.every((block) => block.sizeBytes <= 900)).toBe(true);
    expect(result.manifest.blocks.map((block) => block.id)).toEqual(
      result.blocks.map((block) => block.id),
    );

    const dataBlocks = result.blocks.filter((block) =>
      block.path.startsWith("$.data.items["),
    );
    expect(rebuildArray(dataBlocks, "$.data.items")).toEqual(
      envelope.data.items,
    );
  });

  it("chunks large unknown JSON arrays by deterministic item ranges", () => {
    const value = Array.from({ length: 200 }, (_, index) => ({
      index,
      label: "x".repeat(20),
    }));

    const result = buildDataBlocks({
      scope: "json.array",
      collectedAt: "2026-06-05T00:00:00.000Z",
      content: value,
      blockTargetBytes: 700,
      maxBlockBytes: 1_200,
    });

    expect(result.manifest.contentKind).toBe("json");
    expect(result.blocks.length).toBeGreaterThan(1);
    expect(result.blocks.every((block) => block.sizeBytes <= 1_200)).toBe(true);
    expect(rebuildArray(result.blocks, "$")).toEqual(value);
  });

  it("chunks large unknown JSON objects by sorted top-level key groups", () => {
    const value = Object.fromEntries(
      Array.from({ length: 80 }, (_, index) => [
        `key_${String(index).padStart(3, "0")}`,
        { index, text: "value".repeat(12) },
      ]),
    );

    const result = buildDataBlocks({
      scope: "json.object",
      collectedAt: "2026-06-05T00:00:00.000Z",
      content: value,
      blockTargetBytes: 750,
      maxBlockBytes: 1_100,
    });

    expect(result.blocks.length).toBeGreaterThan(1);
    expect(result.blocks.every((block) => block.sizeBytes <= 1_100)).toBe(true);
    expect(
      Object.assign({}, ...result.blocks.map((block) => block.value)),
    ).toEqual(value);
    expect(result.blocks.map((block) => block.path)).toEqual(
      [...result.blocks.map((block) => block.path)].sort(),
    );
  });

  it("recursively chunks a single large object property by the target byte limit", () => {
    const value = {
      profile: Object.fromEntries(
        Array.from({ length: 60 }, (_, index) => [
          `field_${String(index).padStart(3, "0")}`,
          { index, text: "value".repeat(12) },
        ]),
      ),
    };

    const result = buildDataBlocks({
      scope: "json.object.single-property",
      collectedAt: "2026-06-05T00:00:00.000Z",
      content: value,
      blockTargetBytes: 750,
      maxBlockBytes: 10_000,
    });

    expect(result.blocks.length).toBeGreaterThan(1);
    expect(result.blocks.every((block) => block.sizeBytes <= 750)).toBe(true);
    expect(
      result.blocks.every((block) => block.path.startsWith("$.profile.")),
    ).toBe(true);
    expect(
      Object.assign({}, ...result.blocks.map((block) => block.value)),
    ).toEqual(value.profile);
  });

  it("chunks huge JSON strings by complete character ranges", () => {
    const value = "abc123".repeat(10_000);

    const result = buildDataBlocks({
      scope: "json.string",
      collectedAt: "2026-06-05T00:00:00.000Z",
      content: value,
      blockTargetBytes: 1_024,
      maxBlockBytes: 2_048,
    });

    expect(result.blocks.length).toBeGreaterThan(1);
    expect(result.blocks.every((block) => block.sizeBytes <= 2_048)).toBe(true);
    expect(rebuildString(result.blocks, "$")).toBe(value);
  });

  it("chunks plain text by character ranges", () => {
    const value = Array.from(
      { length: 500 },
      (_, index) => `line ${index}`,
    ).join("\n");

    const result = buildDataBlocks({
      scope: "text",
      collectedAt: "2026-06-05T00:00:00.000Z",
      content: value,
      mediaType: "text/markdown",
      blockTargetBytes: 300,
      maxBlockBytes: 500,
    });

    expect(result.manifest.contentKind).toBe("text");
    expect(result.blocks.length).toBeGreaterThan(1);
    expect(result.blocks.every((block) => block.sizeBytes <= 500)).toBe(true);
    expect(rebuildString(result.blocks, "$")).toBe(value);
  });

  it("makes progress when a tiny max byte limit cannot fit one encoded character", () => {
    const result = buildDataBlocks({
      scope: "json.string",
      collectedAt: "2026-06-05T00:00:00.000Z",
      content: "🙂🙂🙂",
      blockTargetBytes: 1,
      maxBlockBytes: 1,
    });

    expect(result.blocks.length).toBeGreaterThan(0);
    expect(rebuildString(result.blocks, "$")).toBe("🙂🙂🙂");
  });

  it("represents binary and zip content as metadata-only unsupported payloads", () => {
    const binary = buildDataBlocks({
      scope: "binary",
      collectedAt: "2026-06-05T00:00:00.000Z",
      content: new Uint8Array([1, 2, 3]),
    });
    const zip = buildDataBlocks({
      scope: "zip",
      collectedAt: "2026-06-05T00:00:00.000Z",
      content: new Uint8Array([0x50, 0x4b, 3, 4]),
    });

    expect(binary.manifest.contentKind).toBe("binary");
    expect(binary.manifest.warnings[0]?.code).toBe("binary_metadata_only");
    expect(zip.manifest.contentKind).toBe("zip");
    expect(zip.manifest.warnings[0]?.code).toBe("zip_metadata_only");
  });

  it("represents binary Vana envelopes as metadata without indexing base64 content", () => {
    const binaryData = buildBinaryEnvelopeData({
      bytes: new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x2d, 0x31]),
      mimeType: "application/pdf",
      filename: "roof-report.pdf",
      contentHash: `0x${"a".repeat(64)}`,
      metadata: { title: "Roof report" },
    });
    const result = buildDataBlocks({
      scope: "manual.document",
      collectedAt: "2026-06-09T16:28:09Z",
      content: {
        scope: "manual.document",
        collectedAt: "2026-06-09T16:28:09Z",
        schemaId: "schema-1",
        data: binaryData,
      },
    });

    expect(result.manifest.contentKind).toBe("binary");
    expect(result.manifest.warnings[0]?.code).toBe("binary_metadata_only");
    expect(result.blocks).toHaveLength(2);
    expect(result.blocks[0]?.path).toBe("$.__envelope");
    expect(result.blocks[1]).toMatchObject({
      path: "$.data",
      mediaType: "application/json",
      value: {
        contentKind: "binary",
        mimeType: "application/pdf",
        filename: "roof-report.pdf",
        sizeBytes: 6,
        contentHash: `0x${"a".repeat(64)}`,
        metadata: { title: "Roof report" },
        searchable: false,
        rawContentAvailable: true,
      },
    });
    expect(JSON.stringify(result.blocks)).not.toContain(binaryData.content);
  });
});

function rebuildArray(blocks: DataBlockPayload[], path: string): unknown[] {
  const rebuilt: unknown[] = [];
  for (const block of blocks) {
    const match = block.path.match(
      new RegExp(`^${escapeRegExp(path)}\\[(\\d+):(\\d+)\\]$`),
    );
    expect(match, block.path).not.toBeNull();
    const start = Number(match![1]);
    const end = Number(match![2]);
    expect(end - start).toBe((block.value as unknown[]).length);
    rebuilt.splice(start, end - start, ...(block.value as unknown[]));
  }
  return rebuilt;
}

function rebuildString(blocks: DataBlockPayload[], path: string): string {
  let rebuilt = "";
  let expectedStart = 0;
  for (const block of blocks) {
    const match = block.path.match(
      new RegExp(`^${escapeRegExp(path)}\\[chars (\\d+):(\\d+)\\]$`),
    );
    expect(match, block.path).not.toBeNull();
    const start = Number(match![1]);
    const end = Number(match![2]);
    expect(start).toBe(expectedStart);
    expect(end - start).toBe((block.value as string).length);
    rebuilt += block.value as string;
    expectedStart = end;
  }
  return rebuilt;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
