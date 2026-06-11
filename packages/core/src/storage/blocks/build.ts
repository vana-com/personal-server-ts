import type {
  ContentKind,
  DataBlockManifest,
  DataBlockWarning,
  DataScopeBlock,
} from "./types.js";
import {
  base64ToBytes,
  BINARY_ENCODING,
  BINARY_MARKER,
  type BinaryEnvelopeData,
} from "../../contracts/binary.js";

export type {
  ContentKind,
  DataBlockManifest,
  DataBlockRef,
  DataBlockWarning,
} from "./types.js";

export type DataBlockPayload = DataScopeBlock;

export interface BuildDataBlocksInput {
  scope: string;
  collectedAt: string;
  schemaId?: string;
  content: unknown;
  mediaType?: string;
  blockTargetBytes?: number;
  maxBlockBytes?: number;
}

export interface BuildDataBlocksResult {
  manifest: DataBlockManifest;
  blocks: DataBlockPayload[];
}

interface BuildOptions {
  targetBytes: number;
  maxBytes: number;
}

const DEFAULT_BLOCK_TARGET_BYTES = 48 * 1024;
const DEFAULT_MAX_BLOCK_BYTES = 256 * 1024;
const JSON_MEDIA_TYPE = "application/json";
const TEXT_MEDIA_TYPE = "text/plain; charset=utf-8";

const textEncoder = new TextEncoder();

export function buildDataBlocks(
  input: BuildDataBlocksInput,
): BuildDataBlocksResult {
  return buildDataBlocksInternal(input);
}

export async function buildDataBlocksAsync(
  input: BuildDataBlocksInput,
): Promise<BuildDataBlocksResult> {
  return buildDataBlocksInternal(input, await extractBinaryEnvelopeText(input));
}

function buildDataBlocksInternal(
  input: BuildDataBlocksInput,
  extractedBinaryText?: ExtractedBinaryText,
): BuildDataBlocksResult {
  const maxBytes = Math.max(1, input.maxBlockBytes ?? DEFAULT_MAX_BLOCK_BYTES);
  const options = {
    targetBytes: Math.min(
      Math.max(1, input.blockTargetBytes ?? DEFAULT_BLOCK_TARGET_BYTES),
      maxBytes,
    ),
    maxBytes,
  };
  const warnings: DataBlockWarning[] = [];
  const rawSizeBytes = estimateRawSize(input.content);
  const classified = classifyContent(input.content, input.mediaType);
  const blocks: DataBlockPayload[] = [];
  let contentKind: ContentKind = classified.kind;

  if (classified.kind === "json" || classified.kind === "vana-envelope") {
    const json = classified.value;
    if (classified.kind === "vana-envelope" && isPlainObject(json)) {
      const metadata = envelopeMetadata(json);
      if (Object.keys(metadata).length > 0) {
        addJsonBlocks(blocks, "$.__envelope", metadata, options);
      }
      const binaryData = parseBinaryEnvelopeData(json["data"]);
      if (binaryData) {
        contentKind = contentKindForBinaryEnvelope(binaryData);
        const extractedText = extractedBinaryText?.text?.trim();
        addBinaryEnvelopeBlock(blocks, "$.data", binaryData, {
          extractedTextAvailable: Boolean(extractedText),
        });
        if (extractedText) {
          addTextBlocks(blocks, "$.data.text", extractedText, options);
        } else {
          warnings.push({
            code: `${contentKind}_metadata_only`,
            message: `${contentKind} content is represented as metadata only`,
            path: "$.data",
          });
        }
        warnings.push(...(extractedBinaryText?.warnings ?? []));
      } else {
        addJsonBlocks(blocks, "$.data", json["data"], options);
      }
    } else {
      addJsonBlocks(blocks, "$", json, options);
    }
  } else if (classified.kind === "text") {
    addTextBlocks(blocks, "$", classified.value, options);
  } else {
    blocks.push(
      createPayload("$", "application/octet-stream", {
        contentKind: classified.kind,
        sizeBytes: rawSizeBytes,
        supported: false,
      }),
    );
    warnings.push({
      code: `${classified.kind}_metadata_only`,
      message: `${classified.kind} content is represented as metadata only`,
      path: "$",
    });
  }

  const blocksWithIds = assignBlockIds(blocks);
  const manifest = {
    version: 1 as const,
    scope: input.scope,
    collectedAt: input.collectedAt,
    ...(input.schemaId ? { schemaId: input.schemaId } : {}),
    contentKind,
    rawSizeBytes,
    blocks: blocksWithIds.map(({ id, path, mediaType, sizeBytes }) => ({
      id,
      path,
      mediaType,
      sizeBytes,
      ...itemCountForPath(path),
    })),
    warnings,
  };

  return { manifest, blocks: blocksWithIds };
}

interface ExtractedBinaryText {
  text?: string;
  warnings: DataBlockWarning[];
}

async function extractBinaryEnvelopeText(
  input: BuildDataBlocksInput,
): Promise<ExtractedBinaryText | undefined> {
  const classified = classifyContent(input.content, input.mediaType);
  if (classified.kind !== "vana-envelope" || !isPlainObject(classified.value)) {
    return undefined;
  }

  const binaryData = parseBinaryEnvelopeData(classified.value["data"]);
  if (!binaryData || !isPdfBinaryEnvelope(binaryData)) return undefined;

  try {
    const { extractText } = await import("unpdf");
    const extracted = await extractText(base64ToBytes(binaryData.content), {
      mergePages: true,
    });
    const text = normalizeExtractedText(extracted.text);
    if (text === "") {
      return {
        warnings: [
          {
            code: "pdf_text_empty",
            message: "PDF text extraction found no readable text",
            path: "$.data",
          },
        ],
      };
    }
    return { text, warnings: [] };
  } catch (error) {
    return {
      warnings: [
        {
          code: "pdf_text_extraction_failed",
          message: `PDF text extraction failed: ${errorMessage(error)}`,
          path: "$.data",
        },
      ],
    };
  }
}

function parseBinaryEnvelopeData(value: unknown): BinaryEnvelopeData | null {
  if (!isPlainObject(value) || value[BINARY_MARKER] !== true) return null;
  if (value.encoding !== BINARY_ENCODING) return null;
  if (typeof value.content !== "string") return null;
  if (typeof value.mimeType !== "string") return null;
  if (typeof value.sizeBytes !== "number") return null;
  if (typeof value.contentHash !== "string") return null;
  return value as unknown as BinaryEnvelopeData;
}

function contentKindForBinaryEnvelope(data: BinaryEnvelopeData): ContentKind {
  const mimeType = data.mimeType.toLowerCase();
  const filename = data.filename?.toLowerCase() ?? "";
  return mimeType.includes("zip") || filename.endsWith(".zip")
    ? "zip"
    : "binary";
}

function isPdfBinaryEnvelope(data: BinaryEnvelopeData): boolean {
  const mimeType = data.mimeType.toLowerCase();
  const filename = data.filename?.toLowerCase() ?? "";
  return mimeType.includes("pdf") || filename.endsWith(".pdf");
}

function addBinaryEnvelopeBlock(
  blocks: DataBlockPayload[],
  path: string,
  data: BinaryEnvelopeData,
  options: { extractedTextAvailable?: boolean } = {},
): void {
  blocks.push(
    createPayload(path, JSON_MEDIA_TYPE, {
      contentKind: contentKindForBinaryEnvelope(data),
      mimeType: data.mimeType,
      ...(data.filename ? { filename: data.filename } : {}),
      sizeBytes: data.sizeBytes,
      contentHash: data.contentHash,
      ...(data.metadata !== undefined ? { metadata: data.metadata } : {}),
      searchable: options.extractedTextAvailable === true,
      extractedTextAvailable: options.extractedTextAvailable === true,
      rawContentAvailable: true,
    }),
  );
}

function normalizeExtractedText(value: string): string {
  return value
    .replace(/\r\n?/g, "\n")
    .replace(/[ \t]+\n/g, "\n")
    .trim();
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function classifyContent(
  content: unknown,
  mediaType?: string,
):
  | { kind: "vana-envelope" | "json"; value: unknown }
  | { kind: "text"; value: string }
  | { kind: "zip" | "binary" | "unsupported" } {
  if (content instanceof Uint8Array) {
    return looksLikeZip(content) ? { kind: "zip" } : { kind: "binary" };
  }

  if (typeof content === "string") {
    const trimmed = content.trimStart();
    if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
      try {
        const parsed: unknown = JSON.parse(content);
        return {
          kind: isVanaEnvelope(parsed) ? "vana-envelope" : "json",
          value: parsed,
        };
      } catch {
        return { kind: "text", value: content };
      }
    }
    return mediaType?.includes("zip")
      ? { kind: "zip" }
      : { kind: "text", value: content };
  }

  if (
    content === null ||
    typeof content === "number" ||
    typeof content === "boolean" ||
    Array.isArray(content) ||
    isPlainObject(content)
  ) {
    return {
      kind: isVanaEnvelope(content) ? "vana-envelope" : "json",
      value: content,
    };
  }

  return { kind: "unsupported" };
}

function addJsonBlocks(
  blocks: DataBlockPayload[],
  path: string,
  value: unknown,
  options: BuildOptions,
): void {
  if (jsonSize(value) <= options.targetBytes) {
    blocks.push(createPayload(path, JSON_MEDIA_TYPE, value));
    return;
  }

  if (typeof value === "string") {
    addStringBlocks(blocks, path, value, options);
    return;
  }

  if (Array.isArray(value)) {
    addArrayBlocks(blocks, path, value, options);
    return;
  }

  if (isPlainObject(value)) {
    addObjectBlocks(blocks, path, value, options);
    return;
  }

  blocks.push(createPayload(path, JSON_MEDIA_TYPE, value));
}

function addArrayBlocks(
  blocks: DataBlockPayload[],
  path: string,
  value: unknown[],
  options: BuildOptions,
): void {
  let start = 0;
  while (start < value.length) {
    let end = start;
    const chunk: unknown[] = [];
    while (end < value.length) {
      const next = [...chunk, value[end]];
      if (chunk.length > 0 && jsonSize(next) > options.targetBytes) break;
      chunk.push(value[end]);
      end += 1;
    }

    if (chunk.length === 1 && jsonSize(chunk) > options.targetBytes) {
      addJsonBlocks(blocks, `${path}[${start}]`, chunk[0], options);
      start += 1;
      continue;
    }

    blocks.push(
      createPayload(`${path}[${start}:${end}]`, JSON_MEDIA_TYPE, chunk),
    );
    start = end;
  }
}

function addObjectBlocks(
  blocks: DataBlockPayload[],
  path: string,
  value: Record<string, unknown>,
  options: BuildOptions,
): void {
  const keys = Object.keys(value).sort();
  let index = 0;
  while (index < keys.length) {
    const group: Record<string, unknown> = {};
    const firstKey = keys[index]!;
    let lastKey = firstKey;
    while (index < keys.length) {
      const key = keys[index]!;
      const candidate = { ...group, [key]: value[key] };
      if (
        Object.keys(group).length > 0 &&
        jsonSize(candidate) > options.targetBytes
      ) {
        break;
      }
      group[key] = value[key];
      lastKey = key;
      index += 1;
    }

    const groupKeys = Object.keys(group);
    if (groupKeys.length === 1 && jsonSize(group) > options.targetBytes) {
      const key = groupKeys[0]!;
      addJsonBlocks(
        blocks,
        `${path}.${escapePathKey(key)}`,
        group[key],
        options,
      );
      continue;
    }

    blocks.push(
      createPayload(
        `${path}.{${escapePathKey(firstKey)}:${escapePathKey(lastKey)}}`,
        JSON_MEDIA_TYPE,
        group,
      ),
    );
  }
}

function addStringBlocks(
  blocks: DataBlockPayload[],
  path: string,
  value: string,
  options: BuildOptions,
): void {
  let start = 0;
  while (start < value.length) {
    const end = findBoundedStringEnd(value, start, options, jsonSize);
    blocks.push(
      createPayload(
        `${path}[chars ${start}:${end}]`,
        JSON_MEDIA_TYPE,
        value.slice(start, end),
      ),
    );
    start = end;
  }
}

function addTextBlocks(
  blocks: DataBlockPayload[],
  path: string,
  value: string,
  options: BuildOptions,
): void {
  let start = 0;
  while (start < value.length) {
    let end = findBoundedStringEnd(value, start, options, byteSize);
    const newline = value.lastIndexOf("\n", end);
    if (newline > start) end = newline + 1;
    blocks.push(
      createPayload(
        `${path}[chars ${start}:${end}]`,
        TEXT_MEDIA_TYPE,
        value.slice(start, end),
      ),
    );
    start = end;
  }
}

function findBoundedStringEnd(
  value: string,
  start: number,
  options: BuildOptions,
  sizeOf: (chunk: string) => number,
): number {
  let end = Math.min(value.length, start + options.targetBytes);
  while (
    end > start + 1 &&
    sizeOf(value.slice(start, end)) > options.maxBytes
  ) {
    end = start + Math.floor((end - start) / 2);
  }
  return end > start ? end : Math.min(value.length, start + 1);
}

function createPayload(
  path: string,
  mediaType: string,
  value: unknown,
): DataBlockPayload {
  return {
    id: "",
    path,
    mediaType,
    value,
    sizeBytes: mediaType.startsWith("application/json")
      ? jsonSize(value)
      : byteSize(String(value)),
  };
}

function itemCountForPath(path: string): { itemCount?: number } {
  const match = path.match(/\[(\d+):(\d+)\]$/);
  if (!match) return {};
  return { itemCount: Number(match[2]) - Number(match[1]) };
}

function envelopeMetadata(
  envelope: Record<string, unknown>,
): Record<string, unknown> {
  const metadata: Record<string, unknown> = {};
  for (const key of Object.keys(envelope).sort()) {
    if (key !== "data") metadata[key] = envelope[key];
  }
  return metadata;
}

function isVanaEnvelope(value: unknown): boolean {
  if (!isPlainObject(value)) return false;
  return (
    "data" in value &&
    (typeof value["scope"] === "string" ||
      typeof value["collectedAt"] === "string" ||
      typeof value["schemaId"] === "string" ||
      typeof value["schemaUrl"] === "string")
  );
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function looksLikeZip(value: Uint8Array): boolean {
  return value.length >= 4 && value[0] === 0x50 && value[1] === 0x4b;
}

function escapePathKey(key: string): string {
  return /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(key) ? key : JSON.stringify(key);
}

function estimateRawSize(value: unknown): number | undefined {
  if (value instanceof Uint8Array) return value.byteLength;
  if (typeof value === "string") return byteSize(value);
  try {
    return jsonSize(value);
  } catch {
    return undefined;
  }
}

function jsonSize(value: unknown): number {
  return byteSize(JSON.stringify(value));
}

function byteSize(value: string): number {
  return textEncoder.encode(value).byteLength;
}

export function assignBlockIds(blocks: DataBlockPayload[]): DataBlockPayload[] {
  return blocks.map((block, index) => ({
    ...block,
    id: `block-${String(index + 1).padStart(6, "0")}`,
  }));
}
