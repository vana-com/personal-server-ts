import { DataBlockStorageError } from "./errors.js";
import { canonicalJson } from "../hierarchy/canonical-json.js";
import { canonicalDigest } from "../hierarchy/generation.js";
import type { DataBlockManifest, DataScopeBlock } from "./types.js";
import { redactBlockPayloadsForGrantee } from "./redaction.js";

export type BlockRepresentation = "stored" | "grantee";

/** Pin both ordered layout and serialization policy; ordinal ids alone are not identities. */
export function blockRepresentationId(
  manifest: DataBlockManifest,
  representation: BlockRepresentation = "stored",
  view?: string,
): string {
  return canonicalDigest({
    serialization: "utf8-json-v2",
    representation,
    view: view ?? null,
    manifest: {
      ...manifest,
      representationId: undefined,
      cursorView: undefined,
    },
  });
}

/** Identical identity and view evidence for tables of contents and payload pages. */
export function blockRepresentationMetadata(
  manifest: DataBlockManifest,
  representation: BlockRepresentation,
  cursorView?: string,
): Pick<DataBlockManifest, "representationId" | "cursorView"> & {
  representationId: string;
} {
  return {
    representationId: blockRepresentationId(
      manifest,
      representation,
      cursorView,
    ),
    ...(cursorView ? { cursorView } : {}),
  };
}

/** Called only after the full stored block has passed its digest check. */
export function representBlock(
  block: DataScopeBlock,
  manifest: DataBlockManifest,
  representation: BlockRepresentation,
): DataScopeBlock | null {
  if (representation === "stored") return block;
  const context = manifest.redaction ?? {
    dropTopLevelLineage: true,
    dropMetadataLineage: true,
  };
  const served = redactBlockPayloadsForGrantee([block], context)[0];
  if (!served) return null;
  const text =
    typeof served.value === "string"
      ? served.value
      : canonicalJson(served.value);
  return { ...served, sizeBytes: new TextEncoder().encode(text).length };
}

/** Tiny budgets still emit one complete code point (at most four bytes). */
export function pageBlock(
  block: DataScopeBlock,
  offsetBytes: number,
  maxBytes: number,
): { block: DataScopeBlock; nextOffset?: number } {
  const text =
    typeof block.value === "string" ? block.value : canonicalJson(block.value);
  const bytes = new TextEncoder().encode(text);
  if (offsetBytes <= 0 && bytes.length <= maxBytes) return { block };
  const start = Math.min(Math.max(0, offsetBytes), bytes.length);
  if (start < bytes.length && (bytes[start]! & 0xc0) === 0x80)
    throw new DataBlockStorageError(
      "cursor_invalid",
      "Cursor offset is not a UTF-8 boundary",
    );
  let end = Math.min(bytes.length, start + Math.max(1, Math.floor(maxBytes)));
  while (end < bytes.length && end > start && (bytes[end]! & 0xc0) === 0x80)
    end--;
  if (end === start) {
    end++;
    while (end < bytes.length && (bytes[end]! & 0xc0) === 0x80) end++;
  }
  return {
    block: {
      ...block,
      path: `${block.path}[bytes ${start}:${end}]`,
      mediaType: block.mediaType.startsWith("text/")
        ? block.mediaType
        : "text/plain; charset=utf-8",
      value: new TextDecoder("utf-8", { fatal: true }).decode(
        bytes.subarray(start, end),
      ),
      sizeBytes: end - start,
      truncated: end < bytes.length,
    },
    ...(end < bytes.length ? { nextOffset: end } : {}),
  };
}
