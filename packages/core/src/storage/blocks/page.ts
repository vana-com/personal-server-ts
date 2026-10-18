/**
 * Serve `readScopeBlocks` from blocks already built in memory (for example
 * from an envelope that exists only as a read-time view, with no sidecar on
 * disk). Paging, cursors and block selection behave as in the stored-sidecar
 * implementations.
 */

import { encodeDataBlockCursor, validateDataBlockCursor } from "./cursor.js";
import { DataBlockStorageError } from "./errors.js";
import { selectScopeBlocksByIds } from "./select.js";
import type {
  DataBlockManifest,
  DataScopeBlock,
  ReadScopeBlocksResponse,
} from "./types.js";

const TEXT_PAGE_MEDIA_TYPE = "text/plain; charset=utf-8";
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export async function readBuiltScopeBlocks(
  built: { manifest: DataBlockManifest; blocks: DataScopeBlock[] },
  options: {
    cursor?: string;
    maxBytes: number;
    blockIds?: readonly string[];
    /** Bound into every cursor; a cursor from another view is rejected. */
    cursorView?: string;
  },
): Promise<ReadScopeBlocksResponse> {
  const { manifest, blocks: builtBlocks } = built;
  const { scope, collectedAt } = manifest;
  const head = {
    scope,
    collectedAt,
    ...(manifest.schemaId ? { schemaId: manifest.schemaId } : {}),
    contentKind: manifest.contentKind,
  };
  const byId = new Map(builtBlocks.map((block) => [block.id, block]));

  if (options.blockIds?.length) {
    const selection = await selectScopeBlocksByIds(
      manifest,
      options.blockIds,
      { maxBytes: options.maxBytes },
      async (blockId) => byId.get(blockId) ?? null,
    );
    return {
      ...head,
      blocks: selection.blocks,
      warnings: [...manifest.warnings, ...selection.warnings],
    };
  }

  const cursorResult = options.cursor
    ? validateDataBlockCursor(options.cursor, {
        scope,
        collectedAt,
        view: options.cursorView,
      })
    : { ok: true as const, cursor: null };
  if (!cursorResult.ok) {
    throw new DataBlockStorageError(
      "cursor_invalid",
      cursorResult.error.message,
    );
  }

  const maxBytes = Math.max(1, options.maxBytes);
  const startIndex = cursorResult.cursor?.blockIndex ?? 0;
  const startOffset = cursorResult.cursor?.intraBlockOffset ?? 0;
  const blocks: DataScopeBlock[] = [];
  let bytes = 0;
  let nextIndex = startIndex;
  let nextOffset: number | undefined;

  while (nextIndex < manifest.blocks.length) {
    const ref = manifest.blocks[nextIndex];
    const block = ref ? byId.get(ref.id) : undefined;
    if (!ref || !block) {
      nextIndex += 1;
      continue;
    }
    const offset = nextIndex === startIndex ? startOffset : 0;
    if (offset >= ref.sizeBytes) {
      nextIndex += 1;
      continue;
    }
    if (blocks.length > 0 && offset === 0 && bytes + ref.sizeBytes > maxBytes) {
      break;
    }
    const page = pageBlock(block, offset, maxBytes - bytes);
    blocks.push(page.block);
    bytes += page.block.sizeBytes;
    if (page.nextOffset !== undefined) {
      nextOffset = page.nextOffset;
      break;
    }
    nextIndex += 1;
  }

  return {
    ...head,
    blocks,
    ...(nextOffset !== undefined || nextIndex < manifest.blocks.length
      ? {
          nextCursor: encodeDataBlockCursor({
            scope,
            collectedAt,
            blockIndex: nextIndex,
            ...(nextOffset === undefined
              ? {}
              : { intraBlockOffset: nextOffset }),
            ...(options.cursorView ? { view: options.cursorView } : {}),
          }),
        }
      : {}),
    warnings: manifest.warnings,
  };
}

function pageBlock(
  block: DataScopeBlock,
  offsetBytes: number,
  maxBytes: number,
): { block: DataScopeBlock; nextOffset?: number } {
  const text =
    typeof block.value === "string" ? block.value : JSON.stringify(block.value);
  const bytes = textEncoder.encode(text);
  if (offsetBytes <= 0 && bytes.length <= maxBytes) {
    return { block };
  }

  const start = Math.min(Math.max(0, offsetBytes), bytes.length);
  const end = Math.min(bytes.length, start + Math.max(1, maxBytes));
  return {
    block: {
      ...block,
      path: `${block.path}[bytes ${start}:${end}]`,
      mediaType: block.mediaType.startsWith("text/")
        ? block.mediaType
        : TEXT_PAGE_MEDIA_TYPE,
      value: textDecoder.decode(bytes.slice(start, end)),
      sizeBytes: end - start,
      truncated: end < bytes.length,
    },
    ...(end < bytes.length ? { nextOffset: end } : {}),
  };
}
