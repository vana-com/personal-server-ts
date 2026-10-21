/** One verified, immutable representation, then selection and UTF-8 paging. */
import { encodeDataBlockCursor, validateDataBlockCursor } from "./cursor.js";
import { DataBlockStorageError } from "./errors.js";
import { selectScopeBlocksByIds } from "./select.js";
import { manifestBinding, verifyStoredBlock } from "./digest.js";
import {
  blockRepresentationId,
  representBlock,
  pageBlock,
  type BlockRepresentation,
} from "./representation.js";
import type {
  DataBlockManifest,
  DataScopeBlock,
  ReadScopeBlocksResponse,
} from "./types.js";

export interface BlockPageOptions {
  cursor?: string;
  maxBytes: number;
  blockIds?: readonly string[];
  cursorView?: string;
  representation?: BlockRepresentation;
}

export async function readManifestScopeBlocks(
  manifest: DataBlockManifest,
  loadBlock: (id: string) => Promise<DataScopeBlock | null>,
  options: BlockPageOptions,
): Promise<ReadScopeBlocksResponse> {
  const { scope, collectedAt } = manifest;
  const representation = options.representation ?? "stored";
  const representationId = blockRepresentationId(
    manifest,
    representation,
    options.cursorView,
  );
  const cursor = options.cursor
    ? validateDataBlockCursor(options.cursor, {
        scope,
        collectedAt,
        view: options.cursorView,
        representationId,
      })
    : { ok: true as const, cursor: null };
  if (!cursor.ok)
    throw new DataBlockStorageError(
      cursor.error.message.startsWith("representation_mismatch")
        ? "representation_mismatch"
        : "cursor_invalid",
      cursor.error.message,
    );
  const head = {
    scope,
    collectedAt,
    ...(manifest.schemaId ? { schemaId: manifest.schemaId } : {}),
    contentKind: manifest.contentKind,
    ...manifestBinding(manifest),
    representationId,
  };
  const prepare = (block: DataScopeBlock) =>
    representBlock(block, manifest, representation);
  if (options.blockIds?.length) {
    const selection = await selectScopeBlocksByIds(
      manifest,
      options.blockIds,
      { maxBytes: options.maxBytes, prepare },
      loadBlock,
    );
    return {
      ...head,
      blocks: selection.blocks,
      warnings: [...manifest.warnings, ...selection.warnings],
    };
  }
  const maxBytes = Math.max(1, options.maxBytes);
  const startIndex = cursor.cursor?.blockIndex ?? 0;
  const startOffset = cursor.cursor?.intraBlockOffset ?? 0;
  const blocks: DataScopeBlock[] = [];
  let bytes = 0,
    nextIndex = startIndex;
  let nextOffset: number | undefined;
  while (nextIndex < manifest.blocks.length) {
    const ref = manifest.blocks[nextIndex]!;
    if (blocks.length && bytes >= maxBytes) break;
    // Raw refs are conservative size bounds; do not load the next block until needed.
    if (blocks.length && bytes + ref.sizeBytes > maxBytes) break;
    const stored = await loadBlock(ref.id);
    if (!stored)
      throw new DataBlockStorageError(
        "block_payload_not_found",
        `Block ${ref.id} is missing`,
      );
    const block = prepare(verifyStoredBlock(ref, stored));
    if (!block) {
      nextIndex++;
      continue;
    }
    const offset = nextIndex === startIndex ? startOffset : 0;
    if (offset >= block.sizeBytes) {
      nextIndex++;
      continue;
    }
    const page = pageBlock(block, offset, maxBytes - bytes);
    blocks.push(page.block);
    bytes += page.block.sizeBytes;
    if (page.nextOffset !== undefined) {
      nextOffset = page.nextOffset;
      break;
    }
    nextIndex++;
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
            representationId,
          }),
        }
      : {}),
    warnings: manifest.warnings,
  };
}

export async function readBuiltScopeBlocks(
  built: { manifest: DataBlockManifest; blocks: DataScopeBlock[] },
  options: BlockPageOptions,
): Promise<ReadScopeBlocksResponse> {
  const byId = new Map(built.blocks.map((block) => [block.id, block]));
  return readManifestScopeBlocks(
    built.manifest,
    async (id) => byId.get(id) ?? null,
    options,
  );
}
