/**
 * Block-addressed selection: read exactly the blocks a caller names.
 *
 * Search returns a `blockRef` per hit and the manifest is a table of contents,
 * but without this path a client still has to walk `nextCursor` from the start
 * of the scope to reach a block it already knows the id of. Every storage
 * implementation pages the manifest identically, so the selection loop lives
 * here instead of being copied into each of them.
 */

import type {
  DataBlockManifest,
  DataBlockWarning,
  DataScopeBlock,
} from "./types.js";

/** Upper bound on block ids honoured in a single block-addressed read. */
export const MAX_SELECTED_BLOCK_IDS = 50;

/** Ids listed inline in a warning message before it is summarized by count. */
const WARNING_ID_SAMPLE = 10;

const TEXT_PAGE_MEDIA_TYPE = "text/plain; charset=utf-8";
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export interface SelectScopeBlocksResult {
  blocks: DataScopeBlock[];
  warnings: DataBlockWarning[];
}

/**
 * Return the requested blocks in the order they were asked for, bounded by
 * `maxBytes`. Ids that are not in the manifest, ids dropped by the id cap, and
 * ids left out because the byte budget ran out are reported as warnings rather
 * than errors — a partially answered selection is still useful.
 *
 * No cursor is produced: the selection order is the caller's, not the
 * manifest's, so a manifest-index cursor could not resume it.
 */
export async function selectScopeBlocksByIds(
  manifest: DataBlockManifest,
  blockIds: readonly string[],
  options: { maxBytes: number },
  loadBlock: (blockId: string) => Promise<DataScopeBlock | null>,
): Promise<SelectScopeBlocksResult> {
  const maxBytes = Math.max(1, options.maxBytes);
  const refById = new Map(manifest.blocks.map((ref) => [ref.id, ref]));

  const requested: string[] = [];
  const seen = new Set<string>();
  let cappedIds = 0;
  for (const blockId of blockIds) {
    if (typeof blockId !== "string" || !blockId || seen.has(blockId)) continue;
    seen.add(blockId);
    if (requested.length >= MAX_SELECTED_BLOCK_IDS) {
      cappedIds += 1;
      continue;
    }
    requested.push(blockId);
  }

  const blocks: DataScopeBlock[] = [];
  const missingIds: string[] = [];
  const skippedIds: string[] = [];
  const warnings: DataBlockWarning[] = [];
  let bytes = 0;

  for (let index = 0; index < requested.length; index += 1) {
    const blockId = requested[index];
    const ref = refById.get(blockId);
    if (!ref) {
      missingIds.push(blockId);
      continue;
    }
    // Mirrors the cursor path: a block that does not fit whole is only sliced
    // when it is the first one in the page, so a caller always makes progress.
    if (blocks.length > 0 && bytes + ref.sizeBytes > maxBytes) {
      skippedIds.push(...requested.slice(index));
      break;
    }
    const block = await loadBlock(blockId);
    if (!block) {
      missingIds.push(blockId);
      continue;
    }
    const page = pageBlock(block, maxBytes - bytes);
    blocks.push(page.block);
    bytes += page.block.sizeBytes;
    if (page.truncated) {
      skippedIds.push(...requested.slice(index + 1));
      break;
    }
  }

  if (cappedIds > 0) {
    warnings.push({
      code: "block_selection_capped",
      message: `${cappedIds} block ids beyond the ${MAX_SELECTED_BLOCK_IDS} id limit were ignored`,
    });
  }
  if (missingIds.length > 0) {
    warnings.push({
      code: "block_not_found",
      message: `${missingIds.length} requested block ids are not in this scope: ${summarizeIds(missingIds)}`,
    });
  }
  if (skippedIds.length > 0) {
    warnings.push({
      code: "block_selection_truncated",
      message: `maxBytes reached; ${skippedIds.length} requested blocks were not returned: ${summarizeIds(skippedIds)}. Request them in a follow-up read.`,
    });
  }

  return { blocks, warnings };
}

function summarizeIds(ids: readonly string[]): string {
  const sample = ids.slice(0, WARNING_ID_SAMPLE).join(", ");
  return ids.length > WARNING_ID_SAMPLE
    ? `${sample}, ...(${ids.length - WARNING_ID_SAMPLE} more)`
    : sample;
}

function pageBlock(
  block: DataScopeBlock,
  maxBytes: number,
): { block: DataScopeBlock; truncated: boolean } {
  const text =
    typeof block.value === "string" ? block.value : JSON.stringify(block.value);
  const bytes = textEncoder.encode(text);
  if (bytes.length <= maxBytes) {
    return { block, truncated: false };
  }

  const end = Math.max(1, maxBytes);
  return {
    block: {
      ...block,
      path: `${block.path}[bytes 0:${end}]`,
      mediaType: block.mediaType.startsWith("text/")
        ? block.mediaType
        : TEXT_PAGE_MEDIA_TYPE,
      value: textDecoder.decode(bytes.slice(0, end)),
      sizeBytes: end,
      truncated: true,
    },
    truncated: true,
  };
}
