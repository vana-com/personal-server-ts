import {
  mkdir,
  open,
  readFile,
  writeFile,
  readdir,
  unlink,
  rename,
  stat,
  rm,
} from "node:fs/promises";
import { dirname, join, relative } from "node:path";
import { randomUUID } from "node:crypto";
import {
  DataFileEnvelopeSchema,
  type DataFileEnvelope,
} from "@opendatalabs/vana-sdk/browser";
import {
  buildDataFilePath,
  buildScopeDir,
  filenameToTimestamp,
  type HierarchyManagerOptions,
  type WriteResult,
} from "@opendatalabs/personal-server-ts-core/storage/hierarchy";
import {
  DataBlockStorageError,
  encodeDataBlockCursor,
  validateDataBlockCursor,
  type DataBlockManifest,
  type DataScopeBlock,
  type ReadScopeBlocksResponse,
} from "@opendatalabs/personal-server-ts-core/storage/blocks";
import { previewJsonEnvelopePrefix } from "@opendatalabs/personal-server-ts-core/storage/preview";

/** Atomic write: mkdir -p, write temp file, rename */
export async function writeDataFile(
  options: HierarchyManagerOptions,
  envelope: DataFileEnvelope,
): Promise<WriteResult> {
  const filePath = buildDataFilePath(
    options.dataDir,
    envelope.scope,
    envelope.collectedAt,
  );
  const dir = dirname(filePath);

  await mkdir(dir, { recursive: true });

  const content = JSON.stringify(envelope, null, 2);
  const tempPath = filePath + ".tmp." + randomUUID();

  await writeFile(tempPath, content, "utf-8");
  await rename(tempPath, filePath);

  const stats = await stat(filePath);

  return {
    path: filePath,
    relativePath: relative(options.dataDir, filePath),
    sizeBytes: stats.size,
  };
}

/** Read and parse a data file */
export async function readDataFile(
  options: HierarchyManagerOptions,
  scope: string,
  collectedAt: string,
): Promise<DataFileEnvelope> {
  const filePath = buildDataFilePath(options.dataDir, scope, collectedAt);
  const content = await readFile(filePath, "utf-8");
  return DataFileEnvelopeSchema.parse(JSON.parse(content));
}

/** Read a bounded UTF-8 text prefix without parsing the full envelope. */
export async function readDataFilePreview(
  options: HierarchyManagerOptions,
  scope: string,
  collectedAt: string,
  maxBytes: number,
): Promise<{ text: string; truncated: boolean }> {
  const filePath = buildDataFilePath(options.dataDir, scope, collectedAt);
  const handle = await open(filePath, "r");
  try {
    const stats = await handle.stat();
    const bytesToRead = Math.max(0, Math.min(maxBytes, stats.size));
    const buffer = Buffer.alloc(bytesToRead);
    const { bytesRead } = await handle.read(buffer, 0, bytesToRead, 0);
    return previewJsonEnvelopePrefix(
      buffer.subarray(0, bytesRead).toString("utf-8"),
      maxBytes,
      { sourceTruncated: stats.size > bytesRead },
    );
  } finally {
    await handle.close();
  }
}

export async function writeBlockManifest(
  options: HierarchyManagerOptions,
  scope: string,
  collectedAt: string,
  manifest: DataBlockManifest,
  blocks: DataScopeBlock[],
): Promise<void> {
  const dir = buildBlockDir(options.dataDir, scope, collectedAt);
  const tempDir = `${dir}.tmp.${randomUUID()}`;

  await mkdir(tempDir, { recursive: true });
  try {
    for (const block of blocks) {
      await writeFile(
        buildBlockPayloadPath(tempDir, block.id),
        JSON.stringify(block),
        "utf-8",
      );
    }

    await rm(dir, { recursive: true, force: true });
    await rename(tempDir, dir);

    const manifestPath = buildBlockManifestPath(
      options.dataDir,
      scope,
      collectedAt,
    );
    const tempManifestPath = `${manifestPath}.tmp.${randomUUID()}`;
    await writeFile(
      tempManifestPath,
      JSON.stringify(manifest, null, 2),
      "utf-8",
    );
    await rename(tempManifestPath, manifestPath);
  } catch (err) {
    await rm(tempDir, { recursive: true, force: true });
    throw err;
  }
}

export async function readScopeBlocks(
  options: HierarchyManagerOptions,
  scope: string,
  collectedAt: string,
  readOptions: { cursor?: string; maxBytes: number },
): Promise<ReadScopeBlocksResponse> {
  const manifest = await readBlockManifest(options, scope, collectedAt);
  const cursor = readOptions.cursor
    ? validateDataBlockCursor(readOptions.cursor, { scope, collectedAt })
    : undefined;

  if (cursor && !cursor.ok) {
    throw new DataBlockStorageError("cursor_invalid", cursor.error.message);
  }

  const maxBytes = Math.max(1, readOptions.maxBytes);
  const startIndex = cursor?.ok ? cursor.cursor.blockIndex : 0;
  const blocks: DataScopeBlock[] = [];
  let totalBytes = 0;
  let nextIndex = startIndex;

  while (nextIndex < manifest.blocks.length) {
    const ref = manifest.blocks[nextIndex]!;
    if (blocks.length > 0 && totalBytes + ref.sizeBytes > maxBytes) break;

    const block = await readBlockPayload(options, scope, collectedAt, ref.id);
    blocks.push(block);
    totalBytes += ref.sizeBytes;
    nextIndex++;

    if (totalBytes >= maxBytes) break;
  }

  return {
    scope: manifest.scope,
    collectedAt: manifest.collectedAt,
    ...(manifest.schemaId ? { schemaId: manifest.schemaId } : {}),
    contentKind: manifest.contentKind,
    blocks,
    ...(nextIndex < manifest.blocks.length
      ? {
          nextCursor: encodeDataBlockCursor({
            scope,
            collectedAt,
            blockIndex: nextIndex,
          }),
        }
      : {}),
    warnings: manifest.warnings,
  };
}

/** List version filenames for a scope, newest first. Empty array if scope dir doesn't exist. */
export async function listVersions(
  options: HierarchyManagerOptions,
  scope: string,
): Promise<string[]> {
  const scopeDir = buildScopeDir(options.dataDir, scope);

  let entries: string[];
  try {
    entries = await readdir(scopeDir);
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      return [];
    }
    throw err;
  }

  const jsonFiles = entries
    .filter((f) => f.endsWith(".json"))
    .sort()
    .reverse();

  return jsonFiles.map((f) => filenameToTimestamp(f.replace(".json", "")));
}

/** Delete a single data file. Idempotent: a missing file is a no-op (matches deleteByFileId's
 * no-op contract and avoids stalling the sync cursor when the blob is already gone). */
export async function deleteDataFile(
  options: HierarchyManagerOptions,
  scope: string,
  collectedAt: string,
): Promise<void> {
  const filePath = buildDataFilePath(options.dataDir, scope, collectedAt);
  try {
    await unlink(filePath);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
  }
  await deleteBlockSidecars(options, scope, collectedAt);
}

/**
 * Delete all files for a scope by removing the scope directory recursively.
 * No-op if directory doesn't exist.
 */
export async function deleteAllForScope(
  options: HierarchyManagerOptions,
  scope: string,
): Promise<void> {
  const scopeDir = buildScopeDir(options.dataDir, scope);
  await rm(scopeDir, { recursive: true, force: true });
  const blockScopeDir = buildScopeDir(join(options.dataDir, "blocks"), scope);
  await rm(blockScopeDir, { recursive: true, force: true });
}

async function readBlockManifest(
  options: HierarchyManagerOptions,
  scope: string,
  collectedAt: string,
): Promise<DataBlockManifest> {
  try {
    return JSON.parse(
      await readFile(
        buildBlockManifestPath(options.dataDir, scope, collectedAt),
        "utf-8",
      ),
    ) as DataBlockManifest;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      throw new DataBlockStorageError(
        "block_manifest_not_found",
        `Block manifest not found for ${scope} at ${collectedAt}`,
      );
    }
    throw err;
  }
}

async function readBlockPayload(
  options: HierarchyManagerOptions,
  scope: string,
  collectedAt: string,
  blockId: string,
): Promise<DataScopeBlock> {
  try {
    return JSON.parse(
      await readFile(
        buildBlockPayloadPath(
          buildBlockDir(options.dataDir, scope, collectedAt),
          blockId,
        ),
        "utf-8",
      ),
    ) as DataScopeBlock;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      throw new DataBlockStorageError(
        "block_payload_not_found",
        `Block payload not found for ${scope} at ${collectedAt}: ${blockId}`,
      );
    }
    throw err;
  }
}

async function deleteBlockSidecars(
  options: HierarchyManagerOptions,
  scope: string,
  collectedAt: string,
): Promise<void> {
  await rm(buildBlockDir(options.dataDir, scope, collectedAt), {
    recursive: true,
    force: true,
  });
}

function buildBlockDir(
  dataDir: string,
  scope: string,
  collectedAt: string,
): string {
  return join(buildScopeDir(join(dataDir, "blocks"), scope), collectedAt);
}

function buildBlockManifestPath(
  dataDir: string,
  scope: string,
  collectedAt: string,
): string {
  return join(buildBlockDir(dataDir, scope, collectedAt), "manifest.json");
}

function buildBlockPayloadPath(dir: string, blockId: string): string {
  return join(dir, `${encodeURIComponent(blockId)}.json`);
}
