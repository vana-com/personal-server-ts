import {
  access,
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
import {
  createReadStream,
  closeSync,
  existsSync,
  fsyncSync,
  linkSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  rmSync,
  rmdirSync,
  writeFileSync,
} from "node:fs";
import { Readable } from "node:stream";
import { dirname, join, relative, resolve } from "node:path";
import { randomUUID } from "node:crypto";
import {
  DataFileEnvelopeSchema,
  scopeToPathSegments,
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
  selectScopeBlocksByIds,
  validateDataBlockCursor,
  type DataBlockManifest,
  type DataScopeBlock,
  type ReadScopeBlocksResponse,
} from "@opendatalabs/personal-server-ts-core/storage/blocks";
import { previewJsonEnvelopePrefix } from "@opendatalabs/personal-server-ts-core/storage/preview";

const TEXT_PAGE_MEDIA_TYPE = "text/plain; charset=utf-8";
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function syncDirectory(path: string): void {
  if (process.platform === "win32") return;
  const fd = openSync(path, "r");
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

export class PublishedDataFileError extends Error {
  constructor(
    public readonly relativePath: string,
    cause: unknown,
  ) {
    super(cause instanceof Error ? cause.message : String(cause), { cause });
  }
}

/** Synchronous, no-replace publication inside the SQLite writer gate. */
export function publishDataFile(
  options: HierarchyManagerOptions,
  envelope: DataFileEnvelope,
  bytes: Uint8Array,
  operation?: string,
): WriteResult {
  const path = buildDataFilePath(
    options.dataDir,
    envelope.scope,
    envelope.collectedAt,
  );
  const dir = dirname(path);
  const missing: string[] = [];
  for (let parent = dir; !existsSync(parent); parent = dirname(parent)) {
    missing.push(parent);
  }
  mkdirSync(dir, { recursive: true });
  for (const created of missing.reverse()) syncDirectory(dirname(created));
  const temp = `${path}.tmp.${operation ?? randomUUID()}`;
  rmSync(temp, { force: true });
  let published = false;
  try {
    try {
      const fd = openSync(temp, "wx", 0o600);
      try {
        writeFileSync(fd, bytes);
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      try {
        linkSync(temp, path);
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
        if (!readFileSync(path).equals(Buffer.from(bytes))) {
          throw new Error(
            `Stored envelope conflicts with publication at ${path}`,
          );
        }
      }
      published = true;
      syncDirectory(dir);
    } finally {
      rmSync(temp, { force: true });
      syncDirectory(dir);
    }
  } catch (err) {
    if (published) {
      throw new PublishedDataFileError(relative(options.dataDir, path), err);
    }
    throw err;
  }
  return {
    path,
    relativePath: relative(options.dataDir, path),
    sizeBytes: bytes.byteLength,
  };
}

export function deleteDataFileSync(
  options: HierarchyManagerOptions,
  scope: string,
  collectedAt: string,
  operation?: string,
): void {
  const path = buildDataFilePath(options.dataDir, scope, collectedAt);
  rmSync(path, { force: true });
  if (operation) rmSync(`${path}.tmp.${operation}`, { force: true });
  if (existsSync(dirname(path))) syncDirectory(dirname(path));
  rmSync(buildBlockDir(options.dataDir, scope, collectedAt), {
    recursive: true,
    force: true,
  });
}

export function deleteFirstSeenLedgerSync(
  options: HierarchyManagerOptions,
  scope: string,
): void {
  try {
    rmSync(buildFirstSeenLedgerPath(options.dataDir, scope), { force: true });
  } catch {
    /* Derived sidecar cleanup must not block data deletion. */
  }
}

export function snapshotScopeFiles(
  options: HierarchyManagerOptions,
  scope: string,
): { files: string[]; directories: string[] } {
  const files: string[] = [];
  const directories: string[] = [];
  function visit(path: string): void {
    let info;
    try {
      info = lstatSync(path);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return;
      throw err;
    }
    if (!info.isDirectory()) {
      files.push(path);
      return;
    }
    for (const name of readdirSync(path)) visit(join(path, name));
    directories.push(path);
  }
  for (const path of [
    buildScopeDir(resolve(options.dataDir), scope),
    buildScopeDir(join(resolve(options.dataDir), "blocks"), scope),
  ]) {
    for (
      let parent = dirname(path);
      parent !== resolve(options.dataDir);
      parent = dirname(parent)
    ) {
      if (existsSync(parent) && lstatSync(parent).isSymbolicLink()) {
        throw new Error(`Scope parent is a symbolic link: ${parent}`);
      }
    }
    visit(path);
  }
  return { files, directories };
}

export function deleteScopeFilesSync(
  snapshot: ReturnType<typeof snapshotScopeFiles>,
): void {
  for (const path of snapshot.files) rmSync(path, { force: true });
  for (const dir of new Set(snapshot.files.map(dirname))) {
    if (existsSync(dir)) syncDirectory(dir);
  }
  for (const path of snapshot.directories) {
    try {
      rmdirSync(path);
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code !== "ENOENT" && code !== "ENOTEMPTY") throw err;
    }
    if (existsSync(dirname(path))) syncDirectory(dirname(path));
  }
}

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

/** Read a data file without decoding or parsing its potentially large body. */
export async function readDataFileBytes(
  options: HierarchyManagerOptions,
  scope: string,
  collectedAt: string,
): Promise<Uint8Array> {
  return readFile(buildDataFilePath(options.dataDir, scope, collectedAt));
}

/** Open a fresh stream over a stored data file. */
export function readDataFileStream(
  options: HierarchyManagerOptions,
  scope: string,
  collectedAt: string,
): ReadableStream<Uint8Array> {
  return Readable.toWeb(
    createReadStream(buildDataFilePath(options.dataDir, scope, collectedAt)),
  ) as ReadableStream<Uint8Array>;
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

/**
 * Per-scope first-seen ledger: ONE flat file `<dataDir>/first-seen/<scope>.json`.
 *
 * It sits outside the per-version data files (`<dataDir>/<source>/<category>/…`)
 * and outside the block sidecars (`<dataDir>/blocks/…`). A scope's source
 * matches `[a-z0-9][a-z0-9_]*`, so no scope can have `first-seen` (it holds a
 * hyphen) as its directory, and the ledger is never in the SQLite index, so it
 * is not a version and nothing that lists, uploads or serves data reaches it.
 */
function buildFirstSeenLedgerPath(dataDir: string, scope: string): string {
  // Throws for anything that is not a well-formed scope, so the scope can
  // never carry a path separator or `..` into the file name.
  scopeToPathSegments(scope);
  return join(dataDir, "first-seen", `${scope}.json`);
}

/** Returns null when the scope has no ledger file. */
export async function readFirstSeenLedger(
  options: HierarchyManagerOptions,
  scope: string,
): Promise<unknown | null> {
  try {
    return JSON.parse(
      await readFile(buildFirstSeenLedgerPath(options.dataDir, scope), "utf-8"),
    ) as unknown;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw err;
  }
}

/** Atomic write: mkdir -p, write temp file, rename. */
export async function writeFirstSeenLedger(
  options: HierarchyManagerOptions,
  scope: string,
  ledger: unknown,
): Promise<void> {
  const filePath = buildFirstSeenLedgerPath(options.dataDir, scope);
  await mkdir(dirname(filePath), { recursive: true });
  const tempPath = `${filePath}.tmp.${randomUUID()}`;
  try {
    await writeFile(tempPath, JSON.stringify(ledger), "utf-8");
    await rename(tempPath, filePath);
  } catch (err) {
    await rm(tempPath, { force: true });
    throw err;
  }
}

/** Idempotent: a missing file is a no-op. */
export async function deleteFirstSeenLedger(
  options: HierarchyManagerOptions,
  scope: string,
): Promise<void> {
  await rm(buildFirstSeenLedgerPath(options.dataDir, scope), { force: true });
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
  readOptions: {
    cursor?: string;
    maxBytes: number;
    blockIds?: readonly string[];
  },
): Promise<ReadScopeBlocksResponse> {
  const manifest = await readBlockManifest(options, scope, collectedAt);

  if (readOptions.blockIds?.length) {
    const selection = await selectScopeBlocksByIds(
      manifest,
      readOptions.blockIds,
      { maxBytes: readOptions.maxBytes },
      (blockId) =>
        readBlockPayloadIfPresent(options, scope, collectedAt, blockId),
    );
    return {
      scope: manifest.scope,
      collectedAt: manifest.collectedAt,
      ...(manifest.schemaId ? { schemaId: manifest.schemaId } : {}),
      contentKind: manifest.contentKind,
      blocks: selection.blocks,
      warnings: [...manifest.warnings, ...selection.warnings],
    };
  }

  const cursor = readOptions.cursor
    ? validateDataBlockCursor(readOptions.cursor, { scope, collectedAt })
    : undefined;

  if (cursor && !cursor.ok) {
    throw new DataBlockStorageError("cursor_invalid", cursor.error.message);
  }

  const maxBytes = Math.max(1, readOptions.maxBytes);
  const startIndex = cursor?.ok ? cursor.cursor.blockIndex : 0;
  const startOffset = cursor?.ok ? (cursor.cursor.intraBlockOffset ?? 0) : 0;
  const blocks: DataScopeBlock[] = [];
  let totalBytes = 0;
  let nextIndex = startIndex;
  let nextOffset: number | undefined;

  while (nextIndex < manifest.blocks.length) {
    const ref = manifest.blocks[nextIndex]!;
    const offset = nextIndex === startIndex ? startOffset : 0;
    if (offset >= ref.sizeBytes) {
      nextIndex++;
      continue;
    }
    if (
      blocks.length > 0 &&
      offset === 0 &&
      totalBytes + ref.sizeBytes > maxBytes
    )
      break;

    const block = await readBlockPayload(options, scope, collectedAt, ref.id);
    const page = pageBlock(block, offset, maxBytes - totalBytes);
    blocks.push(page.block);
    totalBytes += page.block.sizeBytes;

    if (page.nextOffset !== undefined) {
      nextOffset = page.nextOffset;
      break;
    }

    nextIndex++;

    if (totalBytes >= maxBytes) break;
  }

  return {
    scope: manifest.scope,
    collectedAt: manifest.collectedAt,
    ...(manifest.schemaId ? { schemaId: manifest.schemaId } : {}),
    contentKind: manifest.contentKind,
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
          }),
        }
      : {}),
    warnings: manifest.warnings,
  };
}

/**
 * Manifest as a table of contents. Unlike the internal reader this returns null
 * for a scope that was stored before block sidecars existed, so callers can
 * degrade instead of failing.
 */
export async function readScopeBlockManifest(
  options: HierarchyManagerOptions,
  scope: string,
  collectedAt: string,
): Promise<DataBlockManifest | null> {
  try {
    return await readBlockManifest(options, scope, collectedAt);
  } catch (err) {
    if (
      err instanceof DataBlockStorageError &&
      err.code === "block_manifest_not_found"
    ) {
      return null;
    }
    throw err;
  }
}

export async function hasScopeBlocks(
  options: HierarchyManagerOptions,
  scope: string,
  collectedAt: string,
): Promise<boolean> {
  try {
    await access(buildBlockManifestPath(options.dataDir, scope, collectedAt));
    return true;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      return false;
    }
    throw err;
  }
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

/** Payload read for block-addressed selection: a missing id is a warning, not a throw. */
async function readBlockPayloadIfPresent(
  options: HierarchyManagerOptions,
  scope: string,
  collectedAt: string,
  blockId: string,
): Promise<DataScopeBlock | null> {
  try {
    return await readBlockPayload(options, scope, collectedAt, blockId);
  } catch (err) {
    if (
      err instanceof DataBlockStorageError &&
      err.code === "block_payload_not_found"
    ) {
      return null;
    }
    throw err;
  }
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
  const value = textDecoder.decode(bytes.slice(start, end));

  return {
    block: {
      ...block,
      path: `${block.path}[bytes ${start}:${end}]`,
      mediaType: block.mediaType.startsWith("text/")
        ? block.mediaType
        : TEXT_PAGE_MEDIA_TYPE,
      value,
      sizeBytes: end - start,
      truncated: end < bytes.length,
    },
    ...(end < bytes.length ? { nextOffset: end } : {}),
  };
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
