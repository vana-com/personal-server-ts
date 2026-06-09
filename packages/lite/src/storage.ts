import type { DataStoragePort } from "@opendatalabs/personal-server-ts-core/ports";
import type {
  DataBlockManifest,
  DataScopeBlock,
} from "@opendatalabs/personal-server-ts-core/storage/blocks";
import {
  DataBlockStorageError,
  encodeDataBlockCursor,
  validateDataBlockCursor,
} from "@opendatalabs/personal-server-ts-core/storage/blocks";
import type { DataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import type { WriteResult } from "@opendatalabs/personal-server-ts-core/storage/hierarchy";
import type { IndexEntry } from "@opendatalabs/personal-server-ts-core/storage/index";
import type { PsLiteStorageAdapter } from "./runtime.js";
import { createStorageReadMethods, sortEntries } from "./storage-utils.js";
import {
  previewEnvelopeValue,
  previewJsonEnvelopePrefix,
} from "@opendatalabs/personal-server-ts-core/storage/preview";

export interface PsLitePersistedStorageState {
  version: 1;
  nextId: number;
  entries: IndexEntry[];
  envelopes: DataFileEnvelope[];
  blockManifests?: Array<{
    path: string;
    manifest: DataBlockManifest;
  }>;
  blockPayloads?: Array<{
    path: string;
    block: DataScopeBlock;
  }>;
}

export type PsLiteFileStorageKind = "opfs" | "indexeddb";

export interface PsLiteDataFileStore {
  readonly kind: PsLiteFileStorageKind;
  readEnvelope(path: string): Promise<DataFileEnvelope | null>;
  readEnvelopePreview?(
    path: string,
    options: { maxBytes: number },
  ): Promise<{ text: string; truncated: boolean } | null>;
  writeEnvelope(path: string, envelope: DataFileEnvelope): Promise<number>;
  deleteEnvelope(path: string): Promise<void>;
  readBlockManifest?(path: string): Promise<DataBlockManifest | null>;
  writeBlockManifest?(path: string, manifest: DataBlockManifest): Promise<void>;
  readBlockPayload?(path: string): Promise<DataScopeBlock | null>;
  writeBlockPayload?(path: string, block: DataScopeBlock): Promise<void>;
  deleteBlockTree?(pathPrefix: string): Promise<void>;
}

export interface PsLiteStorageCapabilities {
  metadata: "indexeddb" | "memory" | "custom";
  files: PsLiteFileStorageKind | "memory";
  opfsAvailable: boolean;
}

export interface PsLitePersistenceAdapter {
  read(): Promise<PsLitePersistedStorageState | null>;
  write(state: PsLitePersistedStorageState): Promise<void>;
}

export interface IndexedDbPsLitePersistenceOptions {
  dbName?: string;
  storeName?: string;
  key?: string;
}

const DEFAULT_INDEXED_DB_NAME = "personal-server-lite-storage";
const DEFAULT_INDEXED_DB_STORE = "state";
const DEFAULT_INDEXED_DB_KEY = "data-storage-v1";
const TEXT_PAGE_MEDIA_TYPE = "text/plain; charset=utf-8";
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function initialState(): PsLitePersistedStorageState {
  return {
    version: 1,
    nextId: 1,
    entries: [],
    envelopes: [],
  };
}

function envelopePath(scope: string, collectedAt: string): string {
  return `data/${scope}/${collectedAt}.json`;
}

function blockTreePath(scope: string, collectedAt: string): string {
  return `blocks/${scope}/${collectedAt}`;
}

function blockManifestPath(scope: string, collectedAt: string): string {
  return `${blockTreePath(scope, collectedAt)}/manifest.json`;
}

function blockPayloadPath(
  scope: string,
  collectedAt: string,
  blockId: string,
): string {
  return `${blockTreePath(scope, collectedAt)}/${encodeURIComponent(blockId)}.json`;
}

function normalizeState(
  state: PsLitePersistedStorageState | null,
): PsLitePersistedStorageState {
  if (!state || state.version !== 1) {
    return initialState();
  }
  return {
    version: 1,
    nextId: Math.max(state.nextId, 1),
    entries: state.entries.map((entry) => ({
      ...entry,
      schemaId: entry.schemaId ?? null,
    })),
    envelopes: state.envelopes,
    blockManifests: state.blockManifests ?? [],
    blockPayloads: state.blockPayloads ?? [],
  };
}

export function createIndexedDbFallbackDataFileStore(
  envelopes: Map<string, DataFileEnvelope>,
  blockManifests: Map<string, DataBlockManifest> = new Map(),
  blockPayloads: Map<string, DataScopeBlock> = new Map(),
): PsLiteDataFileStore {
  return {
    kind: "indexeddb",
    async readEnvelope(path) {
      return envelopes.get(path) ?? null;
    },
    async readEnvelopePreview(path, { maxBytes }) {
      const envelope = envelopes.get(path);
      if (!envelope) return null;
      return previewEnvelopeValue(envelope, maxBytes);
    },
    async writeEnvelope(path, envelope) {
      envelopes.set(path, envelope);
      return new TextEncoder().encode(JSON.stringify(envelope)).length;
    },
    async deleteEnvelope(path) {
      envelopes.delete(path);
    },
    async readBlockManifest(path) {
      return blockManifests.get(path) ?? null;
    },
    async writeBlockManifest(path, manifest) {
      blockManifests.set(path, manifest);
    },
    async readBlockPayload(path) {
      return blockPayloads.get(path) ?? null;
    },
    async writeBlockPayload(path, block) {
      blockPayloads.set(path, block);
    },
    async deleteBlockTree(pathPrefix) {
      deleteMapPrefix(blockManifests, pathPrefix);
      deleteMapPrefix(blockPayloads, pathPrefix);
    },
  };
}

function deleteMapPrefix<T>(map: Map<string, T>, pathPrefix: string): void {
  const prefix = pathPrefix.endsWith("/") ? pathPrefix : `${pathPrefix}/`;
  for (const path of map.keys()) {
    if (path === pathPrefix || path.startsWith(prefix)) {
      map.delete(path);
    }
  }
}

async function getOrCreateOpfsDirectory(
  root: FileSystemDirectoryHandle,
  parts: string[],
): Promise<FileSystemDirectoryHandle> {
  let dir = root;
  for (const part of parts) {
    dir = await dir.getDirectoryHandle(part, { create: true });
  }
  return dir;
}

async function getOpfsFileHandle(
  root: FileSystemDirectoryHandle,
  path: string,
  options?: FileSystemGetFileOptions,
): Promise<FileSystemFileHandle> {
  const parts = path.split("/").filter(Boolean);
  const fileName = parts.pop();
  if (!fileName) {
    throw new Error("OPFS path must include a file name");
  }
  const dir = await getOrCreateOpfsDirectory(root, parts);
  return dir.getFileHandle(fileName, options);
}

export async function isOpfsAvailable(): Promise<boolean> {
  return (
    typeof navigator !== "undefined" &&
    typeof navigator.storage?.getDirectory === "function"
  );
}

export async function createOpfsPsLiteDataFileStore(): Promise<PsLiteDataFileStore> {
  if (!(await isOpfsAvailable())) {
    throw new Error("OPFS is not available in this runtime");
  }
  const root = await navigator.storage.getDirectory();

  return {
    kind: "opfs",
    async readEnvelope(path) {
      try {
        const handle = await getOpfsFileHandle(root, path);
        const file = await handle.getFile();
        return JSON.parse(await file.text()) as DataFileEnvelope;
      } catch (err) {
        if (err instanceof DOMException && err.name === "NotFoundError") {
          return null;
        }
        throw err;
      }
    },
    async readEnvelopePreview(path, { maxBytes }) {
      try {
        const handle = await getOpfsFileHandle(root, path);
        const file = await handle.getFile();
        return previewJsonEnvelopePrefix(
          await file.slice(0, maxBytes).text(),
          maxBytes,
          {
            sourceTruncated: file.size > maxBytes,
          },
        );
      } catch (err) {
        if (err instanceof DOMException && err.name === "NotFoundError") {
          return null;
        }
        throw err;
      }
    },
    async writeEnvelope(path, envelope) {
      const encoded = JSON.stringify(envelope);
      const handle = await getOpfsFileHandle(root, path, { create: true });
      const writable = await handle.createWritable();
      await writable.write(encoded);
      await writable.close();
      return new TextEncoder().encode(encoded).length;
    },
    async deleteEnvelope(path) {
      const parts = path.split("/").filter(Boolean);
      const fileName = parts.pop();
      if (!fileName) return;
      try {
        const dir = await getOrCreateOpfsDirectory(root, parts);
        await dir.removeEntry(fileName);
      } catch (err) {
        if (err instanceof DOMException && err.name === "NotFoundError") {
          return;
        }
        throw err;
      }
    },
    async readBlockManifest(path) {
      return readJsonOpfsFile<DataBlockManifest>(root, path);
    },
    async writeBlockManifest(path, manifest) {
      await writeJsonOpfsFile(root, path, manifest);
    },
    async readBlockPayload(path) {
      return readJsonOpfsFile<DataScopeBlock>(root, path);
    },
    async writeBlockPayload(path, block) {
      await writeJsonOpfsFile(root, path, block);
    },
    async deleteBlockTree(pathPrefix) {
      await removeOpfsDirectoryTree(root, pathPrefix);
    },
  };
}

async function readJsonOpfsFile<T>(
  root: FileSystemDirectoryHandle,
  path: string,
): Promise<T | null> {
  try {
    const handle = await getOpfsFileHandle(root, path);
    const file = await handle.getFile();
    return JSON.parse(await file.text()) as T;
  } catch (err) {
    if (err instanceof DOMException && err.name === "NotFoundError") {
      return null;
    }
    throw err;
  }
}

async function writeJsonOpfsFile(
  root: FileSystemDirectoryHandle,
  path: string,
  value: unknown,
): Promise<void> {
  const handle = await getOpfsFileHandle(root, path, { create: true });
  const writable = await handle.createWritable();
  try {
    await writable.write(JSON.stringify(value));
  } finally {
    await writable.close();
  }
}

async function removeOpfsDirectoryTree(
  root: FileSystemDirectoryHandle,
  pathPrefix: string,
): Promise<void> {
  const parts = pathPrefix.split("/").filter(Boolean);
  const directoryName = parts.pop();
  if (!directoryName) return;
  try {
    const parent = await getOrCreateOpfsDirectory(root, parts);
    await parent.removeEntry(directoryName, { recursive: true });
  } catch (err) {
    if (err instanceof DOMException && err.name === "NotFoundError") {
      return;
    }
    throw err;
  }
}

function openIndexedDb(
  dbName: string,
  storeName: string,
): Promise<IDBDatabase> {
  if (typeof indexedDB === "undefined") {
    throw new Error("IndexedDB is not available in this runtime");
  }

  return new Promise((resolve, reject) => {
    const request = indexedDB.open(dbName, 1);

    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(storeName)) {
        db.createObjectStore(storeName);
      }
    };

    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function runIndexedDbTransaction<T>(
  options: Required<IndexedDbPsLitePersistenceOptions>,
  mode: IDBTransactionMode,
  callback: (store: IDBObjectStore) => IDBRequest<T>,
): Promise<T> {
  return openIndexedDb(options.dbName, options.storeName).then(
    (db) =>
      new Promise<T>((resolve, reject) => {
        const transaction = db.transaction(options.storeName, mode);
        const store = transaction.objectStore(options.storeName);
        const request = callback(store);

        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
        transaction.oncomplete = () => db.close();
        transaction.onerror = () => {
          db.close();
          reject(transaction.error);
        };
      }),
  );
}

export function createIndexedDbPsLitePersistence(
  options: IndexedDbPsLitePersistenceOptions = {},
): PsLitePersistenceAdapter {
  const resolved = {
    dbName: options.dbName ?? DEFAULT_INDEXED_DB_NAME,
    storeName: options.storeName ?? DEFAULT_INDEXED_DB_STORE,
    key: options.key ?? DEFAULT_INDEXED_DB_KEY,
  };

  return {
    async read() {
      const state = await runIndexedDbTransaction<
        PsLitePersistedStorageState | undefined
      >(resolved, "readonly", (store) => store.get(resolved.key));
      return state ?? null;
    },
    async write(state) {
      await runIndexedDbTransaction<IDBValidKey>(
        resolved,
        "readwrite",
        (store) => store.put(state, resolved.key),
      );
    },
  };
}

export async function createPersistentPsLiteStorage(
  adapter: PsLiteStorageAdapter,
  persistence: PsLitePersistenceAdapter = createIndexedDbPsLitePersistence(),
  dataFileStore?: PsLiteDataFileStore,
): Promise<DataStoragePort> {
  let state = normalizeState(await persistence.read());
  const fallbackEnvelopes = new Map(
    state.envelopes.map((envelope) => [
      envelopePath(envelope.scope, envelope.collectedAt),
      envelope,
    ]),
  );
  const fallbackBlockManifests = new Map(
    (state.blockManifests ?? []).map(({ path, manifest }) => [path, manifest]),
  );
  const fallbackBlockPayloads = new Map(
    (state.blockPayloads ?? []).map(({ path, block }) => [path, block]),
  );
  const fallbackStore = createIndexedDbFallbackDataFileStore(
    fallbackEnvelopes,
    fallbackBlockManifests,
    fallbackBlockPayloads,
  );
  const fileStore =
    dataFileStore ??
    (adapter.kind !== "custom" && (await isOpfsAvailable())
      ? await createOpfsPsLiteDataFileStore()
      : fallbackStore);
  const capabilities: PsLiteStorageCapabilities = {
    metadata: adapter.kind === "custom" ? "custom" : "indexeddb",
    files: fileStore.kind,
    opfsAvailable: await isOpfsAvailable(),
  };

  let persistQueue: Promise<void> = Promise.resolve();

  async function persist(): Promise<void> {
    const snapshot = {
      ...state,
      envelopes:
        fileStore.kind === "indexeddb"
          ? Array.from(fallbackEnvelopes.values())
          : [],
      blockManifests:
        fileStore.kind === "indexeddb"
          ? Array.from(fallbackBlockManifests.entries()).map(
              ([path, manifest]) => ({ path, manifest }),
            )
          : [],
      blockPayloads:
        fileStore.kind === "indexeddb"
          ? Array.from(fallbackBlockPayloads.entries()).map(
              ([path, block]) => ({ path, block }),
            )
          : [],
    };
    const write = persistQueue.then(() => persistence.write(snapshot));
    persistQueue = write.catch(() => undefined);
    await write;
  }

  function entriesForScope(scope: string): IndexEntry[] {
    return sortEntries(state.entries.filter((entry) => entry.scope === scope));
  }

  const storagePort: DataStoragePort & {
    capabilities: PsLiteStorageCapabilities;
  } = {
    kind: adapter.kind === "custom" ? "custom" : "browser-indexeddb-opfs",
    capabilities,
    ...createStorageReadMethods(() => state.entries, entriesForScope),

    findByFileId(fileId) {
      return state.entries.find((entry) => entry.fileId === fileId);
    },

    findUnsynced(options) {
      const entries = state.entries
        .filter((entry) => entry.fileId === null)
        .sort((a, b) => a.createdAt.localeCompare(b.createdAt));
      return options?.limit === undefined
        ? entries
        : entries.slice(0, options.limit);
    },

    async readEnvelope(scope, collectedAt) {
      const path = envelopePath(scope, collectedAt);
      const envelope =
        (await fileStore.readEnvelope(path)) ??
        (await fallbackStore.readEnvelope(path));
      if (!envelope) {
        throw new Error("Envelope not found");
      }
      return envelope;
    },

    async writeEnvelope(envelope): Promise<WriteResult> {
      const path = envelopePath(envelope.scope, envelope.collectedAt);
      const sizeBytes = await fileStore.writeEnvelope(path, envelope);
      if (fileStore.kind !== "indexeddb") {
        await fallbackStore.deleteEnvelope(path);
      }
      await persist();
      return {
        path,
        relativePath: path,
        sizeBytes,
      };
    },

    async readScopeBlocks(scope, collectedAt, options) {
      const manifestPath = blockManifestPath(scope, collectedAt);
      const manifest =
        (await fileStore.readBlockManifest?.(manifestPath)) ??
        (fileStore === fallbackStore
          ? null
          : await fallbackStore.readBlockManifest?.(manifestPath)) ??
        null;
      if (!manifest) {
        throw new DataBlockStorageError(
          "block_manifest_not_found",
          `Block manifest not found for ${scope} at ${collectedAt}`,
        );
      }

      const cursorResult = options.cursor
        ? validateDataBlockCursor(options.cursor, { scope, collectedAt })
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
        if (!ref) {
          nextIndex += 1;
          continue;
        }
        const offset = nextIndex === startIndex ? startOffset : 0;
        if (offset >= ref.sizeBytes) {
          nextIndex += 1;
          continue;
        }
        if (
          blocks.length > 0 &&
          offset === 0 &&
          bytes + ref.sizeBytes > maxBytes
        ) {
          break;
        }
        const block = await readBlockPayloadFromStores(
          fileStore,
          fallbackStore,
          blockPayloadPath(scope, collectedAt, ref.id),
        );
        if (!block) {
          throw new DataBlockStorageError(
            "block_payload_not_found",
            `Block payload not found for ${scope} at ${collectedAt}: ${ref.id}`,
          );
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
    },

    async hasScopeBlocks(scope, collectedAt) {
      const manifestPath = blockManifestPath(scope, collectedAt);
      const manifest =
        (await fileStore.readBlockManifest?.(manifestPath)) ??
        (fileStore === fallbackStore
          ? null
          : await fallbackStore.readBlockManifest?.(manifestPath)) ??
        null;
      return Boolean(manifest);
    },

    async writeBlockManifest(scope, collectedAt, manifest, blocks) {
      if (!fileStore.writeBlockManifest || !fileStore.writeBlockPayload) {
        throw new Error("Block sidecar storage is not available");
      }
      await fileStore.deleteBlockTree?.(blockTreePath(scope, collectedAt));
      for (const block of blocks) {
        await fileStore.writeBlockPayload(
          blockPayloadPath(scope, collectedAt, block.id),
          block,
        );
      }
      await fileStore.writeBlockManifest(
        blockManifestPath(scope, collectedAt),
        manifest,
      );
      if (fileStore.kind !== "indexeddb") {
        await fallbackStore.deleteBlockTree?.(
          blockTreePath(scope, collectedAt),
        );
      }
      await persist();
    },

    async insertEntry(entry) {
      const indexed: IndexEntry = {
        ...entry,
        schemaId: entry.schemaId ?? null,
        id: state.nextId,
        createdAt: new Date().toISOString(),
      };
      state = {
        ...state,
        nextId: state.nextId + 1,
        entries: [
          ...state.entries.filter((item) => item.path !== entry.path),
          indexed,
        ],
      };
      await persist();
      return indexed;
    },

    async updateFileId(path, fileId) {
      let updated = false;
      state = {
        ...state,
        entries: state.entries.map((entry) => {
          if (entry.path !== path) return entry;
          updated = true;
          return { ...entry, fileId };
        }),
      };
      if (updated) {
        await persist();
      }
      return updated;
    },

    async deleteScope(scope) {
      let deleted = 0;
      const deletedPaths: string[] = [];
      const deletedBlockTrees: string[] = [];
      state = {
        ...state,
        entries: state.entries.filter((entry) => {
          if (entry.scope !== scope) return true;
          deleted += 1;
          deletedPaths.push(envelopePath(entry.scope, entry.collectedAt));
          deletedBlockTrees.push(blockTreePath(entry.scope, entry.collectedAt));
          return false;
        }),
      };
      await Promise.all(
        [
          ...deletedPaths.flatMap((path) => [
            fileStore.deleteEnvelope(path),
            fallbackStore.deleteEnvelope(path),
          ]),
          ...deletedBlockTrees.flatMap((path) => [
            fileStore.deleteBlockTree?.(path),
            fallbackStore.deleteBlockTree?.(path),
          ]),
        ].filter((promise): promise is Promise<void> => promise !== undefined),
      );
      await persist();
      return deleted;
    },

    async deleteByFileId(fileId) {
      const entry = state.entries.find((e) => e.fileId === fileId);
      if (!entry) return false;
      const blobPath = envelopePath(entry.scope, entry.collectedAt);
      // Delete the blob FIRST (both stores tolerate a missing blob); only drop the index row once
      // the blob is gone. If blob deletion throws for a real reason, the row is preserved so the
      // next sync retry re-attempts instead of orphaning the local blob.
      await Promise.all([
        fileStore.deleteEnvelope(blobPath),
        fallbackStore.deleteEnvelope(blobPath),
        fileStore.deleteBlockTree?.(
          blockTreePath(entry.scope, entry.collectedAt),
        ) ?? Promise.resolve(),
        fallbackStore.deleteBlockTree?.(
          blockTreePath(entry.scope, entry.collectedAt),
        ) ?? Promise.resolve(),
      ]);
      state = {
        ...state,
        entries: state.entries.filter((e) => e !== entry),
      };
      await persist();
      return true;
    },
  };

  if (fileStore.readEnvelopePreview) {
    storagePort.readEnvelopePreview = async (
      scope,
      collectedAt,
      { maxBytes },
    ) => {
      const path = envelopePath(scope, collectedAt);
      const primaryPreview = await readPreviewFromFileStore(
        fileStore,
        path,
        maxBytes,
      );
      const preview =
        primaryPreview ??
        (fileStore === fallbackStore
          ? null
          : await readPreviewFromFileStore(fallbackStore, path, maxBytes));
      if (!preview) {
        throw new Error("Envelope not found");
      }
      return preview;
    };
  }

  return storagePort;
}

async function readPreviewFromFileStore(
  store: PsLiteDataFileStore,
  path: string,
  maxBytes: number,
): Promise<{ text: string; truncated: boolean } | null> {
  return (await store.readEnvelopePreview?.(path, { maxBytes })) ?? null;
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

async function readBlockPayloadFromStores(
  primary: PsLiteDataFileStore,
  fallback: PsLiteDataFileStore,
  path: string,
): Promise<DataScopeBlock | null> {
  return (
    (await primary.readBlockPayload?.(path)) ??
    (primary === fallback ? null : await fallback.readBlockPayload?.(path)) ??
    null
  );
}
