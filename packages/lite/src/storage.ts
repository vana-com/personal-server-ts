import { hasPdppOrigin } from "@opendatalabs/personal-server-ts-core/sync";
import {
  canonicalJson,
  envelopeGeneration,
} from "@opendatalabs/personal-server-ts-core/storage/hierarchy";
import type {
  DataStoragePort,
  BoundedEnvelopeRead,
} from "@opendatalabs/personal-server-ts-core/ports";
import {
  boundedJsonByteLength,
  StoredEnvelopeReadError,
} from "@opendatalabs/personal-server-ts-core/storage/disclosure-policy";
import type {
  DataBlockManifest,
  DataScopeBlock,
} from "@opendatalabs/personal-server-ts-core/storage/blocks";
import { buildDataBlocksAsync } from "@opendatalabs/personal-server-ts-core/storage/blocks";
import {
  DataBlockStorageError,
  readManifestScopeBlocks,
} from "@opendatalabs/personal-server-ts-core/storage/blocks";
import type { DataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import type { WriteResult } from "@opendatalabs/personal-server-ts-core/storage/hierarchy";
import type { IndexEntry } from "@opendatalabs/personal-server-ts-core/storage/index";
import { withScopeLock } from "@opendatalabs/personal-server-ts-core/additions";
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
  /** Paths of committed sidecars; inventory never reads file bodies. */
  readyBlockManifests?: string[];
  blockManifests?: Array<{
    path: string;
    manifest: DataBlockManifest;
  }>;
  blockPayloads?: Array<{
    path: string;
    block: DataScopeBlock;
  }>;
  /**
   * Scopes whose first-seen ledger side record could not be deleted along
   * with their data. Retried when the storage loads and on the next ledger
   * delete; until then the leftover is harmless (it is never read once its
   * newest version is gone).
   */
  pendingLedgerDeletes?: string[];
}

export type PsLiteFileStorageKind = "opfs" | "indexeddb" | "custom";

export interface PsLiteDataFileStore {
  readonly kind: PsLiteFileStorageKind;
  readEnvelope(path: string): Promise<DataFileEnvelope | null>;
  /** Enforce the byte bound before parsing or cloning a stored input. */
  readEnvelopeBounded?(
    path: string,
    options: { maxBytes: number },
  ): Promise<BoundedEnvelopeRead | null>;
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

/** Persistent Lite storage with its public backend capability report. */
export interface PsLiteStoragePort extends DataStoragePort {
  readonly capabilities: PsLiteStorageCapabilities;
}

export interface PsLitePersistenceAdapter {
  read(): Promise<PsLitePersistedStorageState | null>;
  write(state: PsLitePersistedStorageState): Promise<void>;
  /**
   * Optional named side records, each stored and rewritten on its own so a
   * big one never inflates the main state. Used for the per-scope first-seen
   * ledgers. An adapter without them keeps ledgers in memory only, and they
   * are rebuilt from the stored versions after a reload.
   */
  readAux?(name: string): Promise<unknown | null>;
  writeAux?(name: string, value: unknown): Promise<void>;
  deleteAux?(name: string): Promise<void>;
}

export interface IndexedDbPsLitePersistenceOptions {
  dbName?: string;
  storeName?: string;
  key?: string;
}

const DEFAULT_INDEXED_DB_NAME = "personal-server-lite-storage";
const DEFAULT_INDEXED_DB_STORE = "state";
const DEFAULT_INDEXED_DB_KEY = "data-storage-v1";

function schemaIdFromEnvelope(envelope: DataFileEnvelope): string | undefined {
  const schemaId = (envelope as { schemaId?: unknown }).schemaId;
  return typeof schemaId === "string" ? schemaId : undefined;
}

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
    readyBlockManifests: state.readyBlockManifests ?? [],
    blockManifests: state.blockManifests ?? [],
    blockPayloads: state.blockPayloads ?? [],
    ...(state.pendingLedgerDeletes?.length
      ? { pendingLedgerDeletes: state.pendingLedgerDeletes }
      : {}),
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
    async readEnvelopeBounded(path, { maxBytes }) {
      const envelope = envelopes.get(path);
      if (!envelope) return null;
      const byteLength = boundedJsonByteLength(envelope, maxBytes);
      return { envelope: structuredClone(envelope), byteLength };
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

function describeStorageError(error: unknown): {
  errorClass: string;
  message: string;
} {
  if (error instanceof Error) {
    return { errorClass: error.name, message: error.message };
  }
  return { errorClass: typeof error, message: String(error) };
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
    async readEnvelopeBounded(path, { maxBytes }) {
      try {
        const file = await (await getOpfsFileHandle(root, path)).getFile();
        if (file.size > maxBytes) {
          throw new StoredEnvelopeReadError(
            "too_large",
            "The stored input exceeds this read's byte allowance",
          );
        }
        return {
          envelope: JSON.parse(await file.text()) as DataFileEnvelope,
          byteLength: file.size,
        };
      } catch (error) {
        if (error instanceof DOMException && error.name === "NotFoundError")
          return null;
        throw error;
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
    // Side records live in the same object store under their own keys, which
    // a build that only knows `resolved.key` never reads.
    async readAux(name) {
      const value = await runIndexedDbTransaction<unknown>(
        resolved,
        "readonly",
        (store) => store.get(`${resolved.key}:${name}`),
      );
      return value ?? null;
    },
    async writeAux(name, value) {
      await runIndexedDbTransaction<IDBValidKey>(
        resolved,
        "readwrite",
        (store) => store.put(value, `${resolved.key}:${name}`),
      );
    },
    async deleteAux(name) {
      await runIndexedDbTransaction<undefined>(resolved, "readwrite", (store) =>
        store.delete(`${resolved.key}:${name}`),
      );
    },
  };
}

/** Publications in this realm when the Web Locks API is not available. */
const realmPublications = new Map<string, Promise<unknown>>();

/**
 * Run a compare-and-publish of one version path exclusively, across every
 * storage instance that shares the file store: other tabs and workers through
 * the Web Locks API, other instances in this realm through a shared chain.
 * The comparison inside reads the file store, never one instance's memory.
 */
function withPublicationLock<T>(
  path: string,
  publish: () => Promise<T>,
): Promise<T> {
  const locks = (
    globalThis as {
      navigator?: {
        locks?: {
          request<R>(name: string, callback: () => Promise<R>): Promise<R>;
        };
      };
    }
  ).navigator?.locks;
  if (locks) return locks.request(`ps-lite:publish:${path}`, publish);
  const previous = realmPublications.get(path) ?? Promise.resolve();
  const next = previous.then(publish, publish);
  const settled = next.catch(() => undefined);
  realmPublications.set(path, settled);
  void settled.then(() => {
    if (realmPublications.get(path) === settled) realmPublications.delete(path);
  });
  return next;
}

export async function createPersistentPsLiteStorage(
  adapter: PsLiteStorageAdapter,
  persistence: PsLitePersistenceAdapter = createIndexedDbPsLitePersistence(),
  dataFileStore?: PsLiteDataFileStore,
): Promise<PsLiteStoragePort> {
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
  const readyBlockManifests = new Set([
    ...(state.readyBlockManifests ?? []),
    ...fallbackBlockManifests.keys(),
  ]);
  const fallbackBlockPayloads = new Map(
    (state.blockPayloads ?? []).map(({ path, block }) => [path, block]),
  );
  // First-seen ledgers: each persisted on its own (`persistence.*Aux`), read
  // lazily, never part of the main state. A ledger the previous build kept
  // inside the main state is ignored: it is a cache, rebuilt on demand.
  const ledgerAux = (scope: string) => `first-seen:${scope}`;
  const firstSeenLedgers = new Map<string, unknown>();
  const pendingLedgerDeletes = new Set<string>(
    state.pendingLedgerDeletes ?? [],
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
      readyBlockManifests: Array.from(readyBlockManifests),
      envelopes:
        fileStore.kind === "indexeddb"
          ? Array.from(fallbackEnvelopes.values())
          : [],
      blockManifests: Array.from(fallbackBlockManifests.entries()).map(
        ([path, manifest]) => ({ path, manifest }),
      ),
      blockPayloads: Array.from(fallbackBlockPayloads.entries()).map(
        ([path, block]) => ({ path, block }),
      ),
      pendingLedgerDeletes:
        pendingLedgerDeletes.size > 0
          ? Array.from(pendingLedgerDeletes)
          : undefined,
    };
    const write = persistQueue.then(() => persistence.write(snapshot));
    persistQueue = write.catch(() => undefined);
    await write;
  }

  async function readPublishedEnvelope(
    path: string,
  ): Promise<DataFileEnvelope | null> {
    return (
      (await fileStore.readEnvelope(path)) ??
      (fileStore === fallbackStore
        ? null
        : await fallbackStore.readEnvelope(path))
    );
  }

  /**
   * PDPP provenance and generation of the bytes at a version path, both from
   * one read; empty if unreadable.
   */
  async function identityOfPublishedBytes(
    path: string,
  ): Promise<{ pdppOrigin?: boolean; generation?: string }> {
    try {
      const envelope = await readPublishedEnvelope(path);
      return envelope
        ? {
            pdppOrigin: hasPdppOrigin(envelope),
            generation: envelopeGeneration(envelope),
          }
        : {};
    } catch {
      return {};
    }
  }

  function entriesForScope(scope: string): IndexEntry[] {
    return sortEntries(state.entries.filter((entry) => entry.scope === scope));
  }

  const storagePort: PsLiteStoragePort = {
    kind: adapter.kind === "custom" ? "custom" : "browser-indexeddb-opfs",
    capabilities,
    ...createStorageReadMethods(() => state.entries, entriesForScope),

    findByFileId(fileId) {
      return state.entries.find((entry) => entry.fileId === fileId);
    },

    findByDataPointId(dataPointId) {
      let newest: IndexEntry | undefined;
      for (const entry of state.entries) {
        if (entry.dataPointId !== dataPointId) continue;
        if (!newest || entry.version >= newest.version) newest = entry;
      }
      return newest;
    },

    findUnsynced(options) {
      const entries = state.entries
        .filter((entry) => entry.dataPointId === null)
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
    async readEnvelopeBounded(scope, collectedAt, limits) {
      const path = envelopePath(scope, collectedAt);
      if (!fileStore.readEnvelopeBounded) {
        throw new StoredEnvelopeReadError(
          "bounded_read_unavailable",
          "The custom Lite file store has no bounded stored-input read",
        );
      }
      const read =
        (await fileStore.readEnvelopeBounded(path, limits)) ??
        (fileStore === fallbackStore
          ? null
          : await fallbackStore.readEnvelopeBounded!(path, limits));
      if (!read) throw new Error("Envelope not found");
      return read;
    },

    /**
     * Publish a version without replacing one. A version path names
     * immutable bytes: readers authorize the version they selected, including
     * its PDPP provenance, before reading the path. The same envelope, in any
     * key order, republishes idempotently (this also moves an IndexedDB
     * fallback copy into OPFS); a different envelope fails.
     */
    async writeEnvelope(envelope): Promise<WriteResult> {
      const path = envelopePath(envelope.scope, envelope.collectedAt);
      return withPublicationLock(path, async () => {
        const published = await readPublishedEnvelope(path);
        // An index row whose bytes were lost still names its version: new
        // bytes may restore it only with the provenance the row records.
        const indexed = state.entries.find((entry) => entry.path === path);
        if (
          (published && canonicalJson(published) !== canonicalJson(envelope)) ||
          (indexed?.pdppOrigin !== undefined &&
            indexed.pdppOrigin !== hasPdppOrigin(envelope))
        ) {
          throw new Error(
            `Stored envelope conflicts with publication at ${path}`,
          );
        }
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
      });
    },

    async readScopeBlocks(scope, collectedAt, options) {
      const manifestPath = blockManifestPath(scope, collectedAt);
      let manifest =
        (await fileStore.readBlockManifest?.(manifestPath)) ??
        (fileStore === fallbackStore
          ? null
          : await fallbackStore.readBlockManifest?.(manifestPath)) ??
        null;
      let inMemoryBlocks: DataScopeBlock[] | null = null;
      if (!manifest) {
        const envelope = await storagePort.readEnvelope(scope, collectedAt);
        const built = await buildDataBlocksAsync({
          scope,
          collectedAt,
          schemaId: schemaIdFromEnvelope(envelope),
          content: envelope,
        });
        manifest = built.manifest;
        inMemoryBlocks = built.blocks;
        try {
          await storagePort.writeBlockManifest?.(
            scope,
            collectedAt,
            built.manifest,
            built.blocks,
          );
        } catch (error) {
          console.warn(
            {
              scope,
              collectedAt,
              ...describeStorageError(error),
            },
            "Block sidecar cache write failed; serving read from local envelope",
          );
        }
      }

      const load = async (id: string) =>
        inMemoryBlocks?.find((b) => b.id === id) ??
        (await readBlockPayloadFromStores(
          fileStore,
          fallbackStore,
          blockPayloadPath(scope, collectedAt, id),
        ));
      try {
        return await readManifestScopeBlocks(manifest, load, options);
      } catch (error) {
        if (
          !(error instanceof DataBlockStorageError) ||
          error.code !== "block_payload_not_found"
        )
          throw error;
        const envelope = await storagePort.readEnvelope(scope, collectedAt);
        const built = await buildDataBlocksAsync({
          scope,
          collectedAt,
          schemaId: schemaIdFromEnvelope(envelope),
          content: envelope,
        });
        inMemoryBlocks = built.blocks;
        // Same cursor is validated against the rebuilt representation before any offsets are consumed.
        return readManifestScopeBlocks(built.manifest, load, options);
      }
    },

    async readBlockManifest(scope, collectedAt) {
      const manifestPath = blockManifestPath(scope, collectedAt);
      return (
        (await fileStore.readBlockManifest?.(manifestPath)) ??
        (fileStore === fallbackStore
          ? null
          : await fallbackStore.readBlockManifest?.(manifestPath)) ??
        null
      );
    },

    async hasScopeBlocks(scope, collectedAt) {
      return readyBlockManifests.has(blockManifestPath(scope, collectedAt));
    },

    async canReadScopeBlocks(scope, collectedAt) {
      if (await storagePort.hasScopeBlocks?.(scope, collectedAt)) {
        return true;
      }
      const path = envelopePath(scope, collectedAt);
      const preview =
        (await readPreviewFromFileStore(fileStore, path, 1)) ??
        (fileStore === fallbackStore
          ? null
          : await readPreviewFromFileStore(fallbackStore, path, 1));
      if (preview) return true;
      const envelope =
        (await fileStore.readEnvelope(path)) ??
        (fileStore === fallbackStore
          ? null
          : await fallbackStore.readEnvelope(path));
      return Boolean(envelope);
    },

    async writeBlockManifest(scope, collectedAt, manifest, blocks) {
      // Invalidate before replacing a tree; a failed build is not ready.
      readyBlockManifests.delete(blockManifestPath(scope, collectedAt));
      await persist();
      const writeTree = async (store: PsLiteDataFileStore) => {
        if (!store.writeBlockManifest || !store.writeBlockPayload) {
          throw new Error("Block sidecar storage is not available");
        }
        await store.deleteBlockTree?.(blockTreePath(scope, collectedAt));
        for (const block of blocks) {
          await store.writeBlockPayload(
            blockPayloadPath(scope, collectedAt, block.id),
            block,
          );
        }
        await store.writeBlockManifest(
          blockManifestPath(scope, collectedAt),
          manifest,
        );
      };

      let wrotePrimary = false;
      try {
        await writeTree(fileStore);
        wrotePrimary = true;
      } catch (error) {
        if (fileStore === fallbackStore) {
          throw error;
        }
        console.warn(
          {
            scope,
            collectedAt,
            fileStoreKind: fileStore.kind,
            fallbackStoreKind: fallbackStore.kind,
            ...describeStorageError(error),
          },
          "Primary block sidecar write failed; using IndexedDB fallback",
        );
        await writeTree(fallbackStore);
      }

      if (wrotePrimary && fileStore.kind !== "indexeddb") {
        await fallbackStore.deleteBlockTree?.(
          blockTreePath(scope, collectedAt),
        );
      }
      readyBlockManifests.add(blockManifestPath(scope, collectedAt));
      await persist();
    },

    async insertEntry(entry) {
      // Storage derives provenance and generation from the bytes it
      // published; a caller's values are never trusted. Lite has no stream
      // read, so it records no content digest and drops a caller's. The row is indexed
      // first, synchronously, so index writes keep their order; its identity
      // follows from the read.
      const {
        pdppOrigin: _callerOrigin,
        generation: _callerGeneration,
        contentDigest: _callerDigest,
        ...callerEntry
      } = entry;
      const version =
        entry.version ??
        state.entries.reduce(
          (max, e) =>
            e.scope === entry.scope && e.version > max ? e.version : max,
          0,
        ) + 1;
      const indexed: IndexEntry = {
        ...callerEntry,
        schemaId: entry.schemaId ?? null,
        version,
        dataPointId: entry.dataPointId ?? null,
        afterTombstoneVersion: entry.afterTombstoneVersion ?? null,
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
      const identity = await identityOfPublishedBytes(entry.path);
      if (identity.pdppOrigin !== undefined) {
        state = {
          ...state,
          entries: state.entries.map((item) =>
            item.path === entry.path && item.id === indexed.id
              ? { ...item, ...identity }
              : item,
          ),
        };
      }
      await persist();
      return identity.pdppOrigin === undefined
        ? indexed
        : { ...indexed, ...identity };
    },

    async backfillGeneration(entry) {
      // The row as the index holds it, never the caller's copy.
      const row = state.entries.find(
        (item) => item.id === entry.id && item.path === entry.path,
      );
      if (!row) return undefined;
      if (row.generation) return row.generation;
      type Identity = { pdppOrigin?: boolean; generation?: string };
      // Provenance and generation change together, only while the row still
      // holds exactly `expected`.
      const swap = (expected: Identity, next: Identity) => {
        let swapped = false;
        state = {
          ...state,
          entries: state.entries.map((item) => {
            if (
              item.id !== row.id ||
              item.pdppOrigin !== expected.pdppOrigin ||
              item.generation !== expected.generation
            ) {
              return item;
            }
            swapped = true;
            const {
              pdppOrigin: _origin,
              generation: _generation,
              ...rest
            } = item;
            return {
              ...rest,
              ...(next.pdppOrigin === undefined
                ? {}
                : { pdppOrigin: next.pdppOrigin }),
              ...(next.generation === undefined
                ? {}
                : { generation: next.generation }),
            };
          }),
        };
        return swapped;
      };
      const first = await identityOfPublishedBytes(row.path);
      if (!first.generation || first.pdppOrigin === undefined) {
        return undefined;
      }
      // Provenance is taken from the bytes with the generation. It may only
      // become stricter: a row recorded as PDPP never becomes legacy.
      if (row.pdppOrigin === true && !first.pdppOrigin) return undefined;
      const before: Identity = { pdppOrigin: row.pdppOrigin };
      const after: Identity = {
        pdppOrigin: first.pdppOrigin,
        generation: first.generation,
      };
      if (!swap(before, after)) {
        const current = state.entries.find((item) => item.id === row.id);
        return current?.generation;
      }
      // The bytes are read again: a version replaced between the two reads
      // is not recorded.
      const second = await identityOfPublishedBytes(row.path);
      if (
        second.generation !== first.generation ||
        second.pdppOrigin !== first.pdppOrigin
      ) {
        // Roll back the disputed generation, never the provenance to a
        // looser value: if either read saw PDPP bytes, the row stays PDPP.
        swap(after, {
          pdppOrigin:
            before.pdppOrigin === true ||
            first.pdppOrigin === true ||
            second.pdppOrigin === true
              ? true
              : before.pdppOrigin,
        });
        await persist();
        return undefined;
      }
      await persist();
      return first.generation;
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

    findLatestVersionByScope(scope) {
      return state.entries.reduce(
        (max, e) => (e.scope === scope && e.version > max ? e.version : max),
        0,
      );
    },

    async updateDataPointId(path, dataPointId) {
      let updated = false;
      state = {
        ...state,
        entries: state.entries.map((entry) => {
          if (entry.path !== path) return entry;
          updated = true;
          return { ...entry, dataPointId };
        }),
      };
      if (updated) {
        await persist();
      }
      return updated;
    },

    async updateEntryVersion(path, version) {
      let updated = false;
      state = {
        ...state,
        entries: state.entries.map((entry) => {
          if (entry.path !== path) return entry;
          updated = true;
          return { ...entry, version };
        }),
      };
      if (updated) {
        await persist();
      }
      return updated;
    },

    async readFirstSeenLedger(scope) {
      if (!firstSeenLedgers.has(scope)) {
        const stored = (await persistence.readAux?.(ledgerAux(scope))) ?? null;
        if (stored !== null) firstSeenLedgers.set(scope, stored);
      }
      return structuredClone(firstSeenLedgers.get(scope) ?? null);
    },

    async writeFirstSeenLedger(scope, ledger) {
      firstSeenLedgers.set(scope, structuredClone(ledger));
      await persistence.writeAux?.(ledgerAux(scope), ledger);
    },

    async deleteFirstSeenLedger(scope) {
      firstSeenLedgers.delete(scope);
      await persistence.deleteAux?.(ledgerAux(scope));
    },

    // Deletions run under the scope's first-seen sidecar lock (a rebuild in
    // flight cannot write it back), and the sidecar goes with the scope's last
    // version, so no delete path leaves a stale ledger behind.
    deleteScope(scope) {
      return withScopeLock(scope, async () => {
        await dropLedger(scope);
        for (const entry of entriesForScope(scope)) {
          readyBlockManifests.delete(
            blockManifestPath(scope, entry.collectedAt),
          );
        }
        // Repeat the barrier on retry, even if a failed write cleared the set.
        await persist();
        let deleted = 0;
        const deletedPaths: string[] = [];
        const deletedBlockTrees: string[] = [];
        state = {
          ...state,
          entries: state.entries.filter((entry) => {
            if (entry.scope !== scope) return true;
            deleted += 1;
            deletedPaths.push(envelopePath(entry.scope, entry.collectedAt));
            deletedBlockTrees.push(
              blockTreePath(entry.scope, entry.collectedAt),
            );
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
          ].filter(
            (promise): promise is Promise<void> => promise !== undefined,
          ),
        );
        await persist();
        return deleted;
      });
    },

    async deleteVersion(scope, collectedAt) {
      const entry = state.entries.find(
        (e) => e.scope === scope && e.collectedAt === collectedAt,
      );
      if (!entry) return false;
      return removeEntry(entry);
    },

    async deleteByFileId(fileId) {
      const entry = state.entries.find((e) => e.fileId === fileId);
      if (!entry) return false;
      return removeEntry(entry);
    },
  };

  /**
   * Delete a scope's ledger side record without ever blocking the data
   * delete that asked for it: a failure leaves the scope on the pending list,
   * which is retried on load and on the next call.
   */
  async function dropLedger(scope: string): Promise<void> {
    const attempt = async (name: string): Promise<boolean> => {
      try {
        await storagePort.deleteFirstSeenLedger!(name);
        return true;
      } catch {
        return false;
      }
    };
    const before = pendingLedgerDeletes.size;
    if (await attempt(scope)) pendingLedgerDeletes.delete(scope);
    else pendingLedgerDeletes.add(scope);
    for (const other of [...pendingLedgerDeletes]) {
      if (other === scope) continue;
      const stillStored = state.entries.some((e) => e.scope === other);
      if (stillStored || (await attempt(other)))
        pendingLedgerDeletes.delete(other);
    }
    if (pendingLedgerDeletes.size !== before) {
      await persist().catch(() => undefined);
    }
  }

  async function removeEntry(entry: IndexEntry): Promise<boolean> {
    return withScopeLock(entry.scope, () => removeEntryLocked(entry));
  }

  async function removeEntryLocked(entry: IndexEntry): Promise<boolean> {
    const blobPath = envelopePath(entry.scope, entry.collectedAt);
    // Delete the blob FIRST (both stores tolerate a missing blob); only drop the index row once
    // the blob is gone. If blob deletion throws for a real reason, the row is preserved so the
    // next sync retry re-attempts instead of orphaning the local blob.
    // A partial delete can remove the tree while leaving the index row.
    // Persist the conservative hint before any destructive file operation.
    readyBlockManifests.delete(
      blockManifestPath(entry.scope, entry.collectedAt),
    );
    await persist();
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
    // The sidecar goes with the scope's last version.
    await persist();
    if (!state.entries.some((e) => e.scope === entry.scope)) {
      await dropLedger(entry.scope);
    }
    return true;
  }

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

  // Collect leftovers from an earlier failed ledger delete.
  if (pendingLedgerDeletes.size > 0) {
    for (const scope of [...pendingLedgerDeletes]) {
      if (state.entries.some((e) => e.scope === scope)) {
        pendingLedgerDeletes.delete(scope);
        continue;
      }
      try {
        await storagePort.deleteFirstSeenLedger!(scope);
        pendingLedgerDeletes.delete(scope);
      } catch {
        // Still pending; retried on the next ledger delete.
      }
    }
    await persist().catch(() => undefined);
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
