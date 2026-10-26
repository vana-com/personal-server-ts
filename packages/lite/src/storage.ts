import type {
  DataStoragePort,
  DataVersionWriter,
} from "@opendatalabs/personal-server-ts-core/ports";
import type {
  DataBlockManifest,
  DataScopeBlock,
} from "@opendatalabs/personal-server-ts-core/storage/blocks";
import { buildDataBlocksAsync } from "@opendatalabs/personal-server-ts-core/storage/blocks";
import {
  DataBlockStorageError,
  encodeDataBlockCursor,
  selectScopeBlocksByIds,
  validateDataBlockCursor,
} from "@opendatalabs/personal-server-ts-core/storage/blocks";
import type { DataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import type { WriteResult } from "@opendatalabs/personal-server-ts-core/storage/hierarchy";
import type {
  IndexEntry,
  NewIndexEntry,
} from "@opendatalabs/personal-server-ts-core/storage/index";
import { withScopeLock } from "@opendatalabs/personal-server-ts-core/additions";
import { IngestPersistedError } from "@opendatalabs/personal-server-ts-core/contracts";
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
  readEnvelopePreview?(
    path: string,
    options: { maxBytes: number },
  ): Promise<{ text: string; truncated: boolean } | null>;
  writeEnvelope(path: string, envelope: DataFileEnvelope): Promise<number>;
  /**
   * Write one envelope as a sequence of text pieces. Nothing is at `path`
   * until `commit`; `abort`, or a crash before `commit`, leaves the path as
   * it was. Stores without it cannot take streamed scope uploads.
   */
  openEnvelopeWriter?(path: string): Promise<PsLiteEnvelopeWriter>;
  deleteEnvelope(path: string): Promise<void>;
  readBlockManifest?(path: string): Promise<DataBlockManifest | null>;
  writeBlockManifest?(path: string, manifest: DataBlockManifest): Promise<void>;
  readBlockPayload?(path: string): Promise<DataScopeBlock | null>;
  writeBlockPayload?(path: string, block: DataScopeBlock): Promise<void>;
  deleteBlockTree?(pathPrefix: string): Promise<void>;
}

/** One envelope file being written by `PsLiteDataFileStore.openEnvelopeWriter`. */
export interface PsLiteEnvelopeWriter {
  /** Append text. Calls must not overlap. */
  write(text: string): Promise<void>;
  /** Make the file visible at its path; resolves to its size in bytes. */
  commit(): Promise<number>;
  /** Discard what was written. Idempotent. */
  abort(): Promise<void>;
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
const TEXT_PAGE_MEDIA_TYPE = "text/plain; charset=utf-8";
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

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
    async openEnvelopeWriter(path) {
      const parts = path.split("/").filter(Boolean);
      const fileName = parts.pop();
      if (!fileName) throw new Error("OPFS path must include a file name");
      const dir = await getOrCreateOpfsDirectory(root, parts);
      const handle = await dir.getFileHandle(fileName, { create: true });
      // A writable stream writes to a swap file; `close` replaces the file in
      // one step and `abort` drops the swap file.
      const writable = await handle.createWritable();
      let sizeBytes = 0;
      let open = true;
      return {
        async write(text) {
          const bytes = textEncoder.encode(text);
          await writable.write(bytes);
          sizeBytes += bytes.byteLength;
        },
        async commit() {
          open = false;
          await writable.close();
          return sizeBytes;
        },
        async abort() {
          if (!open) return;
          open = false;
          await writable.abort();
          // `create: true` left an empty, unindexed file at the path.
          await dir.removeEntry(fileName).catch(() => undefined);
        },
      };
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

  // Every write of the persisted state runs in this queue, one at a time, in
  // call order. A snapshot is taken when its turn comes, so each write carries
  // the latest index, and index changes never interleave.
  let persistQueue: Promise<void> = Promise.resolve();

  function enqueue<T>(step: () => Promise<T>): Promise<T> {
    const run = persistQueue.then(step);
    persistQueue = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  function snapshotOf(source: PsLitePersistedStorageState) {
    return {
      ...source,
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
  }

  async function persist(): Promise<void> {
    await enqueue(() => persistence.write(snapshotOf(state)));
  }

  /**
   * Make `next` the live index, once it is durable. Call only inside
   * `enqueue`. A failed write leaves the live index as it was, so a reader
   * never sees a change that could be lost on restart.
   */
  async function publish(next: PsLitePersistedStorageState): Promise<void> {
    await persistence.write(snapshotOf(next));
    state = next;
  }

  /**
   * Replace the live index with `change(index)`. `change` returns null to
   * leave the index alone. Resolves to whether the index was written.
   */
  function updateIndex(
    change: (
      current: PsLitePersistedStorageState,
    ) => PsLitePersistedStorageState | null,
  ): Promise<boolean> {
    return enqueue(async () => {
      const next = change(state);
      if (!next) return false;
      await publish(next);
      return true;
    });
  }

  function updateEntryField(
    path: string,
    patch: Partial<Pick<IndexEntry, "fileId" | "dataPointId" | "version">>,
  ): Promise<boolean> {
    return updateIndex((current) => {
      if (!current.entries.some((entry) => entry.path === path)) return null;
      return {
        ...current,
        entries: current.entries.map((entry) =>
          entry.path === path ? { ...entry, ...patch } : entry,
        ),
      };
    });
  }

  /**
   * Remove a blob that no index entry names, after its index write failed. A
   * blob that an entry does name is kept. Best effort: the commit's own error
   * is what the caller sees.
   */
  function dropUnindexedEnvelope(path: string): Promise<void> {
    return enqueue(async () => {
      if (state.entries.some((entry) => entry.path === path)) return;
      await Promise.all([
        fileStore.deleteEnvelope(path),
        fallbackStore.deleteEnvelope(path),
      ]);
    }).catch(() => undefined);
  }

  /** Install a row at its path, replacing any row there. Caller holds the path lock. */
  async function installEntry(entry: NewIndexEntry): Promise<IndexEntry> {
    let indexed: IndexEntry | undefined;
    await updateIndex((current) => {
      const version =
        entry.version ??
        current.entries.reduce(
          (max, e) =>
            e.scope === entry.scope && e.version > max ? e.version : max,
          0,
        ) + 1;
      indexed = {
        ...entry,
        schemaId: entry.schemaId ?? null,
        version,
        dataPointId: entry.dataPointId ?? null,
        afterTombstoneVersion: entry.afterTombstoneVersion ?? null,
        id: current.nextId,
        createdAt: new Date().toISOString(),
      };
      return {
        ...current,
        nextId: current.nextId + 1,
        entries: [
          ...current.entries.filter((item) => item.path !== entry.path),
          indexed,
        ],
      };
    });
    return indexed!;
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

    async writeEnvelope(envelope): Promise<WriteResult> {
      const path = envelopePath(envelope.scope, envelope.collectedAt);
      const sizeBytes = await withPathLock(path, async () => {
        const size = await fileStore.writeEnvelope(path, envelope);
        if (fileStore.kind !== "indexeddb") {
          await fallbackStore.deleteEnvelope(path);
        }
        return size;
      });
      await persist();
      return {
        path,
        relativePath: path,
        sizeBytes,
      };
    },

    async writeEnvelopeAndIndex(envelope, entry): Promise<IndexEntry> {
      const path = envelopePath(envelope.scope, envelope.collectedAt);
      // The blob and its row are one step under the path lock, so no erase or
      // replacement of this path runs between them.
      return withPathLock(path, async () => {
        const size = await fileStore.writeEnvelope(path, envelope);
        if (fileStore.kind !== "indexeddb") {
          await fallbackStore.deleteEnvelope(path);
        }
        try {
          return await installEntry({
            ...entry,
            scope: envelope.scope,
            collectedAt: envelope.collectedAt,
            path,
            sizeBytes: entry.sizeBytes ?? size,
          });
        } catch (error) {
          // The bytes are durable here; the caller's recovery depends on that.
          throw new IngestPersistedError(path, error);
        }
      });
    },

    ...(fileStore.openEnvelopeWriter
      ? {
          async openVersionWriter(
            scope: string,
            collectedAt: string,
          ): Promise<DataVersionWriter> {
            const path = envelopePath(scope, collectedAt);
            const file = await fileStore.openEnvelopeWriter!(path);
            return {
              write: (text) => file.write(text),
              abort: () => file.abort(),
              async commit(entry): Promise<WriteResult> {
                // The rename and the index install are one step under the path
                // lock, so no erase of this path runs between them.
                return withPathLock(path, async () => {
                  const sizeBytes = await file.commit();
                  try {
                    // The index entry is what makes the version visible.
                    await installEntry({
                      ...entry,
                      scope,
                      collectedAt,
                      path,
                      sizeBytes,
                    });
                  } catch (error) {
                    await dropUnindexedEnvelope(path);
                    throw error;
                  }
                  if (fileStore.kind !== "indexeddb") {
                    await fallbackStore.deleteEnvelope(path);
                  }
                  return { path, relativePath: path, sizeBytes };
                });
              },
            };
          },
        }
      : {}),

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

      if (options.blockIds?.length) {
        const selection = await selectScopeBlocksByIds(
          manifest,
          options.blockIds,
          { maxBytes: options.maxBytes },
          async (blockId) =>
            inMemoryBlocks?.find((candidate) => candidate.id === blockId) ??
            (await readBlockPayloadFromStores(
              fileStore,
              fallbackStore,
              blockPayloadPath(scope, collectedAt, blockId),
            )),
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
        const block =
          inMemoryBlocks?.find((candidate) => candidate.id === ref.id) ??
          (await readBlockPayloadFromStores(
            fileStore,
            fallbackStore,
            blockPayloadPath(scope, collectedAt, ref.id),
          ));
        if (!block) {
          const envelope = await storagePort.readEnvelope(scope, collectedAt);
          const rebuilt = await buildDataBlocksAsync({
            scope,
            collectedAt,
            schemaId: schemaIdFromEnvelope(envelope),
            content: envelope,
          });
          manifest = rebuilt.manifest;
          inMemoryBlocks = rebuilt.blocks;
          nextIndex = startIndex;
          nextOffset = undefined;
          bytes = 0;
          blocks.length = 0;
          continue;
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

    insertEntry(entry) {
      return withPathLock(entry.path, () => installEntry(entry));
    },

    updateFileId(path, fileId) {
      return updateEntryField(path, { fileId });
    },

    findLatestVersionByScope(scope) {
      return state.entries.reduce(
        (max, e) => (e.scope === scope && e.version > max ? e.version : max),
        0,
      );
    },

    updateDataPointId(path, dataPointId) {
      return updateEntryField(path, { dataPointId });
    },

    updateEntryVersion(path, version) {
      return updateEntryField(path, { version });
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

    // The ledger barrier runs under the scope lock (a rebuild in flight cannot
    // write it back). Each row is then erased under its own path lock, the
    // same owner an ordinary write takes, so no write to a path interleaves
    // with the erase of that path. The scope lock is never held across those
    // path locks: lock order is path, scope, queue.
    async deleteScope(scope) {
      await withScopeLock(scope, async () => {
        await dropLedger(scope);
        for (const entry of entriesForScope(scope)) {
          readyBlockManifests.delete(
            blockManifestPath(scope, entry.collectedAt),
          );
        }
        // Repeat the barrier on retry, even if a failed write cleared the set.
        await persist();
      });
      // A row a later write adds is not in this snapshot; it is not deleted.
      const paths = await enqueue(async () =>
        Array.from(
          new Set(
            state.entries
              .filter((entry) => entry.scope === scope)
              .map((entry) => entry.path),
          ),
        ),
      );
      // Each path settles on its own, so one failed blob delete does not stop
      // the others. Rows whose delete failed stay, for the next retry.
      const outcomes = await Promise.allSettled(
        paths.map((path) =>
          withPathLock(path, () =>
            eraseUnderPathLock(
              path,
              (e) => e.scope === scope && e.path === path,
            ),
          ),
        ),
      );
      const failed = outcomes.find(
        (outcome): outcome is PromiseRejectedResult =>
          outcome.status === "rejected",
      );
      if (failed) throw failed.reason;
      return outcomes.filter(
        (outcome) => outcome.status === "fulfilled" && outcome.value === true,
      ).length;
    },

    // Unfenced: by (scope, collectedAt) alone. Fenced: only the row the caller
    // decided on, by its id and path.
    deleteVersion(scope, collectedAt, fence) {
      // The path is fixed by (scope, collectedAt), so the lock is known now.
      const path = envelopePath(scope, collectedAt);
      return withPathLock(path, () =>
        eraseUnderPathLock(
          path,
          (e) =>
            e.scope === scope &&
            e.collectedAt === collectedAt &&
            e.path === path &&
            (fence === undefined || e.id === fence.id),
        ),
      ).then((outcome) => outcome === true);
    },

    async deleteByFileId(fileId) {
      // The fileId only names the path whose lock to take. The row is
      // re-resolved under that lock, and looked again if it moved.
      for (;;) {
        const path = await enqueue(
          async () =>
            state.entries.find((e) => e.fileId === fileId)?.path ?? null,
        );
        if (path === null) return false;
        const outcome = await withPathLock(path, () =>
          eraseUnderPathLock(path, (e) => e.fileId === fileId),
        );
        if (outcome !== "moved") return outcome;
      }
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

  /**
   * The per-path FIFO lock: the one owner of a path's blob and row. An
   * operation holds it for its whole duration, so operations on one path never
   * interleave. The slot is taken synchronously at call time, so calls run in
   * call order.
   *
   * Lock order, never reversed: path lock, then scope lock, then the index
   * queue. Never take a path lock while holding the scope lock or inside the
   * queue (`enqueue`), or two operations can wait on each other.
   */
  const pathTails = new Map<string, Promise<void>>();
  function withPathLock<T>(path: string, fn: () => Promise<T>): Promise<T> {
    const previous = pathTails.get(path);
    let release!: () => void;
    const mine = new Promise<void>((resolve) => {
      release = resolve;
    });
    const tail = previous ? previous.then(() => mine) : mine;
    pathTails.set(path, tail);
    // A free path starts `fn` now, not a microtask later, so the caller's
    // index-queue slot is taken in call order.
    const run = previous
      ? previous.then(fn)
      : new Promise<T>((resolve) => resolve(fn()));
    return run.finally(() => {
      release();
      if (pathTails.get(path) === tail) pathTails.delete(path);
    });
  }

  /** The plain values an erase needs from a row. Never the stored object. */
  interface ErasedRow {
    id: number;
    scope: string;
    collectedAt: string;
    path: string;
  }

  /**
   * Erase the row `match` picks, and its blob. The caller holds the path lock
   * for `path`. The row is resolved inside the queue at the moment the lock is
   * held, so an earlier update or replacement is seen. Resolves "moved" when
   * the row found sits at another path, and the caller must look again.
   *
   * The blob parts run together, and all of them settle before this returns.
   * If any part fails, the row stays and the first error is rethrown.
   */
  async function eraseUnderPathLock(
    path: string,
    match: (entry: IndexEntry) => boolean,
  ): Promise<boolean | "moved"> {
    const found = await enqueue<ErasedRow | "moved" | null>(async () => {
      const entry = state.entries.find(match);
      if (!entry) return null;
      if (entry.path !== path) return "moved";
      // Persist the conservative hint before any destructive file operation.
      // A partial delete can remove the tree while leaving the row.
      readyBlockManifests.delete(
        blockManifestPath(entry.scope, entry.collectedAt),
      );
      await persistence.write(snapshotOf(state));
      return {
        id: entry.id,
        scope: entry.scope,
        collectedAt: entry.collectedAt,
        path: entry.path,
      };
    });
    if (found === null) return false;
    if (found === "moved") return "moved";
    return withScopeLock(found.scope, async () => {
      const blob = envelopePath(found.scope, found.collectedAt);
      const tree = blockTreePath(found.scope, found.collectedAt);
      const parts = await Promise.allSettled([
        fileStore.deleteEnvelope(blob),
        fallbackStore.deleteEnvelope(blob),
        fileStore.deleteBlockTree?.(tree) ?? Promise.resolve(),
        fallbackStore.deleteBlockTree?.(tree) ?? Promise.resolve(),
      ]);
      const failed = parts.find(
        (part): part is PromiseRejectedResult => part.status === "rejected",
      );
      if (failed) throw failed.reason;
      await enqueue(async () => {
        if (!state.entries.some((e) => e.id === found.id)) return;
        await publish({
          ...state,
          entries: state.entries.filter((e) => e.id !== found.id),
        });
      });
      // The sidecar goes with the scope's last version.
      await persist();
      if (!state.entries.some((e) => e.scope === found.scope)) {
        await dropLedger(found.scope);
      }
      return true;
    });
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
