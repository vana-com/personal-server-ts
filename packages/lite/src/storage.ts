import type { DataStoragePort } from "@opendatalabs/personal-server-ts-core/ports";
import type { DataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import type { WriteResult } from "@opendatalabs/personal-server-ts-core/storage/hierarchy";
import type { IndexEntry } from "@opendatalabs/personal-server-ts-core/storage/index";
import type { PsLiteStorageAdapter } from "./runtime.js";
import { createStorageReadMethods, sortEntries } from "./storage-utils.js";

export interface PsLitePersistedStorageState {
  version: 1;
  nextId: number;
  entries: IndexEntry[];
  envelopes: DataFileEnvelope[];
}

export type PsLiteFileStorageKind = "opfs" | "indexeddb";

export interface PsLiteDataFileStore {
  readonly kind: PsLiteFileStorageKind;
  readEnvelope(path: string): Promise<DataFileEnvelope | null>;
  writeEnvelope(path: string, envelope: DataFileEnvelope): Promise<number>;
  deleteEnvelope(path: string): Promise<void>;
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
  };
}

export function createIndexedDbFallbackDataFileStore(
  envelopes: Map<string, DataFileEnvelope>,
): PsLiteDataFileStore {
  return {
    kind: "indexeddb",
    async readEnvelope(path) {
      return envelopes.get(path) ?? null;
    },
    async writeEnvelope(path, envelope) {
      envelopes.set(path, envelope);
      return new TextEncoder().encode(JSON.stringify(envelope)).length;
    },
    async deleteEnvelope(path) {
      envelopes.delete(path);
    },
  };
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
  };
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
  const fallbackStore = createIndexedDbFallbackDataFileStore(fallbackEnvelopes);
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

    async insertEntry(entry) {
      const version =
        entry.version ??
        state.entries.reduce(
          (max, e) =>
            e.scope === entry.scope && e.version > max ? e.version : max,
          0,
        ) + 1;
      const indexed: IndexEntry = {
        ...entry,
        schemaId: entry.schemaId ?? null,
        version,
        dataPointId: entry.dataPointId ?? null,
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

    async deleteScope(scope) {
      let deleted = 0;
      const deletedPaths: string[] = [];
      state = {
        ...state,
        entries: state.entries.filter((entry) => {
          if (entry.scope !== scope) return true;
          deleted += 1;
          deletedPaths.push(envelopePath(entry.scope, entry.collectedAt));
          return false;
        }),
      };
      await Promise.all(
        deletedPaths.flatMap((path) => [
          fileStore.deleteEnvelope(path),
          fallbackStore.deleteEnvelope(path),
        ]),
      );
      await persist();
      return deleted;
    },
  };
  return storagePort;
}
