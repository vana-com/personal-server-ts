import type {
  DataStorageEntryLookup,
  DataStorageListOptions,
  DataStoragePort,
  DataStorageScopeListOptions,
} from "@opendatalabs/personal-server-ts-core/ports";
import type { DataFileEnvelope } from "@opendatalabs/personal-server-ts-core/schemas/data-file";
import type { WriteResult } from "@opendatalabs/personal-server-ts-core/storage/hierarchy";
import type { IndexEntry } from "@opendatalabs/personal-server-ts-core/storage/index";
import type { PsLiteStorageAdapter } from "./runtime.js";

export interface PsLitePersistedStorageState {
  version: 1;
  nextId: number;
  entries: IndexEntry[];
  envelopes: DataFileEnvelope[];
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

interface ScopeSummary {
  scope: string;
  latestCollectedAt: string;
  versionCount: number;
}

const DEFAULT_INDEXED_DB_NAME = "personal-server-lite";
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

function envelopeKey(scope: string, collectedAt: string): string {
  return `${scope}\n${collectedAt}`;
}

function sortEntries(entries: IndexEntry[]): IndexEntry[] {
  return [...entries].sort((a, b) =>
    b.collectedAt.localeCompare(a.collectedAt),
  );
}

function paginate<T>(
  items: T[],
  options: DataStorageListOptions | DataStorageScopeListOptions,
): T[] {
  const offset = options.offset ?? 0;
  const limit = options.limit ?? items.length;
  return items.slice(offset, offset + limit);
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

function cloneState(
  state: PsLitePersistedStorageState,
): PsLitePersistedStorageState {
  return JSON.parse(JSON.stringify(state)) as PsLitePersistedStorageState;
}

export function createMemoryPsLitePersistence(
  seed?: PsLitePersistedStorageState,
): PsLitePersistenceAdapter {
  let state = seed ? cloneState(seed) : null;
  return {
    async read() {
      return state ? cloneState(state) : null;
    },
    async write(nextState) {
      state = cloneState(nextState);
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
): Promise<DataStoragePort> {
  let state = normalizeState(await persistence.read());
  const envelopes = new Map(
    state.envelopes.map((envelope) => [
      envelopeKey(envelope.scope, envelope.collectedAt),
      envelope,
    ]),
  );

  async function persist(): Promise<void> {
    state = {
      ...state,
      envelopes: Array.from(envelopes.values()),
    };
    await persistence.write(state);
  }

  function entriesForScope(scope: string): IndexEntry[] {
    return sortEntries(state.entries.filter((entry) => entry.scope === scope));
  }

  return {
    kind: adapter.kind === "custom" ? "custom" : "browser-indexeddb-opfs",

    listScopes(options) {
      const summaries = new Map<string, ScopeSummary>();
      for (const entry of state.entries) {
        if (
          options.scopePrefix &&
          !entry.scope.startsWith(options.scopePrefix)
        ) {
          continue;
        }
        const existing = summaries.get(entry.scope);
        summaries.set(entry.scope, {
          scope: entry.scope,
          latestCollectedAt:
            existing &&
            existing.latestCollectedAt.localeCompare(entry.collectedAt) > 0
              ? existing.latestCollectedAt
              : entry.collectedAt,
          versionCount: (existing?.versionCount ?? 0) + 1,
        });
      }
      const scopes = Array.from(summaries.values()).sort((a, b) =>
        a.scope.localeCompare(b.scope),
      );
      return {
        scopes: paginate(scopes, options),
        total: scopes.length,
      };
    },

    listVersions(scope, options) {
      return paginate(entriesForScope(scope), options);
    },

    countVersions(scope) {
      return entriesForScope(scope).length;
    },

    findEntry(lookup: DataStorageEntryLookup) {
      const scoped = entriesForScope(lookup.scope);
      if (lookup.fileId) {
        return scoped.find((entry) => entry.fileId === lookup.fileId);
      }
      if (lookup.at) {
        return scoped.find((entry) => entry.collectedAt === lookup.at);
      }
      return scoped[0];
    },

    async readEnvelope(scope, collectedAt) {
      const envelope = envelopes.get(envelopeKey(scope, collectedAt));
      if (!envelope) {
        throw new Error("Envelope not found");
      }
      return envelope;
    },

    async writeEnvelope(envelope): Promise<WriteResult> {
      envelopes.set(
        envelopeKey(envelope.scope, envelope.collectedAt),
        envelope,
      );
      await persist();
      const path = `${envelope.scope}/${envelope.collectedAt}.json`;
      return {
        path,
        relativePath: path,
        sizeBytes: new TextEncoder().encode(JSON.stringify(envelope)).length,
      };
    },

    insertEntry(entry) {
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
      void persist();
      return indexed;
    },

    async deleteScope(scope) {
      let deleted = 0;
      state = {
        ...state,
        entries: state.entries.filter((entry) => {
          if (entry.scope !== scope) return true;
          deleted += 1;
          envelopes.delete(envelopeKey(entry.scope, entry.collectedAt));
          return false;
        }),
      };
      await persist();
      return deleted;
    },
  };
}
