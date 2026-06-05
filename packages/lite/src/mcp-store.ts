/**
 * IndexedDB-backed `McpConnectionStore` for Web PS Lite.
 *
 * Phase 1 trade-off: persists the per-connection grantee private key in
 * PLAINTEXT in IndexedDB. The owner-derived AES-GCM wrap used for the PS Lite
 * server identity is not yet applied to grantee keys — that's the Phase 2
 * "encrypt grantee private keys at rest" task in
 * `260604-PLAN-vana-mcp-personal-server.md`. The risk is bounded by:
 *
 *   1. The browser same-origin policy — only code running on the PS Lite tab's
 *      origin (e.g. app-dev.vana.org) can read this store.
 *   2. Grantee keys are scoped per-connection and revocable. A leaked key only
 *      lets the holder read the grants that connection already approved; any
 *      revoke removes both the grant and the connection's lookup record.
 *   3. There are no write tools — leaked grantee keys cannot mutate user data.
 *
 * Persistent storage is strongly preferred over in-memory because:
 *   - app-dev page reloads are routine in a browser app;
 *   - Claude's MCP URL is meant to live in the Claude config across sessions;
 *   - the alternative (re-create on every boot) would silently invalidate every
 *     prior Claude connection on every reload, indistinguishable from a real
 *     revoke from the user's perspective.
 */

import type {
  McpConnectionRecord,
  McpConnectionStore,
} from "@opendatalabs/personal-server-ts-core/mcp";

const DEFAULT_DB_NAME = "personal-server-lite";
const DEFAULT_STORE_NAME = "mcpConnections";
const TOKEN_HASH_INDEX = "tokenHash";
const DB_VERSION = 1;

export interface IndexedDbMcpConnectionStoreOptions {
  dbName?: string;
  storeName?: string;
}

interface ResolvedOptions {
  dbName: string;
  storeName: string;
}

function openDb(opts: ResolvedOptions): Promise<IDBDatabase> {
  if (typeof indexedDB === "undefined") {
    throw new Error("IndexedDB is not available in this runtime");
  }
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(opts.dbName, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(opts.storeName)) {
        const store = db.createObjectStore(opts.storeName, { keyPath: "id" });
        store.createIndex(TOKEN_HASH_INDEX, "tokenHash", { unique: true });
      } else {
        const store = request.transaction?.objectStore(opts.storeName);
        if (store && !store.indexNames.contains(TOKEN_HASH_INDEX)) {
          store.createIndex(TOKEN_HASH_INDEX, "tokenHash", { unique: true });
        }
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function runTx<T>(
  opts: ResolvedOptions,
  mode: IDBTransactionMode,
  fn: (store: IDBObjectStore) => IDBRequest<T>,
): Promise<T> {
  return openDb(opts).then(
    (db) =>
      new Promise<T>((resolve, reject) => {
        const transaction = db.transaction(opts.storeName, mode);
        const store = transaction.objectStore(opts.storeName);
        const request = fn(store);
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

function runIndexQuery<T>(
  opts: ResolvedOptions,
  indexName: string,
  fn: (index: IDBIndex) => IDBRequest<T>,
): Promise<T> {
  return openDb(opts).then(
    (db) =>
      new Promise<T>((resolve, reject) => {
        const transaction = db.transaction(opts.storeName, "readonly");
        const store = transaction.objectStore(opts.storeName);
        const request = fn(store.index(indexName));
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

export function createIndexedDbMcpConnectionStore(
  options: IndexedDbMcpConnectionStoreOptions = {},
): McpConnectionStore {
  const resolved: ResolvedOptions = {
    dbName: options.dbName ?? DEFAULT_DB_NAME,
    storeName: options.storeName ?? DEFAULT_STORE_NAME,
  };

  return {
    async create(record) {
      const existing = await runTx<McpConnectionRecord | undefined>(
        resolved,
        "readonly",
        (store) => store.get(record.id),
      );
      if (existing) {
        throw new Error(`mcp connection ${record.id} already exists`);
      }
      await runTx<IDBValidKey>(resolved, "readwrite", (store) =>
        store.put({ ...record }),
      );
    },

    async list() {
      const all = await runTx<McpConnectionRecord[]>(
        resolved,
        "readonly",
        (store) => store.getAll(),
      );
      return all.map((r) => ({ ...r }));
    },

    async getById(id) {
      const record = await runTx<McpConnectionRecord | undefined>(
        resolved,
        "readonly",
        (store) => store.get(id),
      );
      return record ? { ...record } : null;
    },

    async getByTokenHash(tokenHash) {
      const record = await runIndexQuery<McpConnectionRecord | undefined>(
        resolved,
        TOKEN_HASH_INDEX,
        (index) => index.get(tokenHash),
      );
      if (!record) return null;
      if (record.status !== "approved") return null;
      return { ...record };
    },

    async update(id, patch) {
      const existing = await runTx<McpConnectionRecord | undefined>(
        resolved,
        "readonly",
        (store) => store.get(id),
      );
      if (!existing) return null;
      const updated: McpConnectionRecord = { ...existing, ...patch };
      await runTx<IDBValidKey>(resolved, "readwrite", (store) =>
        store.put(updated),
      );
      return { ...updated };
    },
  };
}
