/**
 * Durable per-owner mode records for Web PS Lite, in their own IndexedDB
 * database, never in the data database: clearing or rebuilding the data store
 * must not unset an owner's On. One object store keyed by owner. A save
 * resolves only when its transaction completes. Only the newest tab runs the
 * server, so there is no cross-tab lock.
 */

import {
  parseRecord,
  type AccountModeRecord,
  type ModeRecordStore,
} from "@opendatalabs/personal-server-ts-core/sync/account-mode";

export const ACCOUNT_MODE_DB_NAME = "personal-server-lite-account-mode";
const STORE = "owners";

function openDb(dbName: string): Promise<IDBDatabase> {
  if (typeof indexedDB === "undefined") {
    return Promise.reject(new Error("IndexedDB is not available"));
  }
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(dbName, 1);
    request.onupgradeneeded = () => {
      request.result.createObjectStore(STORE, { keyPath: "owner" });
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("open failed"));
    request.onblocked = () => reject(new Error("open blocked"));
  });
}

export function createIndexedDbModeRecordStore(
  dbName: string = ACCOUNT_MODE_DB_NAME,
): ModeRecordStore {
  return {
    async load() {
      const db = await openDb(dbName);
      try {
        const rows = await new Promise<unknown[]>((resolve, reject) => {
          const request = db
            .transaction(STORE, "readonly")
            .objectStore(STORE)
            .getAll();
          request.onsuccess = () => resolve(request.result);
          request.onerror = () =>
            reject(request.error ?? new Error("read failed"));
        });
        const records = new Map<string, AccountModeRecord>();
        for (const row of rows) {
          const record = parseRecord(row);
          const owner = (row as { owner?: unknown }).owner;
          if (record && typeof owner === "string") records.set(owner, record);
        }
        return records;
      } finally {
        db.close();
      }
    },
    async save(owner, record) {
      const db = await openDb(dbName);
      try {
        await new Promise<void>((resolve, reject) => {
          const tx = db.transaction(STORE, "readwrite");
          tx.objectStore(STORE).put({ owner, ...record });
          tx.oncomplete = () => resolve();
          tx.onerror = () => reject(tx.error ?? new Error("write failed"));
          tx.onabort = () => reject(tx.error ?? new Error("write aborted"));
        });
      } finally {
        db.close();
      }
    },
  };
}
