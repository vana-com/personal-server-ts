/**
 * Durable per-owner mode records for Web PS Lite.
 *
 * Kept in its own IndexedDB database, never in the data database: clearing or
 * rebuilding the data store must not unset an owner's On latch. One object
 * store keyed by owner. A save resolves only when its transaction completes.
 */

import type {
  ModeRecordStore,
  OwnerModeRecord,
} from "@opendatalabs/personal-server-ts-core/sync/account-mode";

export const ACCOUNT_MODE_DB_NAME = "personal-server-lite-account-mode";
const STORE = "owners";

interface StoredRow extends OwnerModeRecord {
  owner: string;
}

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

function isRow(value: unknown): value is StoredRow {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  const num = (x: unknown) =>
    x === null || (typeof x === "number" && Number.isFinite(x));
  return (
    typeof v.owner === "string" &&
    typeof v.switched === "boolean" &&
    num(v.switchedAt) &&
    num(v.cleanOffAt) &&
    num(v.offFetchStartMono) &&
    (v.bootId === null || typeof v.bootId === "string")
  );
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
          request.onsuccess = () => resolve(request.result as unknown[]);
          request.onerror = () =>
            reject(request.error ?? new Error("read failed"));
        });
        const records = new Map<string, OwnerModeRecord>();
        for (const row of rows) {
          // A malformed row loads as a never-seen owner.
          if (!isRow(row)) continue;
          const { owner, ...record } = row;
          records.set(owner, record);
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
