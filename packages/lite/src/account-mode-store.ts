/**
 * Durable per-owner mode records for Web PS Lite.
 *
 * Kept in its own IndexedDB database, never in the data database: clearing or
 * rebuilding the data store must not unset an owner's On latch. One object
 * store keyed by owner. A save resolves only when its transaction completes.
 *
 * One tab owns the database at a time. `claim` takes a Web Lock named after
 * the database with `ifAvailable`, and holds it until the lease is released or
 * the tab goes away (the browser frees the lock when its holder dies). With no
 * Web Locks the claim fails closed. A save is one readwrite transaction that
 * reads the row, applies `assertMonotoneWrite`, then writes, so two tabs
 * cannot both win from the same read. Nothing here is deleted by a refused
 * claim.
 */

import {
  ModeStoreConflictError,
  ModeStoreOwnedError,
  assertMonotoneWrite,
  type DurableModeRecord,
  type ModeRecordStore,
  type ModeStoreLease,
} from "@opendatalabs/personal-server-ts-core/sync/account-mode";

export const ACCOUNT_MODE_DB_NAME = "personal-server-lite-account-mode";
const STORE = "owners";

interface StoredRow extends Omit<DurableModeRecord, "importPending"> {
  owner: string;
  /** Absent in a row written before the import flag existed: no import owed. */
  importPending?: boolean;
}

/** The part of the Web Locks API this store uses. */
export interface ModeLocks {
  request<T>(
    name: string,
    options: { ifAvailable: true },
    callback: (lock: unknown | null) => Promise<T> | T,
  ): Promise<T>;
}

export interface IndexedDbModeRecordStoreOptions {
  /**
   * The Web Locks to claim ownership with. Defaults to `navigator.locks`;
   * `null` (or a browser without it) makes every claim fail closed.
   */
  locks?: ModeLocks | null;
}

function toRecord(row: StoredRow): DurableModeRecord {
  const { owner: _owner, importPending, ...rest } = row;
  return { ...rest, importPending: importPending === true };
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
    (v.bootId === null || typeof v.bootId === "string") &&
    (v.importPending === undefined || typeof v.importPending === "boolean")
  );
}

export function createIndexedDbModeRecordStore(
  dbName: string = ACCOUNT_MODE_DB_NAME,
  options: IndexedDbModeRecordStoreOptions = {},
): ModeRecordStore {
  return {
    async claim() {
      const locks =
        options.locks === undefined
          ? (globalThis.navigator as { locks?: ModeLocks } | undefined)?.locks
          : options.locks;
      if (!locks) {
        throw new ModeStoreOwnedError(
          "Web Locks are not available, so this tab cannot own the records",
        );
      }
      return new Promise<ModeStoreLease>((resolve, reject) => {
        let letGo!: () => void;
        const held = new Promise<void>((done) => {
          letGo = done;
        });
        const request = locks.request(
          `${dbName}:owner`,
          { ifAvailable: true },
          async (lock) => {
            if (!lock) {
              reject(new ModeStoreOwnedError());
              return;
            }
            resolve({
              async release() {
                letGo();
                await request.catch(() => {});
              },
            });
            await held;
          },
        );
        request.catch(reject);
      });
    },

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
        const records = new Map<string, DurableModeRecord>();
        for (const row of rows) {
          // A malformed row loads as a never-seen owner.
          if (!isRow(row)) continue;
          records.set(row.owner, toRecord(row));
        }
        return records;
      } finally {
        db.close();
      }
    },

    async save(owner, record, expected) {
      const db = await openDb(dbName);
      try {
        await new Promise<void>((resolve, reject) => {
          const tx = db.transaction(STORE, "readwrite");
          const rows = tx.objectStore(STORE);
          let rejected: Error | null = null;
          const read = rows.get(owner);
          read.onsuccess = () => {
            try {
              const found: unknown = read.result;
              if (found !== undefined && !isRow(found)) {
                throw new ModeStoreConflictError(
                  "the stored row is unreadable",
                );
              }
              assertMonotoneWrite(
                found === undefined ? null : toRecord(found as StoredRow),
                expected,
                record,
              );
              rows.put({ owner, ...record });
            } catch (error) {
              rejected = error as Error;
              tx.abort();
            }
          };
          tx.oncomplete = () => resolve();
          tx.onerror = () =>
            reject(rejected ?? tx.error ?? new Error("write failed"));
          tx.onabort = () =>
            reject(rejected ?? tx.error ?? new Error("write aborted"));
        });
      } finally {
        db.close();
      }
    },
  };
}
