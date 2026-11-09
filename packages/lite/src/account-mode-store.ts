/**
 * Durable per-owner mode records for Web PS Lite.
 *
 * Kept in its own IndexedDB database, never in the data database: clearing or
 * rebuilding the data store must not unset an owner's On latch. One object
 * store keyed by owner. A save resolves only when its transaction completes.
 *
 * One runtime owns the database at a time. `claim` takes an exclusive owner
 * lock named after the database through an injected port (`AcquireOwnerLock`;
 * `webLocksOwnerLock` is the browser's), and holds it until the lease is
 * released or the holder goes away. With no port, or no Web Locks behind it,
 * the claim fails closed with its own message. There is no steal and no expiry
 * fallback.
 *
 * Nothing here reads or writes without a live lease. `release` marks the lease
 * dead first, so a new call refuses at once; a call already running checks the
 * lease again after its database opens and before its transaction, and gives
 * up if the lease is gone; and the Web Lock is freed only after every such call
 * has finished. A save is one readwrite transaction that reads the row,
 * applies `assertMonotoneWrite`, then writes, so two tabs cannot both win from
 * the same read. Nothing here is deleted by a refused claim.
 *
 * A stored row that fails validation is set aside and replaced by a tombstone
 * (`tombstoneRecord`, history unknown), so the owner is never read as
 * never-seen: no Off can be minted over a lost On or a lost import.
 */

import {
  ModeStoreConflictError,
  ModeStoreOwnedError,
  assertMonotoneWrite,
  tombstoneRecord,
  type DurableModeRecord,
  type ModeRecordStore,
} from "@opendatalabs/personal-server-ts-core/sync/account-mode";

export const ACCOUNT_MODE_DB_NAME = "personal-server-lite-account-mode";
const STORE = "owners";

interface StoredRow extends Omit<DurableModeRecord, "importPending"> {
  owner: string;
  /** Absent in a row written before the import flag existed: no import owed. */
  importPending?: boolean;
}

/** The part of the Web Locks API the browser adapter uses. */
export interface ModeLocks {
  request<T>(
    name: string,
    options: { ifAvailable: true },
    callback: (lock: unknown | null) => Promise<T> | T,
  ): Promise<T>;
}

/** An exclusive hold on an owner lock. Dropping it frees the lock. */
export interface ModeOwnerLock {
  release(): Promise<void>;
}

/**
 * The host's way to take the one exclusive owner lock for a store, injected so
 * that Lite does not pick a mechanism of its own (a browser uses Web Locks, a
 * phone host uses its own native lock). Resolves a hold, or `null` while
 * another holder has the lock. Rejects when the host cannot lock at all. It is
 * held until `release`, never expires and is never stolen.
 */
export type AcquireOwnerLock = (name: string) => Promise<ModeOwnerLock | null>;

/**
 * The browser's port: an exclusive Web Lock taken with `ifAvailable` and held
 * until released (the browser frees it when its holder dies). With no Web Locks
 * it rejects, so the store fails closed instead of running unlocked.
 */
export function webLocksOwnerLock(
  locks: ModeLocks | null | undefined = (
    globalThis.navigator as { locks?: ModeLocks } | undefined
  )?.locks,
): AcquireOwnerLock {
  return (name) => {
    if (!locks) {
      return Promise.reject(
        new ModeStoreOwnedError(
          "Web Locks are not available in this browser context (they need a secure origin and a current browser), so this tab cannot own the account mode records",
        ),
      );
    }
    return new Promise<ModeOwnerLock | null>((resolve, reject) => {
      let letGo!: () => void;
      const held = new Promise<void>((done) => {
        letGo = done;
      });
      const request = locks.request(
        name,
        { ifAvailable: true },
        async (lock) => {
          if (!lock) {
            resolve(null);
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
  };
}

export interface IndexedDbModeRecordStoreOptions {
  /**
   * How to take the owner lock. Required: without it every claim fails closed,
   * because a store nobody locks may have two owners.
   */
  acquireOwnerLock?: AcquireOwnerLock;
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
    (v.importPending === undefined || typeof v.importPending === "boolean") &&
    (v.historyUnknown === undefined || v.historyUnknown === true) &&
    (v.generation === undefined ||
      (typeof v.generation === "number" &&
        Number.isSafeInteger(v.generation) &&
        v.generation >= 0))
  );
}

/**
 * A store for a host that offers no durable place for the records. It never
 * claims, so the module refuses everything with 503 ACCOUNT_MODE_STORE_OWNED:
 * a runtime without durable records must not decide a mode (an in-memory store
 * forgets an On at a restart, and an Off then re-enables legacy writes).
 */
export function createUnavailableModeRecordStore(): ModeRecordStore {
  const refuse = () =>
    Promise.reject(
      new ModeStoreOwnedError(
        "this runtime has no durable account mode store, so it cannot decide the mode",
      ),
    );
  return { claim: refuse, load: refuse, save: refuse };
}

export function createIndexedDbModeRecordStore(
  dbName: string = ACCOUNT_MODE_DB_NAME,
  options: IndexedDbModeRecordStoreOptions = {},
): ModeRecordStore {
  /** The live lease, if any: a call is valid only under the one it started with. */
  let lease: object | null = null;
  /** Calls running under the live lease; release waits for them. */
  const running = new Set<Promise<unknown>>();

  const unowned = () =>
    new ModeStoreOwnedError(
      "this store is not claimed, or its claim was released",
    );

  /** Run `work` under the current lease; it must check `stillMine` before it writes. */
  function underLease<T>(
    work: (stillMine: () => boolean) => Promise<T>,
  ): Promise<T> {
    const mine = lease;
    if (mine === null) return Promise.reject(unowned());
    const call = work(() => lease === mine);
    running.add(call);
    const done = () => running.delete(call);
    call.then(done, done);
    return call;
  }

  return {
    async claim() {
      const acquire = options.acquireOwnerLock;
      if (!acquire) {
        throw new ModeStoreOwnedError(
          "no owner lock was provided, so this runtime cannot own the account mode records",
        );
      }
      const held = await acquire(`${dbName}:owner`);
      if (held === null) throw new ModeStoreOwnedError();
      const mine = {};
      lease = mine;
      return {
        async release() {
          // Dead first: nothing new starts, and a call under way gives up at
          // its next check. The owner lock is freed last.
          if (lease === mine) lease = null;
          await Promise.allSettled([...running]);
          await held.release();
        },
      };
    },

    load() {
      return underLease(async (stillMine) => {
        const db = await openDb(dbName);
        try {
          if (!stillMine()) throw unowned();
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
          const unreadable: string[] = [];
          for (const row of rows) {
            if (isRow(row)) records.set(row.owner, toRecord(row));
            else if (
              typeof row === "object" &&
              row !== null &&
              typeof (row as { owner?: unknown }).owner === "string"
            ) {
              // Unreadable: set aside as a tombstone, never read as unseen.
              unreadable.push((row as { owner: string }).owner);
            }
          }
          if (unreadable.length > 0) {
            if (!stillMine()) throw unowned();
            await new Promise<void>((resolve, reject) => {
              const tx = db.transaction(STORE, "readwrite");
              const store = tx.objectStore(STORE);
              for (const owner of unreadable) {
                store.put({ owner, ...tombstoneRecord() });
              }
              tx.oncomplete = () => resolve();
              tx.onerror = () => reject(tx.error ?? new Error("write failed"));
              tx.onabort = () => reject(tx.error ?? new Error("write aborted"));
            });
            for (const owner of unreadable) {
              records.set(owner, tombstoneRecord());
            }
          }
          return records;
        } finally {
          db.close();
        }
      });
    },

    save(owner, record, expected) {
      return underLease(async (stillMine) => {
        const db = await openDb(dbName);
        try {
          // The lease may have been released while the database opened.
          if (!stillMine()) throw unowned();
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
      });
    },
  };
}
