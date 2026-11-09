import { IDBFactory } from "fake-indexeddb";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  ModeStoreConflictError,
  ModeStoreOwnedError,
  createModeAuthority,
  type DurableModeRecord,
} from "@opendatalabs/personal-server-ts-core/sync/account-mode";
import {
  createIndexedDbModeRecordStore,
  type ModeLocks,
} from "./account-mode-store.js";

/** Web Locks as a browser gives them, for one origin: a name is held or free. */
function createLocks(): ModeLocks {
  const held = new Set<string>();
  return {
    request(name, options, callback) {
      if (held.has(name)) return Promise.resolve(callback(null));
      held.add(name);
      return Promise.resolve(callback({})).finally(() => held.delete(name));
    },
  };
}

const A = "0x1111111111111111111111111111111111111111";
const ON: DurableModeRecord = {
  switched: true,
  switchedAt: 5,
  cleanOffAt: null,
  offFetchStartMono: null,
  bootId: "b",
  importPending: false,
};
const OFF: DurableModeRecord = {
  switched: false,
  switchedAt: null,
  cleanOffAt: 3,
  offFetchStartMono: 3,
  bootId: "b",
  importPending: false,
};

describe("the IndexedDB record store", () => {
  beforeEach(() => {
    vi.stubGlobal("indexedDB", new IDBFactory());
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("loads nothing from a database that does not exist yet", async () => {
    expect((await createIndexedDbModeRecordStore("m").load()).size).toBe(0);
  });

  it("round-trips a record per owner", async () => {
    const store = createIndexedDbModeRecordStore("m");
    await store.save(A, ON, null);
    await store.save("b", OFF, null);
    const loaded = await createIndexedDbModeRecordStore("m").load();
    expect(loaded.get(A)).toEqual(ON);
    expect(loaded.get("b")?.switched).toBe(false);
  });

  it("skips a malformed row, so that owner loads as never seen", async () => {
    const store = createIndexedDbModeRecordStore("m");
    await store.save(A, ON, null);
    const db = await new Promise<IDBDatabase>((resolve, reject) => {
      const request = indexedDB.open("m", 1);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction("owners", "readwrite");
      tx.objectStore("owners").put({ owner: "broken", switched: "yes" });
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
    db.close();
    const loaded = await store.load();
    expect([...loaded.keys()]).toEqual([A]);
  });

  it("rejects when IndexedDB is not available, so the module fails closed", async () => {
    vi.stubGlobal("indexedDB", undefined);
    await expect(createIndexedDbModeRecordStore("m").load()).rejects.toThrow(
      "IndexedDB is not available",
    );
  });

  it("reads a row written before importPending existed as having none", async () => {
    const { importPending: _drop, ...old } = ON;
    const db = await new Promise<IDBDatabase>((resolve, reject) => {
      const request = indexedDB.open("m", 1);
      request.onupgradeneeded = () =>
        request.result.createObjectStore("owners", { keyPath: "owner" });
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction("owners", "readwrite");
      tx.objectStore("owners").put({ owner: A, ...old });
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
    db.close();
    expect((await createIndexedDbModeRecordStore("m").load()).get(A)).toEqual(
      ON,
    );
  });

  // SECOND_RUNTIME_ADMITTED
  it("lets one tab own the database and refuses a second until the first lets go", async () => {
    const locks = createLocks();
    const first = createIndexedDbModeRecordStore("m", { locks });
    const second = createIndexedDbModeRecordStore("m", { locks });
    const lease = await first.claim();
    await expect(second.claim()).rejects.toBeInstanceOf(ModeStoreOwnedError);
    await lease.release();
    await (await second.claim()).release();
  });

  it("fails closed when the browser has no Web Locks", async () => {
    const store = createIndexedDbModeRecordStore("m", { locks: null });
    await expect(store.claim()).rejects.toBeInstanceOf(ModeStoreOwnedError);
  });

  it("two authorities on the database: the second is refused and writes nothing", async () => {
    const locks = createLocks();
    const first = createModeAuthority({
      store: createIndexedDbModeRecordStore("m", { locks }),
      bootId: "b1",
    });
    await first.ready;
    const second = createModeAuthority({
      store: createIndexedDbModeRecordStore("m", { locks }),
      bootId: "b2",
    });
    await second.ready.catch(() => undefined);
    const off = {
      owner: A,
      authOwner: A,
      state: "off" as const,
      fetchStartedAt: Date.now(),
      rawStatus: 200,
    };
    expect(await second.submitEvidence(off)).toMatchObject({
      code: "ACCOUNT_MODE_STORE_OWNED",
    });
    expect((await createIndexedDbModeRecordStore("m").load()).size).toBe(0);
    await first.close();
  });

  // BLIND_OFF_OVERWRITES_ON
  it("rejects an Off over a stored On and a write based on a stale read, in one transaction", async () => {
    const store = createIndexedDbModeRecordStore("m");
    await store.save(A, OFF, null);
    await store.save(A, ON, OFF);
    await expect(store.save(A, OFF, ON)).rejects.toBeInstanceOf(
      ModeStoreConflictError,
    );
    await expect(
      store.save(A, { ...ON, switchedAt: 99 }, OFF),
    ).rejects.toBeInstanceOf(ModeStoreConflictError);
    await expect(store.save(A, ON, null)).rejects.toBeInstanceOf(
      ModeStoreConflictError,
    );
    expect((await store.load()).get(A)).toEqual(ON);
  });

  it("lets only one of two racing saves from the same read win", async () => {
    const store = createIndexedDbModeRecordStore("m");
    await store.save(A, OFF, null);
    const results = await Promise.allSettled([
      store.save(A, { ...OFF, cleanOffAt: 4 }, OFF),
      store.save(A, ON, OFF),
    ]);
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((r) => r.status === "rejected")).toHaveLength(1);
  });

  // LATCH_NOT_DURABLE
  it("keeps an On in its own database when the data database is deleted", async () => {
    const locks = createLocks();
    const first = createModeAuthority({
      store: createIndexedDbModeRecordStore("app-account-mode", { locks }),
      bootId: "b1",
    });
    await first.ready;
    await first.submitEvidence({
      owner: A,
      authOwner: A,
      state: "on",
      fetchStartedAt: Date.now(),
      rawStatus: 200,
    });
    // The data store is a different database; deleting it must not matter.
    await new Promise<void>((resolve, reject) => {
      const request = indexedDB.deleteDatabase("app");
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
    await first.close();
    const second = createModeAuthority({
      store: createIndexedDbModeRecordStore("app-account-mode", { locks }),
      bootId: "b2",
    });
    await second.ready;
    expect(second.read(A).kind).toBe("streams");
  });
});
