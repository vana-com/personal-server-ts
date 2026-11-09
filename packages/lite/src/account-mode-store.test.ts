import { IDBFactory } from "fake-indexeddb";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  createModeAuthority,
  type DurableModeRecord,
} from "@opendatalabs/personal-server-ts-core/sync/account-mode";
import { createIndexedDbModeRecordStore } from "./account-mode-store.js";

const A = "0x1111111111111111111111111111111111111111";
const ON: DurableModeRecord = {
  switched: true,
  switchedAt: 5,
  cleanOffAt: null,
  offFetchStartMono: null,
  bootId: "b",
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
    await store.save(A, ON);
    await store.save("b", { ...ON, switched: false });
    const loaded = await createIndexedDbModeRecordStore("m").load();
    expect(loaded.get(A)).toEqual(ON);
    expect(loaded.get("b")?.switched).toBe(false);
  });

  it("skips a malformed row, so that owner loads as never seen", async () => {
    const store = createIndexedDbModeRecordStore("m");
    await store.save(A, ON);
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

  // LATCH_NOT_DURABLE
  it("keeps an On in its own database when the data database is deleted", async () => {
    const first = createModeAuthority({
      store: createIndexedDbModeRecordStore("app-account-mode"),
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
    const second = createModeAuthority({
      store: createIndexedDbModeRecordStore("app-account-mode"),
      bootId: "b2",
    });
    await second.ready;
    expect(second.read(A).kind).toBe("streams");
  });
});
