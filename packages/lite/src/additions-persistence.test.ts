import { afterEach, describe, expect, it, vi } from "vitest";
import { IDBFactory } from "fake-indexeddb";
import { createIndexedDbPsLiteStateStore } from "./state.js";

afterEach(() => vi.unstubAllGlobals());

describe("bounded additions IndexedDB persistence", () => {
  it("fails blocked upgrades promptly and aborts a late upgrade without mutation", async () => {
    const factory = new IDBFactory();
    vi.stubGlobal("indexedDB", factory);
    const dbName = "blocked-additions";
    const blocker = await new Promise<IDBDatabase>((resolve, reject) => {
      const request = factory.open(dbName, 1);
      request.onupgradeneeded = () => request.result.createObjectStore("state");
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    const store = createIndexedDbPsLiteStateStore({ dbName });
    await expect(
      store.bounded?.set(
        "additions-publication-v1:test",
        { candidate: 1 },
        AbortSignal.timeout(1000),
      ),
    ).rejects.toThrow("blocked");
    blocker.close();
    const result = await new Promise<IDBDatabase>((resolve, reject) => {
      const request = factory.open(dbName);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    expect(result.version).toBe(1);
    const stored = await new Promise<unknown>((resolve, reject) => {
      const request = result
        .transaction("state")
        .objectStore("state")
        .get("additions-publication-v1:test");
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    expect(stored).toBeUndefined();
    result.close();
  });

  it("returns only committed writes and rejects cancellation before starting mutation", async () => {
    vi.stubGlobal("indexedDB", new IDBFactory());
    const store = createIndexedDbPsLiteStateStore({ dbName: "journal-commit" });
    await store.bounded?.set("additions-publication-v1:test", { candidate: 1 });
    const controller = new AbortController();
    controller.abort(new Error("owner deadline"));
    await expect(
      store.bounded?.set(
        "additions-publication-v1:test",
        { candidate: 2 },
        controller.signal,
      ),
    ).rejects.toThrow("owner deadline");
    expect(await store.bounded?.get("additions-publication-v1:test")).toEqual({
      candidate: 1,
    });
    await store.bounded?.delete("additions-publication-v1:test");
    expect(
      await store.bounded?.get("additions-publication-v1:test"),
    ).toBeNull();
  });
});
