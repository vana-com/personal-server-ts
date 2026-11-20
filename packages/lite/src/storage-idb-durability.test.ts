/**
 * The IndexedDB persistence adapter reports a write only once the transaction
 * has committed. A request's `success` event fires before the commit, and the
 * transaction can still abort after it (quota, a closed tab, an `abort()`).
 */
import { IDBFactory, IDBObjectStore } from "fake-indexeddb";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { createIndexedDbPsLitePersistence } from "./storage.js";

const STATE = { entries: [], nextId: 1 } as never;

describe("IndexedDB persistence durability", () => {
  let original: IDBFactory | undefined;

  beforeEach(() => {
    original = (globalThis as { indexedDB?: IDBFactory }).indexedDB;
    (globalThis as { indexedDB?: IDBFactory }).indexedDB = new IDBFactory();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    (globalThis as { indexedDB?: IDBFactory }).indexedDB = original;
  });

  /** Abort the transaction right after the named request reports success. */
  function abortAfterRequestSuccess(method: "put" | "delete") {
    const real = IDBObjectStore.prototype[method] as (
      ...args: unknown[]
    ) => IDBRequest;
    vi.spyOn(IDBObjectStore.prototype, method as never).mockImplementation(
      function (this: IDBObjectStore, ...args: unknown[]) {
        const request = real.apply(this, args);
        request.addEventListener("success", () => this.transaction.abort());
        return request;
      } as never,
    );
  }

  it("commits and reads back a write", async () => {
    const adapter = createIndexedDbPsLitePersistence({ dbName: "ok" });
    await adapter.write(STATE);
    expect(await adapter.read()).toEqual(STATE);
  });

  it("rejects a write whose transaction aborts after the request succeeded", async () => {
    const adapter = createIndexedDbPsLitePersistence({ dbName: "abort-put" });
    abortAfterRequestSuccess("put");
    await expect(adapter.write(STATE)).rejects.toBeDefined();
    vi.restoreAllMocks();
    expect(await adapter.read()).toBeNull();
  });

  it("rejects an aux write whose transaction aborts after the request succeeded", async () => {
    const adapter = createIndexedDbPsLitePersistence({ dbName: "abort-aux" });
    abortAfterRequestSuccess("put");
    await expect(adapter.writeAux!("ledger", { a: 1 })).rejects.toBeDefined();
    vi.restoreAllMocks();
    expect(await adapter.readAux!("ledger")).toBeNull();
  });

  it("rejects an aux delete whose transaction aborts after the request succeeded", async () => {
    const adapter = createIndexedDbPsLitePersistence({ dbName: "abort-del" });
    await adapter.writeAux!("ledger", { a: 1 });
    abortAfterRequestSuccess("delete");
    await expect(adapter.deleteAux!("ledger")).rejects.toBeDefined();
    vi.restoreAllMocks();
    expect(await adapter.readAux!("ledger")).toEqual({ a: 1 });
  });
});
