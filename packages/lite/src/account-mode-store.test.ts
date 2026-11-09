import { IDBFactory } from "fake-indexeddb";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  ModeStoreConflictError,
  ModeStoreOwnedError,
  createModeAuthority,
  tombstoneRecord,
  type DurableModeRecord,
  type ModeRecordStore,
} from "@opendatalabs/personal-server-ts-core/sync/account-mode";
import {
  createIndexedDbModeRecordStore as createStore,
  webLocksOwnerLock,
  type ModeLocks,
} from "./account-mode-store.js";

/** A store whose owner lock is taken from these Web Locks (or none). */
function createIndexedDbModeRecordStore(
  name: string,
  options: { locks?: ModeLocks | null } = {},
) {
  return createStore(name, {
    acquireOwnerLock:
      options.locks === undefined
        ? undefined
        : webLocksOwnerLock(options.locks),
  });
}

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

/** A store with its claim taken, on a shared set of Web Locks. */
async function claimed(
  name = "m",
  locks: ModeLocks = createLocks(),
): Promise<ModeRecordStore & { release(): Promise<void> }> {
  const store = createIndexedDbModeRecordStore(name, { locks });
  const lease = await store.claim();
  return Object.assign(store, { release: () => lease.release() });
}

/** Put a raw row into the owners object store, bypassing the store. */
async function putRaw(name: string, row: Record<string, unknown>) {
  const db = await new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open(name, 1);
    request.onupgradeneeded = () =>
      request.result.createObjectStore("owners", { keyPath: "owner" });
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction("owners", "readwrite");
    tx.objectStore("owners").put(row);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
  db.close();
}

async function rawRows(name: string): Promise<unknown[]> {
  const db = await new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open(name, 1);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  const rows = await new Promise<unknown[]>((resolve, reject) => {
    const request = db
      .transaction("owners", "readonly")
      .objectStore("owners")
      .getAll();
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  db.close();
  return rows;
}

const evidence = (state: "on" | "off") => ({
  owner: A,
  authOwner: A,
  state,
  fetchStartedAt: Date.now(),
  rawStatus: 200,
});

const tick = (ms = 0) =>
  new Promise<void>((resolve) => setTimeout(resolve, ms));

describe("the IndexedDB record store", () => {
  beforeEach(() => {
    vi.stubGlobal("indexedDB", new IDBFactory());
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("loads nothing from a database that does not exist yet", async () => {
    expect((await (await claimed()).load()).size).toBe(0);
  });

  it("round-trips a record per owner", async () => {
    const locks = createLocks();
    const store = await claimed("m", locks);
    await store.save(A, ON, null);
    await store.save("b", OFF, null);
    await store.release();
    const loaded = await (await claimed("m", locks)).load();
    expect(loaded.get(A)).toEqual(ON);
    expect(loaded.get("b")?.switched).toBe(false);
  });

  // LITE_SAVE_WITHOUT_LEASE
  it("neither reads nor writes without a live lease", async () => {
    const store = createIndexedDbModeRecordStore("m", { locks: createLocks() });
    await expect(store.load()).rejects.toBeInstanceOf(ModeStoreOwnedError);
    await expect(store.save(A, ON, null)).rejects.toBeInstanceOf(
      ModeStoreOwnedError,
    );
    const lease = await store.claim();
    await lease.release();
    await expect(store.save(A, ON, null)).rejects.toBeInstanceOf(
      ModeStoreOwnedError,
    );
    await expect(store.load()).rejects.toBeInstanceOf(ModeStoreOwnedError);
    expect(await rawRows("m").catch(() => [])).toEqual([]);
  });

  // QUARANTINE_FORGETS_ON
  it("sets a malformed row aside as a tombstone, so that owner is never read as unseen", async () => {
    const store = await claimed();
    await store.save(A, ON, null);
    await putRaw("m", { owner: "broken", switched: "yes" });
    const loaded = await store.load();
    expect([...loaded.keys()].sort()).toEqual([A, "broken"].sort());
    expect(loaded.get("broken")).toEqual(tombstoneRecord());
    // The tombstone is stored, so it survives another load.
    expect((await store.load()).get("broken")).toEqual(tombstoneRecord());
    expect(await rawRows("m")).toContainEqual({
      owner: "broken",
      ...tombstoneRecord(),
    });
    // Only an On with the import owed replaces it; no Off, no tombstone-over-On.
    await expect(
      store.save("broken", OFF, tombstoneRecord()),
    ).rejects.toBeInstanceOf(ModeStoreConflictError);
    await expect(
      store.save(A, { ...tombstoneRecord() }, ON),
    ).rejects.toBeInstanceOf(ModeStoreConflictError);
    await store.save(
      "broken",
      { ...ON, importPending: true },
      tombstoneRecord(),
    );
    expect((await store.load()).get("broken")).toEqual({
      ...ON,
      importPending: true,
    });
  });

  it("rejects when IndexedDB is not available, so the module fails closed", async () => {
    vi.stubGlobal("indexedDB", undefined);
    await expect((await claimed()).load()).rejects.toThrow(
      "IndexedDB is not available",
    );
  });

  it("reads a row written before importPending existed as having none", async () => {
    const { importPending: _drop, ...old } = ON;
    await putRaw("m", { owner: A, ...old });
    expect((await (await claimed()).load()).get(A)).toEqual(ON);
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

  // LITE_LOCK_PORT_OPTIONAL
  it("starts only with an owner lock port: with none, every claim is refused and nothing is read or written", async () => {
    const store = createStore("m");
    await expect(store.claim()).rejects.toBeInstanceOf(ModeStoreOwnedError);
    await expect(store.load()).rejects.toBeInstanceOf(ModeStoreOwnedError);
    const authority = createModeAuthority({ store, bootId: "b" });
    await expect(authority.ready).rejects.toBeInstanceOf(ModeStoreOwnedError);
    expect(await authority.submitEvidence(evidence("off"))).toMatchObject({
      code: "ACCOUNT_MODE_STORE_OWNED",
    });
    expect(await rawRows("m").catch(() => [])).toEqual([]);
  });

  it("names a missing Web Locks API differently from a busy lock", async () => {
    const store = createIndexedDbModeRecordStore("m", { locks: null });
    const missing = await store.claim().catch((e: Error) => e);
    expect(missing).toBeInstanceOf(ModeStoreOwnedError);
    const locks = createLocks();
    const held = await createIndexedDbModeRecordStore("m", { locks }).claim();
    const busy = await createIndexedDbModeRecordStore("m", { locks })
      .claim()
      .catch((e: Error) => e);
    await held.release();
    expect((missing as Error).message).toMatch(/Web Locks are not available/);
    expect((missing as Error).message).not.toBe((busy as Error).message);
  });

  it("includes the database name in the lock, so two databases do not contend", async () => {
    const locks = createLocks();
    const one = await createIndexedDbModeRecordStore("one", { locks }).claim();
    const two = await createIndexedDbModeRecordStore("two", { locks }).claim();
    await one.release();
    await two.release();
  });

  // LITE_RELEASE_BEFORE_DRAIN
  it("gives up a save whose database opened after the lease was released, and frees the lock only after it", async () => {
    const real = new IDBFactory();
    let openGate: (() => void) | null = null;
    let delayNext = false;
    vi.stubGlobal("indexedDB", {
      open: (...args: Parameters<IDBFactory["open"]>) => {
        if (!delayNext) return real.open(...args);
        delayNext = false;
        // The request is made, and the database is delivered late.
        const late = {} as IDBOpenDBRequest;
        openGate = () => {
          const actual = real.open(...args);
          actual.onupgradeneeded = () =>
            late.onupgradeneeded?.(undefined as never);
          const forward = actual as unknown as Record<string, unknown>;
          Object.defineProperty(late, "result", { get: () => actual.result });
          actual.onupgradeneeded = (event) => late.onupgradeneeded?.(event);
          actual.onsuccess = (event) => late.onsuccess?.(event);
          actual.onerror = (event) => late.onerror?.(event);
          void forward;
        };
        return late;
      },
    });
    const locks = createLocks();
    const a = createIndexedDbModeRecordStore("m", { locks });
    const leaseA = await a.claim();
    delayNext = true;
    const save = a.save(A, ON, null).catch((e: Error) => e);
    await tick(5);
    expect(openGate).not.toBeNull();
    // A lets go while its save is waiting for the database to open.
    let released = false;
    const releasing = leaseA.release().then(() => {
      released = true;
    });
    await tick(5);
    expect(released).toBe(false);
    // B cannot claim yet: A's call has not finished.
    const b = createIndexedDbModeRecordStore("m", { locks });
    await expect(b.claim()).rejects.toBeInstanceOf(ModeStoreOwnedError);
    // The database finally opens. A's save must not write.
    openGate!();
    expect(await save).toBeInstanceOf(ModeStoreOwnedError);
    await releasing;
    const leaseB = await b.claim();
    expect((await b.load()).size).toBe(0);
    await leaseB.release();
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
    expect(await second.submitEvidence(evidence("off"))).toMatchObject({
      code: "ACCOUNT_MODE_STORE_OWNED",
    });
    expect(await rawRows("m").catch(() => [])).toEqual([]);
    await first.close();
  });

  // RefusedAuthorityReclaimsAfterOwnerClose
  it("lets a refused authority reclaim the database after the owner closes, with no reload", async () => {
    const locks = createLocks();
    const first = createModeAuthority({
      store: createIndexedDbModeRecordStore("m", { locks }),
      bootId: "b1",
    });
    await first.ready;
    await first.submitEvidence(evidence("on"));
    const second = createModeAuthority({
      store: createIndexedDbModeRecordStore("m", { locks }),
      bootId: "b2",
      ownerRetryMs: 10,
    });
    await second.ready.catch(() => undefined);
    expect(second.read(A)).toMatchObject({ code: "ACCOUNT_MODE_STORE_OWNED" });
    await first.close();
    await tick(20);
    second.read(A);
    await tick(20);
    expect(second.read(A)).toEqual({ kind: "streams", importRequired: false });
    await second.close();
  });

  // QUARANTINE_FORGETS_ON
  it("keeps a saved On through a corrupt row: after the restart an Off is refused and an On owes the import", async () => {
    const locks = createLocks();
    const first = createModeAuthority({
      store: createIndexedDbModeRecordStore("m", { locks }),
      bootId: "b1",
      hasLegacyFiles: () => true,
    });
    await first.ready;
    await first.submitEvidence(evidence("on"));
    await first.close();
    await putRaw("m", { owner: A, switched: "garbled" });
    const second = createModeAuthority({
      store: createIndexedDbModeRecordStore("m", { locks }),
      bootId: "b2",
      hasLegacyFiles: () => false,
    });
    await second.ready;
    expect(await second.submitEvidence(evidence("off"))).toEqual({
      kind: "refuse",
      code: "ACCOUNT_MODE_UNKNOWN",
      status: 503,
    });
    expect(await second.commitLegacy(A, "op", () => 1)).toMatchObject({
      ok: false,
    });
    expect(await second.submitEvidence(evidence("on"))).toEqual({
      kind: "streams",
      importRequired: true,
    });
    await second.close();
  });

  // CLOSE_BEFORE_DRAIN
  it("holds the Web Lock until the authority has drained an admitted legacy write", async () => {
    const locks = createLocks();
    const first = createModeAuthority({
      store: createIndexedDbModeRecordStore("m", { locks }),
      bootId: "b1",
    });
    await first.ready;
    await first.submitEvidence(evidence("off"));
    let finish!: () => void;
    const latch = new Promise<void>((resolve) => {
      finish = resolve;
    });
    const log: string[] = [];
    const write = first.commitLegacy(A, "op", async () => {
      await latch;
      log.push("write");
    });
    await tick(5);
    const closing = first.close().then(() => log.push("closed"));
    await tick(5);
    await expect(
      createIndexedDbModeRecordStore("m", { locks }).claim(),
    ).rejects.toBeInstanceOf(ModeStoreOwnedError);
    finish();
    await write;
    await closing;
    expect(log).toEqual(["write", "closed"]);
    await (
      await createIndexedDbModeRecordStore("m", { locks }).claim()
    ).release();
  });

  // BLIND_OFF_OVERWRITES_ON
  it("rejects an Off over a stored On and a write based on a stale read, in one transaction", async () => {
    const store = await claimed();
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

  // GENERATION_NOT_PERSISTED
  it("keeps a generation, and lets only an Off at a higher generation replace an On", async () => {
    const locks = createLocks();
    const store = await claimed("m", locks);
    const at3 = { ...ON, generation: 3 };
    await store.save(A, at3, null);
    await expect(
      store.save(A, { ...OFF, generation: 3 }, at3),
    ).rejects.toBeInstanceOf(ModeStoreConflictError);
    await expect(store.save(A, OFF, at3)).rejects.toBeInstanceOf(
      ModeStoreConflictError,
    );
    const reset = { ...OFF, generation: 4 };
    await store.save(A, reset, at3);
    await store.release();
    const loaded = await (await claimed("m", locks)).load();
    expect(loaded.get(A)).toEqual(reset);
  });

  it("sets aside a row whose generation is not a non-negative integer", async () => {
    const locks = createLocks();
    await putRaw("m", { owner: A, ...ON, generation: -1 });
    const loaded = await (await claimed("m", locks)).load();
    expect(loaded.get(A)).toEqual(tombstoneRecord());
  });

  it("lets only one of two racing saves from the same read win", async () => {
    const store = await claimed();
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
    await first.submitEvidence(evidence("on"));
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
      clock: undefined,
    });
    await second.ready;
    expect(second.read(A).kind).toBe("streams");
  });
});
