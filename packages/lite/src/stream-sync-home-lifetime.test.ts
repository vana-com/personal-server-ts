import { IDBFactory, IDBKeyRange } from "fake-indexeddb";
import { describe, expect, it, vi } from "vitest";
import {
  openIndexedDbStreamSyncHome,
  type StreamSyncLocks,
} from "./stream-sync-files.js";

const A = "0x1C5A77d9FA7eF466951B2F01F724BCa3A5820b63" as const;
const NET = "vana:14800:https://g.test";

/** Exclusive Web Locks that answer `ifAvailable` with null while held. */
function fakeLocks() {
  const held = new Set<string>();
  const locks: StreamSyncLocks = {
    async request(name, _options, callback) {
      if (held.has(name)) return callback(null);
      held.add(name);
      try {
        return await callback({ name });
      } finally {
        held.delete(name);
      }
    },
  };
  return { locks, held };
}

/**
 * An IndexedDB factory whose `open` does not report success until released:
 * an operation that awaits the database is then in flight, as one waiting on
 * the disk is.
 */
function gatedFactory(factory: IDBFactory) {
  let release!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const gated = {
    open(name: string, version?: number) {
      const real = factory.open(name, version);
      const proxy = {
        onsuccess: null as null | (() => void),
        onerror: null as null | (() => void),
        onupgradeneeded: null as null | (() => void),
        get result() {
          return real.result;
        },
        get error() {
          return real.error;
        },
      };
      real.onupgradeneeded = () => proxy.onupgradeneeded?.();
      real.onsuccess = () => void gate.then(() => proxy.onsuccess?.());
      real.onerror = () => proxy.onerror?.();
      return proxy;
    },
  } as unknown as IDBFactory;
  return { factory: gated, release };
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function stillPending(promise: Promise<unknown>, ms: number) {
  let settled = false;
  void promise.then(
    () => (settled = true),
    () => (settled = true),
  );
  await sleep(ms);
  return !settled;
}

describe("Lite stream-sync home: the lock outlives file operations", () => {
  it("close waits for an operation in flight; the lock is held until it ends", async () => {
    const idb = new IDBFactory();
    const { locks, held } = fakeLocks();
    const gate = gatedFactory(idb);
    const first = (await openIndexedDbStreamSyncHome({
      ownerAddress: A,
      network: NET,
      factory: gate.factory,
      keyRange: IDBKeyRange,
      locks,
    }))!;
    expect(first).not.toBeNull();
    const write = first.home.files.write("state.json", new Uint8Array([7]));
    await sleep(10);

    const closing = first.close();
    expect(await stillPending(closing, 60)).toBe(true);
    expect(held.size).toBe(1);
    expect(
      await openIndexedDbStreamSyncHome({
        ownerAddress: A,
        network: NET,
        factory: idb,
        keyRange: IDBKeyRange,
        locks,
      }),
    ).toBeNull();
    // An operation that starts now is refused.
    await expect(first.home.files.read("state.json")).rejects.toMatchObject({
      name: "StreamSyncHomeClosedError",
    });

    gate.release();
    await write;
    await closing;
    // The Web Lock goes a moment after the callback's promise resolves.
    await vi.waitFor(() => expect(held.size).toBe(0));

    const second = await openIndexedDbStreamSyncHome({
      ownerAddress: A,
      network: NET,
      factory: idb,
      keyRange: IDBKeyRange,
      locks,
    });
    expect(second).not.toBeNull();
    // The write ended under the first holder's lock, so the second sees it.
    expect(await second!.home.files.read("state.json")).toEqual(
      new Uint8Array([7]),
    );
    await second!.close();
  });

  it("an open iterator holds close until it is returned", async () => {
    const idb = new IDBFactory();
    const { locks, held } = fakeLocks();
    const first = (await openIndexedDbStreamSyncHome({
      ownerAddress: A,
      network: NET,
      factory: idb,
      keyRange: IDBKeyRange,
      locks,
    }))!;
    await first.home.files.appendMany([
      { path: "log", bytes: new Uint8Array([1]) },
      { path: "log", bytes: new Uint8Array([2]) },
    ]);
    const iterator = first.home.files.readChunks("log")[Symbol.asyncIterator]();
    expect((await iterator.next()).done).toBe(false);

    const closing = first.close();
    expect(await stillPending(closing, 60)).toBe(true);
    expect(held.size).toBe(1);

    await iterator.return!();
    await closing;
    // The Web Lock goes a moment after the callback's promise resolves.
    await vi.waitFor(() => expect(held.size).toBe(0));
  });

  it("closes twice without error", async () => {
    const { locks } = fakeLocks();
    const first = (await openIndexedDbStreamSyncHome({
      ownerAddress: A,
      network: NET,
      factory: new IDBFactory(),
      keyRange: IDBKeyRange,
      locks,
    }))!;
    await first.close();
    await first.close();
  });
});
