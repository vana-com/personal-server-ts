import { IDBFactory, IDBKeyRange, IDBObjectStore } from "fake-indexeddb";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createIndexedDbStreamSyncFiles } from "./stream-sync-files.js";

const MIB = 1024 * 1024;
const OVERSIZED = 3 * MIB + 19;

// Seeding multi-MiB records through the fake database is slow.
vi.setConfig({ testTimeout: 60_000 });

afterEach(() => vi.restoreAllMocks());

function pattern(length: number, salt: number): Uint8Array {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i += 1) out[i] = (i * 31 + salt) & 0xff;
  return out;
}

/** Write records the way the adapter did before files were chunked. */
async function seedOldRecords(
  factory: IDBFactory,
  dbName: string,
  records: Record<string, Uint8Array[]>,
) {
  const db = await new Promise<IDBDatabase>((resolve, reject) => {
    const request = factory.open(dbName, 1);
    request.onupgradeneeded = () =>
      request.result.createObjectStore("chunks", { keyPath: "key" });
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  const tx = db.transaction("chunks", "readwrite");
  for (const [path, parts] of Object.entries(records)) {
    parts.forEach((bytes, seq) =>
      tx.objectStore("chunks").put({
        key: `${path}\u0001${String(seq).padStart(10, "0")}`,
        bytes,
      }),
    );
  }
  await new Promise<void>((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
  db.close();
}

function adapter(factory: IDBFactory, dbName: string) {
  return createIndexedDbStreamSyncFiles({
    dbName,
    factory,
    keyRange: IDBKeyRange,
  });
}

async function collect(chunks: AsyncIterable<Uint8Array>) {
  const out: Uint8Array[] = [];
  for await (const chunk of chunks) out.push(chunk);
  return out;
}

const same = (a: Uint8Array | null, b: Uint8Array) =>
  a !== null && Buffer.compare(a, b) === 0;

const join = (parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
};

describe("IndexedDB stream-sync files: records written before chunking", () => {
  it("splits an oversized record on open and keeps the bytes", async () => {
    const factory = new IDBFactory();
    const big = pattern(OVERSIZED, 1);
    const small = pattern(10, 2);
    const tail = pattern(5, 3);
    await seedOldRecords(factory, "old", {
      "d/a": [big],
      "d/mixed": [small, big, tail],
      "d/untouched": [small],
    });

    const files = adapter(factory, "old");
    expect(same(await files.read("d/a"), big)).toBe(true);
    expect(same(await files.read("d/mixed"), join([small, big, tail]))).toBe(
      true,
    );
    expect(same(await files.read("d/untouched"), small)).toBe(true);
    for (const path of ["d/a", "d/mixed", "d/untouched"]) {
      const chunks = await collect(files.readChunks(path));
      expect(Math.max(...chunks.map((c) => c.length))).toBeLessThanOrEqual(MIB);
      expect(same(join(chunks), await files.read(path))).toBe(true);
    }
    expect(await files.size("d/a")).toBe(OVERSIZED);
    expect(await files.list("d")).toEqual(["d/a", "d/mixed", "d/untouched"]);
    files.close();
  });

  it("keeps order when appending after the reopen", async () => {
    const factory = new IDBFactory();
    const big = pattern(OVERSIZED, 4);
    await seedOldRecords(factory, "append", { a: [big] });
    const files = adapter(factory, "append");
    const extra = pattern(MIB + 7, 5);
    await files.appendMany([{ path: "a", bytes: extra }]);
    expect(same(await files.read("a"), join([big, extra]))).toBe(true);
    const chunks = await collect(files.readChunks("a"));
    expect(Math.max(...chunks.map((c) => c.length))).toBeLessThanOrEqual(MIB);
    files.close();
  });

  it("does no work on a second open", async () => {
    const factory = new IDBFactory();
    await seedOldRecords(factory, "twice", { a: [pattern(OVERSIZED, 6)] });
    const first = adapter(factory, "twice");
    await first.size("a");
    first.close();
    const puts = vi.spyOn(IDBObjectStore.prototype, "put");
    const cursors = vi.spyOn(IDBObjectStore.prototype, "openCursor");
    const second = adapter(factory, "twice");
    expect(await second.size("a")).toBe(OVERSIZED);
    expect(puts).not.toHaveBeenCalled();
    expect(cursors).not.toHaveBeenCalled();
    second.close();
  });

  it("leaves the old bytes readable when the migration fails midway", async () => {
    const factory = new IDBFactory();
    const big = pattern(OVERSIZED, 7);
    const tail = pattern(5, 8);
    await seedOldRecords(factory, "crash", { a: [big, tail] });

    const put = IDBObjectStore.prototype.put;
    let puts = 0;
    const spy = vi
      .spyOn(IDBObjectStore.prototype, "put")
      .mockImplementation(function (this: IDBObjectStore, ...args) {
        puts += 1;
        if (puts === 3) throw new Error("injected failure");
        return put.apply(this, args);
      });
    const failing = adapter(factory, "crash");
    await expect(failing.read("a")).rejects.toThrow("injected failure");
    failing.close();
    spy.mockRestore();

    // Nothing was committed: the old records are intact, a retry migrates.
    const raw = await new Promise<IDBDatabase>((resolve) => {
      const request = factory.open("crash", 1);
      request.onsuccess = () => resolve(request.result);
    });
    const keys = await new Promise<IDBValidKey[]>((resolve) => {
      const request = raw
        .transaction("chunks", "readonly")
        .objectStore("chunks")
        .getAllKeys();
      request.onsuccess = () => resolve(request.result);
    });
    expect(keys).toHaveLength(2);
    raw.close();

    const retry = adapter(factory, "crash");
    expect(same(await retry.read("a"), join([big, tail]))).toBe(true);
    retry.close();
  });
});
