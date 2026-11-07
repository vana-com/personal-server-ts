import { IDBFactory, IDBKeyRange } from "fake-indexeddb";
import { describe, expect, it } from "vitest";
import { createStreamSyncReadCacheFiles } from "./stream-sync-read-cache-files.js";
import { createIndexedDbStreamSyncFiles } from "./stream-sync-files.js";

const enc = new TextEncoder();
const dec = new TextDecoder();

function open() {
  return createIndexedDbStreamSyncFiles({
    dbName: `t-${Math.random()}`,
    factory: new IDBFactory(),
    keyRange: IDBKeyRange,
  });
}

describe("IndexedDB stream-sync files appendMany", () => {
  it("appends a batch of files in order and reads each back", async () => {
    const files = open();
    for (let round = 0; round < 3; round += 1) {
      await files.appendMany(
        Array.from({ length: 50 }, (_, i) => ({
          path: `spool/${i}`,
          bytes: enc.encode(`r${round};`),
        })),
      );
    }
    expect(dec.decode((await files.read("spool/0"))!)).toBe("r0;r1;r2;");
    expect(dec.decode((await files.read("spool/49"))!)).toBe("r0;r1;r2;");
    expect(await files.list("spool")).toHaveLength(50);
    await files.sync("spool");
  });

  it("appends twice to one path inside one batch", async () => {
    const files = open();
    await files.appendMany([
      { path: "p", bytes: enc.encode("a") },
      { path: "p", bytes: enc.encode("b") },
    ]);
    expect(dec.decode((await files.read("p"))!)).toBe("ab");
  });

  it("opens one transaction per batch", async () => {
    const factory = new IDBFactory();
    const files = createIndexedDbStreamSyncFiles({
      dbName: "tx-count",
      factory,
      keyRange: IDBKeyRange,
    });
    await files.write("warm", enc.encode("x"));
    const db = await new Promise<IDBDatabase>((resolve) => {
      const request = factory.open("tx-count");
      request.onsuccess = () => resolve(request.result);
    });
    let transactions = 0;
    // The adapter has its own connection; count through the shared prototype.
    const proto = Object.getPrototypeOf(db) as {
      transaction: IDBDatabase["transaction"];
    };
    const wrapped = proto.transaction;
    proto.transaction = function (this: IDBDatabase, ...args: never[]) {
      transactions += 1;
      return (wrapped as (...a: unknown[]) => IDBTransaction).apply(this, args);
    } as IDBDatabase["transaction"];
    try {
      await files.appendMany(
        Array.from({ length: 100 }, (_, i) => ({
          path: `s/${i}`,
          bytes: enc.encode("x"),
        })),
      );
    } finally {
      proto.transaction = wrapped;
    }
    expect(transactions).toBe(1);
  });
});

describe("IndexedDB durability", () => {
  it("requests strict durability for every mutation", async () => {
    const factory = new IDBFactory();
    const request = factory.open("durability");
    const db = await new Promise<IDBDatabase>((resolve) => {
      request.onsuccess = () => resolve(request.result);
    });
    const proto = Object.getPrototypeOf(db) as {
      transaction: IDBDatabase["transaction"];
    };
    const original = proto.transaction;
    const options: (IDBTransactionOptions | undefined)[] = [];
    proto.transaction = function (
      this: IDBDatabase,
      ...args: Parameters<IDBDatabase["transaction"]>
    ) {
      if (args[1] === "readwrite") options.push(args[2]);
      return original.apply(this, args);
    } as IDBDatabase["transaction"];
    try {
      const files = createIndexedDbStreamSyncFiles({
        dbName: "strict-test",
        factory,
        keyRange: IDBKeyRange,
      });
      await files.write("p", enc.encode("a"));
      await files.appendMany([{ path: "p", bytes: enc.encode("b") }]);
      await files.sync("p");
      await files.remove("p");
      expect(options).toHaveLength(3);
      expect(options).toEqual(options.map(() => ({ durability: "strict" })));
    } finally {
      proto.transaction = original;
      db.close();
    }
  });
});

it("writes bounded chunks and removes stale chunks on overwrite", async () => {
  const files = open();
  const bytes = Uint8Array.from(
    { length: 1024 * 1024 + 17 },
    (_, i) => i % 251,
  );
  await files.write("large", bytes);
  expect(await files.read("large")).toEqual(bytes);
  const chunks: Uint8Array[] = [];
  for await (const chunk of files.readChunks("large")) chunks.push(chunk);
  expect(chunks.every((chunk) => chunk.length <= 1024 * 1024)).toBe(true);
  const combined = new Uint8Array(
    chunks.reduce((sum, chunk) => sum + chunk.length, 0),
  );
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.length;
  }
  expect(combined).toEqual(bytes);
  await files.appendMany([{ path: "large", bytes: enc.encode("tail") }]);
  expect((await files.read("large"))?.slice(-4)).toEqual(enc.encode("tail"));
  await files.write("large", enc.encode("short"));
  expect(dec.decode((await files.read("large"))!)).toBe("short");
  const overwritten: Uint8Array[] = [];
  for await (const chunk of files.readChunks("large")) overwritten.push(chunk);
  expect(overwritten).toHaveLength(1);
});

it("keeps read caches for different keys separate in one home", async () => {
  const files = open();
  const first = createStreamSyncReadCacheFiles(files, "key-one");
  const second = createStreamSyncReadCacheFiles(files, "key-two");
  await first.write("views/item", enc.encode("value"));
  expect(await second.read("views/item")).toBeNull();
});
