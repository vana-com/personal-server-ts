/**
 * `StreamSyncFiles` on IndexedDB for PS-Lite (§2.8: Web Lite, Account sheet
 * and RSS frames use OPFS where available, else IndexedDB).
 *
 * One object store holds file chunks keyed `<path>\u0001<seq>`. `write`
 * replaces every chunk of a path in one transaction; `appendMany` adds the
 * next chunk of every path of a batch in one transaction. A transaction that
 * completes is durable, so both resolve only after `oncomplete`.
 */

import type { StreamSyncFiles } from "@opendatalabs/personal-server-ts-core/stream-sync";

const STORE = "chunks";
const SEP = "\u0001";
// Bound each IndexedDB record to 1 MiB to limit memory used by a read step.
const CHUNK_SIZE = 1024 * 1024;
const SEQ_WIDTH = 10;
// Sorts before every chunk key, so no file or directory range contains it.
const RECHUNK_MARKER = "\u0000rechunked-v1";

interface Chunk {
  readonly key: string;
  readonly bytes: Uint8Array;
}

export interface IndexedDbStreamSyncFilesOptions {
  readonly dbName?: string;
  readonly factory?: IDBFactory;
  /** The `IDBKeyRange` of the same implementation as `factory`. */
  readonly keyRange?: typeof IDBKeyRange;
}

function promisify<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function done(tx: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error ?? new Error("transaction aborted"));
  });
}

const chunkKey = (path: string, seq: number) =>
  `${path}${SEP}${String(seq).padStart(SEQ_WIDTH, "0")}`;
const pathOf = (key: string) => key.slice(0, key.lastIndexOf(SEP));

/** Run `visit` on each cursor position; resolves at the end of the cursor. */
function walk(
  request: IDBRequest<IDBCursorWithValue | null>,
  visit: (cursor: IDBCursorWithValue) => void,
): Promise<void> {
  return new Promise((resolve, reject) => {
    request.onerror = () => reject(request.error);
    request.onsuccess = () => {
      const cursor = request.result;
      if (!cursor) return resolve();
      try {
        visit(cursor);
        cursor.continue();
      } catch (error) {
        reject(error);
      }
    };
  });
}

/**
 * Records written before files were split into chunks are one record per
 * write, and can be larger than CHUNK_SIZE. Split them once, when the adapter
 * opens (the caller holds the home lock). A marker record makes later opens
 * skip the work, so the cost is one pass over the home, one record in memory
 * at a time, at the first open only. Remove this once no home written before
 * chunking can exist.
 *
 * Each affected file is replaced in one strict transaction, so a crash leaves
 * the old records or the new ones. Chunk sequence numbers are contiguous
 * (`write` and `appendMany` both produce them), so the file is renumbered
 * from its last record down: a new key is never below its old key, and never
 * overwrites a record not yet read. A file with a gap in its sequence is left
 * as it is.
 */
async function rechunkOversizedRecords(
  database: IDBDatabase,
  fileRange: (path: string) => IDBKeyRange,
): Promise<void> {
  const marked = await promisify(
    database
      .transaction(STORE, "readonly")
      .objectStore(STORE)
      .get(RECHUNK_MARKER),
  );
  if (marked) return;

  const sizes = new Map<string, number[]>();
  const sparse = new Set<string>();
  await walk(
    database.transaction(STORE, "readonly").objectStore(STORE).openCursor(),
    (cursor) => {
      const key = String(cursor.key);
      if (!key.includes(SEP)) return;
      const path = pathOf(key);
      const lengths = sizes.get(path) ?? [];
      if (Number(key.slice(path.length + 1)) !== lengths.length)
        sparse.add(path);
      lengths.push((cursor.value as Chunk).bytes.length);
      sizes.set(path, lengths);
    },
  );

  for (const [path, lengths] of sizes) {
    if (sparse.has(path) || lengths.every((n) => n <= CHUNK_SIZE)) continue;
    const counts = lengths.map((n) => Math.max(1, Math.ceil(n / CHUNK_SIZE)));
    const starts: number[] = [];
    counts.reduce((start, n) => (starts.push(start), start + n), 0);
    const tx = database.transaction(STORE, "readwrite", {
      durability: "strict",
    });
    const committed = done(tx);
    committed.catch(() => {});
    const store = tx.objectStore(STORE);
    let index = lengths.length;
    try {
      await walk(store.openCursor(fileRange(path), "prev"), (cursor) => {
        index -= 1;
        const { bytes } = cursor.value as Chunk;
        for (let part = 0; part < counts[index]!; part += 1) {
          store.put({
            key: chunkKey(path, starts[index]! + part),
            bytes: bytes.slice(part * CHUNK_SIZE, (part + 1) * CHUNK_SIZE),
          } satisfies Chunk);
        }
      });
    } catch (error) {
      tx.abort();
      throw error;
    }
    await committed;
  }

  const tx = database.transaction(STORE, "readwrite", { durability: "strict" });
  tx.objectStore(STORE).put({ key: RECHUNK_MARKER, bytes: new Uint8Array(0) });
  await done(tx);
}

export function createIndexedDbStreamSyncFiles(
  options: IndexedDbStreamSyncFilesOptions = {},
): StreamSyncFiles & { close(): void } {
  const factory = options.factory ?? globalThis.indexedDB;
  const KeyRange = options.keyRange ?? globalThis.IDBKeyRange;
  if (!factory || !KeyRange) {
    throw new Error("IndexedDB is not available in this runtime");
  }
  const fileRange = (path: string) =>
    KeyRange.bound(`${path}${SEP}`, `${path}${SEP}\uffff`);
  const dirRange = (prefix: string) =>
    KeyRange.bound(`${prefix}/`, `${prefix}/\uffff`);
  const dbName = options.dbName ?? "ps-lite-stream-sync";
  let opened: Promise<IDBDatabase> | null = null;
  const db = (): Promise<IDBDatabase> => {
    opened ??= new Promise<IDBDatabase>((resolve, reject) => {
      const request = factory.open(dbName, 1);
      request.onupgradeneeded = () => {
        request.result.createObjectStore(STORE, { keyPath: "key" });
        // A new database holds no record written before chunking.
        request.transaction?.objectStore(STORE).put({
          key: RECHUNK_MARKER,
          bytes: new Uint8Array(0),
        });
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    }).then(async (database) => {
      try {
        await rechunkOversizedRecords(database, fileRange);
      } catch (error) {
        database.close();
        opened = null;
        throw error;
      }
      return database;
    });
    return opened;
  };

  // Engines without the durability option ignore it. The phone WebView engine is unknown.
  async function lastSeq(store: IDBObjectStore, path: string): Promise<number> {
    const cursor = await promisify(
      store.openKeyCursor(fileRange(path), "prev"),
    );
    if (!cursor) return -1;
    return Number(String(cursor.key).slice(path.length + 1));
  }

  return {
    close() {
      void opened?.then((d) => d.close());
      opened = null;
    },
    async write(path, bytes) {
      const tx = (await db()).transaction(STORE, "readwrite", {
        durability: "strict",
      });
      const store = tx.objectStore(STORE);
      store.delete(fileRange(path));
      for (
        let offset = 0, seq = 0;
        offset < bytes.length || seq === 0;
        offset += CHUNK_SIZE, seq += 1
      ) {
        store.put({
          key: chunkKey(path, seq),
          bytes: bytes.slice(offset, offset + CHUNK_SIZE),
        } satisfies Chunk);
      }
      await done(tx);
    },
    async read(path) {
      const tx = (await db()).transaction(STORE, "readonly");
      const chunks = (await promisify(
        tx.objectStore(STORE).getAll(fileRange(path)),
      )) as Chunk[];
      if (chunks.length === 0) return null;
      const out = new Uint8Array(
        chunks.reduce((n, c) => n + c.bytes.length, 0),
      );
      let offset = 0;
      for (const chunk of chunks) {
        out.set(chunk.bytes, offset);
        offset += chunk.bytes.length;
      }
      return out;
    },
    async appendMany(entries) {
      if (entries.length === 0) return;
      // One transaction for the whole batch: a spool flush touches up to 256
      // shard files, and a transaction per file would commit 256 times.
      const tx = (await db()).transaction(STORE, "readwrite", {
        durability: "strict",
      });
      const store = tx.objectStore(STORE);
      const committed = done(tx);
      const next = new Map<string, number>();
      for (const { path, bytes } of entries) {
        let seq = next.get(path);
        if (seq === undefined) seq = (await lastSeq(store, path)) + 1;
        for (
          let offset = 0;
          offset < bytes.length || offset === 0;
          offset += CHUNK_SIZE
        ) {
          store.put({
            key: chunkKey(path, seq),
            bytes: bytes.slice(offset, offset + CHUNK_SIZE),
          } satisfies Chunk);
          seq += 1;
        }
        next.set(path, seq);
      }
      await committed;
    },
    // A transaction that completed is durable: nothing is left to sync.
    async sync() {},
    async *readChunks(path) {
      let after: string | null = null;
      for (;;) {
        const tx = (await db()).transaction(STORE, "readonly");
        const range: IDBKeyRange =
          after === null
            ? fileRange(path)
            : KeyRange.bound(after, `${path}${SEP}\uffff`, true);
        const cursor = await promisify(tx.objectStore(STORE).openCursor(range));
        if (!cursor) return;
        const chunk = cursor.value as Chunk;
        after = chunk.key;
        yield chunk.bytes;
      }
    },
    async size(path) {
      const tx = (await db()).transaction(STORE, "readonly");
      const chunks = (await promisify(
        tx.objectStore(STORE).getAll(fileRange(path)),
      )) as Chunk[];
      return chunks.reduce((n, c) => n + c.bytes.length, 0);
    },
    async list(prefix) {
      const tx = (await db()).transaction(STORE, "readonly");
      const keys = (await promisify(
        tx.objectStore(STORE).getAllKeys(dirRange(prefix)),
      )) as string[];
      return [...new Set(keys.map(pathOf))].sort();
    },
    async remove(prefix) {
      const tx = (await db()).transaction(STORE, "readwrite", {
        durability: "strict",
      });
      const store = tx.objectStore(STORE);
      store.delete(fileRange(prefix));
      store.delete(dirRange(prefix));
      await done(tx);
    },
  };
}
