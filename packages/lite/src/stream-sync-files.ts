/**
 * `StreamSyncFiles` on IndexedDB for PS-Lite (§2.8: Web Lite, Account sheet
 * and RSS frames use OPFS where available, else IndexedDB).
 *
 * One object store holds file chunks keyed `<path>\u0001<seq>`. `write`
 * replaces every chunk of a path in one transaction; `appendMany` adds the
 * next chunk of every path of a batch in one transaction. A transaction that
 * completes is durable, so both resolve only after `oncomplete`.
 */

import {
  bindStreamSyncHome,
  createStreamSyncIoBarrier,
  type StreamSyncFiles,
  type StreamSyncHome,
} from "@opendatalabs/personal-server-ts-core/stream-sync";

const STORE = "chunks";
const SEP = "\u0001";
const SEQ_WIDTH = 10;

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
    opened ??= new Promise((resolve, reject) => {
      const request = factory.open(dbName, 1);
      request.onupgradeneeded = () => {
        request.result.createObjectStore(STORE, { keyPath: "key" });
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    return opened;
  };

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
      const tx = (await db()).transaction(STORE, "readwrite");
      const store = tx.objectStore(STORE);
      store.delete(fileRange(path));
      store.put({
        key: chunkKey(path, 0),
        bytes: bytes.slice(),
      } satisfies Chunk);
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
      const tx = (await db()).transaction(STORE, "readwrite");
      const store = tx.objectStore(STORE);
      const committed = done(tx);
      const next = new Map<string, number>();
      for (const { path, bytes } of entries) {
        let seq = next.get(path);
        if (seq === undefined) seq = (await lastSeq(store, path)) + 1;
        next.set(path, seq + 1);
        store.put({
          key: chunkKey(path, seq),
          bytes: bytes.slice(),
        } satisfies Chunk);
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
        const chunk = (await promisify(tx.objectStore(STORE).get(range))) as
          Chunk | undefined;
        if (!chunk) return;
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
      const tx = (await db()).transaction(STORE, "readwrite");
      const store = tx.objectStore(STORE);
      store.delete(fileRange(prefix));
      store.delete(dirRange(prefix));
      await done(tx);
    },
  };
}

/** The part of `navigator.locks` the home needs. */
export interface StreamSyncLocks {
  request(
    name: string,
    options: { mode: "exclusive"; ifAvailable: true },
    callback: (lock: unknown) => Promise<unknown>,
  ): Promise<unknown>;
}

export interface IndexedDbStreamSyncHomeOptions {
  readonly ownerAddress: `0x${string}`;
  /** See `streamSyncNetwork`. */
  readonly network: string;
  readonly factory?: IDBFactory;
  readonly keyRange?: typeof IDBKeyRange;
  /** Defaults to `navigator.locks`. */
  readonly locks?: StreamSyncLocks;
}

export interface IndexedDbStreamSyncHome {
  readonly home: StreamSyncHome;
  /**
   * Release the lock once every file operation of the home (including open
   * `readChunks` iterators) has finished, then close the database.
   * Operations that start after `close` begins reject. Safe to call twice.
   */
  close(): Promise<void>;
}

/**
 * The stream-sync home of one (owner, network) on this origin: an IndexedDB
 * named after the home, and an exclusive Web Lock of the same name that stays
 * held until `close`. Resolves `null`, and holds nothing, when another
 * instance holds the lock or `navigator.locks` is missing: that instance runs
 * no stream sync (its legacy sync is unaffected). The old unbound database
 * ("ps-lite-stream-sync") is not read, migrated or deleted.
 */
export async function openIndexedDbStreamSyncHome(
  options: IndexedDbStreamSyncHomeOptions,
): Promise<IndexedDbStreamSyncHome | null> {
  const locks =
    options.locks ??
    (globalThis.navigator?.locks as StreamSyncLocks | undefined);
  if (!locks) return null;
  let files: (StreamSyncFiles & { close(): void }) | null = null;
  // Every file operation of the home passes through this barrier, so none
  // starts or ends after the lock is released (see core's io-barrier.ts).
  const barrier = createStreamSyncIoBarrier();
  const home = bindStreamSyncHome({
    ownerAddress: options.ownerAddress,
    network: options.network,
    open: (id) => {
      files = createIndexedDbStreamSyncFiles({
        dbName: `ps-lite-stream-sync-${id}`,
        factory: options.factory,
        keyRange: options.keyRange,
      });
      return barrier.guard(files);
    },
  });
  let release!: () => void;
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  const acquired = await new Promise<boolean>((resolve, reject) => {
    locks
      .request(
        `ps-lite-stream-sync-${home.id}`,
        { mode: "exclusive", ifAvailable: true },
        async (lock) => {
          resolve(lock !== null);
          if (lock !== null) await held;
        },
      )
      .catch(reject);
  });
  if (!acquired) {
    (files as { close(): void } | null)?.close();
    return null;
  }
  return {
    home,
    async close() {
      // Drain first: the lock stays held while any file operation runs.
      await barrier.shut();
      (files as { close(): void } | null)?.close();
      release();
    },
  };
}
