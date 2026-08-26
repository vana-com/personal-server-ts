import type { PendingBlobDeletionStore } from "../ports/index.js";

/**
 * Minimal persistence seam for the pending-blob-deletion marker. Hosts supply
 * the storage (a JSON file on Node, IndexedDB state in the browser); the
 * store keeps the set semantics, de-duplication and mutation ordering in one
 * place. `write` must replace the whole value atomically (tmp + rename on
 * disk, a single IndexedDB put in the browser) so a crash mid-write cannot
 * leave a torn marker file.
 */
export interface PendingBlobDeletionKv {
  read(): Promise<string[] | null>;
  write(scopes: string[]): Promise<void>;
}

/**
 * Every operation is a read-modify-write of the whole marker set, so the
 * store serialises them: a delete recording a marker while a sync cycle's
 * retry clears another must not lose either update. Ordering is FIFO, and a
 * failed operation never blocks the ones queued behind it.
 */
export function createPendingBlobDeletionStore(
  kv: PendingBlobDeletionKv,
): PendingBlobDeletionStore {
  let queue: Promise<unknown> = Promise.resolve();

  function serialized<T>(operation: () => Promise<T>): Promise<T> {
    const run = queue.then(operation, operation);
    queue = run.catch(() => undefined);
    return run;
  }

  async function current(): Promise<string[]> {
    const stored = await kv.read();
    return Array.isArray(stored)
      ? stored.filter((scope): scope is string => typeof scope === "string")
      : [];
  }

  return {
    list() {
      return serialized(current);
    },
    add(scope) {
      return serialized(async () => {
        const scopes = await current();
        if (scopes.includes(scope)) return;
        await kv.write([...scopes, scope]);
      });
    },
    remove(scope) {
      return serialized(async () => {
        const scopes = await current();
        if (!scopes.includes(scope)) return;
        await kv.write(scopes.filter((candidate) => candidate !== scope));
      });
    },
  };
}

/** Non-durable store: markers survive only for the process lifetime. */
export function createMemoryPendingBlobDeletionStore(): PendingBlobDeletionStore {
  let scopes: string[] = [];
  return createPendingBlobDeletionStore({
    async read() {
      return scopes;
    },
    async write(next) {
      scopes = [...next];
    },
  });
}
