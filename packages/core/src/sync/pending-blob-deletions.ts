import type { PendingBlobDeletionStore } from "../ports/index.js";

/**
 * Minimal persistence seam for the pending-blob-deletion marker. Hosts supply
 * the storage (a JSON file on Node, IndexedDB state in the browser); the
 * store keeps the set semantics and de-duplication in one place.
 */
export interface PendingBlobDeletionKv {
  read(): Promise<string[] | null>;
  write(scopes: string[]): Promise<void>;
}

export function createPendingBlobDeletionStore(
  kv: PendingBlobDeletionKv,
): PendingBlobDeletionStore {
  async function current(): Promise<string[]> {
    const stored = await kv.read();
    return Array.isArray(stored)
      ? stored.filter((scope) => typeof scope === "string")
      : [];
  }

  return {
    async list() {
      return current();
    },
    async add(scope) {
      const scopes = await current();
      if (scopes.includes(scope)) return;
      await kv.write([...scopes, scope]);
    },
    async remove(scope) {
      const scopes = await current();
      if (!scopes.includes(scope)) return;
      await kv.write(scopes.filter((candidate) => candidate !== scope));
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
