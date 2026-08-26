import type {
  PendingBlobDeletion,
  PendingBlobDeletionStore,
} from "../ports/index.js";

/**
 * Minimal persistence seam for the pending-blob-deletion markers. Hosts
 * supply the storage (a JSON file on Node, IndexedDB state in the browser);
 * the store keeps the set semantics, de-duplication and mutation ordering in
 * one place. `write` must replace the whole value atomically (tmp + rename on
 * disk, a single IndexedDB put in the browser) so a crash mid-write cannot
 * leave a torn marker file.
 */
export interface PendingBlobDeletionKv {
  read(): Promise<PendingBlobDeletion[] | null>;
  write(keys: PendingBlobDeletion[]): Promise<void>;
}

function markerId(key: PendingBlobDeletion): string {
  return `${key.scope}\u0000${key.version ?? ""}`;
}

/**
 * Accept the stored value from either marker generation: exact keys
 * (`{ scope, version }`) or the pre-key format that recorded whole scopes,
 * which maps to a version-less marker the retry expands into exact keys.
 */
export function normalizePendingBlobDeletions(
  stored: unknown,
): PendingBlobDeletion[] {
  if (!Array.isArray(stored)) return [];
  const keys: PendingBlobDeletion[] = [];
  for (const item of stored) {
    if (typeof item === "string") {
      keys.push({ scope: item, version: null });
    } else if (
      typeof item === "object" &&
      item !== null &&
      typeof (item as { scope?: unknown }).scope === "string"
    ) {
      const version = (item as { version?: unknown }).version;
      keys.push({
        scope: (item as { scope: string }).scope,
        version: typeof version === "string" ? version : null,
      });
    }
  }
  return keys;
}

/**
 * Every operation is a read-modify-write of the whole marker set, so the
 * store serialises them: a delete recording keys while a sync cycle's retry
 * clears others must not lose either update. Ordering is FIFO, and a failed
 * operation never blocks the ones queued behind it.
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

  async function current(): Promise<PendingBlobDeletion[]> {
    return normalizePendingBlobDeletions(await kv.read());
  }

  return {
    list() {
      return serialized(current);
    },
    add(keys) {
      return serialized(async () => {
        if (keys.length === 0) return;
        const existing = await current();
        const known = new Set(existing.map(markerId));
        const next = [...existing];
        for (const key of keys) {
          const id = markerId(key);
          if (known.has(id)) continue;
          known.add(id);
          next.push({ scope: key.scope, version: key.version });
        }
        if (next.length === existing.length) return;
        await kv.write(next);
      });
    },
    remove(keys) {
      return serialized(async () => {
        if (keys.length === 0) return;
        const existing = await current();
        const gone = new Set(keys.map(markerId));
        const next = existing.filter((key) => !gone.has(markerId(key)));
        if (next.length === existing.length) return;
        await kv.write(next);
      });
    },
  };
}

/** Non-durable store: markers survive only for the process lifetime. */
export function createMemoryPendingBlobDeletionStore(): PendingBlobDeletionStore {
  let keys: PendingBlobDeletion[] = [];
  return createPendingBlobDeletionStore({
    async read() {
      return keys;
    },
    async write(next) {
      keys = next.map((key) => ({ ...key }));
    },
  });
}
