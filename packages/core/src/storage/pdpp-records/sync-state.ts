import type { SyncStateStore } from "./types.js";

/**
 * In-process `SyncStateStore`, for the memory record store and for a
 * readonly SQLite handle. State is lost on restart, which expires every
 * handle it held (410): the client restarts from `beginning`.
 */
export function createMemorySyncStateStore(): SyncStateStore & {
  /** Stored entries, live or not yet swept. */
  size(): number;
} {
  const states = new Map<
    string,
    { owner: string; state: string; expiresAt: number; seq: number }
  >();
  let seq = 0;
  const live = (id: string, now: number) => {
    const entry = states.get(id);
    return entry && entry.expiresAt > now ? entry : undefined;
  };
  return {
    put({ id, owner, state, expiresAt, now, maxPerOwner, expect }) {
      if (expect !== undefined && (live(id, now)?.state ?? null) !== expect)
        return false;
      states.delete(id);
      states.set(id, { owner, state, expiresAt, seq: ++seq });
      // Every owner's expired states go, so inactive owners leave nothing.
      for (const [key, s] of states) if (s.expiresAt <= now) states.delete(key);
      const own = [...states.entries()]
        .filter(([, s]) => s.owner === owner)
        .sort(([, a], [, b]) => b.seq - a.seq);
      for (const [key] of own.slice(maxPerOwner)) states.delete(key);
      return true;
    },
    get: (id, now) => live(id, now)?.state,
    delete(id, expected) {
      if (expected === undefined || states.get(id)?.state === expected)
        states.delete(id);
    },
    size: () => states.size,
  };
}
