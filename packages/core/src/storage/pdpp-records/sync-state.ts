import type { SyncStateStore } from "./types.js";

/**
 * In-process `SyncStateStore`, for the memory record store and for a
 * readonly SQLite handle. State is lost on restart, which expires every
 * handle it held (410): the client restarts from `beginning`.
 */
export function createMemorySyncStateStore(): SyncStateStore {
  const states = new Map<
    string,
    { owner: string; state: string; expiresAt: number; seq: number }
  >();
  let seq = 0;
  return {
    put({ id, owner, state, expiresAt, now, maxPerOwner }) {
      states.delete(id);
      states.set(id, { owner, state, expiresAt, seq: ++seq });
      const own = [...states.entries()].filter(([, s]) => s.owner === owner);
      for (const [key, s] of own) if (s.expiresAt <= now) states.delete(key);
      const live = own
        .filter(([, s]) => s.expiresAt > now)
        .sort(([, a], [, b]) => b.seq - a.seq);
      for (const [key] of live.slice(maxPerOwner)) states.delete(key);
    },
    get(id, now) {
      const entry = states.get(id);
      return entry && entry.expiresAt > now ? entry.state : undefined;
    },
    delete(id) {
      states.delete(id);
    },
  };
}
