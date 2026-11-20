import type { LocalSyncDeps } from "./deps.js";

/**
 * A wake for readers waiting on a connection's apply. Apply calls
 * `announceApplied` after each part commits; a reader that wants the first
 * part waits on `nextApplied` instead of on the whole apply. Keyed by the
 * database's info object. Metered apply jobs wrap the database in a proxy,
 * but preserve this identity, so an early read receives the preview wake.
 */
const waiters = new WeakMap<object, Map<string, Set<() => void>>>();

/** A part of this connection's apply committed. */
export function announceApplied(
  deps: Pick<LocalSyncDeps, "db">,
  connectionId: string,
): void {
  const byId = waiters.get(deps.db.info);
  const set = byId?.get(connectionId);
  if (!set) return;
  byId!.delete(connectionId);
  for (const wake of set) wake();
}

/**
 * Resolves at the next `announceApplied` of this connection. Take it BEFORE
 * reading the state it waits on, so a part that commits between the read and
 * the wait is not missed.
 */
export function nextApplied(
  deps: Pick<LocalSyncDeps, "db">,
  connectionId: string,
): Promise<void> {
  let byId = waiters.get(deps.db.info);
  if (!byId) {
    byId = new Map();
    waiters.set(deps.db.info, byId);
  }
  let set = byId.get(connectionId);
  if (!set) {
    set = new Set();
    byId.set(connectionId, set);
  }
  return new Promise<void>((resolve) => {
    set.add(resolve);
  });
}
