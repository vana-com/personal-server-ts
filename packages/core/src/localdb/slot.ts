import type { LocalSyncDeps } from "./deps.js";

/**
 * Deps for work that already holds `connectionId`'s queue slot. The queue is
 * not reentrant: an operation that takes the slot itself (`applyConnection`,
 * `purgeConnection`) would wait for the holder, which is its own caller. Here
 * that connection's operations run inline; other connections still queue.
 */
export function insideQueue(
  deps: LocalSyncDeps,
  connectionId: string,
): LocalSyncDeps {
  return {
    ...deps,
    queue: {
      run: (id, kind, operation) =>
        id === connectionId ? operation() : deps.queue.run(id, kind, operation),
    },
  };
}

/**
 * Deps for work that holds the queue slots of every connection in
 * `connectionIds`: the operations of each of those connections run inline.
 * A turn that commits rows of several connections holds all their slots
 * (taken in `connectionId` order, see `holdSlots`) and runs under these.
 */
export function insideQueues(
  deps: LocalSyncDeps,
  connectionIds: ReadonlySet<string>,
): LocalSyncDeps {
  return {
    ...deps,
    queue: {
      run: (id, kind, operation) =>
        connectionIds.has(id)
          ? operation()
          : deps.queue.run(id, kind, operation),
    },
  };
}

/**
 * Run `work` holding the slots of `connectionIds`. Slots are taken one after
 * the other in ascending id order, so two turns that share connections cannot
 * each hold one the other waits for. A holder of a slot never waits for a
 * slot of a lower id, and a turn waits on nothing else.
 */
export function holdSlots<T>(
  deps: LocalSyncDeps,
  connectionIds: readonly string[],
  work: (held: LocalSyncDeps) => Promise<T>,
): Promise<T> {
  const ordered = [...new Set(connectionIds)].sort();
  const held = insideQueues(deps, new Set(ordered));
  const take = (at: number): Promise<T> =>
    at === ordered.length
      ? work(held)
      : deps.queue.run(ordered[at]!, "publish", () => take(at + 1));
  return take(0);
}
