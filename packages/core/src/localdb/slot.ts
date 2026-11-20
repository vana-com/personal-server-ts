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
