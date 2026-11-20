/**
 * A small readers-writer lock with writer preference.
 *
 * Shared holders (legacy commits) run together. An exclusive holder (an
 * evidence step that may latch On) waits for every shared holder to finish and
 * blocks new ones until it is done, so no shared holder can start after the
 * exclusive holder has been granted, and none can be mid-write when it runs.
 */

export interface RwLock {
  shared(): Promise<() => void>;
  exclusive(): Promise<() => void>;
}

interface Waiter {
  kind: "shared" | "exclusive";
  grant: (release: () => void) => void;
}

export function createRwLock(): RwLock {
  let readers = 0;
  let writer = false;
  const queue: Waiter[] = [];

  function pump(): void {
    for (;;) {
      const head = queue[0];
      if (!head) return;
      if (head.kind === "exclusive") {
        if (writer || readers > 0) return;
        queue.shift();
        writer = true;
        head.grant(
          once(() => {
            writer = false;
            pump();
          }),
        );
        return;
      }
      if (writer) return;
      queue.shift();
      readers += 1;
      head.grant(
        once(() => {
          readers -= 1;
          pump();
        }),
      );
    }
  }

  function once(fn: () => void): () => void {
    let called = false;
    return () => {
      if (called) return;
      called = true;
      fn();
    };
  }

  function acquire(kind: Waiter["kind"]): Promise<() => void> {
    return new Promise((grant) => {
      queue.push({ kind, grant });
      pump();
    });
  }

  return {
    shared: () => acquire("shared"),
    exclusive: () => acquire("exclusive"),
  };
}
