/**
 * The I/O lifetime barrier of a stream-sync home.
 *
 * A host holds one lock per home (an SQLite lock on disk, a Web Lock in the
 * browser) and the lock is only worth something if no file operation of the
 * home can run without it. Releasing the lock while an operation is still on
 * its way to disk lets a second holder open the home, recover (discard) a run
 * that the first holder is still writing, and then see that holder's late
 * write recreate part of the run.
 *
 * The host guards every `StreamSyncFiles` it hands out for the home (the
 * writer's files and the seed staging files) with one barrier. To release the
 * lock it calls `shut()`, waits, and only then lets go:
 *
 * - an operation that starts after `shut()` rejects with
 *   `StreamSyncHomeClosedError` and never reaches the store;
 * - an operation that started before it keeps running, and `shut()` resolves
 *   only when it has finished;
 * - `readChunks` counts from its first `next()` until it is done, throws, or
 *   is returned; an iterator that was started may finish under the lock.
 *
 * There is no timeout. A drain that does not end keeps the lock, which is the
 * safe side: the process ending releases it.
 */

import type { StreamSyncFiles } from "./ports.js";

export class StreamSyncHomeClosedError extends Error {
  constructor() {
    super(
      "The stream-sync home is closed; file operations are no longer allowed",
    );
    this.name = "StreamSyncHomeClosedError";
  }
}

export interface StreamSyncIoBarrier {
  /** The same files; every operation passes through this barrier. */
  guard(files: StreamSyncFiles): StreamSyncFiles;
  /**
   * Reject new operations from now on; resolve once every started operation
   * has finished. Safe to call again: each call waits for the same drain.
   */
  shut(): Promise<void>;
}

export function createStreamSyncIoBarrier(): StreamSyncIoBarrier {
  let inFlight = 0;
  let closing = false;
  let drained: Promise<void> | null = null;
  let markDrained: (() => void) | null = null;

  const enter = (): void => {
    if (closing) throw new StreamSyncHomeClosedError();
    inFlight += 1;
  };
  const leave = (): void => {
    inFlight -= 1;
    if (inFlight === 0) markDrained?.();
  };
  const run = async <T>(operation: () => Promise<T>): Promise<T> => {
    enter();
    try {
      return await operation();
    } finally {
      leave();
    }
  };

  function guardChunks(
    files: StreamSyncFiles,
    path: string,
  ): AsyncIterable<Uint8Array> {
    return {
      [Symbol.asyncIterator](): AsyncIterator<Uint8Array> {
        let inner: AsyncIterator<Uint8Array> | null = null;
        let counted = false;
        const finish = (): void => {
          if (!counted) return;
          counted = false;
          leave();
        };
        return {
          async next() {
            if (!inner) {
              enter();
              counted = true;
              inner = files.readChunks(path)[Symbol.asyncIterator]();
            }
            try {
              const result = await inner.next();
              if (result.done) finish();
              return result;
            } catch (error) {
              finish();
              throw error;
            }
          },
          async return(value?: unknown) {
            try {
              return inner?.return
                ? await inner.return(value)
                : { done: true as const, value: undefined };
            } finally {
              finish();
            }
          },
          async throw(error?: unknown) {
            try {
              if (inner?.throw) return await inner.throw(error);
              throw error;
            } finally {
              finish();
            }
          },
        };
      },
    };
  }

  return {
    guard: (files) => ({
      write: (path, bytes) => run(() => files.write(path, bytes)),
      read: (path) => run(() => files.read(path)),
      appendMany: (entries) => run(() => files.appendMany(entries)),
      sync: (prefix) => run(() => files.sync(prefix)),
      readChunks: (path) => guardChunks(files, path),
      size: (path) => run(() => files.size(path)),
      list: (prefix) => run(() => files.list(prefix)),
      remove: (prefix) => run(() => files.remove(prefix)),
    }),
    shut() {
      closing = true;
      drained ??= new Promise<void>((resolve) => {
        markDrained = resolve;
        if (inFlight === 0) resolve();
      });
      return drained;
    },
  };
}
