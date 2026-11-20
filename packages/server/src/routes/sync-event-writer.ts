/**
 * The writer for one connection of the owner's change feed.
 *
 * Every event on the feed is an invalidation, not a record of history: a
 * `view` event says "re-read these connections" and a `status` event carries
 * the manager's whole status, so the newest replaces the one before. Two such
 * events that arrive while a frame is still being written can therefore be
 * folded into one with the same meaning for the reader.
 *
 * The writer uses that. It holds what is owed, not a queue of what happened:
 * at most one `ready`, one status, and one set of connection ids. Its size is
 * bounded by the number of connections in the store, not by the number of
 * events. One drain loop writes one frame at a time and waits for the stream
 * to take it. A reader that stops reading blocks that one loop and nothing
 * else: the producers (a commit, a status change) only record what is owed and
 * return, so a slow reader never slows a commit and costs no more memory as
 * the changes go on.
 */
export interface FeedWriter {
  /** Owe the `ready` frame. */
  ready(): void;
  /** Owe this status; replaces an earlier status that was not yet written. */
  status(status: unknown): void;
  /** Owe a `view` frame for these connections, merged with ones not yet written. */
  views(connectionIds: readonly string[]): void;
  /** Drop what is owed and write nothing more. Idempotent. */
  close(): void;
}

export function createFeedWriter(
  write: (event: string, data: unknown) => Promise<void>,
): FeedWriter {
  let readyOwed = false;
  let status: { value: unknown } | null = null;
  const views = new Set<string>();
  let draining = false;
  let closed = false;

  async function drain(): Promise<void> {
    if (draining) return;
    draining = true;
    try {
      while (!closed) {
        let event: string;
        let data: unknown;
        if (readyOwed) {
          readyOwed = false;
          event = "ready";
          data = {};
        } else if (status) {
          event = "status";
          data = status.value;
          status = null;
        } else if (views.size > 0) {
          event = "view";
          data = { connectionIds: [...views] };
          views.clear();
        } else {
          return;
        }
        await write(event, data);
      }
    } catch {
      // A frame could not be built or written: write nothing more.
      close();
    } finally {
      draining = false;
    }
  }

  function close(): void {
    closed = true;
    readyOwed = false;
    status = null;
    views.clear();
  }

  return {
    ready() {
      if (closed) return;
      readyOwed = true;
      void drain();
    },
    status(next) {
      if (closed) return;
      status = { value: next };
      void drain();
    },
    views(connectionIds) {
      if (closed) return;
      for (const id of connectionIds) views.add(id);
      void drain();
    },
    close,
  };
}
