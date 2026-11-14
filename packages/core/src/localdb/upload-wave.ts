/**
 * The uploads of one stream's transfer, started as soon as each is ready and
 * waited for together.
 *
 * Only "every file of the stream is stored before its registry write" matters.
 * Parts, attachments and the head are content addressed and unreachable until
 * that write, so none of them has to wait for another.
 *
 * A wave has no width of its own. How many uploads run is the store's send
 * gate's decision (its adaptive window, the service's quota and Retry-After),
 * and how many encoded parts wait in memory is the store's byte budget: the
 * encoder reserves a part's bytes before it reads the rows for it, and an
 * upload releases them once the part is stored. Both are shared by every
 * stream and connection on the store, so the total is bounded across them.
 * Every store has a governor (`StreamSyncBlobs.governor` is required), so the
 * bounds hold for every store, however slow its PUTs.
 *
 * A wave never leaves a started upload running after it is settled, and never
 * leaves a rejection unobserved: a failed upload is kept, no further upload
 * starts, and the first failure is thrown by `drain`.
 */
export interface UploadWave {
  /**
   * Start `upload` now. Throws the wave's first failure instead of starting
   * anything once an upload has failed.
   */
  start(upload: () => Promise<void>): void;
  /** Wait for every started upload; throw the first failure. */
  drain(): Promise<void>;
  /** Wait for every started upload; never throw. For an exit that already has its error. */
  settle(): Promise<void>;
}

export function newUploadWave(): UploadWave {
  const unfinished = new Set<Promise<void>>();
  let failure: { readonly error: unknown } | undefined;
  const throwIfFailed = () => {
    if (failure) throw failure.error;
  };
  const settle = async () => {
    while (unfinished.size > 0) await Promise.all([...unfinished]);
  };
  return {
    start(upload) {
      throwIfFailed();
      const tracked: Promise<void> = upload().then(
        () => {
          unfinished.delete(tracked);
        },
        (error: unknown) => {
          failure ??= { error };
          unfinished.delete(tracked);
        },
      );
      unfinished.add(tracked);
    },
    async drain() {
      await settle();
      throwIfFailed();
    },
    settle,
  };
}
