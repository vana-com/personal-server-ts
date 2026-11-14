/**
 * The uploads of one stream's transfer, started as soon as each is ready and
 * waited for together.
 *
 * Only "every file of the stream is stored before its registry write" matters.
 * Parts, attachments and the head are content addressed and unreachable until
 * that write, so none of them has to wait for another. The store's send gate
 * decides how many run on the wire; this holds only the uploads that are
 * started and not yet finished.
 *
 * A wave never leaves a started upload running after it is settled, and never
 * leaves a rejection unobserved: a failed upload is kept, no further upload
 * starts, and the first failure is thrown by `drain`.
 */
export interface UploadWave {
  /**
   * Start `upload` once fewer than `limit` uploads of the wave are unfinished.
   * Returns when it has started, not when it is stored. Throws the wave's first
   * failure instead of starting anything once an upload has failed.
   */
  start(upload: () => Promise<void>): Promise<void>;
  /**
   * Start `upload` at once, without waiting for room. For an upload too small
   * to need the bound (a head), so that it never waits behind parts.
   */
  startAlongside(upload: () => Promise<void>): void;
  /** Wait for every started upload; throw the first failure. */
  drain(): Promise<void>;
  /** Wait for every started upload; never throw. For an exit that already has its error. */
  settle(): Promise<void>;
}

/**
 * `limit` bounds the parts a stream holds in memory while they wait for the
 * storage client's turn: each one is its encoded bytes and its ciphertext.
 */
export function newUploadWave(limit: number): UploadWave {
  if (!Number.isInteger(limit) || limit < 1) {
    throw new RangeError(
      `upload wave: limit must be a positive whole number, got ${limit}`,
    );
  }
  const unfinished = new Set<Promise<void>>();
  let failure: { readonly error: unknown } | undefined;
  const throwIfFailed = () => {
    if (failure) throw failure.error;
  };
  const settle = async () => {
    while (unfinished.size > 0) await Promise.all([...unfinished]);
  };
  const launch = (upload: () => Promise<void>) => {
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
  };
  return {
    async start(upload) {
      while (unfinished.size >= limit && !failure) {
        await Promise.race(unfinished);
      }
      throwIfFailed();
      launch(upload);
    },
    startAlongside(upload) {
      throwIfFailed();
      launch(upload);
    },
    async drain() {
      await settle();
      throwIfFailed();
    },
    settle,
  };
}
