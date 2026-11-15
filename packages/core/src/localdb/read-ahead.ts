/**
 * Read one item ahead of the consumer. The source is a paged read of the
 * spool: each page is a round trip to the read connection, and encoding a page
 * (framing, hashing, sealing) runs on the main thread. Taken in turn, each side
 * waits for the other. Here the read of the next page starts when the current
 * one is handed over, so it runs while the consumer works on that one.
 *
 * One read is ever in flight, so the memory held beyond the consumer's own is
 * one page. The consumer's stop, or a failed read, ends the read in flight
 * first and then closes the source.
 */
export async function* readAhead<T>(
  source: AsyncGenerator<T>,
): AsyncGenerator<T> {
  let next: Promise<IteratorResult<T>> | undefined;
  // A read that fails after the consumer stopped is not reported; one it
  // waits for still throws at `await`.
  const start = (): Promise<IteratorResult<T>> => {
    const read = source.next();
    read.catch(() => undefined);
    return read;
  };
  try {
    next = start();
    for (;;) {
      const current = await next;
      next = undefined;
      if (current.done === true) return;
      next = start();
      yield current.value;
    }
  } finally {
    if (next) await next.catch(() => undefined);
    await source.return(undefined);
  }
}
