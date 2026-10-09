/**
 * A per-scope mutex for everything that reads-modifies-writes or deletes a
 * scope's first-seen sidecar (ledger updates, rebuilds, scope and version
 * deletion). It serializes callers inside one process only.
 */

const tails = new Map<string, Promise<void>>();

/** Run `fn` after every earlier call for `scope` has settled; later calls wait for it. */
export async function withScopeLock<T>(
  scope: string,
  fn: () => Promise<T>,
): Promise<T> {
  const previous = tails.get(scope) ?? Promise.resolve();
  let release!: () => void;
  const mine = new Promise<void>((resolve) => {
    release = resolve;
  });
  const tail = previous.then(() => mine);
  tails.set(scope, tail);
  await previous;
  try {
    return await fn();
  } finally {
    release();
    if (tails.get(scope) === tail) tails.delete(scope);
  }
}
