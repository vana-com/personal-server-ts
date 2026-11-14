export type OperationKind = "end" | "publish" | "apply" | "purge";

/**
 * One multi-batch operation at a time per connection. Operations on different
 * connections run together. An `apply` asked for while another `apply` for the
 * same connection is queued or running joins it instead of starting a second.
 */
export function connectionQueue(): {
  run<T>(
    connectionId: string,
    kind: OperationKind,
    fn: () => Promise<T>,
  ): Promise<T>;
} {
  const tails = new Map<string, Promise<unknown>>();
  const applies = new Map<string, Promise<unknown>>();
  return {
    run<T>(connectionId: string, kind: OperationKind, fn: () => Promise<T>) {
      if (kind === "apply") {
        const joined = applies.get(connectionId);
        if (joined) return joined as Promise<T>;
      }
      const previous = tails.get(connectionId) ?? Promise.resolve();
      const result: Promise<T> = previous.then(fn, fn).finally(() => {
        if (tails.get(connectionId) === settled) tails.delete(connectionId);
        if (applies.get(connectionId) === result) applies.delete(connectionId);
      });
      const settled = result.catch(() => undefined);
      tails.set(connectionId, settled);
      if (kind === "apply") applies.set(connectionId, result);
      return result;
    },
  };
}
