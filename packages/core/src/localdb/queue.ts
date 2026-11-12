import { mark } from "./timing.js";

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
  // Timing only: what each connection's queue holds, in order.
  const held = new Map<string, OperationKind[]>();
  return {
    run<T>(connectionId: string, kind: OperationKind, fn: () => Promise<T>) {
      if (kind === "apply") {
        const joined = applies.get(connectionId);
        if (joined) return joined as Promise<T>;
      }
      const previous = tails.get(connectionId) ?? Promise.resolve();
      const ahead = [...(held.get(connectionId) ?? [])];
      held.set(connectionId, [...ahead, kind]);
      const queuedAt = Date.now();
      mark("queue.enqueued", { connectionId, kind, ahead: ahead.join(",") });
      const timedFn = async () => {
        const startedAt = Date.now();
        mark("queue.started", {
          connectionId,
          kind,
          waitedMs: startedAt - queuedAt,
          ahead: ahead.join(","),
        });
        try {
          return await fn();
        } finally {
          const rest = (held.get(connectionId) ?? []).slice();
          rest.splice(rest.indexOf(kind), 1);
          if (rest.length === 0) held.delete(connectionId);
          else held.set(connectionId, rest);
          mark("queue.finished", {
            connectionId,
            kind,
            ranMs: Date.now() - startedAt,
          });
        }
      };
      const result: Promise<T> = previous.then(timedFn, timedFn).finally(() => {
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
