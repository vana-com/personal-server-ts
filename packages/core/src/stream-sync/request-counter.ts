import type { StreamSyncRegistry } from "./ports.js";

/**
 * The registry calls the sync cycle makes, counted. `probeChange` and
 * `waitForChange` are left out: they are the change feed (the probe and the
 * held request), and what the count prices is the cycle that the feed lets a
 * device skip. One call is one registry request.
 *
 * The manager reads the count before and after a cycle that found nothing to
 * do, and so learns what an idle cycle costs this device (it grows with the
 * number of connections and streams) instead of assuming a number.
 */
export function countRegistryRequests<R extends StreamSyncRegistry>(
  registry: R,
): { registry: R; count(): number } {
  let calls = 0;
  const feed = new Set<PropertyKey>(["probeChange", "waitForChange"]);
  const counted = new Proxy(registry, {
    get(target, property, receiver) {
      const member = Reflect.get(target, property, receiver) as unknown;
      if (typeof member !== "function" || feed.has(property)) return member;
      return (...args: unknown[]) => {
        calls += 1;
        return (member as (...a: unknown[]) => unknown).apply(target, args);
      };
    },
  });
  return { registry: counted, count: () => calls };
}
