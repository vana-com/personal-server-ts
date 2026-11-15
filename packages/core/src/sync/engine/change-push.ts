import {
  ChangeFeedAbsentError,
  type StreamSyncRegistry,
} from "../../stream-sync/ports.js";
import type { ChangePush } from "./sync-manager.js";

export { ChangeFeedAbsentError };

/**
 * How long one held request waits at the gateway before it answers "nothing
 * yet". Each answer starts the next request, so an idle client makes one
 * request per this period: 25 s is 0.04 req/s, against 0.2 req/s for the 5 s
 * probe it relieves. It stays under common proxy idle limits (30 to 60 s), and
 * the gateway refuses a wait above 55 s.
 */
export const CHANGE_PUSH_WAIT_MS = 25_000;

/**
 * Longer than the wait by this much, a request with no answer is declared
 * dead (a half-open connection never errors). The cost of a dead request is
 * bounded by this: the push says it is unhealthy and the 5 s probe returns.
 */
const REQUEST_GRACE_MS = 10_000;

const BACKOFF_MIN_MS = 1_000;
const BACKOFF_MAX_MS = 30_000;
/** How often a parked subscription (no one is looking) re-checks the host. */
const PARK_CHECK_MS = 2_000;

/**
 * The timed probe's period while the push is healthy. The unconditional timer
 * cycle already runs every 60 s and is what guarantees completeness, so a
 * probe that fires less often than that adds nothing.
 */
export const DEFAULT_CHANGE_PUSH_HEALTHY_PROBE_MS = 60_000;

export interface RegistryChangePushOptions {
  /** Default true; false: no push, the timed probe alone (as before). */
  enabled?: boolean;
  /** Default {@link DEFAULT_CHANGE_PUSH_HEALTHY_PROBE_MS}. */
  healthyProbeMs?: number;
  /** Default {@link CHANGE_PUSH_WAIT_MS}. */
  waitMs?: number;
  /**
   * Whether anyone is looking now. A hidden Web tab holds no request and
   * pulls once when it is shown again (the host's own signal).
   */
  active?: () => boolean;
}

/**
 * A subscription to the gateway's "the registry moved" signal.
 *
 * The signal is a hint over a lossy channel. Correctness stays in the pull and
 * the manager's timer; this loop only makes the common case fast and says
 * honestly when it cannot be trusted. It keeps one held request open. Each
 * answer carries the registry's sequence; the next request sends it back, so
 * the gateway compares two numbers and a poke that was lost on the wire is
 * found by the next request. It does three things:
 *
 *  - an answer that says `changed` is a poke (`onChange`): the manager pulls;
 *  - the first answer after any failure is a poke too, whether or not the
 *    sequence moved, so a poke lost with the connection costs one pull;
 *  - `onHealth(false)` on any failure or silence, `onHealth(true)` on the next
 *    answer: only while healthy does the manager stretch its probe.
 */
export function createRegistryChangePush(
  registry: Pick<StreamSyncRegistry, "waitForChange">,
  options: RegistryChangePushOptions = {},
): ChangePush | undefined {
  const waitForChange = registry.waitForChange?.bind(registry);
  if (!waitForChange || options.enabled === false) return undefined;
  const waitMs = options.waitMs ?? CHANGE_PUSH_WAIT_MS;
  return {
    healthyProbeMs:
      options.healthyProbeMs ?? DEFAULT_CHANGE_PUSH_HEALTHY_PROBE_MS,
    subscribe(handlers) {
      const lifetime = new AbortController();
      let cursor: string | undefined;
      let healthy = false;
      let afterFailure = false;
      let failures = 0;
      const setHealth = (next: boolean) => {
        if (healthy === next || lifetime.signal.aborted) return;
        healthy = next;
        handlers.onHealth(next);
      };

      // The abort listener goes away on both ways out. A hidden tab sleeps
      // every PARK_CHECK_MS for as long as the subscription lives, and an
      // outage sleeps once per attempt; a listener left behind by each sleep
      // is a leak that grows with the subscription's age.
      const sleep = (ms: number) =>
        new Promise<void>((resolve) => {
          const done = () => {
            clearTimeout(timer);
            lifetime.signal.removeEventListener("abort", done);
            resolve();
          };
          const timer = setTimeout(done, ms);
          lifetime.signal.addEventListener("abort", done, { once: true });
        });

      async function once(): Promise<"answer" | "failed" | "absent"> {
        const request = new AbortController();
        const onStop = () => request.abort(lifetime.signal.reason);
        lifetime.signal.addEventListener("abort", onStop, { once: true });
        const deadline = setTimeout(
          () => request.abort(new Error("change request got no answer")),
          waitMs + REQUEST_GRACE_MS,
        );
        try {
          const answer = await waitForChange!(cursor, waitMs, request.signal);
          if (lifetime.signal.aborted) return "failed";
          cursor = answer.seq;
          failures = 0;
          setHealth(true);
          if (answer.changed || afterFailure) {
            afterFailure = false;
            handlers.onChange();
          }
          return "answer";
        } catch (error) {
          if (error instanceof ChangeFeedAbsentError) return "absent";
          return "failed";
        } finally {
          clearTimeout(deadline);
          lifetime.signal.removeEventListener("abort", onStop);
        }
      }

      void (async () => {
        while (!lifetime.signal.aborted) {
          if (options.active && !options.active()) {
            setHealth(false);
            await sleep(PARK_CHECK_MS);
            continue;
          }
          const outcome = await once();
          if (lifetime.signal.aborted) return;
          if (outcome === "absent") {
            setHealth(false);
            return;
          }
          if (outcome === "failed") {
            setHealth(false);
            afterFailure = true;
            const base = BACKOFF_MIN_MS * 2 ** Math.min(failures, 5);
            failures += 1;
            // Spread over half to one and a half of the back-off, so a fleet
            // that lost the gateway together does not return together.
            await sleep(Math.min(BACKOFF_MAX_MS, base * (0.5 + Math.random())));
          }
        }
      })();

      return () => lifetime.abort(new Error("change push stopped"));
    },
  };
}
