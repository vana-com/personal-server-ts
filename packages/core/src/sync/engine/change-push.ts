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

/**
 * The wait before retry number `failures` + 1 (0 for the first retry): 1 s
 * doubling to 30 s, spread over half to one and a half of the step so a fleet
 * that lost the same dependency together does not return together. The push
 * uses it for its transport; the manager uses it to space retries of a failing
 * cycle, so a failure has one back-off schedule.
 */
export function changePushBackoffMs(
  failures: number,
  random: () => number = Math.random,
): number {
  const base = BACKOFF_MIN_MS * 2 ** Math.min(failures, 5);
  return Math.min(BACKOFF_MAX_MS, base * (0.5 + random()));
}

export interface RegistryChangePushOptions {
  /** Default true; false: no push, the timed probe alone (as before). */
  enabled?: boolean;
  /**
   * Default {@link CHANGE_PUSH_WAIT_MS}, also for a value that is not a finite
   * positive number: a held request of NaN or Infinity seconds is no period.
   */
  waitMs?: number;
}

/**
 * A subscription to the gateway's "the registry moved" signal.
 *
 * It keeps one held request open. Each answer carries the registry's
 * sequence, the registry's position; the next request sends it back, so the
 * gateway compares two numbers and a poke that was lost on the wire is found
 * by the next request. An answer that ends the wait with nothing new carries
 * the gateway's current sequence too, read when the wait ended. The position is
 * not data: the manager reads the registry itself and trusts the position only
 * to say that nothing moved since a cycle that started under it, so a wake that
 * was lost is found at the next answer. It does four things:
 *
 *  - every answer reports its sequence as the position (`onPosition`), before
 *    anything else, so the cycle a poke starts samples the position it follows;
 *  - an answer that says `changed` is a poke (`onChange`): the manager pulls,
 *    or applies the answer's delta. Each held request sends the position the
 *    manager holds the registry up to (`since`), so the gateway can answer
 *    with what changed after it;
 *  - the first answer after any failure is a poke too, whether or not the
 *    sequence moved, so a poke lost with the connection costs one pull. A
 *    failed attempt is not a poke: with every answer lost, only the manager's
 *    timer cycle (and its probe) finds the change;
 *  - `onHealth(false)` on any failure or silence, `onHealth(true)` on the next
 *    answer: only while healthy does the manager skip its timer cycle and
 *    probe.
 */
export function createRegistryChangePush(
  registry: Pick<StreamSyncRegistry, "waitForChange">,
  options: RegistryChangePushOptions = {},
): ChangePush | undefined {
  const waitForChange = registry.waitForChange?.bind(registry);
  if (!waitForChange || options.enabled === false) return undefined;
  const waitMs =
    Number.isFinite(options.waitMs) && (options.waitMs as number) > 0
      ? (options.waitMs as number)
      : CHANGE_PUSH_WAIT_MS;
  return {
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

      // The abort listener goes away on both ways out. An outage sleeps once
      // per attempt; a listener left behind by each sleep is a leak that grows
      // with the subscription's age.
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
        let timer: ReturnType<typeof setTimeout> | undefined;
        let onStop: (() => void) | undefined;
        // The request ends on the first of: the registry's answer, the
        // deadline, or the subscription's end. The last two settle it at once
        // and clear the deadline timer in the same turn, even when the
        // registry ignores the abort; a late answer then finds nobody waiting.
        const ended = new Promise<never>((_resolve, reject) => {
          timer = setTimeout(() => {
            const error = new Error("change request got no answer");
            request.abort(error);
            reject(error);
          }, waitMs + REQUEST_GRACE_MS);
          onStop = () => {
            clearTimeout(timer);
            request.abort(lifetime.signal.reason);
            reject(lifetime.signal.reason);
          };
          lifetime.signal.addEventListener("abort", onStop, { once: true });
        });
        try {
          const wait = waitForChange!(
            cursor,
            waitMs,
            request.signal,
            cursor === undefined ? undefined : handlers.since?.(),
          );
          wait.catch(() => {}); // a late failure after the race is not ours
          const answer = await Promise.race([wait, ended]);
          if (lifetime.signal.aborted) return "failed";
          cursor = answer.seq;
          failures = 0;
          setHealth(true);
          // The position first: the cycle a poke starts samples it.
          handlers.onPosition(answer.seq);
          if (answer.changed || afterFailure) {
            afterFailure = false;
            handlers.onChange(answer.changed ? answer.delta : undefined);
          }
          return "answer";
        } catch (error) {
          if (error instanceof ChangeFeedAbsentError) return "absent";
          return "failed";
        } finally {
          clearTimeout(timer);
          lifetime.signal.removeEventListener("abort", onStop!);
        }
      }

      void (async () => {
        while (!lifetime.signal.aborted) {
          const outcome = await once();
          if (lifetime.signal.aborted) return;
          if (outcome === "absent") {
            // No route: stay unhealthy, so the manager's timer and probe keep
            // watching, and ask again after one held period. An absent route
            // then costs at most the one request per period a present route
            // costs, and a gateway that gains the route is found within a
            // period, with no restart.
            setHealth(false);
            await sleep(waitMs);
            continue;
          }
          if (outcome === "failed") {
            setHealth(false);
            afterFailure = true;
            const wait = changePushBackoffMs(failures);
            failures += 1;
            await sleep(wait);
          }
        }
      })();

      return () => lifetime.abort(new Error("change push stopped"));
    },
  };
}
