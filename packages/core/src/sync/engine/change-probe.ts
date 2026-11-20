import type { StreamSyncRegistry } from "../../stream-sync/ports.js";
import {
  createRegistryChangePush,
  type RegistryChangePushOptions,
} from "./change-push.js";
import type { ChangeProbe } from "./sync-manager.js";

/**
 * Period of the timed registry probe.
 *
 * Two measured limits bound it (D4-SYNC-TRIGGERS, 2026-11-14):
 *
 *  - Cost floor. One idle cycle of one connection of six streams makes 29
 *    registry requests (3 listings, 26 reads; `idle-cycle-requests.test.ts`),
 *    and the timer makes one per 60 s on every open device. The probe ADDS to
 *    that: 60 s / P requests a minute (12 at 5 s). Below 60 s / 29 = 2.1 s the
 *    probe alone would out-request the idle cycle it supplements. More
 *    connections raise the cycle's cost (1 + 28 per connection), so the floor
 *    only falls. The probe is not a saving; it buys latency.
 *  - Latency. A change waits half a period on average. The remaining path is
 *    the writer's publish (about 4.5 s) plus this device's apply (1 to 4 s), so
 *    waiting P/2 = 2.5 s keeps the added wait below the work it follows.
 *
 * 5 s sits inside both bounds. Hosts may change it; 0 switches the probe off.
 * The probe runs only while the held push request cannot announce changes
 * (absent, failing, or answering without a position); a healthy push makes it
 * redundant and the manager skips it.
 */
export const DEFAULT_CHANGE_PROBE_MS = 5_000;

/**
 * A probe read that has not answered after this long failed. A probe is
 * optional: a read that never settles must not hold a pull in flight, so the
 * ordinary timed path and every later poke stay free. It matches the push
 * request's grace (`REQUEST_GRACE_MS`), the same "this connection is dead" bar.
 */
export const PROBE_TIMEOUT_MS = 10_000;

export interface RegistryChangeProbeOptions {
  /**
   * Default {@link DEFAULT_CHANGE_PROBE_MS}, also for a value that is not a
   * finite number (a timer given NaN or Infinity fires at once); 0 or less:
   * no probe.
   */
  intervalMs?: number;
  /**
   * The server push that relieves the probe, when the registry can hold a
   * change request. `{ enabled: false }` keeps the probe alone. A hidden tab
   * is the host's `SyncManager.pause`, not an option here.
   */
  push?: RegistryChangePushOptions;
}

/** The manager's probe over a registry that can answer one; none otherwise. */
export function createRegistryChangeProbe(
  registry: Pick<StreamSyncRegistry, "probeChange" | "waitForChange">,
  options: RegistryChangeProbeOptions = {},
): ChangeProbe | undefined {
  const intervalMs = Number.isFinite(options.intervalMs)
    ? (options.intervalMs as number)
    : DEFAULT_CHANGE_PROBE_MS;
  const probeChange = registry.probeChange?.bind(registry);
  if (!probeChange || !(intervalMs > 0)) return undefined;
  const push = createRegistryChangePush(registry, options.push);
  return {
    read: (lifecycle) => readWithDeadline(probeChange, lifecycle),
    intervalMs,
    ...(push && { push }),
  };
}

/**
 * One probe read that ends. It ends on the first of: the registry's answer,
 * the deadline, or the manager's lifecycle signal (a hide or a stop). Deadline
 * and lifecycle abort the request so it frees its connection, and both settle
 * the read at once even when the registry ignores the signal. Every way out
 * clears the deadline timer and the lifecycle listener, and a late answer from
 * the registry finds the read already settled.
 */
function readWithDeadline(
  probeChange: (signal?: AbortSignal) => Promise<string | null | undefined>,
  lifecycle: AbortSignal,
): Promise<string | null | undefined> {
  const asError = (reason: unknown) =>
    reason instanceof Error ? reason : new Error("registry change probe ended");
  if (lifecycle.aborted) return Promise.reject(asError(lifecycle.reason));
  const controller = new AbortController();
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (settle: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      lifecycle.removeEventListener("abort", onLifecycle);
      settle();
    };
    const fail = (error: Error) => {
      controller.abort(error);
      finish(() => reject(error));
    };
    const onLifecycle = () => fail(asError(lifecycle.reason));
    const timer = setTimeout(
      () => fail(new Error("registry change probe got no answer")),
      PROBE_TIMEOUT_MS,
    );
    lifecycle.addEventListener("abort", onLifecycle, { once: true });
    try {
      probeChange(controller.signal).then(
        (marker) => finish(() => resolve(marker)),
        (error: unknown) => finish(() => reject(error)),
      );
    } catch (error) {
      finish(() => reject(error));
    }
  });
}
