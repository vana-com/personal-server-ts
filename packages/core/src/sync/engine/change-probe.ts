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
  /** Default {@link DEFAULT_CHANGE_PROBE_MS}; 0 or less: no probe. */
  intervalMs?: number;
  active?: () => boolean;
  /**
   * The server push that relieves the probe, when the registry can hold a
   * change request. `{ enabled: false }` keeps the probe alone. The host's
   * `active` gate applies to it too: a hidden tab holds no request.
   */
  push?: Omit<RegistryChangePushOptions, "active">;
}

/** The manager's probe over a registry that can answer one; none otherwise. */
export function createRegistryChangeProbe(
  registry: Pick<StreamSyncRegistry, "probeChange" | "waitForChange">,
  options: RegistryChangeProbeOptions = {},
): ChangeProbe | undefined {
  const intervalMs = options.intervalMs ?? DEFAULT_CHANGE_PROBE_MS;
  const probeChange = registry.probeChange?.bind(registry);
  if (!probeChange || !(intervalMs > 0)) return undefined;
  const push = createRegistryChangePush(registry, {
    ...options.push,
    ...(options.active && { active: options.active }),
  });
  return {
    read: () => readWithDeadline(probeChange),
    intervalMs,
    ...(push && { push }),
    ...(options.active && { active: options.active }),
  };
}

/**
 * One probe read that ends: it is aborted at the deadline (so the request frees
 * its connection) and rejects at the deadline even when the registry ignores
 * the signal.
 */
async function readWithDeadline(
  probeChange: (signal?: AbortSignal) => Promise<string | null | undefined>,
): Promise<string | null | undefined> {
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      const error = new Error("registry change probe got no answer");
      controller.abort(error);
      reject(error);
    }, PROBE_TIMEOUT_MS);
  });
  try {
    return await Promise.race([probeChange(controller.signal), deadline]);
  } finally {
    clearTimeout(timer);
  }
}
