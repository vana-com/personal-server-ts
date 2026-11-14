import type { StreamSyncRegistry } from "../../stream-sync/ports.js";
import type { ChangeProbe } from "./sync-manager.js";

/**
 * Period of the timed registry probe.
 *
 * Two measured limits bound it (D4-SYNC-TRIGGERS, 2026-11-14):
 *
 *  - Cost floor. One idle cycle of one connection of six streams makes 29
 *    registry requests (3 listings, 26 reads; `idle-cycle-requests.test.ts`),
 *    and the timer makes one per 60 s on every open device. A probe is one
 *    request, so it spends no more than that cycle does at any period of at
 *    least 60 s / 29 = 2.1 s. More connections raise the cycle's cost
 *    (1 + 28 per connection), so the floor only falls.
 *  - Latency. A change waits half a period on average. The remaining path is
 *    the writer's publish (about 4.5 s) plus this device's apply (1 to 4 s), so
 *    waiting P/2 = 2.5 s keeps the added wait below the work it follows.
 *
 * 5 s sits inside both bounds. Hosts may change it; 0 switches the probe off.
 */
export const DEFAULT_CHANGE_PROBE_MS = 5_000;

export interface RegistryChangeProbeOptions {
  /** Default {@link DEFAULT_CHANGE_PROBE_MS}; 0 or less: no probe. */
  intervalMs?: number;
  active?: () => boolean;
}

/** The manager's probe over a registry that can answer one; none otherwise. */
export function createRegistryChangeProbe(
  registry: Pick<StreamSyncRegistry, "probeChange">,
  options: RegistryChangeProbeOptions = {},
): ChangeProbe | undefined {
  const intervalMs = options.intervalMs ?? DEFAULT_CHANGE_PROBE_MS;
  const probeChange = registry.probeChange?.bind(registry);
  if (!probeChange || !(intervalMs > 0)) return undefined;
  return {
    read: probeChange,
    intervalMs,
    ...(options.active && { active: options.active }),
  };
}
