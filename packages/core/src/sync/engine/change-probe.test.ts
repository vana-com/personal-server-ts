import { describe, expect, it, vi } from "vitest";
import type { StreamSyncRegistry } from "../../stream-sync/ports.js";
import {
  DEFAULT_CHANGE_PROBE_MS,
  createRegistryChangeProbe,
} from "./change-probe.js";
import { DEFAULT_CHANGE_PUSH_HEALTHY_PROBE_MS } from "./change-push.js";

const registry = (probeChange?: StreamSyncRegistry["probeChange"]) =>
  ({ ...(probeChange && { probeChange }) }) as unknown as StreamSyncRegistry;

describe("createRegistryChangeProbe", () => {
  it("reads the registry's own probe on the default period", async () => {
    const probeChange = vi.fn(async () => "m");
    const probe = createRegistryChangeProbe(registry(probeChange))!;
    expect(probe.intervalMs).toBe(DEFAULT_CHANGE_PROBE_MS);
    expect(await probe.read()).toBe("m");
    expect(probeChange).toHaveBeenCalledTimes(1);
  });

  it("is absent when the registry cannot probe or the period is 0", () => {
    expect(createRegistryChangeProbe(registry())).toBeUndefined();
    expect(
      createRegistryChangeProbe(
        registry(async () => "m"),
        { intervalMs: 0 },
      ),
    ).toBeUndefined();
  });

  it("passes the host's period and visibility gate through", () => {
    const active = () => false;
    const probe = createRegistryChangeProbe(
      registry(async () => "m"),
      {
        intervalMs: 9_000,
        active,
      },
    )!;
    expect(probe.intervalMs).toBe(9_000);
    expect(probe.active).toBe(active);
  });

  it("keeps the period above the cost-parity floor of the smallest idle cycle", () => {
    // 29 registry requests per idle cycle for one connection of six streams,
    // one cycle per 60 s: a probe may not out-spend that.
    const IDLE_CYCLE_REQUESTS_ONE_CONNECTION = 29;
    const floorMs = 60_000 / IDLE_CYCLE_REQUESTS_ONE_CONNECTION;
    expect(DEFAULT_CHANGE_PROBE_MS).toBeGreaterThan(floorMs);
  });

  it("adds a push when the registry can hold a change request, with the host's visibility gate", () => {
    const waitForChange = vi.fn();
    const active = () => true;
    const probe = createRegistryChangeProbe(
      {
        probeChange: async () => "m",
        waitForChange,
      } as unknown as StreamSyncRegistry,
      { active, push: { healthyProbeMs: 90_000 } },
    )!;
    expect(probe.push?.healthyProbeMs).toBe(90_000);
  });

  it("has no push when the registry cannot hold a request or the host turns it off", () => {
    const withWait = {
      probeChange: async () => "m",
      waitForChange: vi.fn(),
    } as unknown as StreamSyncRegistry;
    expect(
      createRegistryChangeProbe(registry(async () => "m"))!.push,
    ).toBeUndefined();
    expect(
      createRegistryChangeProbe(withWait, { push: { enabled: false } })!.push,
    ).toBeUndefined();
    expect(createRegistryChangeProbe(withWait)!.push).toBeDefined();
  });

  it("stretches the healthy period well above the short probe and below the timer's 60 s guarantee", () => {
    expect(DEFAULT_CHANGE_PUSH_HEALTHY_PROBE_MS).toBeGreaterThan(
      DEFAULT_CHANGE_PROBE_MS,
    );
    expect(DEFAULT_CHANGE_PUSH_HEALTHY_PROBE_MS).toBeLessThanOrEqual(60_000);
  });
});
