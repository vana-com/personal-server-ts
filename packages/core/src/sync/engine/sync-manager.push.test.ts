// The registry change push as the manager uses it.
//
// A poke is only a request to pull (`requestPull`); the pull still compares the
// registry's change marker and runs the cycle, so a poke can be lost, doubled
// or late without a wrong result. While the subscription is healthy the timed
// probe stretches to a minute; when it is not, the short probe returns, so the
// push can only ever make the system faster than it was.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Logger } from "../../logger/index.js";
import type { DownloadWorkerDeps } from "../workers/download.js";
import type { UploadWorkerDeps } from "../workers/upload.js";
import {
  createSyncManager,
  type ChangePush,
  type SyncManagerOptions,
} from "./sync-manager.js";

const logger = {
  info: vi.fn(),
  error: vi.fn(),
  warn: vi.fn(),
  debug: vi.fn(),
  trace: vi.fn(),
  fatal: vi.fn(),
} as unknown as Logger;

function build(options: Partial<SyncManagerOptions>) {
  return createSyncManager(
    {
      logger,
      serverOwner: "0x1111111111111111111111111111111111111111",
      storage: { findUnsynced: () => [] },
    } as unknown as UploadWorkerDeps,
    { logger } as unknown as DownloadWorkerDeps,
    {
      accountStorageMode: { read: () => "switched" },
      pollInterval: 60_000,
      ...options,
    },
  );
}

/** A push the test drives by hand. */
function fakePush(healthyProbeMs = 60_000) {
  const state = {
    subscribed: 0,
    stopped: 0,
    handlers: null as null | {
      onChange(): void;
      onHealth(healthy: boolean): void;
    },
  };
  const push: ChangePush = {
    healthyProbeMs,
    subscribe(handlers) {
      state.subscribed += 1;
      state.handlers = handlers;
      return () => {
        state.stopped += 1;
      };
    },
  };
  return { push, state };
}

beforeEach(() => {
  vi.useFakeTimers();
});
afterEach(() => {
  vi.useRealTimers();
});

describe("a poke", () => {
  it("pulls: a moved marker runs a cycle at once, long before the 5 s probe or the 60 s timer", async () => {
    const { push, state } = fakePush();
    let marker = "m1";
    const cycle = vi.fn(async () => {});
    const read = vi.fn(async () => marker);
    const manager = build({
      localSync: { cycle },
      changeProbe: { read, intervalMs: 5_000, push },
    });
    manager.start();
    await vi.advanceTimersByTimeAsync(0);
    state.handlers!.onChange(); // first poke: nothing applied yet
    await vi.advanceTimersByTimeAsync(0);
    cycle.mockClear();

    marker = "m2";
    state.handlers!.onChange();
    await vi.advanceTimersByTimeAsync(0);
    expect(cycle).toHaveBeenCalledTimes(1);
    await manager.stop();
  });

  it("costs no cycle when the registry did not actually move (a doubled poke)", async () => {
    const { push, state } = fakePush();
    const cycle = vi.fn(async () => {});
    const manager = build({
      localSync: { cycle },
      changeProbe: { read: async () => "m1", intervalMs: 5_000, push },
    });
    manager.start();
    await vi.advanceTimersByTimeAsync(0);
    state.handlers!.onChange();
    await vi.advanceTimersByTimeAsync(0);
    cycle.mockClear();
    state.handlers!.onChange();
    state.handlers!.onChange();
    await vi.advanceTimersByTimeAsync(0);
    expect(cycle).not.toHaveBeenCalled();
    await manager.stop();
  });

  it("does not stop a failing cycle from being reported, and never throws into the subscription", async () => {
    const { push, state } = fakePush();
    let marker = "m1";
    const manager = build({
      localSync: {
        cycle: async () => {
          throw new Error("cycle failed");
        },
      },
      changeProbe: { read: async () => marker, intervalMs: 5_000, push },
    });
    manager.start();
    await vi.advanceTimersByTimeAsync(0);
    marker = "m2";
    expect(() => state.handlers!.onChange()).not.toThrow();
    await vi.advanceTimersByTimeAsync(0);
    await manager.stop();
  });
});

describe("the timed probe while the subscription is healthy", () => {
  async function probesIn(ms: number, healthy: boolean | null) {
    const { push, state } = fakePush();
    const read = vi.fn(async () => "m1");
    const manager = build({
      localSync: { cycle: async () => {} },
      changeProbe: { read, intervalMs: 5_000, push },
    });
    manager.start();
    await vi.advanceTimersByTimeAsync(0);
    if (healthy !== null) state.handlers!.onHealth(healthy);
    read.mockClear();
    await vi.advanceTimersByTimeAsync(ms);
    await manager.stop();
    return read.mock.calls.length;
  }

  it("stretches to the healthy period: one probe a minute instead of twelve", async () => {
    expect(await probesIn(60_000, null)).toBe(12); // never subscribed healthy: unchanged
    expect(await probesIn(60_000, true)).toBe(1);
  });

  it("returns to the short period as soon as the subscription is not healthy", async () => {
    const { push, state } = fakePush();
    const read = vi.fn(async () => "m1");
    const manager = build({
      localSync: { cycle: async () => {} },
      changeProbe: { read, intervalMs: 5_000, push },
    });
    manager.start();
    await vi.advanceTimersByTimeAsync(0);
    state.handlers!.onHealth(true);
    await vi.advanceTimersByTimeAsync(30_000);
    read.mockClear();
    state.handlers!.onHealth(false);
    await vi.advanceTimersByTimeAsync(10_000);
    expect(read.mock.calls.length).toBeGreaterThanOrEqual(1);
    await vi.advanceTimersByTimeAsync(20_000);
    expect(read.mock.calls.length).toBeGreaterThanOrEqual(5);
    await manager.stop();
  });

  it("keeps the 60 s timer cycle unconditional, whatever the subscription says", async () => {
    const { push, state } = fakePush();
    const cycle = vi.fn(async () => {});
    const manager = build({
      localSync: { cycle },
      changeProbe: { read: async () => "m1", intervalMs: 5_000, push },
    });
    manager.start();
    await vi.advanceTimersByTimeAsync(0);
    state.handlers!.onHealth(true);
    cycle.mockClear();
    await vi.advanceTimersByTimeAsync(120_000);
    expect(cycle.mock.calls.length).toBeGreaterThanOrEqual(2);
    await manager.stop();
  });
});

describe("the subscription's lifecycle", () => {
  it("subscribes on start, ends on stop, and resubscribes on a restart", async () => {
    const { push, state } = fakePush();
    const manager = build({
      localSync: { cycle: async () => {} },
      changeProbe: { read: async () => "m1", intervalMs: 5_000, push },
    });
    expect(state.subscribed).toBe(0);
    manager.start();
    manager.start(); // idempotent
    expect(state.subscribed).toBe(1);
    await manager.stop();
    expect(state.stopped).toBe(1);
    manager.start();
    expect(state.subscribed).toBe(2);
    await manager.stop();
  });

  it("ignores a poke or health report from a subscription that already ended", async () => {
    const { push, state } = fakePush();
    const cycle = vi.fn(async () => {});
    const read = vi.fn(async () => "m1");
    const manager = build({
      localSync: { cycle },
      changeProbe: { read, intervalMs: 5_000, push },
    });
    manager.start();
    await vi.advanceTimersByTimeAsync(0);
    const old = state.handlers!;
    await manager.stop();
    read.mockClear();
    old.onChange();
    old.onHealth(true);
    await vi.advanceTimersByTimeAsync(0);
    expect(read).not.toHaveBeenCalled();
  });

  it("changes nothing for a probe without a push", async () => {
    const read = vi.fn(async () => "m1");
    const manager = build({
      localSync: { cycle: async () => {} },
      changeProbe: { read, intervalMs: 5_000 },
    });
    manager.start();
    await vi.advanceTimersByTimeAsync(0);
    read.mockClear();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(read.mock.calls.length).toBe(12);
    await manager.stop();
  });
});
