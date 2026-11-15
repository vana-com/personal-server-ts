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
import type { StreamSyncRegistry } from "../../stream-sync/ports.js";
import { createRegistryChangePush } from "./change-push.js";
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

  it("a plain probe poke (focus, online) still skips a marker that did not move", async () => {
    const { push } = fakePush();
    const cycle = vi.fn(async () => {});
    const manager = build({
      localSync: { cycle },
      changeProbe: { read: async () => "m1", intervalMs: 5_000, push },
    });
    manager.start();
    await vi.advanceTimersByTimeAsync(0);
    await manager.requestPull(); // applies m1
    cycle.mockClear();
    await manager.requestPull();
    await manager.requestPull();
    expect(cycle).not.toHaveBeenCalled();
    await manager.stop();
  });

  it("a push answer that says the sequence moved cycles even when the probe marker is equal", async () => {
    // The marker fingerprints one row: a second row stamped in the same
    // millisecond leaves it unchanged. The gateway's sequence is exact, so a
    // verified change must not be judged by the lossy marker.
    const { push, state } = fakePush();
    const cycle = vi.fn(async () => {});
    const manager = build({
      localSync: { cycle },
      changeProbe: { read: async () => "m1", intervalMs: 5_000, push },
    });
    manager.start();
    await vi.advanceTimersByTimeAsync(0);
    await manager.requestPull(); // m1 is applied
    cycle.mockClear();

    state.handlers!.onChange();
    await vi.advanceTimersByTimeAsync(0);
    expect(cycle).toHaveBeenCalledTimes(1);
    await manager.stop();
  });

  it("still cycles when the marker probe itself fails: a verified change does not need it", async () => {
    const { push, state } = fakePush();
    const cycle = vi.fn(async () => {});
    const manager = build({
      localSync: { cycle },
      changeProbe: {
        read: async () => {
          throw new Error("probe down");
        },
        intervalMs: 5_000,
        push,
      },
    });
    manager.start();
    await vi.advanceTimersByTimeAsync(0);
    cycle.mockClear();
    state.handlers!.onChange();
    await vi.advanceTimersByTimeAsync(0);
    expect(cycle).toHaveBeenCalledTimes(1);
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

describe("a pushed change does not wait for the optional probe", () => {
  const never = () => new Promise<string>(() => {});

  /** A probe whose reads answer "m1" until the test makes them hang. */
  function hangingProbe() {
    let hang = false;
    const read = vi.fn(async () => (hang ? never() : "m1"));
    return { read, hang: () => (hang = true) };
  }

  it("starts a cycle at once although the probe read never settles", async () => {
    const { push, state } = fakePush();
    const cycle = vi.fn(async () => {});
    const probe = hangingProbe();
    const manager = build({
      localSync: { cycle },
      changeProbe: { read: probe.read, intervalMs: 5_000, push },
    });
    manager.start();
    await vi.advanceTimersByTimeAsync(0);
    await manager.requestPull(); // the marker is established
    cycle.mockClear();
    probe.hang();

    state.handlers!.onChange();
    await vi.advanceTimersByTimeAsync(0);
    expect(cycle).toHaveBeenCalledTimes(1); // long before the next 60 s tick
    await manager.stop();
  });

  it("does not join a timed probe read that is already pending", async () => {
    const { push, state } = fakePush();
    const cycle = vi.fn(async () => {});
    const probe = hangingProbe();
    const manager = build({
      localSync: { cycle },
      changeProbe: { read: probe.read, intervalMs: 5_000, push },
    });
    manager.start();
    await vi.advanceTimersByTimeAsync(0);
    await manager.requestPull();
    cycle.mockClear();
    probe.hang();
    probe.read.mockClear();
    await vi.advanceTimersByTimeAsync(5_000); // the timed probe starts and hangs
    expect(probe.read).toHaveBeenCalledTimes(1);
    expect(cycle).not.toHaveBeenCalled();

    state.handlers!.onChange();
    await vi.advanceTimersByTimeAsync(0);
    expect(cycle).toHaveBeenCalledTimes(1);
    await manager.stop();
  });

  it("keeps cycles one at a time: a forced request during a running cycle waits for a follow-up", async () => {
    const { push, state } = fakePush();
    let running = 0;
    let overlap = 0;
    let release: () => void = () => {};
    const cycle = vi.fn(async () => {
      running += 1;
      overlap = Math.max(overlap, running);
      await new Promise<void>((r) => (release = r));
      running -= 1;
    });
    const probe = hangingProbe();
    const manager = build({
      localSync: { cycle },
      changeProbe: { read: probe.read, intervalMs: 5_000, push },
    });
    manager.start();
    await vi.advanceTimersByTimeAsync(0);
    probe.hang();
    state.handlers!.onChange();
    await vi.advanceTimersByTimeAsync(0);
    state.handlers!.onChange(); // arrives while the first cycle runs
    await vi.advanceTimersByTimeAsync(0);
    expect(cycle).toHaveBeenCalledTimes(1);
    release();
    await vi.advanceTimersByTimeAsync(0);
    release();
    await vi.advanceTimersByTimeAsync(0);
    expect(cycle).toHaveBeenCalledTimes(2);
    expect(overlap).toBe(1);
    await manager.stop();
  });

  it("records the marker a forced cycle covered, so the next probe does not repeat it", async () => {
    const { push, state } = fakePush();
    let marker = "m1";
    const cycle = vi.fn(async () => {});
    const manager = build({
      localSync: { cycle },
      changeProbe: { read: async () => marker, intervalMs: 5_000, push },
    });
    manager.start();
    await vi.advanceTimersByTimeAsync(0);
    await manager.requestPull();
    cycle.mockClear();

    marker = "m2";
    state.handlers!.onChange();
    await vi.advanceTimersByTimeAsync(0);
    expect(cycle).toHaveBeenCalledTimes(1);
    await manager.requestPull(); // m2 was applied by the forced cycle
    expect(cycle).toHaveBeenCalledTimes(1);
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

describe("the real subscription driving the manager", () => {
  /** A registry whose held requests the test answers or fails by hand. */
  function heldRegistry() {
    const pending: Array<{
      after: string | undefined;
      answer: (a: { seq: string; changed: boolean }) => void;
      fail: (e: Error) => void;
    }> = [];
    const registry = {
      waitForChange: (
        after: string | undefined,
        _waitMs: number,
        signal: AbortSignal,
      ) =>
        new Promise<{ seq: string; changed: boolean }>((resolve, reject) => {
          pending.push({ after, answer: resolve, fail: reject });
          signal.addEventListener("abort", () => reject(signal.reason), {
            once: true,
          });
        }),
    } as unknown as StreamSyncRegistry;
    return { registry, pending };
  }

  async function started() {
    const { registry, pending } = heldRegistry();
    const push = createRegistryChangePush(registry)!;
    const cycle = vi.fn(async () => {});
    // The probe marker never moves: every cycle that follows is the push's doing.
    const manager = build({
      localSync: { cycle },
      changeProbe: { read: async () => "m1", intervalMs: 5_000, push },
    });
    manager.start();
    await vi.advanceTimersByTimeAsync(0);
    pending[0].answer({ seq: "1", changed: true }); // learns the cursor
    await vi.advanceTimersByTimeAsync(0);
    await manager.requestPull(); // m1 applied
    cycle.mockClear();
    return { manager, pending, cycle };
  }

  it("a changed sequence cycles although the probe marker is unchanged", async () => {
    const { manager, pending, cycle } = await started();
    pending[1].answer({ seq: "2", changed: true });
    await vi.advanceTimersByTimeAsync(0);
    expect(cycle).toHaveBeenCalledTimes(1);
    await manager.stop();
  });

  it("a failed or timed-out attempt starts no cycle: with every answer lost only the 60 s timer applies the change", async () => {
    const { manager, pending, cycle } = await started();
    // Fail every held request the subscription sends, for a minute.
    let failed = 1;
    for (let waited = 0; waited < 55_000; waited += 1_000) {
      while (failed < pending.length) pending[failed++].fail(new Error("lost"));
      await vi.advanceTimersByTimeAsync(1_000);
    }
    expect(failed).toBeGreaterThanOrEqual(3); // it did reconnect, repeatedly
    expect(cycle).not.toHaveBeenCalled(); // and no reconnect started a cycle
    await vi.advanceTimersByTimeAsync(5_000); // the 60 s timer
    expect(cycle).toHaveBeenCalled();
    await manager.stop();
  });

  it("the first answer after a failure cycles although neither the sequence nor the marker moved", async () => {
    const { manager, pending, cycle } = await started();
    pending[1].fail(new Error("socket reset"));
    await vi.advanceTimersByTimeAsync(2_000); // back-off, then the next request
    expect(pending.length).toBeGreaterThanOrEqual(3);
    pending[2].answer({ seq: "1", changed: false });
    await vi.advanceTimersByTimeAsync(0);
    expect(cycle).toHaveBeenCalledTimes(1);
    // Later empty answers do not cycle.
    pending[3].answer({ seq: "1", changed: false });
    await vi.advanceTimersByTimeAsync(0);
    expect(cycle).toHaveBeenCalledTimes(1);
    await manager.stop();
  });
});
