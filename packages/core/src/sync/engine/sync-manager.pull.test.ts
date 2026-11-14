// Starting a sync cycle on demand.
//
// A cycle runs when the timer fires, when local data changed, when a caller
// asks (`trigger`), and when a signal says remote state may have changed
// (`requestPull`: focus, visibility, online, a short change probe). The
// guarantees under test: a request never overlaps a running cycle, is never
// dropped, and many requests during one cycle cost one follow-up cycle.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Logger } from "../../logger/index.js";
import type { DownloadWorkerDeps } from "../workers/download.js";
import type { UploadWorkerDeps } from "../workers/upload.js";
import { createSyncManager, type SyncManagerOptions } from "./sync-manager.js";

const logger = {
  info: vi.fn(),
  error: vi.fn(),
  warn: vi.fn(),
  debug: vi.fn(),
  trace: vi.fn(),
  fatal: vi.fn(),
} as unknown as Logger;

// A stream-sync Account: the cycle is `localSync.cycle()` and nothing else, so
// the legacy upload and download workers are never reached.
function build(
  cycle: () => Promise<unknown>,
  options: Partial<SyncManagerOptions> = {},
) {
  return createSyncManager(
    {
      logger,
      serverOwner: "0x1111111111111111111111111111111111111111",
      storage: { findUnsynced: () => [] },
    } as unknown as UploadWorkerDeps,
    { logger } as unknown as DownloadWorkerDeps,
    {
      accountStorageMode: { read: () => "switched" },
      localSync: { cycle },
      pollInterval: 60_000,
      ...options,
    },
  );
}

/** A cycle the test finishes by hand, counting overlap. */
function heldCycles() {
  const state = {
    started: 0,
    finished: 0,
    running: 0,
    maxRunning: 0,
    release: [] as Array<() => void>,
  };
  const cycle = () => {
    state.started += 1;
    state.running += 1;
    state.maxRunning = Math.max(state.maxRunning, state.running);
    return new Promise<void>((resolve) => {
      state.release.push(() => {
        state.running -= 1;
        state.finished += 1;
        resolve();
      });
    });
  };
  const finishOne = async () => {
    state.release.shift()?.();
    await vi.advanceTimersByTimeAsync(0);
  };
  return { state, cycle, finishOne };
}

beforeEach(() => {
  vi.useFakeTimers();
});
afterEach(() => {
  vi.useRealTimers();
});

describe("a requested cycle", () => {
  it("never overlaps a running cycle and costs one follow-up cycle however many requests arrive", async () => {
    const held = heldCycles();
    const manager = build(held.cycle);
    manager.start();
    await vi.advanceTimersByTimeAsync(0);
    expect(held.state.started).toBe(1);

    for (let i = 0; i < 5; i++) void manager.trigger();
    await vi.advanceTimersByTimeAsync(0);
    expect(held.state.started).toBe(1);

    await held.finishOne();
    expect(held.state.started).toBe(2);
    await held.finishOne();
    await vi.advanceTimersByTimeAsync(0);

    expect(held.state.started).toBe(2);
    expect(held.state.maxRunning).toBe(1);
    await manager.stop();
  });

  it("is not dropped when it arrives as the running cycle ends", async () => {
    // The request lands in a microtask queued by the last step of the cycle:
    // after the loop decided it was done, before the cycle was marked idle.
    let calls = 0;
    const manager: ReturnType<typeof build> = build(async () => {
      calls += 1;
      if (calls === 1) queueMicrotask(() => void manager.trigger());
    });
    manager.start();
    await vi.advanceTimersByTimeAsync(0);
    await vi.advanceTimersByTimeAsync(0);

    expect(calls).toBe(2);
    await manager.stop();
  });

  it("keeps the timer as the fallback: a cycle still starts every poll interval", async () => {
    let calls = 0;
    const manager = build(async () => {
      calls += 1;
    });
    manager.start();
    await vi.advanceTimersByTimeAsync(0);
    expect(calls).toBe(1);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(calls).toBe(2);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(calls).toBe(3);
    await manager.stop();
  });
});

describe("requestPull without a change probe", () => {
  it("starts a cycle within one tick", async () => {
    let calls = 0;
    const manager = build(async () => {
      calls += 1;
    });
    manager.start();
    await vi.advanceTimersByTimeAsync(0);
    calls = 0;

    void manager.requestPull();
    await vi.advanceTimersByTimeAsync(0);

    expect(calls).toBe(1);
    await manager.stop();
  });

  it("answers a signal burst in one task with one cycle", async () => {
    let calls = 0;
    const manager = build(async () => {
      calls += 1;
    });
    manager.start();
    await vi.advanceTimersByTimeAsync(0);
    calls = 0;

    // `visibilitychange`, `focus` and `online` can fire together.
    void manager.requestPull();
    void manager.requestPull();
    void manager.requestPull();
    await vi.advanceTimersByTimeAsync(0);

    expect(calls).toBe(1);
    await manager.stop();
  });

  it("does nothing while stopped", async () => {
    let calls = 0;
    const manager = build(async () => {
      calls += 1;
    });
    await manager.requestPull();
    expect(calls).toBe(0);
  });
});

describe("requestPull with a change probe", () => {
  function probed(markers: Array<string | null | undefined | Error>) {
    let reads = 0;
    let calls = 0;
    const cycle = vi.fn(async () => {
      calls += 1;
    });
    const read = vi.fn(async () => {
      const next = markers[Math.min(reads, markers.length - 1)];
      reads += 1;
      if (next instanceof Error) throw next;
      return next;
    });
    const manager = build(cycle, { changeProbe: { read, intervalMs: 5_000 } });
    return { manager, cycle, read, calls: () => calls };
  }

  it("runs a cycle when the marker moved, and none when it did not", async () => {
    const { manager, cycle, read } = probed(["m1", "m1", "m2"]);
    manager.start();
    await vi.advanceTimersByTimeAsync(0);
    cycle.mockClear();

    await manager.requestPull(); // first marker: nothing applied yet
    expect(cycle).toHaveBeenCalledTimes(1);
    await manager.requestPull(); // same marker
    expect(cycle).toHaveBeenCalledTimes(1);
    await manager.requestPull(); // moved
    expect(cycle).toHaveBeenCalledTimes(2);
    expect(read).toHaveBeenCalledTimes(3);
    await manager.stop();
  });

  it("probes on its own period, so a change waits for one probe, not the 60 s timer", async () => {
    const { manager, cycle } = probed(["m1", "m1", "m1", "m2"]);
    manager.start();
    await vi.advanceTimersByTimeAsync(0);
    cycle.mockClear();

    await vi.advanceTimersByTimeAsync(5_000); // m1: first marker, one cycle
    expect(cycle).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(5_000); // m1: unchanged
    await vi.advanceTimersByTimeAsync(5_000); // m1: unchanged
    expect(cycle).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(5_000); // m2
    expect(cycle).toHaveBeenCalledTimes(2);
    await manager.stop();
  });

  it("still runs the 60 s cycle when nothing changed", async () => {
    const { manager, cycle } = probed(["m1"]);
    manager.start();
    await vi.advanceTimersByTimeAsync(0);
    expect(cycle).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(60_000);
    // 12 probes: the first one pulled once, the rest saw no change; plus the timer.
    expect(cycle).toHaveBeenCalledTimes(3);
    await manager.stop();
  });

  it("treats a probe that cannot answer as a change", async () => {
    const { manager, cycle } = probed([new Error("offline")]);
    manager.start();
    await vi.advanceTimersByTimeAsync(0);
    cycle.mockClear();
    await manager.requestPull();
    await manager.requestPull();
    expect(cycle).toHaveBeenCalledTimes(2);

    const unsupported = probed([undefined]);
    unsupported.manager.start();
    await vi.advanceTimersByTimeAsync(0);
    unsupported.cycle.mockClear();
    await unsupported.manager.requestPull();
    await unsupported.manager.requestPull();
    expect(unsupported.cycle).toHaveBeenCalledTimes(2);
    await manager.stop();
    await unsupported.manager.stop();
  });

  it("does not remember a marker whose cycle failed", async () => {
    let fail = true;
    const cycle = vi.fn(async () => {
      if (fail) throw new Error("registry down");
    });
    const manager = build(cycle, {
      changeProbe: { read: async () => "m1", intervalMs: 5_000 },
    });
    manager.start();
    await vi.advanceTimersByTimeAsync(0);
    cycle.mockClear();

    await manager.requestPull().catch(() => undefined);
    fail = false;
    await manager.requestPull();
    await manager.requestPull();

    expect(cycle).toHaveBeenCalledTimes(2); // failed, then retried; then settled
    await manager.stop();
  });

  it("does not remember a marker when the cycle was blocked", async () => {
    let blockedNow = true;
    const cycle = vi.fn(async () => {});
    const manager = build(cycle, {
      canSync: () =>
        blockedNow
          ? { ok: false, reason: "unregistered", message: "register first" }
          : { ok: true },
      changeProbe: { read: async () => "m1", intervalMs: 5_000 },
    });
    manager.start();
    await vi.advanceTimersByTimeAsync(0);
    await manager.requestPull();
    expect(cycle).not.toHaveBeenCalled();
    blockedNow = false;
    await manager.requestPull();
    expect(cycle).toHaveBeenCalledTimes(1);
    await manager.stop();
  });

  it("skips the timed probe while the host says it is not worth probing, but not a signal", async () => {
    let active = false;
    const read = vi.fn(async () => "m1");
    const manager = build(async () => {}, {
      changeProbe: { read, intervalMs: 5_000, active: () => active },
    });
    manager.start();
    await vi.advanceTimersByTimeAsync(0);
    await vi.advanceTimersByTimeAsync(20_000);
    expect(read).not.toHaveBeenCalled();

    await manager.requestPull();
    expect(read).toHaveBeenCalledTimes(1);

    active = true;
    await vi.advanceTimersByTimeAsync(5_000);
    expect(read).toHaveBeenCalledTimes(2);
    await manager.stop();
  });

  it("stops probing when stopped", async () => {
    const read = vi.fn(async () => "m1");
    const manager = build(async () => {}, {
      changeProbe: { read, intervalMs: 5_000 },
    });
    manager.start();
    await vi.advanceTimersByTimeAsync(0);
    await manager.stop();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(read).not.toHaveBeenCalled();
  });

  it("answers a burst in one task with at most two probes and one cycle", async () => {
    const { manager, cycle, read } = probed(["m1"]);
    manager.start();
    await vi.advanceTimersByTimeAsync(0);
    cycle.mockClear();

    void manager.requestPull();
    void manager.requestPull();
    void manager.requestPull();
    await vi.advanceTimersByTimeAsync(0);
    await vi.advanceTimersByTimeAsync(0);

    // One probe in flight, never two at once. A signal that arrives while a
    // probe is out may postdate it, so the burst asks for one more read.
    expect(read).toHaveBeenCalledTimes(2);
    expect(cycle).toHaveBeenCalledTimes(1);
    await manager.stop();
  });
});
