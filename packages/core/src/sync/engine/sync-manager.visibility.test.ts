// Hiding the tab: the host pauses the manager, shows it again: the host resumes
// it. While paused the manager holds no request and no timer, however the hide
// came (a held request, a failure cooldown, a running cycle). Each resume
// starts exactly one subscription. The push here is the real one, over a
// registry whose held requests the test controls.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Logger } from "../../logger/index.js";
import type { DownloadWorkerDeps } from "../workers/download.js";
import type { UploadWorkerDeps } from "../workers/upload.js";
import type { StreamSyncRegistry } from "../../stream-sync/ports.js";
import { createRegistryChangeProbe } from "./change-probe.js";
import { createSyncManager, type SyncManagerOptions } from "./sync-manager.js";
import { deltaToCycle } from "./local-sync.test-helper.js";

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

/** A registry whose held change requests end only when aborted or answered. */
function heldRegistry() {
  const held: { signal: AbortSignal; fail(error: Error): void }[] = [];
  /** Probe reads held open; the registry ignores their cancellation. */
  const probes: {
    signal: AbortSignal;
    settled: boolean;
    answer(marker: string): void;
  }[] = [];
  let requests = 0;
  let failNext = false;
  let holdProbes = false;
  const registry = {
    probeChange: (signal: AbortSignal) => {
      if (!holdProbes) return Promise.resolve("m1");
      return new Promise<string>((resolve) => {
        const probe = {
          signal,
          settled: false,
          answer: (marker: string) => {
            probe.settled = true;
            resolve(marker);
          },
        };
        probes.push(probe);
      });
    },
    waitForChange: (_after: unknown, _ms: number, signal: AbortSignal) => {
      requests += 1;
      if (failNext) return Promise.reject(new Error("gateway down"));
      return new Promise<never>((_resolve, reject) => {
        const fail = (error: Error) => reject(error);
        held.push({ signal, fail });
        signal.addEventListener("abort", () => reject(new Error("aborted")), {
          once: true,
        });
      });
    },
  } as unknown as StreamSyncRegistry;
  return {
    registry,
    get requests() {
      return requests;
    },
    /** Requests the registry holds open right now. */
    get open() {
      return held.filter((h) => !h.signal.aborted).length;
    },
    set failing(value: boolean) {
      failNext = value;
    },
    set holdProbes(value: boolean) {
      holdProbes = value;
    },
    probes,
    /** Probe reads neither aborted nor answered. */
    get openProbes() {
      return probes.filter((p) => !p.settled && !p.signal.aborted).length;
    },
  };
}

function managerOver(
  gateway: ReturnType<typeof heldRegistry>,
  cycle: () => Promise<unknown>,
) {
  return build({
    localSync: { cycle, applyDelta: deltaToCycle },
    changeProbe: createRegistryChangeProbe(gateway.registry, {
      intervalMs: 5_000,
    })!,
  });
}

beforeEach(() => {
  vi.useFakeTimers();
});
afterEach(() => {
  vi.useRealTimers();
});

/** Let promise continuations and zero-delay timers run. */
const settle = () => vi.advanceTimersByTimeAsync(0);
const HOUR = 3_600_000;

describe("pause and resume", () => {
  it("a hide during a held request aborts it and leaves no timer and no request", async () => {
    const gateway = heldRegistry();
    const cycle = vi.fn(async () => {});
    const manager = managerOver(gateway, cycle);
    manager.start();
    await settle();
    expect(gateway.open).toBe(1);
    cycle.mockClear();
    const requests = gateway.requests;

    manager.pause();
    await settle();
    expect(gateway.open).toBe(0);
    expect(vi.getTimerCount()).toBe(0);

    await vi.advanceTimersByTimeAsync(HOUR);
    expect(gateway.requests).toBe(requests);
    expect(cycle).not.toHaveBeenCalled();
    await manager.stop();
  });

  it("a hide during a held probe aborts it and clears its deadline; hide and show never overlap reads; a late answer changes nothing", async () => {
    const gateway = heldRegistry();
    gateway.holdProbes = true;
    const cycle = vi.fn(async () => {});
    const manager = managerOver(gateway, cycle);
    manager.start();
    await settle();
    cycle.mockClear();
    await vi.advanceTimersByTimeAsync(5_000); // the timed probe goes out, held
    expect(gateway.probes).toHaveLength(1);
    const old = gateway.probes[0]!;

    manager.pause();
    expect(old.signal.aborted).toBe(true); // before any time passes
    await settle();
    expect(vi.getTimerCount()).toBe(0); // the probe's deadline included

    manager.resume();
    await vi.advanceTimersByTimeAsync(5_000);
    expect(gateway.probes).toHaveLength(2);
    expect(gateway.openProbes).toBe(1); // the old read does not overlap the new

    old.answer("m1"); // the registry ignored the cancel and answers late
    await settle();
    expect(cycle).not.toHaveBeenCalled();
    gateway.probes[1]!.answer("m1");
    await settle();
    // The new read is compared with no baseline: the late answer set none.
    expect(cycle).toHaveBeenCalledTimes(1);
    await manager.stop();
  });

  it("stop aborts a held probe and leaves no timer", async () => {
    const gateway = heldRegistry();
    gateway.holdProbes = true;
    const manager = managerOver(
      gateway,
      vi.fn(async () => {}),
    );
    manager.start();
    await settle();
    await vi.advanceTimersByTimeAsync(5_000);
    expect(gateway.openProbes).toBe(1);
    await manager.stop();
    expect(gateway.openProbes).toBe(0);
    expect(gateway.probes[0]!.signal.aborted).toBe(true);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("a local ingest while visible, then a hide before its debounce ends: no timer while hidden, one owed cycle on show", async () => {
    const gateway = heldRegistry();
    const cycle = vi.fn(async () => {});
    const manager = managerOver(gateway, cycle);
    manager.start();
    await settle();
    cycle.mockClear();

    manager.notifyNewData(); // the debounce timer starts
    expect(vi.getTimerCount()).toBeGreaterThan(0);
    manager.pause(); // before it fires
    await settle();
    expect(vi.getTimerCount()).toBe(0);
    await vi.advanceTimersByTimeAsync(HOUR);
    expect(cycle).not.toHaveBeenCalled();

    manager.resume();
    await settle();
    expect(cycle).toHaveBeenCalledTimes(1);
    await manager.stop();
  });

  it("a hide during a failure cooldown clears it: no request comes back while hidden", async () => {
    const gateway = heldRegistry();
    gateway.failing = true;
    const cycle = vi.fn(async () => {});
    const manager = managerOver(gateway, cycle);
    manager.start();
    await vi.advanceTimersByTimeAsync(3_000); // failed once, cooling down
    const requests = gateway.requests;
    expect(requests).toBeGreaterThan(0);

    manager.pause();
    await settle();
    expect(vi.getTimerCount()).toBe(0);
    await vi.advanceTimersByTimeAsync(HOUR);
    expect(gateway.requests).toBe(requests);

    gateway.failing = false;
    manager.resume();
    await settle();
    expect(gateway.open).toBe(1);
    await manager.stop();
  });

  it("a hide during a running cycle lets it finish, then holds no timer and runs no follow-up", async () => {
    const gateway = heldRegistry();
    let release!: (error?: Error) => void;
    const cycle = vi.fn(
      () =>
        new Promise<void>((resolve, reject) => {
          release = (error) => (error ? reject(error) : resolve());
        }),
    );
    const manager = managerOver(gateway, cycle);
    manager.start();
    await settle();
    expect(cycle).toHaveBeenCalledTimes(1); // the start-up cycle is running
    void manager.requestPull().catch(() => {}); // owes a follow-up
    await settle();

    manager.pause();
    release(new Error("storage down")); // the running cycle fails while hidden
    await settle();
    expect(vi.getTimerCount()).toBe(0); // no retry cooldown while hidden
    await vi.advanceTimersByTimeAsync(HOUR);
    expect(cycle).toHaveBeenCalledTimes(1);
    expect(gateway.open).toBe(0);

    cycle.mockImplementation(async () => {});
    manager.resume();
    await settle();
    expect(cycle).toHaveBeenCalledTimes(2); // the owed follow-up, once
    expect(gateway.open).toBe(1);
    await manager.stop();
  });

  it("a hide during a cycle failure's retry cooldown clears the retry; the show runs it once", async () => {
    const gateway = heldRegistry();
    let release!: (error?: Error) => void;
    const cycle = vi.fn(
      () =>
        new Promise<void>((resolve, reject) => {
          release = (error) => (error ? reject(error) : resolve());
        }),
    );
    const manager = managerOver(gateway, cycle);
    manager.start();
    await settle();
    void manager.requestPull().catch(() => {}); // owes a follow-up
    await settle();
    release(new Error("storage down")); // fails while visible: cooldown starts
    await settle();
    const cooling = vi.getTimerCount();
    expect(cooling).toBeGreaterThan(0);

    manager.pause();
    await settle();
    expect(vi.getTimerCount()).toBe(0);
    await vi.advanceTimersByTimeAsync(HOUR);
    expect(cycle).toHaveBeenCalledTimes(1);

    cycle.mockImplementation(async () => {});
    manager.resume();
    await settle();
    expect(cycle).toHaveBeenCalledTimes(2);
    await manager.stop();
  });

  it("showing many times starts exactly one subscription each time", async () => {
    const gateway = heldRegistry();
    const manager = managerOver(
      gateway,
      vi.fn(async () => {}),
    );
    manager.start();
    await settle();
    for (let round = 1; round <= 3; round++) {
      manager.pause();
      manager.pause(); // a second hide changes nothing
      await settle();
      expect(gateway.open).toBe(0);
      manager.resume();
      manager.resume();
      manager.resume();
      await settle();
      expect(gateway.open).toBe(1);
      expect(gateway.requests).toBe(1 + round);
    }
    await manager.stop();
    expect(gateway.open).toBe(0);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("a signal or a local ingest while hidden starts nothing; the show runs the owed cycle once", async () => {
    const gateway = heldRegistry();
    const cycle = vi.fn(async () => {});
    const manager = managerOver(gateway, cycle);
    manager.start();
    await settle();
    manager.pause();
    cycle.mockClear();

    await manager.requestPull(); // focus or online while hidden
    manager.notifyNewData(); // a local ingest while hidden
    await vi.advanceTimersByTimeAsync(HOUR);
    expect(cycle).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);

    manager.resume();
    await settle();
    expect(cycle).toHaveBeenCalledTimes(1);
    await manager.stop();
  });

  it("the timers come back after a show: a cycle runs at the poll period", async () => {
    const gateway = heldRegistry();
    const cycle = vi.fn(async () => {});
    const manager = managerOver(gateway, cycle);
    manager.start();
    await settle();
    manager.pause();
    manager.resume();
    await settle();
    cycle.mockClear();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(cycle).toHaveBeenCalled();
    await manager.stop();
  });

  it("pause and resume before start or after stop do nothing", async () => {
    const gateway = heldRegistry();
    const manager = managerOver(
      gateway,
      vi.fn(async () => {}),
    );
    manager.pause();
    manager.resume();
    await settle();
    expect(gateway.requests).toBe(0);
    manager.start();
    await settle();
    await manager.stop();
    manager.resume();
    await settle();
    expect(gateway.open).toBe(0);
    expect(vi.getTimerCount()).toBe(0);
  });
});
