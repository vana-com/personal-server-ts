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
  let requests = 0;
  let failNext = false;
  const registry = {
    probeChange: async () => "m1",
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
  };
}

function managerOver(
  gateway: ReturnType<typeof heldRegistry>,
  cycle: () => Promise<unknown>,
) {
  return build({
    localSync: { cycle },
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
