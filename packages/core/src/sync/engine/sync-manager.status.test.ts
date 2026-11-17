// `subscribeStatus`: a listener hears each change of `getStatus()` and nothing
// else, so a host that shows sync state needs no timer. Fake timers and no
// sleeps: the manager runs its cycles over a local-sync cycle the test holds.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Logger } from "../../logger/index.js";
import type { DownloadWorkerDeps } from "../workers/download.js";
import type { UploadWorkerDeps } from "../workers/upload.js";
import type { StreamSyncRegistry } from "../../stream-sync/ports.js";
import type { SyncStatus } from "../types.js";
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

function build(
  options: Partial<SyncManagerOptions> = {},
  storage: { findUnsynced: () => unknown[] } = { findUnsynced: () => [] },
) {
  return createSyncManager(
    {
      logger,
      serverOwner: "0x1111111111111111111111111111111111111111",
      storage,
    } as unknown as UploadWorkerDeps,
    { logger } as unknown as DownloadWorkerDeps,
    {
      accountStorageMode: { read: () => "switched" },
      pollInterval: 60_000,
      ...options,
    },
  );
}

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date("2026-11-15T10:00:00.000Z"));
});
afterEach(() => {
  vi.useRealTimers();
});

/** Let promise continuations and zero-delay timers run. */
const settle = () => vi.advanceTimersByTimeAsync(0);
const HOUR = 3_600_000;

/** A local-sync cycle that ends when the test says so. */
function heldCycle() {
  const ends: (() => void)[] = [];
  return {
    cycle: () =>
      new Promise<void>((resolve) => {
        ends.push(resolve);
      }),
    end: () => ends.shift()?.(),
    get running() {
      return ends.length;
    },
  };
}

const heard = (manager: ReturnType<typeof build>) => {
  const events: SyncStatus[] = [];
  const unsubscribe = manager.subscribeStatus((s) => events.push(s));
  return { events, unsubscribe };
};
const shape = (events: readonly SyncStatus[]) =>
  events.map((s) => [s.running, s.syncing, s.lastSync !== null]);

describe("subscribeStatus", () => {
  it("(a) the first cycle with no data ends with exactly one event that has lastSync set and syncing false", async () => {
    const manager = build({
      localSync: { cycle: async () => {}, applyDelta: deltaToCycle },
    });
    manager.start();
    const { events } = heard(manager); // the cycle is already running
    await settle();
    const done = events.filter((s) => s.lastSync !== null && !s.syncing);
    expect(done).toHaveLength(1);
    expect(done[0]).toEqual(manager.getStatus());
    expect(events.at(-1)).toBe(done[0]);
    await manager.stop();
  });

  it("(b) a syncing to idle transition emits, and a pull that finds nothing new emits nothing", async () => {
    const held = heldCycle();
    const manager = build({
      localSync: { cycle: held.cycle, applyDelta: deltaToCycle },
    });
    manager.start();
    await settle();
    held.end();
    await settle();
    const { events } = heard(manager);
    const run = manager.trigger();
    await settle();
    expect(manager.getStatus().syncing).toBe(true);
    expect(events.at(-1)?.syncing).toBe(true); // the start is heard
    vi.setSystemTime(new Date("2026-11-15T10:00:05.000Z"));
    held.end();
    await run;
    expect(events.at(-1)).toEqual(manager.getStatus());
    expect(events.at(-1)).toMatchObject({
      syncing: false,
      lastSync: "2026-11-15T10:00:05.000Z",
    });

    // Reading the status changes nothing, so it tells no one.
    events.length = 0;
    manager.getStatus();
    manager.getStatus();
    expect(events).toEqual([]);
    await manager.stop();
  });

  it("(b2) an idle pull that reads an unchanged registry marker emits nothing", async () => {
    const registry = {
      probeChange: () => Promise.resolve("m1"),
      waitForChange: () => new Promise<never>(() => {}),
    } as unknown as StreamSyncRegistry;
    const cycle = vi.fn(async () => {});
    const manager = build({
      localSync: { cycle, applyDelta: deltaToCycle },
      changeProbe: createRegistryChangeProbe(registry, { intervalMs: 5_000 })!,
    });
    manager.start();
    await settle();
    await manager.requestPull(); // reads the marker; the first one may cycle
    await settle();
    const { events } = heard(manager);
    cycle.mockClear();
    await manager.requestPull(); // same marker: no cycle
    await settle();
    expect(cycle).not.toHaveBeenCalled();
    expect(events).toEqual([]);
    await manager.stop();
  });

  it("(c) a subscriber taken before start hears the first cycle, from start to idle", async () => {
    const manager = build({
      localSync: { cycle: async () => {}, applyDelta: deltaToCycle },
    });
    const { events } = heard(manager);
    expect(events).toEqual([]);
    manager.start();
    await settle();
    // running, cycle started, a pass finished, cycle ended.
    expect(shape(events)).toEqual([
      [true, false, false],
      [true, true, false],
      [true, true, true],
      [true, false, true],
    ]);
    await manager.stop();
  });

  it("(c2) the pending count moving is a change", async () => {
    let unsynced: unknown[] = [];
    const manager = build(
      { accountStorageMode: undefined },
      { findUnsynced: () => unsynced },
    );
    const { events } = heard(manager);
    unsynced = [{}, {}, {}];
    manager.notifyNewData();
    expect(events.map((s) => s.pendingFiles)).toEqual([3]);
    manager.notifyNewData(); // still 3: nothing to tell
    expect(events).toHaveLength(1);
    await manager.stop();
  });

  it("(d) with no subscriber, and after unsubscribe, the manager reads nothing extra", async () => {
    let reads = 0;
    const accountStorageMode = {
      read: () => {
        reads += 1;
        return "switched" as const;
      },
    };
    const manager = build({
      accountStorageMode,
      localSync: { cycle: async () => {}, applyDelta: deltaToCycle },
    });
    await manager.trigger();
    const bare = reads;
    reads = 0;
    const { events, unsubscribe } = heard(manager);
    await manager.trigger();
    expect(events.length).toBeGreaterThan(0);
    expect(reads).toBeGreaterThan(bare); // listening reads the status to compare
    unsubscribe();
    unsubscribe(); // a second call is harmless
    const delivered = events.length;
    reads = 0;
    await manager.trigger();
    expect(reads).toBe(bare);
    expect(events).toHaveLength(delivered);
  });

  it("(d) stop leaves the subscription registered, delivers the stop once, and leaves no timer", async () => {
    const manager = build({
      localSync: { cycle: async () => {}, applyDelta: deltaToCycle },
    });
    const { events } = heard(manager);
    manager.start();
    await settle();
    events.length = 0;
    await manager.stop();
    expect(shape(events)).toEqual([[false, false, true]]);
    expect(vi.getTimerCount()).toBe(0);
    await vi.advanceTimersByTimeAsync(HOUR);
    expect(events).toHaveLength(1);
    // The same manager started again is heard again.
    events.length = 0;
    manager.start();
    await settle();
    expect(events.some((s) => s.running)).toBe(true);
    await manager.stop();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("(d) pause leaves no timer of its own, and the status reads the same", async () => {
    const manager = build({
      localSync: { cycle: async () => {}, applyDelta: deltaToCycle },
    });
    manager.start();
    await settle();
    const timers = vi.getTimerCount();
    const { events } = heard(manager);
    manager.pause();
    expect(events).toEqual([]);
    manager.resume();
    expect(vi.getTimerCount()).toBe(timers);
    await manager.stop();
  });

  it("(d) a listener that calls getStatus on every event and trigger on the first does not loop", async () => {
    const cycle = vi.fn(async () => {});
    const manager = build({ localSync: { cycle, applyDelta: deltaToCycle } });
    let calls = 0;
    let reads = 0;
    manager.subscribeStatus(() => {
      calls += 1;
      manager.getStatus();
      reads += 1;
      if (calls === 1) void manager.trigger().catch(() => {});
    });
    await manager.trigger(); // the host's own cycle; no timer is started
    await settle();
    const delivered = calls;
    const cycles = cycle.mock.calls.length;
    expect(reads).toBe(delivered);
    expect(cycles).toBeLessThanOrEqual(2); // its own and the one the listener asked for
    expect(vi.getTimerCount()).toBe(0);
    await vi.advanceTimersByTimeAsync(HOUR);
    expect(calls).toBe(delivered);
    expect(cycle.mock.calls.length).toBe(cycles);
  });

  it("a listener that triggers inside the delivery is not nested: its change is delivered after it returns", async () => {
    const manager = build({
      localSync: { cycle: async () => {}, applyDelta: deltaToCycle },
    });
    let depth = 0;
    let deepest = 0;
    let calls = 0;
    manager.subscribeStatus(() => {
      depth += 1;
      deepest = Math.max(deepest, depth);
      calls += 1;
      if (calls === 1) void manager.trigger().catch(() => {});
      depth -= 1;
    });
    const quiet: SyncStatus[] = [];
    manager.subscribeStatus((s) => quiet.push(s));
    manager.start();
    await settle();
    expect(deepest).toBe(1);
    expect(quiet.at(-1)).toEqual(manager.getStatus());
    await manager.stop();
  });

  it("a listener that throws does not stop the others or the manager", async () => {
    const manager = build({
      localSync: { cycle: async () => {}, applyDelta: deltaToCycle },
    });
    manager.subscribeStatus(() => {
      throw new Error("listener bug");
    });
    const { events } = heard(manager);
    manager.start();
    await settle();
    expect(events.at(-1)).toMatchObject({ syncing: false });
    expect(logger.warn).toHaveBeenCalledWith(
      { error: "listener bug" },
      "a sync status listener threw",
    );
    await manager.stop();
  });
});
