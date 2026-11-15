// `subscribeStatus` over the legacy cycle (Account Off): the workers are held
// by the test, so each point inside a long cycle can be seen on its own. A host
// that shows progress hears the uploads move, an error, a block and its lift,
// scopes hydrated, a stop during a cycle, and a delete, as they happen and not
// only when the cycle ends.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Logger } from "../../logger/index.js";
import type { DownloadWorkerDeps } from "../workers/download.js";
import type { UploadWorkerDeps } from "../workers/upload.js";
import type { SyncStatus } from "../types.js";

vi.mock("../workers/upload.js", () => ({ uploadAll: vi.fn() }));
vi.mock("../workers/download.js", () => ({
  downloadAll: vi.fn(),
  downloadScopes: vi.fn(),
}));
vi.mock("../workers/lost-data-points.js", () => ({
  requeueLostDataPoints: vi.fn(async () => ({ requeued: [], failed: [] })),
}));
vi.mock("../workers/delete.js", () => ({
  deleteScope: vi.fn(),
  retryPendingBlobDeletions: vi.fn(async () => {}),
}));

import { uploadAll } from "../workers/upload.js";
import { downloadAll, downloadScopes } from "../workers/download.js";
import { deleteScope } from "../workers/delete.js";
import { createSyncManager, type SyncManagerOptions } from "./sync-manager.js";

const logger = {
  info: vi.fn(),
  error: vi.fn(),
  warn: vi.fn(),
  debug: vi.fn(),
  trace: vi.fn(),
  fatal: vi.fn(),
} as unknown as Logger;

/** One call of a mocked worker that ends when the test says so. */
function held<T>(value: T) {
  const ends: ((v?: unknown) => void)[] = [];
  const fails: ((e: Error) => void)[] = [];
  return {
    run: () =>
      new Promise<T>((resolve, reject) => {
        ends.push(() => resolve(value));
        fails.push(reject);
      }),
    end: () => ends.shift()?.(),
    fail: (message: string) => fails.shift()?.(new Error(message)),
    get open() {
      return ends.length;
    },
  };
}

let unsynced: unknown[];
function build(options: Partial<SyncManagerOptions> = {}) {
  return createSyncManager(
    {
      logger,
      serverOwner: "0x1111111111111111111111111111111111111111",
      storage: { findUnsynced: () => unsynced },
    } as unknown as UploadWorkerDeps,
    {
      logger,
      cursor: { read: async () => null, write: async () => {} },
    } as unknown as DownloadWorkerDeps,
    { pollInterval: 60_000, ...options },
  );
}

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date("2026-11-15T10:00:00.000Z"));
  unsynced = [];
  vi.mocked(uploadAll).mockReset().mockResolvedValue([]);
  vi.mocked(downloadAll).mockReset().mockResolvedValue([]);
  vi.mocked(downloadScopes)
    .mockReset()
    .mockResolvedValue(undefined as never);
  vi.mocked(deleteScope).mockReset();
});
afterEach(() => {
  vi.useRealTimers();
});

const settle = () => vi.advanceTimersByTimeAsync(0);
const listen = (manager: ReturnType<typeof build>) => {
  const events: SyncStatus[] = [];
  manager.subscribeStatus((s) => events.push(s));
  return events;
};

describe("subscribeStatus inside a long legacy cycle", () => {
  it("the pending count is heard when the uploads finish, before the download does", async () => {
    unsynced = [{}, {}, {}];
    const download = held([]);
    vi.mocked(downloadAll).mockImplementation(download.run as never);
    vi.mocked(uploadAll).mockImplementation(async () => {
      unsynced = [{}];
      return [];
    });
    const manager = build();
    const events = listen(manager);
    const run = manager.trigger();
    await settle();
    expect(download.open).toBe(1);
    expect(events.at(-1)).toMatchObject({ syncing: true, pendingFiles: 1 });
    download.end();
    await run;
    expect(events.at(-1)).toMatchObject({ syncing: false, pendingFiles: 1 });
  });

  it("an error is heard when it happens, while the cycle is still running", async () => {
    const download = held([]);
    vi.mocked(downloadAll).mockImplementation(download.run as never);
    const manager = build();
    const events = listen(manager);
    const run = manager.trigger();
    await settle();
    expect(events.some((s) => s.errors.length > 0)).toBe(false);
    download.fail("gateway down");
    await run;
    const first = events.find((s) => s.errors.length > 0)!;
    expect(first.syncing).toBe(true);
    expect(first.errors[0]?.message).toContain("gateway down");
  });

  it("a pass that finishes while a follow-up is owed shows lastSync with syncing still true", async () => {
    const download = held([]);
    vi.mocked(downloadAll).mockImplementation(download.run as never);
    const manager = build();
    manager.start(); // only a running manager repeats a pass
    await settle();
    const events = listen(manager);
    void manager.trigger(); // a request during the pass owes one more
    vi.setSystemTime(new Date("2026-11-15T10:00:07.000Z"));
    download.end();
    await settle();
    expect(download.open).toBe(1); // the second pass is running
    expect(events.at(-1)).toMatchObject({
      syncing: true,
      lastSync: "2026-11-15T10:00:07.000Z",
    });
    download.end();
    await manager.stop();
  });

  it("a block is heard, and so is its lift while the next cycle is still running", async () => {
    let ok = false;
    const cycle = held(undefined);
    const manager = build({
      accountStorageMode: { read: () => "switched" } as never,
      localSync: { cycle: cycle.run } as never,
      canSync: async () =>
        ok
          ? { ok: true }
          : { ok: false, reason: "unregistered", message: "register first" },
    });
    const events = listen(manager);
    await manager.trigger();
    expect(events.at(-1)).toMatchObject({
      syncing: false,
      blocked: { reason: "unregistered" },
    });
    ok = true;
    const run = manager.trigger();
    await settle();
    expect(cycle.open).toBe(1);
    expect(events.at(-1)).toMatchObject({ syncing: true, blocked: null });
    cycle.end();
    await run;
  });

  it("a queued cycle is heard as syncing before it starts", async () => {
    const hydrate = held(undefined);
    vi.mocked(downloadScopes).mockImplementation(hydrate.run as never);
    const manager = build();
    const events = listen(manager);
    const hydrating = manager.hydrateScopes(["s"]);
    await settle();
    expect(hydrate.open).toBe(1);
    const run = manager.trigger(); // waits behind the hydrate
    await settle();
    expect(events.at(-1)).toMatchObject({ syncing: true });
    hydrate.end();
    await hydrating;
    await run;
  });

  it("stop during a cycle is heard at once, as running false with syncing still true", async () => {
    const download = held([]);
    vi.mocked(downloadAll).mockImplementation(download.run as never);
    const manager = build();
    manager.start();
    await settle();
    expect(download.open).toBe(1);
    const events = listen(manager);
    const stopping = manager.stop();
    await settle();
    expect(events.at(-1)).toMatchObject({ running: false, syncing: true });
    download.end();
    await stopping;
    expect(events.at(-1)).toMatchObject({ running: false, syncing: false });
  });
});

describe("subscribeStatus around hydrate and delete", () => {
  it("each hydrated scope is heard as it lands", async () => {
    const hydrate = held(undefined);
    vi.mocked(downloadScopes).mockImplementation(hydrate.run as never);
    const manager = build();
    const events = listen(manager);
    const run = manager.hydrateScopes(["a", "b"]);
    await settle();
    hydrate.end();
    await settle();
    expect(events.at(-1)?.hydratedScopes).toEqual(["a"]);
    hydrate.end();
    await run;
    expect(events.at(-1)?.hydratedScopes).toEqual(["a", "b"]);
  });

  it("a blocked hydrate, its lift while the cycle it runs is open, and an unknown account mode are heard", async () => {
    let ok = false;
    let mode: "switched" | "unknown" = "switched";
    const cycle = held(undefined);
    const manager = build({
      canSync: async () =>
        ok ? { ok: true } : { ok: false, reason: "unregistered", message: "m" },
      accountStorageMode: { read: () => mode } as never,
      localSync: { cycle: cycle.run } as never,
    });
    const events = listen(manager);
    await manager.hydrateScopes(["a"]);
    expect(events.at(-1)?.blocked).toMatchObject({ reason: "unregistered" });
    ok = true;
    const lifting = manager.hydrateScopes(["a"]);
    await settle();
    expect(cycle.open).toBe(1);
    expect(events.at(-1)?.blocked).toBeNull(); // before the cycle it runs ends
    cycle.end();
    await lifting;
    mode = "unknown";
    await manager.hydrateScopes(["a"]);
    expect(events.at(-1)?.blocked).toMatchObject({
      reason: "account_mode_unknown",
    });
  });

  it("a subscriber taken after an unsubscribe starts from the value it finds, not from the one it last heard", async () => {
    const manager = build();
    const off = manager.subscribeStatus(() => {});
    off();
    // Pending files moved while no one listened and nothing told the manager.
    unsynced = [{}, {}];
    const events: SyncStatus[] = [];
    manager.subscribeStatus((s) => events.push(s));
    expect(events).toEqual([]);
  });

  it("a delete that removes pending files is heard", async () => {
    unsynced = [{}, {}];
    vi.mocked(deleteScope).mockImplementation((async () => {
      unsynced = [];
      return { durable: false, scope: "s", steps: {} };
    }) as never);
    const manager = build();
    const events = listen(manager);
    await manager.deleteScope("s");
    expect(events.at(-1)?.pendingFiles).toBe(0);
    expect(events).toHaveLength(1);
  });
});
