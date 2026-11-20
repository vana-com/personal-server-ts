// `subscribeStatus` review round: the quarantine release, anything a listener
// can throw, the cost of a status read (a count, never the rows) and the
// notification of one upload batch, and the pass boundary of the legacy cycle.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Logger } from "../../logger/index.js";
import type { DownloadWorkerDeps } from "../workers/download.js";
import type { UploadWorkerDeps } from "../workers/upload.js";
import type { SyncStatus } from "../types.js";
import { createUploadStateTracker } from "../upload-state.js";

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
  retryPendingBlobDeletions: vi.fn(async () => ({
    completed: [],
    superseded: [],
    failed: [],
    remaining: 0,
    waiting: 0,
    parked: [],
    unavailable: null,
  })),
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

function build(
  options: Partial<SyncManagerOptions> = {},
  upload: Record<string, unknown> = {},
) {
  return createSyncManager(
    {
      logger,
      serverOwner: "0x1111111111111111111111111111111111111111",
      storage: { findUnsynced: () => [] },
      ...upload,
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
  vi.mocked(uploadAll).mockReset().mockResolvedValue([]);
  vi.mocked(downloadAll).mockReset().mockResolvedValue([]);
  vi.mocked(downloadScopes)
    .mockReset()
    .mockResolvedValue(undefined as never);
  vi.mocked(deleteScope).mockReset();
  vi.mocked(logger.warn).mockReset();
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

describe("retryQuarantinedUploads", () => {
  it("emits once when the release clears entries the tracker holds", async () => {
    const tracker = createUploadStateTracker();
    tracker.markTooLarge({ scope: "s.big", path: "s/1.json" }, 9);
    const manager = build(
      {},
      {
        uploadState: tracker,
        uploadAttempts: {
          recover: async () => true,
          release: async () => ["s/1.json"],
        },
      },
    );
    const events = listen(manager);
    expect(manager.getStatus().uploads?.tooLarge).toHaveLength(1);

    await manager.retryQuarantinedUploads();

    expect(events).toHaveLength(1);
    expect(events[0]?.uploads?.tooLarge).toEqual([]);
  });

  it("emits when the release fails part way, after the entries it had cleared", async () => {
    const tracker = createUploadStateTracker();
    tracker.markTooLarge({ scope: "s.a", path: "s/1.json" }, 9);
    tracker.markTooLarge({ scope: "s.a", path: "s/2.json" }, 9);
    const partial = {
      *[Symbol.iterator]() {
        yield "s/1.json";
        throw new Error("storage went away");
      },
    };
    const manager = build(
      {},
      {
        uploadState: tracker,
        uploadAttempts: {
          recover: async () => true,
          release: async () => partial,
        },
      },
    );
    const events = listen(manager);

    await expect(manager.retryQuarantinedUploads()).rejects.toThrow(
      "storage went away",
    );

    expect(events).toHaveLength(1);
    expect(events[0]?.uploads?.tooLarge.map((u) => u.path)).toEqual([
      "s/2.json",
    ]);
  });
});

describe("a listener that throws anything", () => {
  const thrown: [string, unknown][] = [
    ["null", null],
    ["undefined", undefined],
    ["a string", "text"],
    ["an Error", new Error("listener failed")],
  ];
  for (const [what, value] of thrown)
    it(`${what} is reported, and start still runs its first cycle`, async () => {
      const manager = build();
      const after = vi.fn();
      manager.subscribeStatus(() => {
        throw value;
      });
      manager.subscribeStatus(after);

      manager.start();
      await settle();

      expect(after).toHaveBeenCalled(); // the next listener still ran
      expect(downloadAll).toHaveBeenCalled(); // start reached its first cycle
      expect(logger.warn).toHaveBeenCalledWith(
        { error: value instanceof Error ? value.message : String(value) },
        "a sync status listener threw",
      );
      await manager.stop();
    });

  it("a logger that throws while reporting does not leave delivery either", async () => {
    vi.mocked(logger.warn).mockImplementation(() => {
      throw new Error("logger is down");
    });
    const manager = build();
    manager.subscribeStatus(() => {
      throw new Error("listener failed");
    });

    manager.start();
    await settle();

    expect(downloadAll).toHaveBeenCalled();
    await manager.stop();
  });
});

describe("the cost of a status read", () => {
  it("counts the unsynced rows without listing them when the storage can", () => {
    const findUnsynced = vi.fn(() => {
      throw new Error("a status read must not list the rows");
    });
    const manager = build(
      {},
      { storage: { findUnsynced, countUnsynced: () => 7 } },
    );
    expect(manager.getStatus().pendingFiles).toBe(7);
    expect(findUnsynced).not.toHaveBeenCalled();
  });

  it("falls back to listing the rows when the storage cannot count", () => {
    const manager = build(
      {},
      { storage: { findUnsynced: () => [{}, {}, {}] } },
    );
    expect(manager.getStatus().pendingFiles).toBe(3);
  });

  it("an upload cycle reads the status the same number of times for 5 failed files and for 500, and tells the listener once for them", async () => {
    const run = async (failures: number) => {
      let reads = 0;
      vi.mocked(uploadAll)
        .mockReset()
        .mockImplementation((async (
          _deps: unknown,
          options: { onError: (e: unknown, error: Error) => void },
        ) => {
          for (let i = 0; i < failures; i++)
            options.onError(
              { fileId: null, scope: "s.a", path: `s/${i}.json` },
              new Error(`boom ${i}`),
            );
          return [];
        }) as never);
      const manager = build(
        {},
        {
          storage: {
            findUnsynced: () => [],
            countUnsynced: () => {
              reads += 1;
              return 0;
            },
          },
        },
      );
      const events = listen(manager);
      reads = 0;
      await manager.trigger();
      return { reads, events };
    };
    const clean = await run(0);
    const few = await run(5);
    const many = await run(500);
    expect(many.reads).toBe(few.reads); // not one read per failed file
    expect(many.reads).toBeLessThanOrEqual(clean.reads + 2);
    expect(many.events.length).toBe(clean.events.length + 1); // one for the errors
    expect(many.events.at(-1)?.errors).toHaveLength(10); // the ring keeps 10
  });
});

describe("the pass boundary of the legacy cycle", () => {
  it("shows lastSync at the end of a pass while the next pass is still waiting for canSync", async () => {
    let calls = 0;
    let release!: () => void;
    const held = new Promise<void>((resolve) => (release = resolve));
    let endPass!: () => void;
    vi.mocked(downloadAll).mockImplementationOnce(
      () => new Promise((resolve) => (endPass = () => resolve([]))) as never,
    );
    const manager = build({
      canSync: async () => {
        calls += 1;
        if (calls === 2) await held; // the owed pass waits here
        return { ok: true };
      },
    });
    manager.start(); // only a running manager repeats a pass
    await settle();
    const events = listen(manager);
    void manager.trigger(); // a request during the pass owes one more
    vi.setSystemTime(new Date("2026-11-15T10:00:07.000Z"));
    endPass();
    await settle();

    expect(calls).toBe(2); // the second pass has not passed canSync
    expect(events.at(-1)).toMatchObject({
      syncing: true,
      lastSync: "2026-11-15T10:00:07.000Z",
    });
    release();
    await settle();
    await manager.stop();
  });
});
