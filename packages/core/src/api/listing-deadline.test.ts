import { afterEach, expect, it, vi } from "vitest";
import {
  handlePersonalServerDataRequest,
  type PersonalServerDataApiDeps,
} from "./index.js";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";
import { createGatewayDataPointFeed } from "../sync/data-point-feed.js";
import { createScopeDeletionTracker } from "../sync/scope-deletions.js";

afterEach(() => vi.useRealTimers());

it.each(["hanging", "slow"])(
  "bounds the whole inventory with a %s deletion gateway and keeps known tombstones",
  async (mode) => {
    vi.useFakeTimers();
    const storage = createMemoryDataStorage();
    const scopes = Array.from(
      { length: 20 },
      (_, i) => `notes.items${i.toString().padStart(2, "0")}`,
    );
    for (const scope of scopes) {
      await storage.insertEntry({
        fileId: scope,
        scope,
        collectedAt: "2026-10-20T00:00:00.000Z",
        path: scope,
        sizeBytes: 123,
        version: scope === scopes[1] ? 3 : 1,
        dataPointId: scope === scopes[1] ? "registered-readd" : null,
      });
    }
    let now = 0;
    const getDataPoint = vi.fn(
      () =>
        new Promise<null>((resolve) => {
          if (mode === "slow") setTimeout(() => resolve(null), 10_000);
        }),
    );
    const tracker = createScopeDeletionTracker({
      serverOwner: "0x1111111111111111111111111111111111111111",
      now: () => new Date(now),
      maxStalenessMs: 1,
      feed: { getDataPoint, listDataPointsByOwner: vi.fn() },
    });
    tracker.markDeleted(scopes[0]!, {
      deletedAt: "2026-10-20T01:00:00.000Z",
      version: "2",
    });
    tracker.markDeleted(scopes[1]!, {
      deletedAt: "2026-10-20T01:00:00.000Z",
      version: "2",
    });
    now = 100;
    const deps: PersonalServerDataApiDeps = {
      storage,
      scopeDeletions: tracker,
      auth: {
        authorizeOwner: vi.fn(),
        authorizeBuilderList: vi.fn(),
        authorizeBuilderRead: vi.fn(),
      },
      accessLogWriter: { write: vi.fn() },
    };
    let response: Response | undefined;
    const pending = handlePersonalServerDataRequest(
      new Request("https://ps.local/?limit=100"),
      deps,
    ).then((value) => {
      response = value;
    });
    await vi.advanceTimersByTimeAsync(1000);
    expect(
      response,
      "inventory must finish within one short shared deadline",
    ).toBeDefined();
    await pending;
    expect(response!.status).toBe(200);
    const body = await response!.json();
    expect(body.total).toBe(19);
    expect(body.scopes.map((row: { scope: string }) => row.scope)).toEqual(
      scopes.slice(1),
    );
    expect(tracker.knownDeletion(scopes[0]!)).toMatchObject({ version: "2" });
    await vi.advanceTimersByTimeAsync(10_000);
    expect(tracker.knownDeletion(scopes[0]!)).toMatchObject({ version: "2" });
  },
);

it("cancels the HTTP deletion lookup at the discovery deadline", async () => {
  vi.useFakeTimers();
  let signal: AbortSignal | null | undefined;
  const fetcher = vi.fn<typeof fetch>(
    (_url, init) =>
      new Promise((_resolve, reject) => {
        signal = init?.signal;
        signal?.addEventListener("abort", () => reject(signal?.reason), {
          once: true,
        });
      }),
  );
  const tracker = createScopeDeletionTracker({
    serverOwner: "0x1111111111111111111111111111111111111111",
    feed: createGatewayDataPointFeed({
      gatewayUrl: "https://gateway.test",
      fetch: fetcher,
    }),
  });
  const result = tracker.resolve("notes.documents", { gatewayTimeoutMs: 25 });
  await vi.advanceTimersByTimeAsync(25);
  await expect(result).resolves.toMatchObject({
    deleted: false,
    verified: false,
  });
  expect(signal?.aborted).toBe(true);
  expect(fetcher).toHaveBeenCalledTimes(1);
});

it("honors a tombstone learned while a discovery lookup is timing out", async () => {
  vi.useFakeTimers();
  const tracker = createScopeDeletionTracker({
    serverOwner: "0x1111111111111111111111111111111111111111",
    feed: {
      getDataPoint: () => new Promise(() => {}),
      listDataPointsByOwner: vi.fn(),
    },
  });
  const result = tracker.resolve("notes.documents", { gatewayTimeoutMs: 25 });
  tracker.markDeleted("notes.documents", {
    deletedAt: "2026-10-20T01:00:00.000Z",
    version: "2",
  });
  await vi.advanceTimersByTimeAsync(25);
  await expect(result).resolves.toMatchObject({ deleted: true, version: "2" });
});

it("does not let an older successful lookup erase a newer local tombstone", async () => {
  let finish!: (record: null) => void;
  const tracker = createScopeDeletionTracker({
    serverOwner: "0x1111111111111111111111111111111111111111",
    feed: {
      getDataPoint: () =>
        new Promise((resolve) => {
          finish = resolve;
        }),
      listDataPointsByOwner: vi.fn(),
    },
  });
  const result = tracker.resolve("notes.documents", { gatewayTimeoutMs: 250 });
  tracker.markDeleted(
    "notes.documents",
    { deletedAt: "2026-10-20T01:00:00.000Z", version: "2" },
    "local-delete",
  );
  finish(null);
  await expect(result).resolves.toMatchObject({ deleted: true, version: "2" });
  expect(tracker.knownDeletion("notes.documents")).toMatchObject({
    version: "2",
  });
});
