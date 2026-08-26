import { describe, it, expect, vi } from "vitest";

import type { DeleteScopeDeps } from "./delete.js";
import {
  BLOB_DELETE_BATCH_SIZE,
  deleteScope,
  planBlobDeletions,
  retryPendingBlobDeletions,
} from "./delete.js";
import { computeDataPointId } from "../data-point-id.js";
import { createMemoryPendingBlobDeletionStore } from "../pending-blob-deletions.js";
import type { Logger } from "../../logger/index.js";
import type { IndexEntry } from "../../storage/index/types.js";
import type {
  DataPointFeedPort,
  DataStoragePort,
  DeleteBlobVersionsOutcome,
  DeleteDataPort,
  PendingBlobDeletionStore,
} from "../../ports/index.js";

const SCOPE = "instagram.profile";
const OWNER = "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12";
const DATA_POINT_ID = computeDataPointId(OWNER, SCOPE);
const DELETED_AT = "2026-08-25T10:00:00.000Z";

function makeLogger(): Logger {
  return {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  } as unknown as Logger;
}

function allDeleted(
  _scope: string,
  versions: string[],
): Promise<DeleteBlobVersionsOutcome> {
  return Promise.resolve({ deleted: versions, missing: [], failed: [] });
}

function makeDeleteData(overrides?: Partial<DeleteDataPort>): DeleteDataPort {
  return {
    tombstone: vi.fn(async () => ({
      status: "tombstoned" as const,
      dataPointId: DATA_POINT_ID,
      version: "4",
      deletedAt: DELETED_AT,
    })),
    deleteBlobVersions: vi.fn(allDeleted),
    ...overrides,
  };
}

function makePending(): PendingBlobDeletionStore {
  const store = createMemoryPendingBlobDeletionStore();
  return {
    list: vi.fn(() => store.list()),
    add: vi.fn((keys) => store.add(keys)),
    remove: vi.fn((keys) => store.remove(keys)),
  };
}

function entry(overrides: Partial<IndexEntry>): IndexEntry {
  return {
    id: 1,
    fileId: null,
    schemaId: null,
    path: `${SCOPE}/x.json`,
    scope: SCOPE,
    collectedAt: "2026-08-01T00:00:00.000Z",
    createdAt: "2026-08-01T00:00:00.000Z",
    sizeBytes: 10,
    version: 1,
    dataPointId: "0xdp",
    ...overrides,
  };
}

function feedAnswering(
  answer: (scope: string) => Promise<{
    deletedAt: string | null;
    expectedVersion: string;
  } | null>,
): DataPointFeedPort & { getDataPoint: ReturnType<typeof vi.fn> } {
  const getDataPoint = vi.fn(
    async ({ scope }: { ownerAddress: string; scope: string }) => {
      const row = await answer(scope);
      return row
        ? {
            id: computeDataPointId(OWNER, scope),
            ownerAddress: OWNER,
            scope,
            dataHash: "0x" + "11".repeat(32),
            metadataHash: "0x" + "22".repeat(32),
            expectedVersion: row.expectedVersion,
            addedAt: "2026-08-25T11:00:00.000Z",
            deletedAt: row.deletedAt,
          }
        : null;
    },
  );
  return { getDataPoint, listDataPointsByOwner: vi.fn() };
}

function makeDeps(
  overrides?: Partial<DeleteScopeDeps> & { localVersions?: IndexEntry[] },
): DeleteScopeDeps & { calls: string[] } {
  const calls: string[] = [];
  const deleteData = makeDeleteData();
  (deleteData.tombstone as ReturnType<typeof vi.fn>).mockImplementation(
    async () => {
      calls.push("gateway");
      return {
        status: "tombstoned",
        dataPointId: DATA_POINT_ID,
        version: "4",
        deletedAt: DELETED_AT,
      };
    },
  );
  (
    deleteData.deleteBlobVersions as ReturnType<typeof vi.fn>
  ).mockImplementation(async (scope: string, versions: string[]) => {
    calls.push("storage");
    return allDeleted(scope, versions);
  });
  const { localVersions = [], ...depOverrides } = overrides ?? {};
  const storage: Partial<DataStoragePort> = {
    listVersions: vi.fn(() => localVersions),
    deleteScope: vi.fn(async () => {
      calls.push("local");
      return 2;
    }),
  };
  return {
    calls,
    storage: storage as DataStoragePort,
    serverOwner: OWNER,
    deleteData,
    pendingBlobDeletions: makePending(),
    logger: makeLogger(),
    ...depOverrides,
  };
}

function versionsSent(deleteData: DeleteDataPort): string[][] {
  return (
    deleteData.deleteBlobVersions as ReturnType<typeof vi.fn>
  ).mock.calls.map((call) => call[1] as string[]);
}

describe("planBlobDeletions", () => {
  it("covers the registry range as bounds plus covered local keys outside it", () => {
    const storage = {
      listVersions: vi.fn(() => [
        entry({ version: 2 }),
        // Unsynced, no marker: covered, and its key is above the tombstone.
        entry({ id: 2, version: 9, dataPointId: null }),
        // Re-add on top of tombstone 4: not covered, key survives.
        entry({
          id: 3,
          version: 7,
          dataPointId: null,
          afterTombstoneVersion: 4,
        }),
      ]),
    };

    expect(planBlobDeletions(storage, SCOPE, "4")).toEqual({
      keys: ["9"],
      range: { from: "1", to: "4" },
    });
  });

  it("enumerates only the covered local keys when no tombstone version is known", () => {
    const storage = {
      listVersions: vi.fn(() => [
        entry({ version: 3 }),
        entry({ id: 2, version: 5, dataPointId: null }),
      ]),
    };
    expect(planBlobDeletions(storage, SCOPE, null)).toEqual({
      keys: ["3", "5"],
      range: null,
    });
  });

  it("never materialises the registry range, however large the tombstone version", () => {
    const huge = "18446744073709551617";
    const started = Date.now();
    const plan = planBlobDeletions({ listVersions: () => [] }, SCOPE, huge);
    expect(plan).toEqual({ keys: [], range: { from: "1", to: huge } });
    expect(Date.now() - started).toBeLessThan(1000);
  });

  it("walks every page of local versions", () => {
    // Unsynced and unmarked: every one is covered, whatever its version.
    const page = Array.from({ length: 500 }, (_, i) =>
      entry({ id: i + 1, version: i + 1, dataPointId: null }),
    );
    const listVersions = vi
      .fn()
      .mockReturnValueOnce(page)
      .mockReturnValueOnce([
        entry({ id: 501, version: 501, dataPointId: null }),
      ]);
    const plan = planBlobDeletions({ listVersions }, SCOPE, "2");
    expect(listVersions).toHaveBeenCalledTimes(2);
    // Versions 1 and 2 are inside the range; the other 499 are exact keys.
    expect(plan.keys).toHaveLength(499);
    expect(plan.keys[0]).toBe("3");
    expect(plan.keys[498]).toBe("501");
  });
});

describe("deleteScope orchestration", () => {
  it("runs gateway tombstone, then exact blob deletes, then local delete", async () => {
    const deps = makeDeps({ localVersions: [entry({ version: 2 })] });

    const result = await deleteScope(deps, SCOPE);

    expect(deps.calls).toEqual(["gateway", "storage", "local"]);
    expect(versionsSent(deps.deleteData!)).toEqual([["1", "2", "3", "4"]]);
    expect(result).toEqual({
      scope: SCOPE,
      dataPointId: DATA_POINT_ID,
      durable: true,
      steps: {
        gateway: { status: "ok", version: "4", deletedAt: DELETED_AT },
        storage: {
          status: "ok",
          blobsDeleted: 4,
          blobsMissing: 0,
          blobsPending: 0,
        },
        local: { status: "ok", deletedCount: 2 },
      },
      pendingBlobDeletion: false,
    });
    expect(await deps.pendingBlobDeletions!.list()).toEqual([]);
  });

  it("never sends a scope-wide delete: a re-add uploaded between the tombstone and the blob pass survives", async () => {
    // Replica B registers version 5 (and uploads its blob under key 5) at
    // any point after A's tombstone at 4. A's pass only touches keys 1..4.
    const deps = makeDeps({ localVersions: [] });
    let storedKeys = ["1", "2", "3"];
    (
      deps.deleteData!.deleteBlobVersions as ReturnType<typeof vi.fn>
    ).mockImplementation(async (_scope: string, versions: string[]) => {
      // B's re-add blob appears mid-pass.
      storedKeys = [...storedKeys, "5"];
      const deleted = versions.filter((v) => storedKeys.includes(v));
      storedKeys = storedKeys.filter((v) => !versions.includes(v));
      return {
        deleted,
        missing: versions.filter((v) => !deleted.includes(v)),
        failed: [],
      };
    });

    const result = await deleteScope(deps, SCOPE);

    expect(versionsSent(deps.deleteData!)).toEqual([["1", "2", "3", "4"]]);
    expect(storedKeys).toEqual(["5"]);
    expect(result.steps.storage).toEqual({
      status: "ok",
      blobsDeleted: 3,
      blobsMissing: 1,
      blobsPending: 0,
    });
  });

  it("never touches storage or the local copy when the gateway tombstone fails", async () => {
    const deps = makeDeps();
    (deps.deleteData!.tombstone as ReturnType<typeof vi.fn>).mockRejectedValue(
      new Error("Gateway error: 503 Service Unavailable"),
    );

    const result = await deleteScope(deps, SCOPE);

    expect(deps.calls).toEqual([]);
    expect(result.durable).toBe(false);
    expect(result.steps).toEqual({
      gateway: {
        status: "failed",
        error: "Gateway error: 503 Service Unavailable",
      },
      storage: { status: "skipped", reason: "gateway-failed" },
      local: { status: "skipped", reason: "gateway-failed" },
    });
  });

  it("records exact retry markers for the keys that failed, still deletes locally", async () => {
    const deps = makeDeps();
    (
      deps.deleteData!.deleteBlobVersions as ReturnType<typeof vi.fn>
    ).mockImplementation(async (_scope: string, versions: string[]) => ({
      deleted: versions.filter((v) => v !== "2" && v !== "3"),
      missing: [],
      failed: [
        { version: "2", error: "vana-storage delete failed: 503" },
        { version: "3", error: "vana-storage delete failed: 503" },
      ],
    }));

    const result = await deleteScope(deps, SCOPE);

    expect(result.durable).toBe(true);
    expect(result.steps.storage).toEqual({
      status: "failed",
      error: "2 blob delete(s) failed: vana-storage delete failed: 503",
      blobsDeleted: 2,
      blobsMissing: 0,
      blobsPending: 2,
    });
    expect(result.pendingBlobDeletion).toBe(true);
    expect(result.steps.local).toEqual({ status: "ok", deletedCount: 2 });
    expect(await deps.pendingBlobDeletions!.list()).toEqual([
      { scope: SCOPE, version: "2" },
      { scope: SCOPE, version: "3" },
    ]);
  });

  it("queues every key when the storage port itself throws", async () => {
    const deps = makeDeps();
    (
      deps.deleteData!.deleteBlobVersions as ReturnType<typeof vi.fn>
    ).mockRejectedValue(new Error("network down"));

    const result = await deleteScope(deps, SCOPE);

    expect(result.steps.storage).toMatchObject({
      status: "failed",
      blobsPending: 4,
    });
    expect(await deps.pendingBlobDeletions!.list()).toHaveLength(4);
  });

  it("sends one rate-limited batch and defers the rest of the range as bounds", async () => {
    const deps = makeDeps();
    (deps.deleteData!.tombstone as ReturnType<typeof vi.fn>).mockResolvedValue({
      status: "tombstoned",
      dataPointId: DATA_POINT_ID,
      version: "40",
      deletedAt: DELETED_AT,
    });

    const result = await deleteScope(deps, SCOPE);

    const sent = versionsSent(deps.deleteData!);
    expect(sent).toHaveLength(1);
    expect(sent[0]).toHaveLength(BLOB_DELETE_BATCH_SIZE);
    expect(sent[0][0]).toBe("1");
    expect(result.steps.storage).toEqual({
      status: "deferred",
      blobsDeleted: BLOB_DELETE_BATCH_SIZE,
      blobsMissing: 0,
      blobsPending: 40 - BLOB_DELETE_BATCH_SIZE,
    });
    expect(result.pendingBlobDeletion).toBe(true);
    expect(await deps.pendingBlobDeletions!.list()).toEqual([
      {
        scope: SCOPE,
        version: null,
        range: { from: String(BLOB_DELETE_BATCH_SIZE + 1), to: "40" },
      },
    ]);
  });

  it("handles a tombstone version past Number.MAX_SAFE_INTEGER without materialising keys", async () => {
    const huge = "18446744073709551617";
    const deps = makeDeps();
    (deps.deleteData!.tombstone as ReturnType<typeof vi.fn>).mockResolvedValue({
      status: "tombstoned",
      dataPointId: DATA_POINT_ID,
      version: huge,
      deletedAt: DELETED_AT,
    });

    const result = await deleteScope(deps, SCOPE);

    expect(versionsSent(deps.deleteData!)[0]).toHaveLength(
      BLOB_DELETE_BATCH_SIZE,
    );
    expect(result.steps.storage).toMatchObject({
      status: "deferred",
      blobsPending: Number.MAX_SAFE_INTEGER,
    });
    expect(await deps.pendingBlobDeletions!.list()).toEqual([
      {
        scope: SCOPE,
        version: null,
        range: { from: String(BLOB_DELETE_BATCH_SIZE + 1), to: huge },
      },
    ]);
  });

  it("clears stale retry markers for keys storage now acknowledges", async () => {
    const deps = makeDeps();
    await deps.pendingBlobDeletions!.add([{ scope: SCOPE, version: "2" }]);
    (
      deps.deleteData!.deleteBlobVersions as ReturnType<typeof vi.fn>
    ).mockImplementation(async (_scope: string, versions: string[]) => ({
      deleted: [],
      missing: versions,
      failed: [],
    }));

    const result = await deleteScope(deps, SCOPE);

    expect(result.steps.storage).toMatchObject({
      status: "ok",
      blobsMissing: 4,
    });
    expect(await deps.pendingBlobDeletions!.list()).toEqual([]);
  });

  it("treats a never-registered scope as durable and clears only its local keys", async () => {
    const deps = makeDeps({
      localVersions: [entry({ version: 1, dataPointId: null })],
    });
    (deps.deleteData!.tombstone as ReturnType<typeof vi.fn>).mockResolvedValue({
      status: "not-registered",
      dataPointId: DATA_POINT_ID,
    });

    const result = await deleteScope(deps, SCOPE);

    expect(result.durable).toBe(true);
    expect(result.steps.gateway).toEqual({
      status: "skipped",
      reason: "not-registered",
    });
    expect(versionsSent(deps.deleteData!)).toEqual([["1"]]);
    expect(result.steps.local.status).toBe("ok");
  });

  it("marks an already-deleted point as ok with reason already-deleted and still clears blobs", async () => {
    const deps = makeDeps();
    (deps.deleteData!.tombstone as ReturnType<typeof vi.fn>).mockResolvedValue({
      status: "already-deleted",
      dataPointId: DATA_POINT_ID,
      version: "4",
      deletedAt: DELETED_AT,
    });

    const result = await deleteScope(deps, SCOPE);

    expect(result.steps.gateway).toEqual({
      status: "ok",
      reason: "already-deleted",
      version: "4",
      deletedAt: DELETED_AT,
    });
    expect(versionsSent(deps.deleteData!)).toEqual([["1", "2", "3", "4"]]);
  });

  it("queues a version-less marker when the gateway did not report the tombstone version", async () => {
    const deps = makeDeps({
      localVersions: [entry({ version: 2, dataPointId: null })],
    });
    (deps.deleteData!.tombstone as ReturnType<typeof vi.fn>).mockResolvedValue({
      status: "already-deleted",
      dataPointId: DATA_POINT_ID,
      version: "0",
      deletedAt: null,
    });

    const result = await deleteScope(deps, SCOPE);

    // Only the local key can be enumerated now; the registry range waits.
    expect(versionsSent(deps.deleteData!)).toEqual([["2"]]);
    expect(result.steps.storage).toMatchObject({
      status: "deferred",
      blobsPending: 1,
    });
    expect(await deps.pendingBlobDeletions!.list()).toEqual([
      { scope: SCOPE, version: null },
    ]);
  });

  it("is local-only and NOT durable when no remote delete port is wired", async () => {
    const deps = makeDeps({ deleteData: null });

    const result = await deleteScope(deps, SCOPE);

    expect(deps.calls).toEqual(["local"]);
    expect(result.durable).toBe(false);
    expect(result.steps.gateway).toEqual({
      status: "skipped",
      reason: "sync-disabled",
    });
    expect(result.steps.storage).toEqual({
      status: "skipped",
      reason: "sync-disabled",
    });
  });

  it("reports a local delete failure without hiding the remote outcome", async () => {
    const deps = makeDeps();
    (deps.storage.deleteScope as ReturnType<typeof vi.fn>).mockRejectedValue(
      new Error("index locked"),
    );

    const result = await deleteScope(deps, SCOPE);

    expect(result.durable).toBe(true);
    expect(result.steps.storage.status).toBe("ok");
    expect(result.steps.local).toEqual({
      status: "failed",
      error: "index locked",
    });
  });
});

describe("deleteScope vs a registration racing a not-registered answer", () => {
  it("tombstones the row that a registration raced in", async () => {
    let lookups = 0;
    const dataPointFeed = feedAnswering(async () =>
      ++lookups === 1
        ? { deletedAt: null, expectedVersion: "1" }
        : { deletedAt: DELETED_AT, expectedVersion: "2" },
    );
    const deps = makeDeps({ dataPointFeed });
    (deps.deleteData!.tombstone as ReturnType<typeof vi.fn>)
      .mockResolvedValueOnce({
        status: "not-registered",
        dataPointId: DATA_POINT_ID,
      })
      .mockResolvedValueOnce({
        status: "tombstoned",
        dataPointId: DATA_POINT_ID,
        version: "2",
        deletedAt: DELETED_AT,
      });

    const result = await deleteScope(deps, SCOPE);

    expect(deps.deleteData!.tombstone).toHaveBeenCalledTimes(2);
    expect(result.durable).toBe(true);
    expect(result.steps.gateway).toMatchObject({ status: "ok", version: "2" });
    expect(versionsSent(deps.deleteData!)).toEqual([["1", "2"]]);
    expect(result.steps.local).toEqual({ status: "ok", deletedCount: 2 });
  });

  it("refuses and keeps the local copy when the scope keeps being registered concurrently", async () => {
    const dataPointFeed = feedAnswering(async () => ({
      deletedAt: null,
      expectedVersion: "1",
    }));
    const deps = makeDeps({ dataPointFeed });
    (deps.deleteData!.tombstone as ReturnType<typeof vi.fn>).mockResolvedValue({
      status: "not-registered",
      dataPointId: DATA_POINT_ID,
    });

    const result = await deleteScope(deps, SCOPE);

    expect(result.durable).toBe(false);
    expect(result.steps.gateway.status).toBe("failed");
    expect(result.steps.gateway.error).toContain("registered concurrently");
    expect(result.steps.local).toEqual({
      status: "skipped",
      reason: "gateway-failed",
    });
    expect(deps.storage.deleteScope).not.toHaveBeenCalled();
    expect(deps.deleteData!.deleteBlobVersions).not.toHaveBeenCalled();
  });

  it("refuses a not-registered delete when the registry cannot be re-read", async () => {
    const dataPointFeed = feedAnswering(async () => {
      throw new Error("gateway down");
    });
    const deps = makeDeps({ dataPointFeed });
    (deps.deleteData!.tombstone as ReturnType<typeof vi.fn>).mockResolvedValue({
      status: "not-registered",
      dataPointId: DATA_POINT_ID,
    });

    const result = await deleteScope(deps, SCOPE);

    expect(result.durable).toBe(false);
    expect(result.steps.gateway).toEqual({
      status: "failed",
      error: "gateway down",
    });
    expect(deps.storage.deleteScope).not.toHaveBeenCalled();
  });
});

describe("retryPendingBlobDeletions", () => {
  it("retries exact keys, clears the acknowledged ones and keeps the failed", async () => {
    const pending = makePending();
    await pending.add([
      { scope: "a.b", version: "1" },
      { scope: "a.b", version: "2" },
      { scope: "c.d", version: "7" },
    ]);
    const deleteData = makeDeleteData();
    (
      deleteData.deleteBlobVersions as ReturnType<typeof vi.fn>
    ).mockImplementation(async (scope: string, versions: string[]) =>
      scope === "a.b"
        ? {
            deleted: ["1"],
            missing: [],
            failed: [{ version: "2", error: "still down" }],
          }
        : { deleted: [], missing: versions, failed: [] },
    );

    const result = await retryPendingBlobDeletions({
      deleteData,
      pendingBlobDeletions: pending,
      logger: makeLogger(),
    });

    expect(result).toEqual({
      completed: [
        { scope: "a.b", version: "1" },
        { scope: "c.d", version: "7" },
      ],
      superseded: [],
      failed: [{ scope: "a.b", version: "2", error: "still down" }],
      remaining: 1,
    });
    expect(await pending.list()).toEqual([{ scope: "a.b", version: "2" }]);
  });

  it("drains at most one rate-limited batch per pass, in stored order", async () => {
    const pending = makePending();
    await pending.add(
      Array.from({ length: BLOB_DELETE_BATCH_SIZE + 5 }, (_, i) => ({
        scope: SCOPE,
        version: String(i + 1),
      })),
    );
    const deleteData = makeDeleteData();

    const first = await retryPendingBlobDeletions({
      deleteData,
      pendingBlobDeletions: pending,
      logger: makeLogger(),
    });
    expect(first.completed).toHaveLength(BLOB_DELETE_BATCH_SIZE);
    expect(first.remaining).toBe(5);
    expect(versionsSent(deleteData)[0][0]).toBe("1");

    const second = await retryPendingBlobDeletions({
      deleteData,
      pendingBlobDeletions: pending,
      logger: makeLogger(),
    });
    expect(second.completed).toHaveLength(5);
    expect(second.remaining).toBe(0);
  });

  it("drains a range marker from its head, advancing the bounds in place", async () => {
    const pending = makePending();
    await pending.add([
      { scope: SCOPE, version: "99" },
      { scope: SCOPE, version: null, range: { from: "1", to: "20" } },
    ]);
    const deleteData = makeDeleteData();

    const first = await retryPendingBlobDeletions({
      deleteData,
      pendingBlobDeletions: pending,
      logger: makeLogger(),
    });

    // Exact keys go first, then the range head fills the rest of the batch.
    expect(versionsSent(deleteData)[0]).toEqual([
      "99",
      ...Array.from({ length: BLOB_DELETE_BATCH_SIZE - 1 }, (_, i) =>
        String(i + 1),
      ),
    ]);
    expect(first.remaining).toBe(1);
    expect(await pending.list()).toEqual([
      {
        scope: SCOPE,
        version: null,
        range: { from: String(BLOB_DELETE_BATCH_SIZE), to: "20" },
      },
    ]);

    const second = await retryPendingBlobDeletions({
      deleteData,
      pendingBlobDeletions: pending,
      logger: makeLogger(),
    });
    expect(second.remaining).toBe(0);
    expect(await pending.list()).toEqual([]);
  });

  it("turns a failed key from a range into an exact marker and still advances the range", async () => {
    const pending = makePending();
    await pending.add([
      { scope: SCOPE, version: null, range: { from: "1", to: "3" } },
    ]);
    const deleteData = makeDeleteData();
    (
      deleteData.deleteBlobVersions as ReturnType<typeof vi.fn>
    ).mockImplementation(async () => ({
      deleted: ["1", "3"],
      missing: [],
      failed: [{ version: "2", error: "429 Too Many Requests" }],
    }));

    const result = await retryPendingBlobDeletions({
      deleteData,
      pendingBlobDeletions: pending,
      logger: makeLogger(),
    });

    expect(result.failed).toEqual([
      { scope: SCOPE, version: "2", error: "429 Too Many Requests" },
    ]);
    expect(await pending.list()).toEqual([{ scope: SCOPE, version: "2" }]);
  });

  it("expands a version-less marker into exact keys from the registry before deleting", async () => {
    const pending = makePending();
    await pending.add([{ scope: SCOPE, version: null }]);
    const deleteData = makeDeleteData();
    const dataPointFeed = feedAnswering(async () => ({
      deletedAt: DELETED_AT,
      expectedVersion: "3",
    }));
    const storage = {
      listVersions: vi.fn(() => [entry({ version: 6, dataPointId: null })]),
    };

    const result = await retryPendingBlobDeletions({
      deleteData,
      pendingBlobDeletions: pending,
      dataPointFeed,
      serverOwner: OWNER,
      storage,
      logger: makeLogger(),
    });

    // Exact local key first, then the registry range head.
    expect(versionsSent(deleteData)).toEqual([["6", "1", "2", "3"]]);
    expect(result.completed).toHaveLength(4);
    expect(await pending.list()).toEqual([]);
  });

  it("drops a version-less marker when the scope is live again (old tombstone version unknowable)", async () => {
    const pending = makePending();
    await pending.add([{ scope: SCOPE, version: null }]);
    const deleteData = makeDeleteData();
    const dataPointFeed = feedAnswering(async () => ({
      deletedAt: null,
      expectedVersion: "6",
    }));
    const logger = makeLogger();

    const result = await retryPendingBlobDeletions({
      deleteData,
      pendingBlobDeletions: pending,
      dataPointFeed,
      serverOwner: OWNER,
      logger,
    });

    expect(result.superseded).toEqual([SCOPE]);
    expect(deleteData.deleteBlobVersions).not.toHaveBeenCalled();
    expect(await pending.list()).toEqual([]);
    expect(logger.warn).toHaveBeenCalledWith(
      expect.objectContaining({ scope: SCOPE, version: "6" }),
      expect.stringContaining("re-added"),
    );
  });

  it("keeps a version-less marker when the registry cannot be read", async () => {
    const pending = makePending();
    await pending.add([{ scope: SCOPE, version: null }]);
    const deleteData = makeDeleteData();
    const dataPointFeed = feedAnswering(async () => {
      throw new Error("gateway down");
    });

    const result = await retryPendingBlobDeletions({
      deleteData,
      pendingBlobDeletions: pending,
      dataPointFeed,
      serverOwner: OWNER,
      logger: makeLogger(),
    });

    expect(result.failed).toEqual([
      { scope: SCOPE, version: null, error: "gateway down" },
    ]);
    expect(deleteData.deleteBlobVersions).not.toHaveBeenCalled();
    expect(await pending.list()).toEqual([{ scope: SCOPE, version: null }]);
  });

  it("is a no-op without a delete port or marker store", async () => {
    const result = await retryPendingBlobDeletions({ logger: makeLogger() });
    expect(result).toEqual({
      completed: [],
      superseded: [],
      failed: [],
      remaining: 0,
    });
  });
});

describe("deleteScope read-side memory", () => {
  function makeTracker() {
    return {
      markDeleted: vi.fn(),
      markLive: vi.fn(),
      noteFeedSynced: vi.fn(),
      knownDeletion: vi.fn(() => null),
      feedAgeMs: vi.fn(() => null),
      resolve: vi.fn(),
      maxStalenessMs: 0,
    };
  }

  it("records the tombstone so this replica's reads refuse the scope at once", async () => {
    const scopeDeletions = makeTracker();
    const deps = makeDeps({ scopeDeletions });

    await deleteScope(deps, SCOPE);

    expect(scopeDeletions.markDeleted).toHaveBeenCalledWith(
      SCOPE,
      { deletedAt: DELETED_AT, version: "4" },
      "local-delete",
    );
  });

  it("falls back to the current time when the gateway echoes no deletedAt", async () => {
    const scopeDeletions = makeTracker();
    const deps = makeDeps({
      scopeDeletions,
      now: () => new Date("2026-08-26T12:00:00.000Z"),
    });
    (deps.deleteData!.tombstone as ReturnType<typeof vi.fn>).mockResolvedValue({
      status: "tombstoned",
      dataPointId: DATA_POINT_ID,
      version: "4",
      deletedAt: null,
    });

    await deleteScope(deps, SCOPE);

    expect(scopeDeletions.markDeleted).toHaveBeenCalledWith(
      SCOPE,
      { deletedAt: "2026-08-26T12:00:00.000Z", version: "4" },
      "local-delete",
    );
  });

  it("records nothing when the tombstone fails or the point was never registered", async () => {
    const failed = makeTracker();
    const failing = makeDeps({ scopeDeletions: failed });
    (
      failing.deleteData!.tombstone as ReturnType<typeof vi.fn>
    ).mockRejectedValue(new Error("Gateway error: 503"));
    await deleteScope(failing, SCOPE);
    expect(failed.markDeleted).not.toHaveBeenCalled();

    const unregistered = makeTracker();
    const never = makeDeps({ scopeDeletions: unregistered });
    (never.deleteData!.tombstone as ReturnType<typeof vi.fn>).mockResolvedValue(
      { status: "not-registered", dataPointId: DATA_POINT_ID },
    );
    await deleteScope(never, SCOPE);
    expect(unregistered.markDeleted).not.toHaveBeenCalled();
  });
});
