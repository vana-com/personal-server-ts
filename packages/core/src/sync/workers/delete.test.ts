import { describe, it, expect, vi } from "vitest";

import type { DeleteScopeDeps } from "./delete.js";
import { deleteScope, retryPendingBlobDeletions } from "./delete.js";
import { computeDataPointId } from "../data-point-id.js";
import type { Logger } from "../../logger/index.js";
import type {
  DataStoragePort,
  DeleteDataPort,
  PendingBlobDeletionStore,
} from "../../ports/index.js";

const SCOPE = "instagram.profile";
const OWNER = "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12";
const DATA_POINT_ID = computeDataPointId(OWNER, SCOPE);

function makeLogger(): Logger {
  return {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  } as unknown as Logger;
}

function makeDeleteData(overrides?: Partial<DeleteDataPort>): DeleteDataPort {
  return {
    tombstone: vi.fn(async () => ({
      status: "tombstoned" as const,
      dataPointId: DATA_POINT_ID,
      version: "4",
      deletedAt: "2026-08-25T10:00:00.000Z",
    })),
    deleteBlobs: vi.fn(async () => ({ blobsDeleted: 3 })),
    ...overrides,
  };
}

function makePending(): PendingBlobDeletionStore & { scopes: string[] } {
  const scopes: string[] = [];
  return {
    scopes,
    list: vi.fn(async () => [...scopes]),
    add: vi.fn(async (scope: string) => {
      if (!scopes.includes(scope)) scopes.push(scope);
    }),
    remove: vi.fn(async (scope: string) => {
      const i = scopes.indexOf(scope);
      if (i >= 0) scopes.splice(i, 1);
    }),
  };
}

function makeDeps(overrides?: Partial<DeleteScopeDeps>): DeleteScopeDeps & {
  calls: string[];
} {
  const calls: string[] = [];
  const deleteData = makeDeleteData();
  (deleteData.tombstone as ReturnType<typeof vi.fn>).mockImplementation(
    async () => {
      calls.push("gateway");
      return {
        status: "tombstoned",
        dataPointId: DATA_POINT_ID,
        version: "4",
        deletedAt: "2026-08-25T10:00:00.000Z",
      };
    },
  );
  (deleteData.deleteBlobs as ReturnType<typeof vi.fn>).mockImplementation(
    async () => {
      calls.push("storage");
      return { blobsDeleted: 3 };
    },
  );
  const storage: Partial<DataStoragePort> = {
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
    ...overrides,
  };
}

describe("deleteScope orchestration", () => {
  it("runs gateway tombstone, then storage blobs, then local delete", async () => {
    const deps = makeDeps();

    const result = await deleteScope(deps, SCOPE);

    expect(deps.calls).toEqual(["gateway", "storage", "local"]);
    expect(result).toEqual({
      scope: SCOPE,
      dataPointId: DATA_POINT_ID,
      durable: true,
      steps: {
        gateway: {
          status: "ok",
          version: "4",
          deletedAt: "2026-08-25T10:00:00.000Z",
        },
        storage: { status: "ok", blobsDeleted: 3 },
        local: { status: "ok", deletedCount: 2 },
      },
      pendingBlobDeletion: false,
    });
  });

  it("never touches storage or the local copy when the gateway tombstone fails", async () => {
    const deps = makeDeps();
    (deps.deleteData!.tombstone as ReturnType<typeof vi.fn>).mockRejectedValue(
      new Error("Gateway error: 503 Service Unavailable"),
    );

    const result = await deleteScope(deps, SCOPE);

    expect(deps.deleteData!.deleteBlobs).not.toHaveBeenCalled();
    expect(deps.storage.deleteScope).not.toHaveBeenCalled();
    expect(result.durable).toBe(false);
    expect(result.steps.gateway).toEqual({
      status: "failed",
      error: "Gateway error: 503 Service Unavailable",
    });
    expect(result.steps.storage).toEqual({
      status: "skipped",
      reason: "gateway-failed",
    });
    expect(result.steps.local).toEqual({
      status: "skipped",
      reason: "gateway-failed",
    });
  });

  it("reports a storage failure after a gateway success, still deletes locally, and leaves a retry marker", async () => {
    const deps = makeDeps();
    (
      deps.deleteData!.deleteBlobs as ReturnType<typeof vi.fn>
    ).mockRejectedValue(new Error("vana-storage delete failed: 502"));

    const result = await deleteScope(deps, SCOPE);

    expect(result.durable).toBe(true);
    expect(result.steps.gateway.status).toBe("ok");
    expect(result.steps.storage).toEqual({
      status: "failed",
      error: "vana-storage delete failed: 502",
    });
    expect(result.steps.local).toEqual({ status: "ok", deletedCount: 2 });
    expect(result.pendingBlobDeletion).toBe(true);
    expect(deps.pendingBlobDeletions!.add).toHaveBeenCalledWith(SCOPE);
    expect(await deps.pendingBlobDeletions!.list()).toEqual([SCOPE]);
  });

  it("clears a stale retry marker once storage acknowledges", async () => {
    const deps = makeDeps();
    await deps.pendingBlobDeletions!.add(SCOPE);

    await deleteScope(deps, SCOPE);

    expect(deps.pendingBlobDeletions!.remove).toHaveBeenCalledWith(SCOPE);
    expect(await deps.pendingBlobDeletions!.list()).toEqual([]);
  });

  it("treats a never-registered scope as durable and still clears blobs + local", async () => {
    const deps = makeDeps();
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
    expect(deps.deleteData!.deleteBlobs).toHaveBeenCalledWith(SCOPE);
    expect(deps.storage.deleteScope).toHaveBeenCalledWith(SCOPE);
  });

  it("marks an already-deleted point as ok with reason already-deleted", async () => {
    const deps = makeDeps();
    (deps.deleteData!.tombstone as ReturnType<typeof vi.fn>).mockResolvedValue({
      status: "already-deleted",
      dataPointId: DATA_POINT_ID,
      version: "4",
      deletedAt: "2026-08-20T00:00:00.000Z",
    });

    const result = await deleteScope(deps, SCOPE);

    expect(result.steps.gateway).toEqual({
      status: "ok",
      reason: "already-deleted",
      version: "4",
      deletedAt: "2026-08-20T00:00:00.000Z",
    });
    expect(result.durable).toBe(true);
  });

  it("is local-only and NOT durable when no remote delete port is wired", async () => {
    const deps = makeDeps({
      deleteData: null,
      pendingBlobDeletions: undefined,
    });

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
    expect(result.steps.local).toEqual({ status: "ok", deletedCount: 2 });
  });

  it("reports a local delete failure without hiding the remote outcome", async () => {
    const deps = makeDeps();
    (deps.storage.deleteScope as ReturnType<typeof vi.fn>).mockRejectedValue(
      new Error("EACCES"),
    );

    const result = await deleteScope(deps, SCOPE);

    expect(result.durable).toBe(true);
    expect(result.steps.gateway.status).toBe("ok");
    expect(result.steps.storage.status).toBe("ok");
    expect(result.steps.local).toEqual({ status: "failed", error: "EACCES" });
  });
});

describe("deleteScope vs a concurrent remote re-add", () => {
  function feedAnswering(
    answer: (scope: string) => Promise<{
      deletedAt: string | null;
      expectedVersion: string;
    } | null>,
  ) {
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

  it("leaves the storage blobs alone when another replica re-added the scope after the tombstone", async () => {
    // Replica B registered version 5 between A's tombstone (4) and A's
    // scope-wide blob delete: the prefix now holds B's live ciphertext.
    const dataPointFeed = feedAnswering(async () => ({
      deletedAt: null,
      expectedVersion: "5",
    }));
    const deps = makeDeps({ dataPointFeed });

    const result = await deleteScope(deps, SCOPE);

    expect(deps.calls).toEqual(["gateway", "local"]);
    expect(deps.deleteData!.deleteBlobs).not.toHaveBeenCalled();
    expect(result.durable).toBe(true);
    expect(result.steps.storage).toEqual({
      status: "skipped",
      reason: "re-added",
    });
    expect(result.pendingBlobDeletion).toBe(false);
    expect(deps.pendingBlobDeletions!.add).not.toHaveBeenCalled();
    expect(deps.logger.warn).toHaveBeenCalledWith(
      expect.objectContaining({ scope: SCOPE, version: "5" }),
      expect.stringContaining("re-added"),
    );
  });

  it("deletes the blobs when the registry still shows the tombstone", async () => {
    const dataPointFeed = feedAnswering(async () => ({
      deletedAt: "2026-08-25T10:00:00.000Z",
      expectedVersion: "4",
    }));
    const deps = makeDeps({ dataPointFeed });

    const result = await deleteScope(deps, SCOPE);

    expect(deps.calls).toEqual(["gateway", "storage", "local"]);
    expect(dataPointFeed.getDataPoint).toHaveBeenCalledTimes(1);
    expect(result.steps.storage).toEqual({ status: "ok", blobsDeleted: 3 });
  });

  it("defers the blob delete to the retry when the re-add check cannot reach the gateway", async () => {
    const dataPointFeed = feedAnswering(async () => {
      throw new Error("gateway down");
    });
    const deps = makeDeps({ dataPointFeed });

    const result = await deleteScope(deps, SCOPE);

    expect(deps.deleteData!.deleteBlobs).not.toHaveBeenCalled();
    expect(result.steps.storage).toEqual({
      status: "failed",
      error: "gateway down",
    });
    expect(result.pendingBlobDeletion).toBe(true);
    expect(await deps.pendingBlobDeletions!.list()).toEqual([SCOPE]);
    // The local copy the tombstone covers still goes.
    expect(result.steps.local).toEqual({ status: "ok", deletedCount: 2 });
  });
});

describe("retryPendingBlobDeletions", () => {
  it("retries each pending scope and clears the marker on success", async () => {
    const pending = makePending();
    await pending.add("a.b");
    await pending.add("c.d");
    const deleteData = makeDeleteData();
    (deleteData.deleteBlobs as ReturnType<typeof vi.fn>)
      .mockResolvedValueOnce({ blobsDeleted: 1 })
      .mockRejectedValueOnce(new Error("still down"));

    const result = await retryPendingBlobDeletions({
      deleteData,
      pendingBlobDeletions: pending,
      logger: makeLogger(),
    });

    expect(result).toEqual({
      completed: ["a.b"],
      superseded: [],
      failed: [{ scope: "c.d", error: "still down" }],
    });
    expect(await pending.list()).toEqual(["c.d"]);
  });

  it("is a no-op without a delete port or marker store", async () => {
    const result = await retryPendingBlobDeletions({ logger: makeLogger() });
    expect(result).toEqual({ completed: [], superseded: [], failed: [] });
  });

  it("drops the marker without deleting when the scope was re-added after its tombstone", async () => {
    const pending = makePending();
    await pending.add(SCOPE);
    await pending.add("still.deleted");
    const deleteData = makeDeleteData();
    const getDataPoint = vi.fn(
      async ({ scope }: { ownerAddress: string; scope: string }) => ({
        id: computeDataPointId(OWNER, scope),
        ownerAddress: OWNER,
        scope,
        dataHash: "0x" + "11".repeat(32),
        metadataHash: "0x" + "22".repeat(32),
        expectedVersion: "6",
        addedAt: "2026-08-25T11:00:00.000Z",
        // The re-added scope is live again; the other is still tombstoned.
        deletedAt: scope === SCOPE ? null : "2026-08-25T10:00:00.000Z",
      }),
    );
    const logger = makeLogger();

    const result = await retryPendingBlobDeletions({
      deleteData,
      pendingBlobDeletions: pending,
      dataPointFeed: { getDataPoint, listDataPointsByOwner: vi.fn() },
      serverOwner: OWNER,
      logger,
    });

    expect(result).toEqual({
      completed: ["still.deleted"],
      superseded: [SCOPE],
      failed: [],
    });
    // The live version's ciphertext under the prefix must survive.
    expect(deleteData.deleteBlobs).toHaveBeenCalledTimes(1);
    expect(deleteData.deleteBlobs).toHaveBeenCalledWith("still.deleted");
    expect(await pending.list()).toEqual([]);
    expect(logger.warn).toHaveBeenCalledWith(
      expect.objectContaining({ scope: SCOPE, version: "6" }),
      expect.stringContaining("re-added"),
    );
  });

  it("still retries when the feed cannot say (lookup error is a failed retry, marker kept)", async () => {
    const pending = makePending();
    await pending.add(SCOPE);
    const deleteData = makeDeleteData();

    const result = await retryPendingBlobDeletions({
      deleteData,
      pendingBlobDeletions: pending,
      dataPointFeed: {
        getDataPoint: vi.fn(async () => {
          throw new Error("gateway down");
        }),
        listDataPointsByOwner: vi.fn(),
      },
      serverOwner: OWNER,
      logger: makeLogger(),
    });

    expect(result.failed).toEqual([{ scope: SCOPE, error: "gateway down" }]);
    expect(deleteData.deleteBlobs).not.toHaveBeenCalled();
    expect(await pending.list()).toEqual([SCOPE]);
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
      "2026-08-25T10:00:00.000Z",
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
      "2026-08-26T12:00:00.000Z",
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
