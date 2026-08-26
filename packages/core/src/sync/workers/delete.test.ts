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
      failed: [{ scope: "c.d", error: "still down" }],
    });
    expect(await pending.list()).toEqual(["c.d"]);
  });

  it("is a no-op without a delete port or marker store", async () => {
    const result = await retryPendingBlobDeletions({ logger: makeLogger() });
    expect(result).toEqual({ completed: [], failed: [] });
  });
});
