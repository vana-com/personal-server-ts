import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

import type { UploadWorkerDeps } from "../workers/upload.js";
import type { DownloadWorkerDeps } from "../workers/download.js";
import type { StorageAdapter } from "../../storage/adapters/interface.js";
import type { GatewayClient } from "@opendatalabs/vana-sdk/browser";
import type { ServerSigner } from "../../signing/signer.js";
import type { SyncCursor } from "../cursor.js";
import type { Logger } from "../../logger/index.js";
import type { DataStoragePort } from "../../ports/index.js";

// Mock workers so we control their behavior
vi.mock("../workers/upload.js", () => ({
  uploadAll: vi.fn(),
}));

vi.mock("../workers/download.js", () => ({
  downloadAll: vi.fn(),
}));

import { uploadAll } from "../workers/upload.js";
import { downloadAll } from "../workers/download.js";
import { createSyncManager } from "./sync-manager.js";

function makeMockLogger(): Logger {
  return {
    info: vi.fn(),
    error: vi.fn(),
    warn: vi.fn(),
    debug: vi.fn(),
    trace: vi.fn(),
    fatal: vi.fn(),
  } as unknown as Logger;
}

function makeMockUploadDeps(): UploadWorkerDeps {
  const mockStorage: Partial<DataStoragePort> = {
    findUnsynced: vi.fn().mockReturnValue([]),
    updateFileId: vi.fn().mockReturnValue(true),
  };

  return {
    storage: mockStorage as DataStoragePort,
    storageAdapter: {} as StorageAdapter,
    gateway: {} as GatewayClient,
    signer: {} as ServerSigner,
    masterKey: new Uint8Array(65).fill(0xaa),
    serverOwner: "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12",
    logger: makeMockLogger(),
  };
}

function makeMockDownloadDeps(): DownloadWorkerDeps {
  const mockCursor: SyncCursor = {
    read: vi.fn().mockResolvedValue(null),
    write: vi.fn().mockResolvedValue(undefined),
  };

  return {
    storage: {} as DataStoragePort,
    storageAdapter: {} as StorageAdapter,
    gateway: {} as GatewayClient,
    cursor: mockCursor,
    masterKey: new Uint8Array(65).fill(0xaa),
    serverOwner: "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12",
    logger: makeMockLogger(),
  };
}

describe("SyncManager", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
    (uploadAll as ReturnType<typeof vi.fn>).mockResolvedValue([]);
    (downloadAll as ReturnType<typeof vi.fn>).mockResolvedValue([]);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("start() triggers an immediate sync cycle", async () => {
    const uploadDeps = makeMockUploadDeps();
    const downloadDeps = makeMockDownloadDeps();
    const manager = createSyncManager(uploadDeps, downloadDeps, {
      pollInterval: 60_000,
    });

    manager.start();

    // Flush microtasks to let the immediate cycle complete
    await vi.advanceTimersByTimeAsync(0);

    expect(uploadAll).toHaveBeenCalledTimes(1);
    expect(downloadAll).toHaveBeenCalledTimes(1);

    await manager.stop();
  });

  it("stop() prevents further cycles", async () => {
    const uploadDeps = makeMockUploadDeps();
    const downloadDeps = makeMockDownloadDeps();
    const manager = createSyncManager(uploadDeps, downloadDeps, {
      pollInterval: 10_000,
    });

    manager.start();

    // Flush the immediate cycle
    await vi.advanceTimersByTimeAsync(0);
    expect(uploadAll).toHaveBeenCalledTimes(1);

    await manager.stop();

    // Advance past multiple intervals — should NOT trigger another cycle
    await vi.advanceTimersByTimeAsync(50_000);

    expect(uploadAll).toHaveBeenCalledTimes(1);
    expect(manager.running).toBe(false);
  });

  it("trigger() runs a cycle immediately", async () => {
    const uploadDeps = makeMockUploadDeps();
    const downloadDeps = makeMockDownloadDeps();
    const manager = createSyncManager(uploadDeps, downloadDeps, {
      pollInterval: 60_000,
    });

    await manager.trigger();

    expect(uploadAll).toHaveBeenCalledTimes(1);
    expect(downloadAll).toHaveBeenCalledTimes(1);
  });

  it("skips sync cycles when runtime registration blocks sync", async () => {
    const uploadDeps = makeMockUploadDeps();
    const downloadDeps = makeMockDownloadDeps();
    const manager = createSyncManager(uploadDeps, downloadDeps, {
      canSync: () => ({
        ok: false,
        reason: "unregistered",
        message: "Register this Personal Server before syncing.",
      }),
    });

    await manager.trigger();

    expect(uploadAll).not.toHaveBeenCalled();
    expect(downloadAll).not.toHaveBeenCalled();
    expect(manager.getStatus()).toMatchObject({
      blocked: {
        reason: "unregistered",
        message: "Register this Personal Server before syncing.",
      },
    });
  });

  it("notifyNewData() schedules a debounced sync cycle while running", async () => {
    const uploadDeps = makeMockUploadDeps();
    const downloadDeps = makeMockDownloadDeps();
    const manager = createSyncManager(uploadDeps, downloadDeps, {
      pollInterval: 60_000,
      notifyDebounceMs: 500,
    });

    manager.start();
    await vi.advanceTimersByTimeAsync(0);
    vi.clearAllMocks();

    manager.notifyNewData();
    manager.notifyNewData();

    await vi.advanceTimersByTimeAsync(499);
    expect(uploadAll).not.toHaveBeenCalled();
    expect(downloadAll).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1);

    expect(uploadAll).toHaveBeenCalledTimes(1);
    expect(downloadAll).toHaveBeenCalledTimes(1);

    await manager.stop();
  });

  it("notifyNewData() does not sync while stopped", async () => {
    const uploadDeps = makeMockUploadDeps();
    const downloadDeps = makeMockDownloadDeps();
    const manager = createSyncManager(uploadDeps, downloadDeps, {
      pollInterval: 60_000,
      notifyDebounceMs: 500,
    });

    manager.notifyNewData();
    await vi.advanceTimersByTimeAsync(500);

    expect(uploadAll).not.toHaveBeenCalled();
    expect(downloadAll).not.toHaveBeenCalled();
  });

  it("getStatus() returns correct pending count", () => {
    const uploadDeps = makeMockUploadDeps();
    const downloadDeps = makeMockDownloadDeps();

    // Mock findUnsynced to return 3 pending entries
    (
      uploadDeps.storage.findUnsynced as ReturnType<typeof vi.fn>
    ).mockReturnValue([
      { id: 1, path: "a.json" },
      { id: 2, path: "b.json" },
      { id: 3, path: "c.json" },
    ]);

    const manager = createSyncManager(uploadDeps, downloadDeps);
    const status = manager.getStatus();

    expect(status.pendingFiles).toBe(3);
    expect(status.enabled).toBe(true);
    expect(status.running).toBe(false);
    expect(status.syncing).toBe(false);
    expect(status.lastSync).toBeNull();
    expect(status.errors).toEqual([]);
  });

  it("getStatus() separates lifecycle from active sync cycle", async () => {
    const uploadDeps = makeMockUploadDeps();
    const downloadDeps = makeMockDownloadDeps();
    const manager = createSyncManager(uploadDeps, downloadDeps, {
      pollInterval: 60_000,
    });

    expect(manager.running).toBe(false);
    expect(manager.getStatus().running).toBe(false);
    expect(manager.getStatus().syncing).toBe(false);

    manager.start();
    expect(manager.running).toBe(true);
    expect(manager.getStatus().running).toBe(true);
    expect(manager.getStatus().syncing).toBe(true);

    // Flush the immediate cycle
    await vi.advanceTimersByTimeAsync(0);
    expect(manager.getStatus().syncing).toBe(false);

    await manager.stop();
    expect(manager.running).toBe(false);
    expect(manager.getStatus().running).toBe(false);
    expect(manager.getStatus().syncing).toBe(false);
  });

  it("upload errors are captured in getStatus().errors", async () => {
    const uploadDeps = makeMockUploadDeps();
    const downloadDeps = makeMockDownloadDeps();

    (uploadAll as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      new Error("Storage unavailable"),
    );

    const manager = createSyncManager(uploadDeps, downloadDeps);

    await manager.trigger();

    const status = manager.getStatus();
    expect(status.errors).toHaveLength(1);
    expect(status.errors[0].message).toContain("Storage unavailable");
    expect(status.errors[0].fileId).toBeNull();
    expect(status.errors[0].timestamp).toBeTruthy();
  });

  it("crash recovery: unsynced entries from previous session are uploaded", async () => {
    const uploadDeps = makeMockUploadDeps();
    const downloadDeps = makeMockDownloadDeps();

    (uploadAll as ReturnType<typeof vi.fn>).mockResolvedValue([
      { path: "leftover.json", fileId: "file-001", url: "https://example.com" },
    ]);

    const manager = createSyncManager(uploadDeps, downloadDeps, {
      pollInterval: 60_000,
    });

    manager.start();

    // Flush the immediate cycle (crash recovery)
    await vi.advanceTimersByTimeAsync(0);

    expect(uploadAll).toHaveBeenCalledTimes(1);

    await manager.stop();
  });

  it("multiple start() calls are idempotent (no duplicate intervals)", async () => {
    const uploadDeps = makeMockUploadDeps();
    const downloadDeps = makeMockDownloadDeps();
    const manager = createSyncManager(uploadDeps, downloadDeps, {
      pollInterval: 10_000,
    });

    manager.start();
    manager.start(); // no-op
    manager.start(); // no-op

    // Flush the immediate cycle
    await vi.advanceTimersByTimeAsync(0);

    // Only one initial cycle should have run
    expect(uploadAll).toHaveBeenCalledTimes(1);

    // Advance by one interval period
    await vi.advanceTimersByTimeAsync(10_000);

    // Should have one more cycle from the single interval
    expect(uploadAll).toHaveBeenCalledTimes(2);

    await manager.stop();
  });

  describe("durable delete", () => {
    function makeDeleteData() {
      return {
        tombstone: vi.fn(async () => ({
          status: "tombstoned" as const,
          dataPointId: "0xdp",
          version: "2",
          deletedAt: "2026-08-25T10:00:00.000Z",
        })),
        deleteBlobs: vi.fn(async () => ({ blobsDeleted: 1 })),
      };
    }

    function makePending(initial: string[] = []) {
      const scopes = [...initial];
      return {
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

    it("deleteScope() runs tombstone -> blobs -> local through the wired ports", async () => {
      const uploadDeps = makeMockUploadDeps();
      uploadDeps.storage.deleteScope = vi.fn(async () => 2);
      const deleteData = makeDeleteData();
      const manager = createSyncManager(uploadDeps, makeMockDownloadDeps(), {
        deleteData,
        pendingBlobDeletions: makePending(),
      });

      const result = await manager.deleteScope("instagram.profile");

      expect(deleteData.tombstone).toHaveBeenCalledWith("instagram.profile");
      expect(deleteData.deleteBlobs).toHaveBeenCalledWith("instagram.profile");
      expect(uploadDeps.storage.deleteScope).toHaveBeenCalledWith(
        "instagram.profile",
      );
      expect(result.durable).toBe(true);
      expect(result.steps.local).toEqual({ status: "ok", deletedCount: 2 });
    });

    it("deleteScope() is local-only when no delete port is wired", async () => {
      const uploadDeps = makeMockUploadDeps();
      uploadDeps.storage.deleteScope = vi.fn(async () => 1);
      const manager = createSyncManager(uploadDeps, makeMockDownloadDeps());

      const result = await manager.deleteScope("instagram.profile");

      expect(result.durable).toBe(false);
      expect(result.steps.gateway).toEqual({
        status: "skipped",
        reason: "sync-disabled",
      });
    });

    it("retries pending blob deletions at the start of every cycle", async () => {
      const deleteData = makeDeleteData();
      const pending = makePending(["chatgpt.conversations"]);
      const manager = createSyncManager(
        makeMockUploadDeps(),
        makeMockDownloadDeps(),
        { deleteData, pendingBlobDeletions: pending },
      );

      await manager.trigger();

      expect(deleteData.deleteBlobs).toHaveBeenCalledWith(
        "chatgpt.conversations",
      );
      expect(pending.remove).toHaveBeenCalledWith("chatgpt.conversations");
      expect(uploadAll).toHaveBeenCalledTimes(1);
      // The upload worker shares the marker store for its own guarded cleanup.
      expect(uploadAll).toHaveBeenCalledWith(
        expect.objectContaining({ pendingBlobDeletions: pending }),
        expect.anything(),
      );
    });

    it("hands the retry the deletion-aware feed so a re-added scope is not wiped", async () => {
      const deleteData = makeDeleteData();
      const pending = makePending(["chatgpt.conversations"]);
      const getDataPoint = vi.fn(async () => ({
        id: "0xdp",
        ownerAddress: "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12",
        scope: "chatgpt.conversations",
        dataHash: "0x" + "11".repeat(32),
        metadataHash: "0x" + "22".repeat(32),
        expectedVersion: "3",
        addedAt: "2026-08-25T11:00:00.000Z",
        deletedAt: null,
      }));
      const downloadDeps = makeMockDownloadDeps();
      downloadDeps.dataPointFeed = {
        getDataPoint,
        listDataPointsByOwner: vi.fn(),
      };
      const manager = createSyncManager(makeMockUploadDeps(), downloadDeps, {
        deleteData,
        pendingBlobDeletions: pending,
      });

      await manager.trigger();

      expect(getDataPoint).toHaveBeenCalledWith({
        ownerAddress: "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12",
        scope: "chatgpt.conversations",
      });
      expect(deleteData.deleteBlobs).not.toHaveBeenCalled();
      expect(pending.remove).toHaveBeenCalledWith("chatgpt.conversations");
    });

    it("does not start a delete while a sync cycle is mid-upload", async () => {
      const uploadDeps = makeMockUploadDeps();
      uploadDeps.storage.deleteScope = vi.fn(async () => 1);
      const deleteData = makeDeleteData();
      let releaseUpload!: () => void;
      const uploadStarted = new Promise<void>((started) => {
        (uploadAll as ReturnType<typeof vi.fn>).mockImplementationOnce(() => {
          started();
          return new Promise<never[]>((resolve) => {
            releaseUpload = () => resolve([]);
          });
        });
      });
      const manager = createSyncManager(uploadDeps, makeMockDownloadDeps(), {
        deleteData,
      });

      const cycle = manager.trigger();
      await uploadStarted;
      expect(uploadAll).toHaveBeenCalledTimes(1);

      const deletion = manager.deleteScope("instagram.profile");
      // Let any eagerly-scheduled work run: the delete must still be queued.
      for (let i = 0; i < 5; i += 1) await Promise.resolve();
      expect(deleteData.tombstone).not.toHaveBeenCalled();

      releaseUpload();
      await cycle;
      const result = await deletion;

      expect(deleteData.tombstone).toHaveBeenCalledWith("instagram.profile");
      expect(result.durable).toBe(true);
    });

    it("does not start a sync cycle while a delete is in flight", async () => {
      const uploadDeps = makeMockUploadDeps();
      uploadDeps.storage.deleteScope = vi.fn(async () => 1);
      let releaseTombstone!: () => void;
      const deleteData = makeDeleteData();
      const tombstoneStarted = new Promise<void>((started) => {
        deleteData.tombstone.mockImplementationOnce(() => {
          started();
          return new Promise((resolve) => {
            releaseTombstone = () =>
              resolve({
                status: "tombstoned" as const,
                dataPointId: "0xdp",
                version: "2",
                deletedAt: "2026-08-25T10:00:00.000Z",
              });
          });
        });
      });
      const manager = createSyncManager(uploadDeps, makeMockDownloadDeps(), {
        deleteData,
      });

      const deletion = manager.deleteScope("instagram.profile");
      await tombstoneStarted;
      const cycle = manager.trigger();
      for (let i = 0; i < 5; i += 1) await Promise.resolve();
      expect(uploadAll).not.toHaveBeenCalled();

      releaseTombstone();
      await deletion;
      await cycle;

      expect(uploadAll).toHaveBeenCalledTimes(1);
      // The local delete finished before the cycle's upload began.
      const deleteOrder = (
        uploadDeps.storage.deleteScope as ReturnType<typeof vi.fn>
      ).mock.invocationCallOrder[0];
      const uploadOrder = (uploadAll as ReturnType<typeof vi.fn>).mock
        .invocationCallOrder[0];
      expect(deleteOrder).toBeLessThan(uploadOrder);
    });

    it("a failed delete does not block the next cycle", async () => {
      const uploadDeps = makeMockUploadDeps();
      uploadDeps.storage.deleteScope = vi.fn(async () => {
        throw new Error("index locked");
      });
      const deleteData = makeDeleteData();
      const manager = createSyncManager(uploadDeps, makeMockDownloadDeps(), {
        deleteData,
      });

      const result = await manager.deleteScope("instagram.profile");
      expect(result.steps.local.status).toBe("failed");

      await manager.trigger();
      expect(uploadAll).toHaveBeenCalledTimes(1);
    });
  });
});
