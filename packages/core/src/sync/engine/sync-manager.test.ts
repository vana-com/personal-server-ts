import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

import type { UploadWorkerDeps } from "../workers/upload.js";
import type { DownloadWorkerDeps } from "../workers/download.js";
import type { StorageAdapter } from "../../storage/adapters/interface.js";
import type { GatewayClient } from "@opendatalabs/vana-sdk/browser";
import type { ServerSigner } from "../../signing/signer.js";
import type { SyncCursor } from "../cursor.js";
import type { Logger } from "../../logger/index.js";
import type {
  DataStoragePort,
  PendingBlobDeletion,
} from "../../ports/index.js";
import { createMemoryPendingBlobDeletionStore } from "../pending-blob-deletions.js";

// Mock workers so we control their behavior
vi.mock("../workers/upload.js", () => ({
  uploadAll: vi.fn(),
}));

vi.mock("../workers/download.js", () => ({
  downloadAll: vi.fn(),
  downloadScopes: vi.fn(),
}));

vi.mock("../workers/lost-data-points.js", () => ({
  requeueLostDataPoints: vi.fn(async () => ({ requeued: [], failed: [] })),
}));

import { uploadAll } from "../workers/upload.js";
import { downloadAll, downloadScopes } from "../workers/download.js";
import { requeueLostDataPoints } from "../workers/lost-data-points.js";
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
    (downloadScopes as ReturnType<typeof vi.fn>).mockResolvedValue([]);
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

  it("publishes boot hydration before the full download cycle resolves", async () => {
    let releaseFullDownload!: () => void;
    const fullDownload = new Promise<never[]>((resolve) => {
      releaseFullDownload = () => resolve([]);
    });
    (downloadAll as ReturnType<typeof vi.fn>).mockReturnValue(fullDownload);
    const manager = createSyncManager(
      makeMockUploadDeps(),
      makeMockDownloadDeps(),
      {
        hydrateScopes: ["chatgpt.conversations"],
        transferMode: "download-only",
      },
    );

    manager.start();
    await vi.waitFor(() => expect(downloadAll).toHaveBeenCalledOnce());

    expect(downloadScopes).toHaveBeenCalledWith(
      expect.anything(),
      ["chatgpt.conversations"],
      { retryMemory: expect.anything() },
    );
    expect(manager.getStatus()).toMatchObject({
      syncing: true,
      hydratedScopes: ["chatgpt.conversations"],
      lastSync: null,
    });

    releaseFullDownload();
    await manager.stop();
  });

  it("keeps full-cycle startup behavior when no hydration scopes are set", async () => {
    const manager = createSyncManager(
      makeMockUploadDeps(),
      makeMockDownloadDeps(),
      { transferMode: "download-only" },
    );

    manager.start();
    await vi.advanceTimersByTimeAsync(0);

    expect(downloadScopes).not.toHaveBeenCalled();
    expect(downloadAll).toHaveBeenCalledOnce();
    expect(manager.getStatus().hydratedScopes).toEqual([]);
    await manager.stop();
  });

  it("falls back to the full cycle when boot hydration fails", async () => {
    const downloadDeps = makeMockDownloadDeps();
    (downloadScopes as ReturnType<typeof vi.fn>).mockRejectedValue(
      new Error("gateway unavailable"),
    );
    const manager = createSyncManager(makeMockUploadDeps(), downloadDeps, {
      hydrateScopes: ["chatgpt.conversations"],
      transferMode: "download-only",
    });

    await manager.trigger();

    expect(downloadAll).toHaveBeenCalledOnce();
    expect(manager.getStatus()).toMatchObject({
      hydratedScopes: [],
      errors: [],
    });
    expect(downloadDeps.logger.warn).toHaveBeenCalledWith(
      { error: "gateway unavailable" },
      "Scope hydration failed; continuing with full sync",
    );
  });

  it("runs download-only cycles when uploads are disabled", async () => {
    const manager = createSyncManager(
      makeMockUploadDeps(),
      makeMockDownloadDeps(),
      { transferMode: "download-only" },
    );

    manager.start();
    await vi.advanceTimersByTimeAsync(0);

    expect(uploadAll).not.toHaveBeenCalled();
    expect(downloadAll).toHaveBeenCalledTimes(1);
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

  it("checks for lost data points once per boot, then retries only failed scopes, a bounded number of times", async () => {
    const check = vi.mocked(requeueLostDataPoints);
    check.mockReset();
    check
      .mockResolvedValueOnce({ requeued: [], failed: ["a.scope"] })
      .mockResolvedValue({ requeued: [], failed: ["a.scope"] });
    const manager = createSyncManager(
      makeMockUploadDeps(),
      makeMockDownloadDeps(),
      {
        pollInterval: 60_000,
      },
    );

    for (let i = 0; i < 8; i += 1) await manager.trigger();

    expect(check).toHaveBeenCalledTimes(5);
    expect(check.mock.calls[0]?.[1]).toBeUndefined();
    expect(check.mock.calls[1]?.[1]).toEqual(["a.scope"]);
  });

  it("stops checking after a clean full pass", async () => {
    const check = vi.mocked(requeueLostDataPoints);
    check.mockReset();
    check.mockResolvedValue({ requeued: ["x"], failed: [] });
    const manager = createSyncManager(
      makeMockUploadDeps(),
      makeMockDownloadDeps(),
      {
        pollInterval: 60_000,
      },
    );

    for (let i = 0; i < 3; i += 1) await manager.trigger();

    expect(check).toHaveBeenCalledTimes(1);
  });

  it("skips sync cycles when runtime registration blocks sync", async () => {
    const uploadDeps = makeMockUploadDeps();
    const downloadDeps = makeMockDownloadDeps();
    const manager = createSyncManager(uploadDeps, downloadDeps, {
      hydrateScopes: ["chatgpt.conversations"],
      canSync: () => ({
        ok: false,
        reason: "unregistered",
        message: "Register this Personal Server before syncing.",
      }),
    });

    await manager.trigger();

    expect(uploadAll).not.toHaveBeenCalled();
    expect(downloadScopes).not.toHaveBeenCalled();
    expect(downloadAll).not.toHaveBeenCalled();
    expect(manager.getStatus()).toMatchObject({
      blocked: {
        reason: "unregistered",
        message: "Register this Personal Server before syncing.",
      },
    });
  });

  it("keeps explicit hydration behind the runtime sync gate", async () => {
    const downloadDeps = makeMockDownloadDeps();
    const manager = createSyncManager(makeMockUploadDeps(), downloadDeps, {
      canSync: () => ({
        ok: false,
        reason: "unregistered",
        message: "Register this Personal Server before syncing.",
      }),
    });

    await manager.hydrateScopes(["chatgpt.conversations"]);

    expect(downloadScopes).not.toHaveBeenCalled();
    expect(manager.getStatus()).toMatchObject({
      blocked: {
        reason: "unregistered",
        message: "Register this Personal Server before syncing.",
      },
      hydratedScopes: [],
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
        deleteBlobVersions: vi.fn(
          async (_scope: string, versions: string[]) => ({
            deleted: versions,
            missing: [],
            failed: [],
          }),
        ),
      };
    }

    function makePending(initial: PendingBlobDeletion[] = []) {
      const store = createMemoryPendingBlobDeletionStore();
      const ready = store.add(initial);
      return {
        list: vi.fn(async () => {
          await ready;
          return store.list();
        }),
        add: vi.fn(async (keys: PendingBlobDeletion[]) => {
          await ready;
          return store.add(keys);
        }),
        remove: vi.fn(async (keys: PendingBlobDeletion[]) => {
          await ready;
          return store.remove(keys);
        }),
      };
    }

    /** Covered local rows, one per version, as the index lists them. */
    function localRows(versions: number[]) {
      return versions.map((version) => ({
        path: `instagram.profile/v${version}.json`,
        scope: "instagram.profile",
        collectedAt: `2026-08-0${version}T00:00:00.000Z`,
        version,
        dataPointId: "0xdp",
        afterTombstoneVersion: null,
      }));
    }

    /** Per-version local storage: listing reads the live rows, each erase removes its own row. */
    function perVersionStorage(
      storage: Record<string, unknown>,
      rows: ReturnType<typeof localRows>,
    ) {
      storage.listVersions = vi.fn(() => rows);
      storage.deleteVersion = vi.fn(
        async (_scope: string, collectedAt: string) => {
          const at = rows.findIndex((row) => row.collectedAt === collectedAt);
          if (at < 0) return false;
          rows.splice(at, 1);
          return true;
        },
      );
    }

    it("deleteScope() runs tombstone -> blobs -> local through the wired ports", async () => {
      const uploadDeps = makeMockUploadDeps();
      perVersionStorage(uploadDeps.storage, localRows([1, 2]));
      const deleteData = makeDeleteData();
      const manager = createSyncManager(uploadDeps, makeMockDownloadDeps(), {
        deleteData,
        pendingBlobDeletions: makePending(),
      });

      const result = await manager.deleteScope("instagram.profile");

      expect(deleteData.tombstone).toHaveBeenCalledWith("instagram.profile");
      expect(deleteData.deleteBlobVersions).toHaveBeenCalledWith(
        "instagram.profile",
        ["1", "2"],
      );
      expect(uploadDeps.storage.deleteVersion).toHaveBeenCalledTimes(2);
      expect(uploadDeps.storage.deleteVersion).toHaveBeenCalledWith(
        "instagram.profile",
        "2026-08-01T00:00:00.000Z",
        expect.objectContaining({ path: "instagram.profile/v1.json" }),
      );
      expect(uploadDeps.storage.deleteVersion).toHaveBeenCalledWith(
        "instagram.profile",
        "2026-08-02T00:00:00.000Z",
        expect.objectContaining({ path: "instagram.profile/v2.json" }),
      );
      expect(result.durable).toBe(true);
      expect(result.steps.local).toEqual({ status: "ok", deletedCount: 2 });
    });

    it("deleteScope() is local-only when no delete port is wired", async () => {
      const uploadDeps = makeMockUploadDeps();
      uploadDeps.storage.deleteScope = vi.fn(async () => 1);
      uploadDeps.storage.listVersions = vi.fn(() => []);
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
      const pending = makePending([
        { scope: "chatgpt.conversations", version: "3" },
      ]);
      const manager = createSyncManager(
        makeMockUploadDeps(),
        makeMockDownloadDeps(),
        { deleteData, pendingBlobDeletions: pending },
      );

      await manager.trigger();

      expect(deleteData.deleteBlobVersions).toHaveBeenCalledWith(
        "chatgpt.conversations",
        ["3"],
      );
      expect(pending.remove).toHaveBeenCalledWith([
        { scope: "chatgpt.conversations", version: "3" },
      ]);
      expect(uploadAll).toHaveBeenCalledTimes(1);
      // The upload worker shares the marker store for its own guarded cleanup.
      expect(uploadAll).toHaveBeenCalledWith(
        expect.objectContaining({ pendingBlobDeletions: pending }),
        expect.anything(),
      );
    });

    it("hands the retry the deletion-aware feed so an unexpanded marker of a re-added scope is dropped", async () => {
      const deleteData = makeDeleteData();
      const pending = makePending([
        { scope: "chatgpt.conversations", version: null },
      ]);
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
      expect(deleteData.deleteBlobVersions).not.toHaveBeenCalled();
      expect(pending.remove).toHaveBeenCalledWith([
        { scope: "chatgpt.conversations", version: null },
      ]);
    });

    it("re-submits a rolled-back delete inside the cycle, then reports it in status once the attempts run out", async () => {
      const uploadDeps = makeMockUploadDeps();
      uploadDeps.storage.listVersions = vi.fn(() => []);
      uploadDeps.storage.deleteScope = vi.fn(async () => 0);
      const deleteData = makeDeleteData();
      // Every tombstone fails: the registry always reports the rollback.
      const tombstoneFinality = {
        tombstoneState: vi.fn(async () => ({
          finalized: null,
          settling: false,
          rolledBack: "2",
        })),
        recheckNow: vi.fn(),
      };
      // The additions ledger is deleted through the manager's own queue, as
      // bootstrap wires it; awaiting that inside the cycle would deadlock.
      const additionsDeleteScope = vi.fn(async (scope: string) => {
        if (scope.startsWith("vana.system.")) return;
        await manager.deleteScope(`vana.system.additions.${scope}`);
      });
      uploadDeps.additions = {
        deleteScope: additionsDeleteScope,
      } as unknown as UploadWorkerDeps["additions"];
      const manager = createSyncManager(uploadDeps, makeMockDownloadDeps(), {
        deleteData,
        pendingBlobDeletions: makePending(),
        tombstoneFinality,
      });

      await manager.deleteScope("instagram.profile");
      expect(deleteData.tombstone).toHaveBeenCalledTimes(2); // scope + ledger
      expect(manager.getStatus().deletions).toEqual({
        retrying: [],
        failed: [],
      });

      await manager.trigger();
      await vi.advanceTimersByTimeAsync(0);
      // Both queued scopes were re-submitted inside the cycle, and the source
      // scope's additions ledger was deleted again after it (no deadlock).
      expect(deleteData.tombstone).toHaveBeenCalledTimes(5);
      expect(additionsDeleteScope).toHaveBeenCalledWith("instagram.profile");
      expect(manager.getStatus().deletions?.retrying).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ scope: "instagram.profile", attempts: 1 }),
        ]),
      );

      for (let cycle = 0; cycle < 40; cycle++) {
        vi.setSystemTime(Date.now() + 10 * 60_000);
        await manager.trigger();
        await vi.advanceTimersByTimeAsync(0);
      }

      const status = manager.getStatus();
      expect(status.deletions?.failed).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ scope: "instagram.profile", attempts: 5 }),
        ]),
      );
      expect(status.errors).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            scope: "instagram.profile",
            message: expect.stringContaining("did not complete"),
          }),
        ]),
      );

      // The user deletes again: a fresh set of attempts.
      await manager.deleteScope("instagram.profile");
      expect(
        manager
          .getStatus()
          .deletions?.failed.some((s) => s.scope === "instagram.profile"),
      ).toBe(false);
    });

    it("does not start a delete while a sync cycle is mid-upload", async () => {
      const uploadDeps = makeMockUploadDeps();
      uploadDeps.storage.deleteScope = vi.fn(async () => 1);
      uploadDeps.storage.listVersions = vi.fn(() => []);
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
      perVersionStorage(uploadDeps.storage, localRows([1]));
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
        uploadDeps.storage.deleteVersion as ReturnType<typeof vi.fn>
      ).mock.invocationCallOrder[0];
      const uploadOrder = (uploadAll as ReturnType<typeof vi.fn>).mock
        .invocationCallOrder[0];
      expect(deleteOrder).toBeLessThan(uploadOrder);
    });

    it("a failed delete does not block the next cycle", async () => {
      const uploadDeps = makeMockUploadDeps();
      perVersionStorage(uploadDeps.storage, localRows([1]));
      uploadDeps.storage.deleteVersion = vi.fn(async () => {
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
