import { describe, it, expect, vi, beforeEach } from "vitest";

import type { UploadWorkerDeps } from "../workers/upload.js";
import type { DownloadWorkerDeps } from "../workers/download.js";
import type { DataStoragePort, DeleteDataPort } from "../../ports/index.js";
import type { Logger } from "../../logger/index.js";

vi.mock("../workers/upload.js", () => ({ uploadAll: vi.fn(async () => []) }));
vi.mock("../workers/download.js", () => ({
  downloadAll: vi.fn(async () => []),
  downloadScopes: vi.fn(),
}));
vi.mock("../workers/lost-data-points.js", () => ({
  requeueLostDataPoints: vi.fn(async () => ({ requeued: [], failed: [] })),
}));

import { createSyncManager } from "./sync-manager.js";

const logger = () =>
  ({
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  }) as unknown as Logger;

function rig() {
  const scopes = new Set(["acme.items", "acme.orders"]);
  const storage = {
    findUnsynced: () => [],
    listScopes: () => ({
      total: scopes.size,
      scopes: [...scopes].map((scope) => ({
        scope,
        latestCollectedAt: "2026-11-01T00:00:00.000Z",
        versionCount: 1,
      })),
    }),
    listVersions: (scope: string) =>
      scopes.has(scope)
        ? [
            {
              id: 1,
              fileId: null,
              schemaId: null,
              path: `${scope}/x.json`,
              scope,
              collectedAt: "2026-11-01T00:00:00.000Z",
              createdAt: "2026-11-01T00:00:00.000Z",
              sizeBytes: 1,
              version: 1,
              dataPointId: "0xdp",
            },
          ]
        : [],
    deleteScope: async (scope: string) => (scopes.delete(scope) ? 1 : 0),
    deleteVersion: async (scope: string) => scopes.delete(scope),
  } as unknown as DataStoragePort;
  const tombstone = vi.fn(async () => ({
    status: "tombstoned" as const,
    dataPointId: "0x1",
    version: "2",
    deletedAt: "2026-11-02T00:00:00.000Z",
  }));
  const deleteData: DeleteDataPort = {
    tombstone,
    deleteBlobVersions: async (_s, versions) => ({
      deleted: versions,
      missing: [],
      failed: [],
    }),
  };
  const upload = {
    storage,
    serverOwner: "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12",
    logger: logger(),
  } as unknown as UploadWorkerDeps;
  const download = {
    storage,
    cursor: { read: async () => null, write: async () => {} },
    logger: logger(),
  } as unknown as DownloadWorkerDeps;
  return { scopes, tombstone, deleteData, upload, download };
}

describe("sync manager: retire legacy scopes after the switch", () => {
  beforeEach(() => vi.clearAllMocks());

  it("switch off: a cycle deletes nothing, whatever the views say", async () => {
    const r = rig();
    const manager = createSyncManager(r.upload, r.download, {
      deleteData: r.deleteData,
      retireLegacy: null,
    });
    await manager.trigger();
    expect(r.tombstone).not.toHaveBeenCalled();
    expect(r.scopes.size).toBe(2);
  });

  it("switch on: a cycle deletes the complete scopes and keeps the others", async () => {
    const r = rig();
    const manager = createSyncManager(r.upload, r.download, {
      deleteData: r.deleteData,
      retireLegacy: { viewIsComplete: (s) => s === "acme.items" },
    });
    await manager.trigger();
    expect([...r.scopes]).toEqual(["acme.orders"]);
    expect(r.tombstone).toHaveBeenCalledTimes(1);
  });

  it("switch on but no remote delete port: nothing is deleted locally", async () => {
    const r = rig();
    const manager = createSyncManager(r.upload, r.download, {
      retireLegacy: { viewIsComplete: () => true },
    });
    await manager.trigger();
    expect(r.scopes.size).toBe(2);
  });
});
