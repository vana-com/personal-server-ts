// Storage deletes owed after a tombstone, on an account that has switched to
// stream sync.
//
// A blob is deleted only once the tombstone that covers it is final at the
// gateway. Finality is a change to a version row, which moves no registry
// position and sends no wake. A switched pass used to run only the stream-sync
// cycle, so nothing ever finished those deletes. The pass now drains them and
// stays unsettled while any are left, like a backed-off publish.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Logger } from "../../logger/index.js";
import type {
  PendingBlobDeletion,
  TombstoneFinalityState,
} from "../../ports/index.js";
import type { DownloadWorkerDeps } from "../workers/download.js";
import type { UploadWorkerDeps } from "../workers/upload.js";
import { createMemoryPendingBlobDeletionStore } from "../pending-blob-deletions.js";
import {
  createSyncManager,
  type ChangePush,
  type SyncManagerOptions,
} from "./sync-manager.js";

const logger = {
  info: vi.fn(),
  error: vi.fn(),
  warn: vi.fn(),
  debug: vi.fn(),
  trace: vi.fn(),
  fatal: vi.fn(),
} as unknown as Logger;

const MARKER: PendingBlobDeletion = {
  scope: "chatgpt.conversations",
  version: "3",
};
const PENDING: TombstoneFinalityState = {
  finalized: null,
  settling: true,
  rolledBack: null,
};
const FINAL: TombstoneFinalityState = {
  finalized: "3",
  settling: false,
  rolledBack: null,
};

beforeEach(() => {
  vi.useFakeTimers();
});
afterEach(() => {
  vi.useRealTimers();
});

function setup(
  options: {
    finality?: TombstoneFinalityState;
    withFinality?: boolean;
    withDeleteData?: boolean;
  } = {},
) {
  let finality = options.finality ?? PENDING;
  const store = createMemoryPendingBlobDeletionStore();
  const ready = store.add([MARKER]);
  const pending = {
    list: vi.fn(async () => {
      await ready;
      return store.list();
    }),
    add: vi.fn((keys: PendingBlobDeletion[]) => store.add(keys)),
    remove: vi.fn((keys: PendingBlobDeletion[]) => store.remove(keys)),
  };
  const deleteData = {
    tombstone: vi.fn(),
    deleteBlobVersions: vi.fn(async (_scope: string, versions: string[]) => ({
      deleted: versions,
      missing: [],
      failed: [],
    })),
  };
  const tombstoneFinality = {
    tombstoneState: vi.fn(async () => finality),
  };
  const findUnsynced = vi.fn(() => []);
  const download = vi.fn();
  const cycle = vi.fn(async () => ({ connections: [] }));
  const read = vi.fn(async () => "m1");
  let handlers: Parameters<ChangePush["subscribe"]>[0] | null = null;
  const push: ChangePush = {
    subscribe(h) {
      handlers = h;
      return () => {};
    },
  };
  const manager = createSyncManager(
    {
      logger,
      serverOwner: "0x1111111111111111111111111111111111111111",
      storage: { findUnsynced, listVersions: () => [] },
    } as unknown as UploadWorkerDeps,
    { logger, storage: { download } } as unknown as DownloadWorkerDeps,
    {
      accountStorageMode: { read: () => "switched" },
      pollInterval: 60_000,
      localSync: { cycle },
      changeProbe: { read, intervalMs: 5_000, push },
      ...(options.withDeleteData === false
        ? {}
        : { deleteData: deleteData as never }),
      pendingBlobDeletions: pending,
      ...(options.withFinality === false ? {} : { tombstoneFinality }),
    } satisfies SyncManagerOptions,
  );
  return {
    manager,
    store,
    deleteData,
    tombstoneFinality,
    findUnsynced,
    cycle,
    read,
    setFinality(next: TombstoneFinalityState) {
      finality = next;
    },
    /** A healthy push at a fixed sequence, and a first clean timer pass. */
    async start() {
      manager.start();
      await vi.advanceTimersByTimeAsync(0);
      handlers!.onHealth(true);
      handlers!.onPosition("7");
      await vi.advanceTimersByTimeAsync(60_000);
    },
  };
}

describe("a switched device owes storage deletes whose tombstone is not final", () => {
  it("keeps the pass unsettled, deletes the blob once the tombstone is final, then goes quiet", async () => {
    const t = setup();
    await t.start();
    // Finality is pending: the blob stays, the debt stays, the clock runs.
    expect(t.deleteData.deleteBlobVersions).not.toHaveBeenCalled();
    expect(await t.store.list()).toEqual([MARKER]);
    expect(t.tombstoneFinality.tombstoneState).toHaveBeenCalled();

    // Only the version row changes: no position moves, no wake is sent.
    t.setFinality(FINAL);
    t.tombstoneFinality.tombstoneState.mockClear();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(t.tombstoneFinality.tombstoneState).toHaveBeenCalledTimes(1);
    expect(t.deleteData.deleteBlobVersions).toHaveBeenCalledTimes(1);
    expect(t.deleteData.deleteBlobVersions).toHaveBeenCalledWith(
      "chatgpt.conversations",
      ["3"],
    );
    expect(await t.store.list()).toEqual([]);
    // Only the stream-sync cycle ran: no legacy upload or download, and no
    // tombstone was sent.
    expect(t.findUnsynced).not.toHaveBeenCalled();
    expect(t.deleteData.tombstone).not.toHaveBeenCalled();

    // The debt is clear: the next pass settles, and then nothing runs.
    await vi.advanceTimersByTimeAsync(60_000);
    t.cycle.mockClear();
    t.read.mockClear();
    t.tombstoneFinality.tombstoneState.mockClear();
    await vi.advanceTimersByTimeAsync(24 * 60 * 60_000);
    expect(t.cycle).not.toHaveBeenCalled();
    expect(t.read).not.toHaveBeenCalled();
    expect(t.tombstoneFinality.tombstoneState).not.toHaveBeenCalled();
    await t.manager.stop();
  });

  it("a retry that fails keeps the pass unsettled, so the clock retries it", async () => {
    const t = setup({ finality: FINAL });
    let storageUp = false;
    t.deleteData.deleteBlobVersions.mockImplementation(
      async (_scope: string, versions: string[]) =>
        storageUp
          ? { deleted: versions, missing: [], failed: [] }
          : {
              deleted: [],
              missing: [],
              failed: versions.map((version) => ({
                version,
                error: "storage down",
              })),
            },
    );
    await t.start();
    expect(await t.store.list()).toEqual([MARKER]);
    const tries = t.deleteData.deleteBlobVersions.mock.calls.length;
    expect(tries).toBeGreaterThanOrEqual(2); // start pass and one timer pass

    storageUp = true;
    await vi.advanceTimersByTimeAsync(60_000);
    expect(t.deleteData.deleteBlobVersions).toHaveBeenCalledTimes(tries + 1);
    expect(await t.store.list()).toEqual([]);
    await t.manager.stop();
  });

  it("without a finality port it frees nothing: the markers stay and the status says why", async () => {
    // The worker's no-port branch releases every marker at once. A switched
    // pass cannot tell whether the tombstone may still roll back, so it
    // must not take that branch.
    const t = setup({ withFinality: false });
    await t.start();
    await vi.advanceTimersByTimeAsync(5 * 60_000);
    expect(t.deleteData.deleteBlobVersions).not.toHaveBeenCalled();
    expect(await t.store.list()).toEqual([MARKER]);
    expect(t.manager.getStatus().blobDeletions).toEqual({
      remaining: 1,
      waiting: 0,
      unavailable: "finality-port",
    });
    await t.manager.stop();
  });

  it("without a delete port the pass does not claim the debt cleared", async () => {
    const t = setup({ withDeleteData: false });
    await t.start();
    expect(await t.store.list()).toEqual([MARKER]);
    expect(t.manager.getStatus().blobDeletions).toEqual({
      remaining: 1,
      waiting: 0,
      unavailable: "delete-port",
    });
    await t.manager.stop();
  });

  describe("a rolled-back tombstone", () => {
    const ROLLED_BACK = {
      finalized: null,
      settling: false,
      rolledBack: {
        tombstoneVersion: "3",
        head: {
          dataPointId: "0xdp",
          expectedVersion: "2",
          dataHash: "0x" + "11".repeat(32),
          metadataHash: "0x" + "22".repeat(32),
        },
      },
    } as never;

    it("is parked: one visible failure, ciphertext kept, no tombstone sent, no timer cycle", async () => {
      const t = setup({ finality: ROLLED_BACK });
      await t.start();
      expect(t.deleteData.tombstone).not.toHaveBeenCalled();
      expect(t.deleteData.deleteBlobVersions).not.toHaveBeenCalled();
      expect(await t.store.list()).toEqual([MARKER]);
      const status = t.manager.getStatus();
      expect(status.deletions?.failed).toEqual([
        expect.objectContaining({
          scope: MARKER.scope,
          tombstoneVersion: "3",
          reason: "no-reissue-path",
        }),
      ]);
      expect(
        status.errors.filter((e) => e.scope === MARKER.scope),
      ).toHaveLength(1);
      expect(status.blobDeletions).toEqual({
        remaining: 1,
        waiting: 0,
        unavailable: null,
      });

      // Parked debt is not runnable work: the device goes quiet.
      t.cycle.mockClear();
      t.tombstoneFinality.tombstoneState.mockClear();
      await vi.advanceTimersByTimeAsync(24 * 60 * 60_000);
      expect(t.cycle).not.toHaveBeenCalled();
      expect(t.tombstoneFinality.tombstoneState).not.toHaveBeenCalled();
      await t.manager.stop();
    });

    it("is read again on a relevant change, reported once, and freed when a later delete is final", async () => {
      const t = setup({ finality: ROLLED_BACK });
      await t.start();
      await t.manager.trigger(); // another pass: the same rollback
      expect(
        t.manager.getStatus().errors.filter((e) => e.scope === MARKER.scope),
      ).toHaveLength(1);

      t.setFinality(FINAL); // the user deleted again and it settled
      await t.manager.trigger();
      expect(t.deleteData.deleteBlobVersions).toHaveBeenCalledTimes(1);
      expect(await t.store.list()).toEqual([]);
      const status = t.manager.getStatus();
      expect(status.deletions?.failed).toEqual([]);
      expect(status.blobDeletions).toBeUndefined();
      await t.manager.stop();
    });
  });
});
