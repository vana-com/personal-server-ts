/**
 * Blob cleanup must never free a storage key while a registry slot that can
 * still claim it is open (personal-server-ts #521 review, P1).
 *
 * The gateway queues a tombstone as a `pending` version and settles it on
 * chain later. Until the tombstone is final, settlement can fail, and the
 * gateway then rolls the head back and lets a writer recover the failed slot.
 * If cleanup has already deleted the blob at that slot, another writer can
 * put different bytes there, and the recovered registration commits to bytes
 * that are no longer stored. These tests drive the production delete worker
 * against an emulated gateway (contiguous versions, per-version settlement
 * status, failed-slot recovery as data-gateway #172 allows) and an emulated
 * write-once vana-storage.
 */
import { describe, expect, it, vi } from "vitest";
import { keccak256, toHex } from "viem";

import {
  deleteScope,
  retryPendingBlobDeletions,
  TOMBSTONE_RESUBMIT_MAX_ATTEMPTS,
} from "./delete.js";
import type {
  DeleteScopeDeps,
  RetryPendingBlobDeletionsDeps,
} from "./delete.js";
import { createTombstoneResubmitTracker } from "../tombstone-resubmits.js";
import { computeDataPointId } from "../data-point-id.js";
import { createMemoryPendingBlobDeletionStore } from "../pending-blob-deletions.js";
import { createInventoryTombstoneFinality } from "../tombstone-finality.js";
import { TOMBSTONE_DATA_HASH, TOMBSTONE_METADATA_HASH } from "../tombstone.js";
import { createMemoryDataStorage } from "../../test-utils/memory-storage.js";
import type { Logger } from "../../logger/index.js";
import type {
  DataPointFeedPort,
  DeleteDataPort,
  TombstoneFence,
  TombstoneOutcome,
} from "../../ports/index.js";

const SCOPE = "github.repositories";
const OWNER = "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12";
const DATA_POINT_ID = computeDataPointId(OWNER, SCOPE);

type Status = "pending" | "submitting" | "confirmed" | "finalized" | "failed";

interface Row {
  dataHash: string;
  metadataHash: string;
  status: Status;
  deletedAt: string | null;
}

/**
 * One scope's gateway registry: contiguous versions over the non-failed rows;
 * a failed row stays listed but out of the version max, and any writer may
 * recover its slot (data-gateway #172).
 */
class Gateway {
  readonly versions = new Map<bigint, Row>();

  private top(): bigint {
    let top = 0n;
    for (const [version, row] of this.versions) {
      if (row.status !== "failed" && version > top) top = version;
    }
    return top;
  }

  head() {
    const version = this.top();
    if (version === 0n) return null;
    const row = this.versions.get(version)!;
    return { version, ...row };
  }

  queueTombstone(): bigint {
    const version = this.top() + 1n;
    this.versions.set(version, {
      dataHash: TOMBSTONE_DATA_HASH,
      metadataHash: TOMBSTONE_METADATA_HASH,
      status: "pending",
      deletedAt: `2026-10-29T0${Number(version)}:00:00.000Z`,
    });
    return version;
  }

  register(version: bigint, dataHash: string) {
    if (version !== this.top() + 1n)
      throw new Error(`Gateway error: 409 next version is ${this.top() + 1n}`);
    this.versions.set(version, {
      dataHash,
      metadataHash: `0x${"33".repeat(32)}`,
      status: "pending",
      deletedAt: null,
    });
  }

  settle(version: bigint, status: Status) {
    this.versions.get(version)!.status = status;
  }

  feed(): DataPointFeedPort {
    return {
      listDataPointsByOwner: vi.fn(),
      getDataPoint: vi.fn(async () => {
        const head = this.head();
        return head
          ? {
              id: DATA_POINT_ID,
              ownerAddress: OWNER,
              scope: SCOPE,
              dataHash: head.dataHash,
              metadataHash: head.metadataHash,
              expectedVersion: head.version.toString(),
              addedAt: "2026-10-29T00:00:00.000Z",
              deletedAt: head.deletedAt,
            }
          : null;
      }),
    };
  }

  /** `GET /v1/data/:id/versions` as the version inventory client parses it. */
  inventoryPage = vi.fn(
    async (_scope: string, paging: { after?: string; limit?: number } = {}) => {
      const after = BigInt(paging.after ?? "0");
      const limit = paging.limit ?? 100;
      const rows = [...this.versions.entries()]
        .filter(([version]) => version > after)
        .sort(([a], [b]) => (a < b ? -1 : 1));
      const page = rows.slice(0, limit);
      const hasMore = rows.length > limit;
      const head = this.head();
      return {
        data: {
          head: head
            ? {
                expectedVersion: head.version.toString(),
                dataHash: head.dataHash,
                metadataHash: head.metadataHash,
                status: head.status,
                deletedAt: head.deletedAt,
              }
            : null,
          versions: page.map(([version, row]) => ({
            expectedVersion: version.toString(),
            dataHash: row.dataHash,
            metadataHash: row.metadataHash,
            status: row.status,
            addedAt: "2026-10-29T00:00:00.000Z",
            isTombstone: row.dataHash === TOMBSTONE_DATA_HASH,
          })),
        },
        pagination: {
          limit,
          hasMore,
          nextAfter: hasMore ? page.at(-1)![0].toString() : null,
        },
      };
    },
  );
}

/** Write-once vana-storage: a PUT of different bytes to a held key is refused. */
class Storage {
  readonly blobs = new Map<string, Uint8Array>();

  put(version: bigint, bytes: Uint8Array): "created" | "conflict" {
    const key = version.toString();
    if (this.blobs.has(key)) return "conflict";
    this.blobs.set(key, bytes);
    return "created";
  }

  hashAt(version: bigint): string | null {
    const bytes = this.blobs.get(version.toString());
    return bytes ? keccak256(bytes) : null;
  }
}

const logger = {
  debug: vi.fn(),
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
} as unknown as Logger;

function setup(
  options: {
    finality?: boolean;
    /**
     * Queue a tombstone even over a tombstone head. The gateway's DELETE
     * route answers "already deleted" there; the #521 review's emulated
     * interleaving queues one anyway, and this reproduces it literally.
     */
    tombstoneOverTombstone?: boolean;
  } = {},
) {
  const gateway = new Gateway();
  const storage = new Storage();
  const deleteData: DeleteDataPort = {
    tombstone: vi.fn(
      async (
        _scope: string,
        fence?: { head: TombstoneFence },
      ): Promise<TombstoneOutcome> => {
        // As the gateway port does: a head that is already a tombstone answers
        // "already deleted" with its version, else a tombstone is queued.
        const head = gateway.head();
        if (
          fence &&
          head &&
          !head.deletedAt &&
          (head.version.toString() !== fence.head.expectedVersion ||
            head.dataHash !== fence.head.dataHash ||
            head.metadataHash !== fence.head.metadataHash)
        ) {
          throw new Error("Scope head is not the one the fenced delete saw");
        }
        if (head === null) {
          return { status: "not-registered", dataPointId: DATA_POINT_ID };
        }
        if (head.deletedAt && !options.tombstoneOverTombstone) {
          return {
            status: "already-deleted",
            dataPointId: DATA_POINT_ID,
            version: head.version.toString(),
            deletedAt: head.deletedAt,
          };
        }
        const version = gateway.queueTombstone();
        return {
          status: "tombstoned",
          dataPointId: DATA_POINT_ID,
          version: version.toString(),
          deletedAt: gateway.versions.get(version)!.deletedAt,
          replaced: {
            expectedVersion: head.version.toString(),
            dataHash: head.dataHash,
            metadataHash: head.metadataHash,
          },
        };
      },
    ),
    deleteBlobVersions: vi.fn(async (_scope: string, versions: string[]) => {
      const deleted: string[] = [];
      const missing: string[] = [];
      for (const version of versions) {
        if (storage.blobs.delete(version)) deleted.push(version);
        else missing.push(version);
      }
      return { deleted, missing, failed: [] };
    }),
  };
  // Sync cycles are a minute apart; finality rechecks back off per scope.
  let clock = Date.parse("2026-10-29T12:00:00.000Z");
  const localStorage = createMemoryDataStorage();
  const deps: DeleteScopeDeps & RetryPendingBlobDeletionsDeps = {
    storage: localStorage,
    serverOwner: OWNER,
    deleteData,
    pendingBlobDeletions: createMemoryPendingBlobDeletionStore(),
    dataPointFeed: gateway.feed(),
    logger,
    ...(options.finality === false
      ? {}
      : {
          tombstoneFinality: createInventoryTombstoneFinality(
            { page: gateway.inventoryPage },
            { now: () => clock },
          ),
        }),
  };
  // A failed tombstone is re-submitted through the same delete path the sync
  // manager wires (one sync-cycle mutation at a time).
  const resubmits = createTombstoneResubmitTracker({ now: () => clock });
  if (options.finality !== false) {
    deps.tombstoneResubmits = resubmits;
    deps.resubmitDeletion = (scope, resubmit) =>
      deleteScope(deps, scope, resubmit);
  }
  /**
   * Every sync cycle starts with a retry pass. By default each call stands
   * for enough elapsed time that no recheck backoff is pending.
   */
  const cycle = (elapsedMs = 60 * 60_000) => {
    clock += elapsedMs;
    return retryPendingBlobDeletions(deps);
  };
  /** A local entry the deletion covers that never registered (a crashed upload). */
  const unsyncedLocal = (version: number) =>
    localStorage.insertEntry({
      fileId: null,
      schemaId: null,
      path: `${SCOPE}/local-${version}.json`,
      scope: SCOPE,
      collectedAt: "2026-10-28T00:00:00.000Z",
      sizeBytes: 10,
      version,
      dataPointId: null,
    });
  /** A local copy of a registered version, as the download worker writes it. */
  const syncedLocal = (version: number) =>
    localStorage.insertEntry({
      fileId: `file-${version}`,
      schemaId: null,
      path: `${SCOPE}/synced-${version}.json`,
      scope: SCOPE,
      collectedAt: `2026-10-2${version}T00:00:00.000Z`,
      sizeBytes: 10,
      version,
      dataPointId: DATA_POINT_ID,
    });
  return {
    gateway,
    storage,
    deps,
    deleteData,
    cycle,
    unsyncedLocal,
    syncedLocal,
    localStorage,
    resubmits,
  };
}

const bytes = (text: string) => new TextEncoder().encode(text);

describe("blob cleanup waits for the tombstone to be final", () => {
  it("a failed tombstone cannot let another writer replace a recovered slot's bytes", async () => {
    const { gateway, storage, deps, cycle } = setup({
      tombstoneOverTombstone: true,
    });
    // An earlier deletion of the scope, final on chain.
    gateway.queueTombstone();
    gateway.settle(1n, "finalized");

    // 1. A observes tombstone v1, re-adds with ingest marker 1, and uploads
    //    its ciphertext at v2 before registering.
    const aBytes = bytes("A: re-added ciphertext");
    expect(storage.put(2n, aBytes)).toBe("created");

    // 2. A second deletion queues tombstone v2. Its cleanup runs: the delete's
    //    own pass and the retry passes of later sync cycles. Then B writes
    //    different ciphertext to key v2.
    const result = await deleteScope(deps, SCOPE);
    expect(result.steps.gateway).toMatchObject({ status: "ok", version: "2" });
    await cycle();
    await cycle();
    expect(storage.put(2n, bytes("B: other ciphertext"))).toBe("conflict");

    // 3. The second tombstone fails; the gateway rolls the head back to v1.
    gateway.settle(2n, "failed");
    expect(gateway.head()?.version).toBe(1n);
    await cycle();

    // 4. A's registration recovers the failed v2 slot.
    gateway.register(2n, keccak256(aBytes));
    await cycle();
    await cycle();

    // The registered commitment still matches the stored bytes.
    expect(storage.hashAt(2n)).toBe(gateway.versions.get(2n)!.dataHash);
    expect(storage.hashAt(2n)).toBe(keccak256(aBytes));
  });

  it("an upload racing a delete over a live head keeps its slot's bytes when the tombstone fails", async () => {
    const { gateway, storage, deps, cycle } = setup();
    gateway.register(1n, keccak256(bytes("v1")));
    storage.put(1n, bytes("v1"));
    gateway.settle(1n, "finalized");

    // A reads head v1 and uploads its next version at v2, not registered yet.
    const aBytes = bytes("A: v2");
    expect(storage.put(2n, aBytes)).toBe("created");
    // The owner deletes the scope on this replica: tombstone v2 is queued.
    await deleteScope(deps, SCOPE);
    await cycle();
    // A stale writer B, which still sees head v1, uploads to v2.
    expect(storage.put(2n, bytes("B: v2"))).toBe("conflict");
    // Settlement fails; rollback restores v1; A's registration recovers v2.
    gateway.settle(2n, "failed");
    gateway.register(2n, keccak256(aBytes));
    await cycle();

    expect(storage.hashAt(2n)).toBe(gateway.versions.get(2n)!.dataHash);
    // The live v1 head kept its bytes too.
    expect(storage.hashAt(1n)).toBe(keccak256(bytes("v1")));
  });

  it("a pending tombstone frees no key; once it is finalized the queued cleanup frees every covered key", async () => {
    const { gateway, storage, deps, deleteData, cycle } = setup();
    gateway.register(1n, keccak256(bytes("v1")));
    storage.put(1n, bytes("v1"));
    gateway.settle(1n, "finalized");

    const result = await deleteScope(deps, SCOPE);
    expect(result.steps.storage).toMatchObject({
      status: "deferred",
      blobsDeleted: 0,
      blobsPending: 2,
    });
    expect(result.pendingBlobDeletion).toBe(true);
    expect(deleteData.deleteBlobVersions).not.toHaveBeenCalled();

    // Submitted and even confirmed are not final: a reorg can push a
    // confirmed version back to pending, and it can still fail.
    gateway.settle(2n, "submitting");
    await cycle();
    gateway.settle(2n, "confirmed");
    await cycle();
    expect(deleteData.deleteBlobVersions).not.toHaveBeenCalled();
    expect(storage.blobs.has("1")).toBe(true);

    gateway.settle(2n, "finalized");
    const retried = await cycle();
    expect(retried.completed).toEqual([
      { scope: SCOPE, version: "1" },
      { scope: SCOPE, version: "2" },
    ]);
    expect(retried.remaining).toBe(0);
    expect(storage.blobs.size).toBe(0);
  });

  it("an already-final tombstone is cleaned up in the delete's own pass", async () => {
    const { gateway, storage, deps } = setup();
    gateway.register(1n, keccak256(bytes("v1")));
    storage.put(1n, bytes("v1"));
    gateway.queueTombstone();
    gateway.settle(2n, "finalized");

    const result = await deleteScope(deps, SCOPE);

    expect(result.steps.gateway).toMatchObject({ status: "ok" });
    expect(result.steps.storage).toMatchObject({ status: "ok" });
    expect(result.pendingBlobDeletion).toBe(false);
    expect(storage.blobs.size).toBe(0);
  });

  it("a failed tombstone's keys stay until a later deletion is final, then all of them go", async () => {
    const { gateway, storage, deps, cycle } = setup();
    gateway.register(1n, keccak256(bytes("v1")));
    storage.put(1n, bytes("v1"));
    gateway.settle(1n, "finalized");

    await deleteScope(deps, SCOPE); // tombstone v2
    gateway.settle(2n, "failed");
    expect(gateway.head()?.version).toBe(1n);
    await cycle();
    // The deletion did not happen: the live v1 head keeps its bytes. The
    // retry re-submitted it; the new tombstone recovers the failed slot.
    expect(storage.blobs.has("1")).toBe(true);
    expect(gateway.head()).toMatchObject({ version: 2n, status: "pending" });

    // The owner deletes again meanwhile (the gateway answers "already
    // deleted"), and the tombstone becomes final.
    await deleteScope(deps, SCOPE);
    gateway.settle(2n, "finalized");
    const retried = await cycle();

    expect(retried.remaining).toBe(0);
    expect(storage.blobs.size).toBe(0);
  });

  it("keeps a local key above the tombstone until a tombstone at or above it is final", async () => {
    const { gateway, storage, deps, cycle, unsyncedLocal } = setup();
    gateway.register(1n, keccak256(bytes("v1")));
    storage.put(1n, bytes("v1"));
    gateway.settle(1n, "finalized");
    // A crashed upload left a local entry at version 3 and A's bytes at key 3.
    unsyncedLocal(3);
    const aBytes = bytes("A: v3");
    storage.put(3n, aBytes);

    await deleteScope(deps, SCOPE); // tombstone v2
    gateway.settle(2n, "finalized");
    await cycle();

    // Tombstone v2 covers keys 1 and 2 only; slot 3 is still open.
    expect(storage.blobs.has("1")).toBe(false);
    expect(storage.put(3n, bytes("B: v3"))).toBe("conflict");
    gateway.register(3n, keccak256(aBytes));
    expect(storage.hashAt(3n)).toBe(gateway.versions.get(3n)!.dataHash);

    // A later deletion that is final covers key 3 too.
    gateway.settle(3n, "finalized");
    await deleteScope(deps, SCOPE); // tombstone v4
    gateway.settle(4n, "finalized");
    await cycle();
    expect(storage.blobs.size).toBe(0);
  });

  it("a re-delete at a higher slot after a failed tombstone drains the old keys once final", async () => {
    const { gateway, storage, deps, cycle } = setup();
    gateway.register(1n, keccak256(bytes("v1")));
    storage.put(1n, bytes("v1"));
    gateway.settle(1n, "finalized");
    await deleteScope(deps, SCOPE); // tombstone v2
    gateway.settle(2n, "failed");
    // A writer recovers slot 2 with data, which settles.
    gateway.register(2n, keccak256(bytes("v2")));
    storage.put(2n, bytes("v2"));
    gateway.settle(2n, "finalized");
    await cycle();
    expect(storage.blobs.size).toBe(2);

    await deleteScope(deps, SCOPE); // tombstone v3
    gateway.settle(3n, "finalized");
    const retried = await cycle();

    expect(retried.remaining).toBe(0);
    expect(storage.blobs.size).toBe(0);
  });

  it("holds an unregistered scope's local keys and backs off its finality reads", async () => {
    const { gateway, storage, deps, cycle, unsyncedLocal } = setup();
    unsyncedLocal(1);
    storage.put(1n, bytes("crashed upload"));

    const result = await deleteScope(deps, SCOPE);
    expect(result.steps.gateway).toMatchObject({
      status: "skipped",
      reason: "not-registered",
    });
    // No tombstone exists, so slot 1 stays open and its bytes stay.
    for (let minute = 0; minute < 30; minute++) await cycle(60_000);

    expect(storage.blobs.has("1")).toBe(true);
    // One read in the delete, then at most one per backoff step over the
    // 30 minutes (1, 2, 4, 8 and 15 minute rechecks), not one per cycle.
    expect(gateway.inventoryPage.mock.calls.length).toBeLessThanOrEqual(6);
  });

  it("without a finality port the legacy behaviour (delete on acknowledgement) is unchanged", async () => {
    const { gateway, storage, deps } = setup({ finality: false });
    gateway.register(1n, keccak256(bytes("v1")));
    storage.put(1n, bytes("v1"));

    const result = await deleteScope(deps, SCOPE);

    expect(result.steps.storage).toMatchObject({ status: "ok" });
    expect(storage.blobs.size).toBe(0);
  });

  it("a finality read that fails defers the keys to a later cycle", async () => {
    const { gateway, storage, deps, deleteData, cycle } = setup();
    gateway.register(1n, keccak256(bytes("v1")));
    storage.put(1n, bytes("v1"));
    gateway.inventoryPage.mockRejectedValueOnce(
      new Error("Gateway inventory request failed (503)"),
    );

    const result = await deleteScope(deps, SCOPE);
    expect(result.steps.storage).toMatchObject({ status: "deferred" });
    expect(deleteData.deleteBlobVersions).not.toHaveBeenCalled();

    gateway.settle(2n, "finalized");
    await cycle();
    expect(storage.blobs.size).toBe(0);
  });

  it("keeps a key the tombstone did not cover even after it is final", async () => {
    const { gateway, storage, deps, cycle } = setup();
    gateway.register(1n, keccak256(bytes("v1")));
    storage.put(1n, bytes("v1"));
    await deleteScope(deps, SCOPE); // tombstone v2
    // A re-add registered above the pending tombstone (gateway #172 allows it).
    gateway.register(3n, keccak256(bytes("v3")));
    storage.put(3n, bytes("v3"));
    gateway.settle(2n, "finalized");

    await cycle();

    expect(storage.blobs.has("1")).toBe(false);
    expect(storage.hashAt(3n)).toBe(keccak256(bytes("v3")));
  });
});

describe("storage cleanup converges on the user's delete", () => {
  const MINUTE = 60_000;

  it("reads finality every sync cycle while the tombstone settles, and cleans up within one cycle of finalization", async () => {
    const { gateway, storage, deps, cycle } = setup();
    gateway.register(1n, keccak256(bytes("v1")));
    storage.put(1n, bytes("v1"));
    gateway.settle(1n, "finalized");

    await deleteScope(deps, SCOPE); // tombstone v2, pending
    const readsAtDelete = gateway.inventoryPage.mock.calls.length;
    gateway.settle(2n, "submitting");
    for (let minute = 0; minute < 6; minute++) await cycle(MINUTE);
    // One signed inventory read per cycle while the tombstone settles.
    expect(gateway.inventoryPage.mock.calls.length - readsAtDelete).toBe(6);
    expect(storage.blobs.has("1")).toBe(true);

    gateway.settle(2n, "finalized");
    const retried = await cycle(MINUTE);

    expect(retried.remaining).toBe(0);
    expect(storage.blobs.size).toBe(0);
  });

  it("re-submits a tombstone that failed, and the new tombstone's finality drains the queued keys", async () => {
    const {
      gateway,
      storage,
      deps,
      deleteData,
      cycle,
      syncedLocal,
      localStorage,
    } = setup();
    gateway.register(1n, keccak256(bytes("v1")));
    storage.put(1n, bytes("v1"));
    gateway.settle(1n, "finalized");
    syncedLocal(1);

    await deleteScope(deps, SCOPE); // tombstone v2
    expect(localStorage.listVersions(SCOPE, { limit: 100 })).toHaveLength(0);
    gateway.settle(2n, "failed");
    // Rollback: the gateway shows v1 live again and the download worker
    // pulls it back into the local index.
    expect(gateway.head()).toMatchObject({ version: 1n, deletedAt: null });
    syncedLocal(1);

    await cycle(MINUTE);

    // The user's delete is re-submitted through the delete path: a new
    // tombstone takes the free slot, and the re-pulled copy is erased again.
    expect(deleteData.tombstone).toHaveBeenCalledTimes(2);
    expect(gateway.head()).toMatchObject({
      version: 2n,
      status: "pending",
      dataHash: TOMBSTONE_DATA_HASH,
    });
    expect(localStorage.listVersions(SCOPE, { limit: 100 })).toHaveLength(0);
    expect(storage.blobs.has("1")).toBe(true);

    gateway.settle(2n, "finalized");
    const retried = await cycle(MINUTE);

    expect(retried.remaining).toBe(0);
    expect(storage.blobs.size).toBe(0);
    expect(deleteData.tombstone).toHaveBeenCalledTimes(2);
  });

  it("never re-deletes a scope the user re-added on this replica after the delete", async () => {
    const { gateway, storage, deps, deleteData, cycle, unsyncedLocal } =
      setup();
    gateway.register(1n, keccak256(bytes("v1")));
    storage.put(1n, bytes("v1"));
    gateway.settle(1n, "finalized");

    await deleteScope(deps, SCOPE); // tombstone v2
    // The user adds the data back before the failure is noticed.
    unsyncedLocal(2);
    gateway.settle(2n, "failed");
    for (let minute = 0; minute < 30; minute++) await cycle(MINUTE);

    expect(deleteData.tombstone).toHaveBeenCalledTimes(1);
    expect(storage.blobs.has("1")).toBe(true);
  });

  it("never re-deletes a scope another writer re-added at the gateway after the failure", async () => {
    const { gateway, storage, deps, deleteData, cycle } = setup();
    gateway.register(1n, keccak256(bytes("v1")));
    storage.put(1n, bytes("v1"));
    gateway.settle(1n, "finalized");

    await deleteScope(deps, SCOPE); // tombstone v2
    gateway.settle(2n, "failed");
    // Another replica registers new data in the freed slot above the
    // rolled-back head: the user's newer write wins over the failed delete.
    gateway.register(2n, keccak256(bytes("re-add")));
    for (let minute = 0; minute < 30; minute++) await cycle(MINUTE);

    expect(deleteData.tombstone).toHaveBeenCalledTimes(1);
  });

  it("does not re-submit when the head rolled back below the one the delete replaced, and the user's next delete drains the covered keys", async () => {
    const { gateway, storage, deps, deleteData, cycle, resubmits } = setup();
    gateway.register(1n, keccak256(bytes("v1")));
    storage.put(1n, bytes("v1"));
    gateway.settle(1n, "finalized");
    gateway.register(2n, keccak256(bytes("v2")));
    storage.put(2n, bytes("v2"));

    await deleteScope(deps, SCOPE); // tombstone v3 over pending data v2
    // v2's settlement fails, and v3 with it: the head rolls back to v1, which
    // is not the head the user's tombstone replaced. Whether v1 is the older
    // data or a re-add cannot be told apart here, so nothing is re-submitted.
    gateway.settle(2n, "failed");
    gateway.settle(3n, "failed");
    expect(gateway.head()?.version).toBe(1n);
    for (let minute = 0; minute < 10; minute++) await cycle(MINUTE);
    expect(deleteData.tombstone).toHaveBeenCalledTimes(1);
    expect(logger.info).toHaveBeenCalledWith(
      expect.objectContaining({ scope: SCOPE, head: "1", remembered: "2" }),
      expect.stringContaining("not the one the delete replaced"),
    );

    // The user deletes again: the tombstone recovers slot 2.
    await deleteScope(deps, SCOPE);
    expect(gateway.head()).toMatchObject({
      version: 2n,
      dataHash: TOMBSTONE_DATA_HASH,
      status: "pending",
    });
    const reads = gateway.inventoryPage.mock.calls.length;
    for (let minute = 0; minute < 4; minute++) await cycle(MINUTE);
    // Read every cycle while the new tombstone settles.
    expect(gateway.inventoryPage.mock.calls.length - reads).toBe(4);

    gateway.settle(2n, "finalized");
    await cycle(MINUTE);

    // Keys 1 and 2 are under the finalized tombstone v2; slot 3 is open
    // again, so its key would stay held (there is none here).
    expect(storage.blobs.size).toBe(0);
    expect(resubmits.snapshot()).toEqual({ retrying: [], failed: [] });
  });

  it("does not tombstone a re-add that lands between the rollback read and the re-submission", async () => {
    const { gateway, storage, deps, deleteData, cycle } = setup();
    gateway.register(1n, keccak256(bytes("v1")));
    storage.put(1n, bytes("v1"));
    gateway.settle(1n, "finalized");
    await deleteScope(deps, SCOPE); // tombstone v2
    gateway.settle(2n, "failed");

    // Another replica re-adds in the free slot while this pass runs.
    const resubmit = deps.resubmitDeletion!;
    deps.resubmitDeletion = async (scope, options) => {
      gateway.register(2n, keccak256(bytes("re-add")));
      storage.put(2n, bytes("re-add"));
      return resubmit(scope, options);
    };
    await cycle(MINUTE);
    gateway.settle(2n, "finalized");
    for (let minute = 0; minute < 5; minute++) await cycle(MINUTE);

    expect(deleteData.tombstone).toHaveBeenCalledTimes(2);
    expect(gateway.head()).toMatchObject({ version: 2n, deletedAt: null });
    expect(storage.hashAt(2n)).toBe(keccak256(bytes("re-add")));
  });

  it("does not tombstone a re-add that recovered a failed data slot below the failed tombstone", async () => {
    const { gateway, storage, deps, deleteData, cycle, syncedLocal } = setup();
    gateway.register(1n, keccak256(bytes("v1")));
    storage.put(1n, bytes("v1"));
    gateway.settle(1n, "finalized");
    gateway.register(2n, keccak256(bytes("v2")));
    storage.put(2n, bytes("v2"));
    syncedLocal(1);
    syncedLocal(2);

    await deleteScope(deps, SCOPE); // tombstone v3 over pending data v2
    gateway.settle(2n, "failed");
    gateway.settle(3n, "failed");
    expect(gateway.head()?.version).toBe(1n);
    // Before this replica reads again, the user re-adds elsewhere: the write
    // recovers slot 2 with new bytes and finalizes; download pulls it back.
    storage.blobs.delete("2");
    gateway.register(2n, keccak256(bytes("re-add")));
    storage.put(2n, bytes("re-add"));
    gateway.settle(2n, "finalized");
    syncedLocal(2);

    for (let minute = 0; minute < 10; minute++) await cycle(MINUTE);

    expect(deleteData.tombstone).toHaveBeenCalledTimes(1);
    expect(gateway.head()).toMatchObject({ version: 2n, deletedAt: null });
    expect(storage.hashAt(2n)).toBe(keccak256(bytes("re-add")));
  });

  it("keeps re-submitting when the re-submitted tombstone fails too", async () => {
    const { gateway, storage, deps, deleteData, cycle } = setup();
    gateway.register(1n, keccak256(bytes("v1")));
    storage.put(1n, bytes("v1"));
    gateway.settle(1n, "finalized");
    gateway.register(2n, keccak256(bytes("v2")));
    storage.put(2n, bytes("v2"));
    gateway.settle(2n, "finalized");

    await deleteScope(deps, SCOPE); // tombstone v3
    gateway.settle(3n, "failed"); // head back to v2
    await cycle(MINUTE); // re-submitted at v3
    expect(deleteData.tombstone).toHaveBeenCalledTimes(2);
    gateway.settle(3n, "failed");
    await cycle(2 * MINUTE); // re-submitted again over the same head v2
    expect(deleteData.tombstone).toHaveBeenCalledTimes(3);
    gateway.settle(3n, "finalized");
    await cycle(MINUTE);

    expect(storage.blobs.size).toBe(0);
  });

  it("a re-submission sends no storage batch of its own", async () => {
    const { gateway, storage, deps, deleteData, cycle } = setup();
    // Scope history: 40 versions under a finalized tombstone v40 that is
    // still draining, then a re-add at v41 deleted by tombstone v42.
    for (let v = 1n; v <= 39n; v++) {
      gateway.register(v, keccak256(bytes(`v${v}`)));
      storage.put(v, bytes(`v${v}`));
      gateway.settle(v, "finalized");
    }
    await deleteScope(deps, SCOPE); // tombstone v40
    gateway.settle(40n, "finalized");
    gateway.register(41n, keccak256(bytes("v41")));
    storage.put(41n, bytes("v41"));
    gateway.settle(41n, "finalized");
    await deleteScope(deps, SCOPE); // tombstone v42
    gateway.settle(42n, "failed");
    vi.mocked(deleteData.deleteBlobVersions).mockClear();

    await cycle(MINUTE);

    expect(deleteData.tombstone).toHaveBeenCalledTimes(3);
    const sent = vi
      .mocked(deleteData.deleteBlobVersions)
      .mock.calls.reduce((total, [, versions]) => total + versions.length, 0);
    expect(sent).toBeLessThanOrEqual(15);
  });

  it("clears a reported failure once the scope's keys drain", async () => {
    const { gateway, storage, deps, cycle, resubmits } = setup();
    gateway.register(1n, keccak256(bytes("v1")));
    storage.put(1n, bytes("v1"));
    gateway.settle(1n, "finalized");
    await deleteScope(deps, SCOPE); // tombstone v2
    for (let minute = 0; minute < 180; minute++) {
      if (gateway.versions.get(2n)?.status === "pending")
        gateway.settle(2n, "failed");
      await cycle(MINUTE);
    }
    expect(resubmits.snapshot().failed).toHaveLength(1);

    // The user deletes on another device; that tombstone becomes final.
    gateway.queueTombstone();
    gateway.settle(2n, "finalized");
    await cycle(60 * MINUTE);

    expect(storage.blobs.size).toBe(0);
    expect(resubmits.snapshot()).toEqual({ retrying: [], failed: [] });
  });

  it("gives up after a bounded number of re-submissions and reports the failure", async () => {
    const { gateway, storage, deps, deleteData, cycle, resubmits } = setup();
    gateway.register(1n, keccak256(bytes("v1")));
    storage.put(1n, bytes("v1"));
    gateway.settle(1n, "finalized");

    await deleteScope(deps, SCOPE); // tombstone v2
    // Every tombstone of this scope fails to settle.
    for (let minute = 0; minute < 180; minute++) {
      const row = gateway.versions.get(2n);
      if (row?.status === "pending") gateway.settle(2n, "failed");
      await cycle(MINUTE);
    }

    expect(deleteData.tombstone).toHaveBeenCalledTimes(
      1 + TOMBSTONE_RESUBMIT_MAX_ATTEMPTS,
    );
    // Nothing was freed: the gateway shows the scope live.
    expect(storage.blobs.has("1")).toBe(true);
    expect(resubmits.snapshot()).toEqual({
      retrying: [],
      failed: [
        expect.objectContaining({
          scope: SCOPE,
          attempts: TOMBSTONE_RESUBMIT_MAX_ATTEMPTS,
          tombstoneVersion: "2",
        }),
      ],
    });
    expect(logger.error).toHaveBeenCalledWith(
      expect.objectContaining({ scope: SCOPE }),
      expect.stringContaining("Scope deletion did not complete"),
    );
  });
});

describe("createInventoryTombstoneFinality", () => {
  const row = (version: number, status: Status, tombstone = true) => ({
    expectedVersion: String(version),
    dataHash: tombstone ? TOMBSTONE_DATA_HASH : toHex(version, { size: 32 }),
    metadataHash: tombstone
      ? TOMBSTONE_METADATA_HASH
      : toHex(version, { size: 32 }),
    status,
    addedAt: "2026-10-29T00:00:00.000Z",
    isTombstone: tombstone,
  });

  function pages(
    ...chunks: Array<Array<ReturnType<typeof row>>>
  ): ReturnType<typeof vi.fn> {
    const page = vi.fn();
    chunks.forEach((versions, index) => {
      const hasMore = index < chunks.length - 1;
      page.mockResolvedValueOnce({
        data: { versions },
        pagination: {
          limit: 1000,
          hasMore,
          nextAfter: hasMore ? versions.at(-1)!.expectedVersion : null,
        },
      });
    });
    return page;
  }

  it("answers the highest finalized tombstone at or above the asked version, across pages", async () => {
    const page = pages(
      [row(4, "finalized"), row(5, "finalized", false)],
      [row(6, "finalized"), row(7, "confirmed")],
    );
    const finality = createInventoryTombstoneFinality({ page });

    await expect(finality.tombstoneState(SCOPE, "4")).resolves.toEqual({
      finalized: "6",
      settling: true,
      rolledBack: null,
    });
    expect(page).toHaveBeenNthCalledWith(1, SCOPE, {
      after: "3",
      limit: 1000,
    });
    expect(page).toHaveBeenNthCalledWith(2, SCOPE, {
      after: "5",
      limit: 1000,
    });
  });

  it("does not count confirmed, pending or failed tombstones, or finalized data", async () => {
    const finality = createInventoryTombstoneFinality({
      page: pages([
        row(2, "confirmed"),
        row(3, "failed"),
        row(4, "pending"),
        row(5, "finalized", false),
      ]),
    });

    await expect(finality.tombstoneState(SCOPE, "2")).resolves.toMatchObject({
      finalized: null,
    });
  });

  const liveHead = (version: number) => ({
    expectedVersion: String(version),
    dataHash: toHex(version, { size: 32 }),
    metadataHash: toHex(version, { size: 32 }),
    status: "finalized",
    deletedAt: null,
  });
  const onePage = (
    head: ReturnType<typeof liveHead> | null,
    versions: Array<ReturnType<typeof row>>,
  ) =>
    vi.fn(async () => ({
      data: { head, versions },
      pagination: { limit: 1000, hasMore: false, nextAfter: null },
    }));

  it("reports a rollback only when the newest version is a failed tombstone over a live head", async () => {
    const rolledBack = createInventoryTombstoneFinality({
      page: onePage(liveHead(1), [row(2, "failed")]),
    });
    await expect(rolledBack.tombstoneState(SCOPE, "2")).resolves.toEqual({
      finalized: null,
      settling: false,
      rolledBack: {
        tombstoneVersion: "2",
        head: {
          expectedVersion: "1",
          dataHash: toHex(1, { size: 32 }),
          metadataHash: toHex(1, { size: 32 }),
        },
      },
    });

    // A newer write above the failed tombstone, even a failed one.
    const newerWrite = createInventoryTombstoneFinality({
      page: onePage(liveHead(1), [row(2, "failed"), row(3, "failed", false)]),
    });
    await expect(newerWrite.tombstoneState(SCOPE, "2")).resolves.toMatchObject({
      rolledBack: null,
    });

    // The head is an older tombstone: the scope is still deleted.
    const deletedHead = createInventoryTombstoneFinality({
      page: onePage(
        {
          expectedVersion: "1",
          dataHash: TOMBSTONE_DATA_HASH,
          metadataHash: TOMBSTONE_METADATA_HASH,
          status: "finalized",
          deletedAt: "2026-10-29T00:00:00.000Z",
        },
        [row(2, "failed")],
      ),
    });
    await expect(deletedHead.tombstoneState(SCOPE, "2")).resolves.toMatchObject(
      { rolledBack: null },
    );

    // A tombstone still settling.
    const settling = createInventoryTombstoneFinality({
      page: onePage(liveHead(1), [row(2, "failed"), row(3, "submitting")]),
    });
    await expect(settling.tombstoneState(SCOPE, "2")).resolves.toMatchObject({
      settling: true,
      rolledBack: null,
    });
  });

  it("treats an unknown status as settling and never backs off while settling", async () => {
    let clock = 0;
    const page = onePage(liveHead(1), [row(2, "reorged")]);
    const finality = createInventoryTombstoneFinality(
      { page },
      { now: () => clock },
    );
    for (let cycle = 0; cycle < 5; cycle++) {
      clock += 60_000;
      await expect(finality.tombstoneState(SCOPE, "2")).resolves.toMatchObject({
        settling: true,
      });
    }
    expect(page).toHaveBeenCalledTimes(5);
  });

  it("backs off a scope with nothing settling until recheckNow", async () => {
    let clock = 0;
    const page = onePage(liveHead(1), []);
    const finality = createInventoryTombstoneFinality(
      { page },
      { now: () => clock },
    );
    await finality.tombstoneState(SCOPE, "2");
    clock += 30_000;
    await finality.tombstoneState(SCOPE, "2");
    expect(page).toHaveBeenCalledTimes(1);

    finality.recheckNow!(SCOPE);
    await finality.tombstoneState(SCOPE, "2");
    expect(page).toHaveBeenCalledTimes(2);
  });
});
