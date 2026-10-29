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

import { deleteScope, retryPendingBlobDeletions } from "./delete.js";
import type { DeleteScopeDeps } from "./delete.js";
import { computeDataPointId } from "../data-point-id.js";
import { createMemoryPendingBlobDeletionStore } from "../pending-blob-deletions.js";
import { createInventoryTombstoneFinality } from "../tombstone-finality.js";
import { TOMBSTONE_DATA_HASH, TOMBSTONE_METADATA_HASH } from "../tombstone.js";
import { createMemoryDataStorage } from "../../test-utils/memory-storage.js";
import type { Logger } from "../../logger/index.js";
import type {
  DataPointFeedPort,
  DeleteDataPort,
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
      return {
        data: {
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
    tombstone: vi.fn(async (): Promise<TombstoneOutcome> => {
      // As the gateway port does: a head that is already a tombstone answers
      // "already deleted" with its version, else a tombstone is queued.
      const head = gateway.head();
      if (head?.deletedAt && !options.tombstoneOverTombstone) {
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
      };
    }),
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
  const deps: DeleteScopeDeps = {
    storage: createMemoryDataStorage(),
    serverOwner: OWNER,
    deleteData,
    pendingBlobDeletions: createMemoryPendingBlobDeletionStore(),
    dataPointFeed: gateway.feed(),
    logger,
    ...(options.finality === false
      ? {}
      : {
          tombstoneFinality: createInventoryTombstoneFinality({
            page: gateway.inventoryPage,
          }),
        }),
  };
  /** Every sync cycle starts with a retry pass. */
  const cycle = () => retryPendingBlobDeletions(deps);
  return { gateway, storage, deps, deleteData, cycle };
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
    await cycle();
    // The deletion did not happen: the live v1 head keeps its bytes.
    expect(gateway.head()?.version).toBe(1n);
    expect(storage.blobs.has("1")).toBe(true);

    // The owner deletes again; the gateway recovers the failed slot with the
    // new tombstone, and this one becomes final.
    await deleteScope(deps, SCOPE);
    expect(gateway.head()).toMatchObject({ version: 2n, status: "pending" });
    gateway.settle(2n, "finalized");
    const retried = await cycle();

    expect(retried.remaining).toBe(0);
    expect(storage.blobs.size).toBe(0);
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

    await expect(
      finality.finalizedTombstoneAtOrAbove(SCOPE, "4"),
    ).resolves.toBe("6");
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

    await expect(
      finality.finalizedTombstoneAtOrAbove(SCOPE, "2"),
    ).resolves.toBeNull();
  });
});
