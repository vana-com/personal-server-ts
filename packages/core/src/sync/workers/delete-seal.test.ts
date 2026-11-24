/**
 * The delete worker and the legacy-write seal.
 *
 * Classification of the worker's durable steps:
 * - gateway tombstone: a removal, taken under the seal's `remove` in every
 *   mode. After the switch the gateway decides (cutover policy v3 admits the
 *   exact tombstone over a live head); `delete-switched.test.ts` runs that
 *   against a gateway fake. The seal's lock still orders it against the On
 *   latch;
 * - blob deletes at the storage backend and the retry markers: they remove
 *   remote objects or record bookkeeping, and add no visible legacy version;
 * - local removal: a pure removal, sealed in every mode by the storage's own
 *   `remove`, or run directly when the caller passes its hold.
 */
import { describe, expect, it, vi } from "vitest";
import { deleteScope } from "./delete.js";
import { LegacyWriteRefusedError } from "../../api/legacy-write-gate.js";
import { createLegacyWriteSeal } from "../../storage/legacy-write-seal.js";
import { authorityHearing } from "../../test-utils/account-mode.js";
import { createMemoryDataStorage } from "../../test-utils/memory-storage.js";
import { createMemoryPendingBlobDeletionStore } from "../pending-blob-deletions.js";
import type { Logger } from "../../logger/index.js";
import type { DeleteDataPort } from "../../ports/index.js";

const OWNER = "0x1111111111111111111111111111111111111111";
const SCOPE = "notes.entries";

const logger = () =>
  ({
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  }) as unknown as Logger;

function gate() {
  let open!: () => void;
  const opened = new Promise<void>((resolve) => {
    open = resolve;
  });
  return { opened, open };
}
const tick = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

async function setup(state: "off" | "on", tombstoneGate?: Promise<void>) {
  const authority = await authorityHearing(OWNER, state);
  const seal = createLegacyWriteSeal({ authority, owner: OWNER });
  const storage = createMemoryDataStorage({ legacyWriteSeal: seal });
  storage.entries.push({
    id: 1,
    fileId: null,
    schemaId: null,
    path: `${SCOPE}/1.json`,
    scope: SCOPE,
    collectedAt: "2026-11-01T00:00:00.000Z",
    createdAt: "2026-11-01T00:00:00.000Z",
    sizeBytes: 10,
    version: 1,
    casRevision: 1,
    dataPointId: null,
  });
  const deleteData = {
    tombstone: vi.fn(async () => {
      await tombstoneGate;
      return {
        status: "tombstoned" as const,
        dataPointId: "0xdp",
        version: "1",
        deletedAt: "2026-11-09T00:00:00.000Z",
        replaced: null,
      };
    }),
    deleteBlobVersions: vi.fn(async (_scope: string, versions: string[]) => ({
      deleted: versions,
      missing: [],
      failed: [],
    })),
  } as unknown as DeleteDataPort & { tombstone: ReturnType<typeof vi.fn> };
  const deps = {
    storage,
    serverOwner: OWNER,
    deleteData,
    pendingBlobDeletions: createMemoryPendingBlobDeletionStore(),
    logger: logger(),
  };
  return { authority, seal, storage, deleteData, deps };
}

const on = (authority: Awaited<ReturnType<typeof setup>>["authority"]) =>
  authority.submitEvidence({
    owner: OWNER,
    state: "on",
  });

describe("the gateway tombstone is a removal under the seal's lock", () => {
  // TOMBSTONE_UNSEALED
  it("is sent on a switched account: the gateway, not the seal, decides", async () => {
    const f = await setup("on");
    const result = await deleteScope(f.deps, SCOPE);
    expect(f.deleteData.tombstone).toHaveBeenCalledTimes(1);
    expect(result.steps.gateway.status).toBe("ok");
    expect(result.durable).toBe(true);
    // Only the write that adds data stays closed.
    await expect(f.seal.commit(async () => undefined)).rejects.toBeInstanceOf(
      LegacyWriteRefusedError,
    );
  });

  it("runs on an unswitched account and removes the local copy", async () => {
    const f = await setup("off");
    const result = await deleteScope(f.deps, SCOPE);
    expect(result.steps.gateway.status).toBe("ok");
    expect(result.steps.local).toEqual({ status: "ok", deletedCount: 1 });
    expect(f.storage.entries).toHaveLength(0);
  });

  // TOMBSTONE_UNSEALED
  it("is a commit: an On submitted while the tombstone is in flight waits for it", async () => {
    const barrier = gate();
    const f = await setup("off", barrier.opened);
    const deleting = deleteScope(f.deps, SCOPE);
    await vi.waitFor(() => expect(f.deleteData.tombstone).toHaveBeenCalled());
    let answered = false;
    const latch = on(f.authority).then((decision) => {
      answered = true;
      return decision;
    });
    await tick();
    await tick();
    expect(answered).toBe(false);
    barrier.open();
    // Past the tombstone, the local removal is a `remove` queued behind the
    // waiting On (writer preference), so the delete finishes after the latch.
    await Promise.all([deleting, latch]);
    expect(f.storage.entries).toHaveLength(0);
  });

  it("waits behind an On that was submitted first, then goes out as a removal", async () => {
    const barrier = gate();
    const f = await setup("off");
    const write = f.seal.commit(() => barrier.opened);
    await tick();
    const latch = on(f.authority);
    await tick();
    const deleting = deleteScope(f.deps, SCOPE);
    await tick();
    expect(f.deleteData.tombstone).not.toHaveBeenCalled();
    barrier.open();
    await write;
    await latch;
    expect((await deleting).steps.gateway.status).toBe("ok");
    expect(f.deleteData.tombstone).toHaveBeenCalledTimes(1);
  });
});

describe("the local removal is a removal", () => {
  // REMOVAL_REFUSED
  it("runs on a switched account when no gateway is wired (nothing new is written)", async () => {
    const f = await setup("on");
    const result = await deleteScope({ ...f.deps, deleteData: null }, SCOPE);
    expect(result.steps.local).toEqual({ status: "ok", deletedCount: 1 });
    expect(f.storage.entries).toHaveLength(0);
  });
});
