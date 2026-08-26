import { describe, expect, it, vi } from "vitest";

import type { PendingBlobDeletion } from "../ports/index.js";
import {
  createMemoryPendingBlobDeletionStore,
  createPendingBlobDeletionStore,
  normalizePendingBlobDeletions,
} from "./pending-blob-deletions.js";

const A1 = { scope: "instagram.profile", version: "1" };
const A2 = { scope: "instagram.profile", version: "2" };
const B7 = { scope: "chatgpt.conversations", version: "7" };

describe("pending blob deletion store", () => {
  it("adds, lists and removes exact keys without duplicates", async () => {
    const store = createMemoryPendingBlobDeletionStore();

    await store.add([A1, A1, A2]);
    await store.add([B7, A2]);

    expect(await store.list()).toEqual([A1, A2, B7]);

    await store.remove([A1, { scope: "never.added", version: "1" }]);
    expect(await store.list()).toEqual([A2, B7]);
  });

  it("keeps a version-less marker distinct from exact keys of the same scope", async () => {
    const store = createMemoryPendingBlobDeletionStore();
    const unresolved = { scope: "instagram.profile", version: null };

    await store.add([unresolved, A1]);
    await store.remove([unresolved]);

    expect(await store.list()).toEqual([A1]);
  });

  it("persists through the host kv and tolerates a missing/garbage value", async () => {
    let persisted: PendingBlobDeletion[] | null = null;
    const kv = {
      read: vi.fn(async () => persisted),
      write: vi.fn(async (keys: PendingBlobDeletion[]) => {
        persisted = keys;
      }),
    };
    const store = createPendingBlobDeletionStore(kv);

    expect(await store.list()).toEqual([]);
    await store.add([A1]);
    expect(kv.write).toHaveBeenCalledWith([A1]);
    expect(await store.list()).toEqual([A1]);

    persisted = [
      A2,
      42,
      null,
      { nope: true },
    ] as unknown as PendingBlobDeletion[];
    expect(await store.list()).toEqual([A2]);
  });

  it("normalises the pre-key format (whole scopes) into version-less markers", () => {
    expect(
      normalizePendingBlobDeletions(["a.b", { scope: "c.d", version: "3" }]),
    ).toEqual([
      { scope: "a.b", version: null },
      { scope: "c.d", version: "3" },
    ]);
    expect(normalizePendingBlobDeletions({ scopes: [] })).toEqual([]);
  });

  it("keeps well-formed range markers and drops malformed ranges", () => {
    expect(
      normalizePendingBlobDeletions([
        { scope: "a.b", version: null, range: { from: "16", to: "40" } },
        { scope: "a.b", version: null, range: { from: "9", to: "2" } },
        { scope: "a.b", version: null, range: { from: "x", to: "2" } },
      ]),
    ).toEqual([
      { scope: "a.b", version: null, range: { from: "16", to: "40" } },
      { scope: "a.b", version: null },
      { scope: "a.b", version: null },
    ]);
  });

  it("treats ranges with different bounds as different markers", async () => {
    const store = createMemoryPendingBlobDeletionStore();
    const r1 = { scope: "a.b", version: null, range: { from: "1", to: "9" } };
    const r2 = { scope: "a.b", version: null, range: { from: "5", to: "9" } };
    await store.add([r1, r1, r2]);
    expect(await store.list()).toEqual([r1, r2]);
    await store.remove([r1]);
    expect(await store.list()).toEqual([r2]);
  });

  it("serialises concurrent mutations so no marker is lost", async () => {
    // A kv whose write completes only when released, so two operations that
    // start together would both read the same snapshot without the lock.
    let persisted: PendingBlobDeletion[] = [];
    const releases: Array<() => void> = [];
    const kv = {
      read: vi.fn(async () => persisted),
      write: vi.fn(
        (keys: PendingBlobDeletion[]) =>
          new Promise<void>((resolve) => {
            releases.push(() => {
              persisted = keys;
              resolve();
            });
          }),
      ),
    };
    const store = createPendingBlobDeletionStore(kv);

    const ops = Promise.all([
      store.add([A1]),
      store.add([B7]),
      store.remove([A1]),
      store.add([A2]),
    ]);
    // Only one write is in flight at any time; release them as they appear.
    while (releases.length > 0 || kv.write.mock.calls.length < 4) {
      const release = releases.shift();
      if (release) release();
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
    await ops;

    expect(persisted).toEqual([B7, A2]);
    expect(kv.write.mock.calls.map(([keys]) => keys)).toEqual([
      [A1],
      [A1, B7],
      [B7],
      [B7, A2],
    ]);
  });

  it("keeps serving after a failed operation", async () => {
    let persisted: PendingBlobDeletion[] = [];
    let failNext = true;
    const store = createPendingBlobDeletionStore({
      read: async () => persisted,
      write: async (keys) => {
        if (failNext) {
          failNext = false;
          throw new Error("disk full");
        }
        persisted = keys;
      },
    });

    const [first, second] = await Promise.allSettled([
      store.add([A1]),
      store.add([B7]),
    ]);

    expect(first.status).toBe("rejected");
    expect(second.status).toBe("fulfilled");
    expect(await store.list()).toEqual([B7]);
  });
});
