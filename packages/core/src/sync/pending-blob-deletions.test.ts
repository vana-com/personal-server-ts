import { describe, expect, it, vi } from "vitest";

import {
  createMemoryPendingBlobDeletionStore,
  createPendingBlobDeletionStore,
} from "./pending-blob-deletions.js";

describe("pending blob deletion store", () => {
  it("adds, lists and removes scopes without duplicates", async () => {
    const store = createMemoryPendingBlobDeletionStore();

    await store.add("instagram.profile");
    await store.add("instagram.profile");
    await store.add("chatgpt.conversations");

    expect(await store.list()).toEqual([
      "instagram.profile",
      "chatgpt.conversations",
    ]);

    await store.remove("instagram.profile");
    await store.remove("never.added");
    expect(await store.list()).toEqual(["chatgpt.conversations"]);
  });

  it("persists through the host kv and tolerates a missing/garbage value", async () => {
    let persisted: string[] | null = null;
    const kv = {
      read: vi.fn(async () => persisted),
      write: vi.fn(async (scopes: string[]) => {
        persisted = scopes;
      }),
    };
    const store = createPendingBlobDeletionStore(kv);

    expect(await store.list()).toEqual([]);
    await store.add("a.b");
    expect(kv.write).toHaveBeenCalledWith(["a.b"]);
    expect(await store.list()).toEqual(["a.b"]);

    persisted = ["x.y", 42, null] as unknown as string[];
    expect(await store.list()).toEqual(["x.y"]);
  });

  it("serialises concurrent mutations so no marker is lost", async () => {
    // A kv whose write completes only when released, so two operations that
    // start together would both read the same snapshot without the lock.
    let persisted: string[] = [];
    const releases: Array<() => void> = [];
    const kv = {
      read: vi.fn(async () => persisted),
      write: vi.fn(
        (scopes: string[]) =>
          new Promise<void>((resolve) => {
            releases.push(() => {
              persisted = scopes;
              resolve();
            });
          }),
      ),
    };
    const store = createPendingBlobDeletionStore(kv);

    const ops = Promise.all([
      store.add("a.b"),
      store.add("c.d"),
      store.remove("a.b"),
      store.add("e.f"),
    ]);
    // Only one write is in flight at any time; release them as they appear.
    while (releases.length > 0 || kv.write.mock.calls.length < 4) {
      const release = releases.shift();
      if (release) release();
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
    await ops;

    expect(persisted).toEqual(["c.d", "e.f"]);
    expect(kv.write.mock.calls.map(([scopes]) => scopes)).toEqual([
      ["a.b"],
      ["a.b", "c.d"],
      ["c.d"],
      ["c.d", "e.f"],
    ]);
  });

  it("keeps serving after a failed operation", async () => {
    let persisted: string[] = [];
    let failNext = true;
    const store = createPendingBlobDeletionStore({
      read: async () => persisted,
      write: async (scopes) => {
        if (failNext) {
          failNext = false;
          throw new Error("disk full");
        }
        persisted = scopes;
      },
    });

    const [first, second] = await Promise.allSettled([
      store.add("a.b"),
      store.add("c.d"),
    ]);

    expect(first.status).toBe("rejected");
    expect(second.status).toBe("fulfilled");
    // The failed add never landed; the next one saw the real state.
    expect(await store.list()).toEqual(["c.d"]);
  });
});
