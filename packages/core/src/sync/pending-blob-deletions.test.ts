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
});
