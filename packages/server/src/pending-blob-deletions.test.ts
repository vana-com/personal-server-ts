import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { createFilePendingBlobDeletionStore } from "./pending-blob-deletions.js";

describe("createFilePendingBlobDeletionStore", () => {
  let dir: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "pending-blob-deletions-"));
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("starts empty when the file does not exist", async () => {
    const store = createFilePendingBlobDeletionStore(
      join(dir, "nested", "pending-blob-deletions.json"),
    );
    expect(await store.list()).toEqual([]);
  });

  it("persists markers to disk and survives a fresh store instance", async () => {
    const path = join(dir, "pending-blob-deletions.json");
    const store = createFilePendingBlobDeletionStore(path);

    await store.add("instagram.profile");
    await store.add("chatgpt.conversations");
    await store.remove("instagram.profile");

    expect(JSON.parse(await readFile(path, "utf8"))).toEqual({
      version: 1,
      scopes: ["chatgpt.conversations"],
    });
    expect(await createFilePendingBlobDeletionStore(path).list()).toEqual([
      "chatgpt.conversations",
    ]);
  });

  it("does not lose markers when a delete and a retry mutate the file concurrently", async () => {
    const path = join(dir, "pending-blob-deletions.json");
    const store = createFilePendingBlobDeletionStore(path);
    await store.add("retrying.scope");

    // A retry clearing its marker while two deletes record theirs: every
    // operation is a read-modify-write of the same file.
    await Promise.all([
      store.remove("retrying.scope"),
      store.add("first.scope"),
      store.add("second.scope"),
      store.add("first.scope"),
    ]);

    expect(await store.list()).toEqual(["first.scope", "second.scope"]);
    expect(JSON.parse(await readFile(path, "utf8"))).toEqual({
      version: 1,
      scopes: ["first.scope", "second.scope"],
    });
  });
});
