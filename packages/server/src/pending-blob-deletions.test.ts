import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { createFilePendingBlobDeletionStore } from "./pending-blob-deletions.js";

const A1 = { scope: "instagram.profile", version: "1" };
const A2 = { scope: "instagram.profile", version: "2" };
const B7 = { scope: "chatgpt.conversations", version: "7" };

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

  it("persists exact keys to disk and survives a fresh store instance", async () => {
    const path = join(dir, "pending-blob-deletions.json");
    const store = createFilePendingBlobDeletionStore(path);

    await store.add([A1, B7]);
    await store.remove([A1]);

    expect(JSON.parse(await readFile(path, "utf8"))).toEqual({
      version: 2,
      keys: [B7],
      planned: {},
    });
    expect(await createFilePendingBlobDeletionStore(path).list()).toEqual([B7]);
  });

  it("keeps each marker's tombstone finality gate across a fresh store instance", async () => {
    const path = join(dir, "pending-blob-deletions.json");
    const gated = { ...A2, tombstoneVersion: "4" };
    const range = {
      scope: "instagram.profile",
      version: null,
      range: { from: "1", to: "4" },
      tombstoneVersion: "4",
    };
    await createFilePendingBlobDeletionStore(path).add([gated, range]);

    expect(await createFilePendingBlobDeletionStore(path).list()).toEqual([
      gated,
      range,
    ]);
  });

  it("keeps the planned watermark on disk next to the keys, and reads files without one", async () => {
    const path = join(dir, "pending-blob-deletions.json");
    await writeFile(path, JSON.stringify({ version: 2, keys: [B7] }));
    const store = createFilePendingBlobDeletionStore(path);
    expect(await store.plannedThrough!("instagram.profile")).toBeNull();

    const tail = {
      scope: "instagram.profile",
      version: null,
      range: { from: "16", to: "40" },
    };
    await store.enqueue!("instagram.profile", [tail], "40");
    await store.remove([tail]);

    const fresh = createFilePendingBlobDeletionStore(path);
    expect(await fresh.plannedThrough!("instagram.profile")).toBe("40");
    expect(await fresh.list()).toEqual([B7]);
  });

  it("reads a version-1 file of whole scopes as version-less markers", async () => {
    const path = join(dir, "pending-blob-deletions.json");
    await writeFile(
      path,
      JSON.stringify({ version: 1, scopes: ["instagram.profile"] }),
    );

    expect(await createFilePendingBlobDeletionStore(path).list()).toEqual([
      { scope: "instagram.profile", version: null },
    ]);
  });

  it("does not lose markers when a delete and a retry mutate the file concurrently", async () => {
    const path = join(dir, "pending-blob-deletions.json");
    const store = createFilePendingBlobDeletionStore(path);
    await store.add([B7]);

    // A retry clearing its key while two deletes record theirs: every
    // operation is a read-modify-write of the same file.
    await Promise.all([
      store.remove([B7]),
      store.add([A1]),
      store.add([A2]),
      store.add([A1]),
    ]);

    expect(await store.list()).toEqual([A1, A2]);
    expect(JSON.parse(await readFile(path, "utf8"))).toEqual({
      version: 2,
      keys: [A1, A2],
      planned: {},
    });
  });
});
