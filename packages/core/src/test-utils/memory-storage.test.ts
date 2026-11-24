import { describe, expect, it } from "vitest";
import { createMemoryDataStorage } from "./memory-storage.js";

describe("memory data storage findEntry", () => {
  it("answers another scope's file id as a missing one", async () => {
    const storage = createMemoryDataStorage();
    for (const [scope, fileId] of [
      ["chatgpt.conversations", "file-chatgpt"],
      ["youtube.history", "file-youtube"],
    ] as const) {
      const entry = await storage.insertEntry({
        fileId,
        path: `${scope}/2026-11-01.json`,
        scope,
        collectedAt: "2026-11-01T00:00:00Z",
        sizeBytes: 10,
      });
      expect(entry.fileId).toBe(fileId);
    }
    const own = storage.findEntry({
      scope: "chatgpt.conversations",
      fileId: "file-chatgpt",
    });
    expect(own?.scope).toBe("chatgpt.conversations");
    expect(
      storage.findEntry({
        scope: "chatgpt.conversations",
        fileId: "file-youtube",
      }),
    ).toBeUndefined();
    expect(
      storage.findEntry({ scope: "chatgpt.conversations", fileId: "nope" }),
    ).toBeUndefined();
  });
});

describe("memory data storage index projections", () => {
  it("pages unsynced rows by increasing index id across a synced row", async () => {
    const storage = createMemoryDataStorage();
    const scope = "sample.records";
    const collectedAt = "2026-01-01T00:00:00Z";
    const insert = (fileId: string, dataPointId?: string) =>
      storage.insertEntry({
        fileId,
        scope,
        collectedAt,
        path: `sample/${fileId}.json`,
        sizeBytes: 1,
        ...(dataPointId === undefined ? {} : { dataPointId }),
      });
    const first = await insert("one");
    await insert("two", "published-two");
    const third = await insert("three");
    expect(storage.findUnsyncedPage({ afterId: 0, limit: 1 })).toEqual([first]);
    expect(storage.findUnsyncedPage({ afterId: first.id, limit: 1 })).toEqual([
      third,
    ]);
    expect(storage.findUnsyncedPage({ afterId: third.id, limit: 1 })).toEqual(
      [],
    );
  });

  it("lists versions by CAS revision rather than public version or collection time", async () => {
    const storage = createMemoryDataStorage();
    const scope = "sample.records";
    const oldRevision = await storage.insertEntry({
      fileId: "late",
      path: "sample/late.json",
      scope,
      collectedAt: "2026-02-01T00:00:00Z",
      sizeBytes: 1,
      version: 99,
      casRevision: 1,
    });
    const newRevision = await storage.insertEntry({
      fileId: "early",
      path: "sample/early.json",
      scope,
      collectedAt: "2026-01-01T00:00:00Z",
      sizeBytes: 1,
      version: 2,
      casRevision: 2,
    });
    expect(storage.listVersions(scope, { limit: 2, offset: 0 })).toEqual([
      newRevision,
      oldRevision,
    ]);
    expect(storage.listVersions(scope, { limit: 1, offset: 1 })).toEqual([
      oldRevision,
    ]);
  });
});
