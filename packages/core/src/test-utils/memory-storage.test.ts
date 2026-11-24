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

describe("memory data storage scope summaries", () => {
  it("filters and pages sorted scopes while counting all matching scopes", async () => {
    const storage = createMemoryDataStorage();
    const insert = (scope: string, fileId: string, collectedAt: string) =>
      storage.insertEntry({
        scope,
        fileId,
        collectedAt,
        path: `${scope}/${fileId}.json`,
        sizeBytes: 1,
      });
    await insert("sample.z", "z", "2026-01-01T00:00:00Z");
    await insert("unrelated.a", "other", "2026-01-01T00:00:00Z");
    await insert("sample.a", "a-old", "2026-02-01T00:00:00Z");
    await insert("sample.a", "a-new", "2026-01-01T00:00:00Z");

    expect(storage.listScopes({ scopePrefix: "sample.", limit: 1 })).toEqual({
      scopes: [
        {
          scope: "sample.a",
          latestCollectedAt: "2026-01-01T00:00:00Z",
          versionCount: 2,
        },
      ],
      total: 2,
    });
    expect(
      storage.listScopes({ scopePrefix: "sample.", limit: 1, offset: 1 }),
    ).toEqual({
      scopes: [
        {
          scope: "sample.z",
          latestCollectedAt: "2026-01-01T00:00:00Z",
          versionCount: 1,
        },
      ],
      total: 2,
    });
  });

  it("finds the highest public version sharing a data point id", async () => {
    const storage = createMemoryDataStorage();
    const insert = (fileId: string, version: number, dataPointId: string) =>
      storage.insertEntry({
        scope: "sample.records",
        fileId,
        collectedAt: "2026-01-01T00:00:00Z",
        path: `sample/${fileId}.json`,
        sizeBytes: 1,
        version,
        dataPointId,
      });
    const winner = await insert("winner", 8, "target");
    await insert("later-lower-version", 4, "target");
    await insert("unrelated-higher", 9, "other");
    expect(storage.findByDataPointId("target")).toEqual(winner);
    expect(storage.findByDataPointId("missing")).toBeUndefined();
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

describe("memory data storage guarded updates", () => {
  it("does not publish or change the version for a stale index id", async () => {
    const storage = createMemoryDataStorage();
    const scope = "sample.records";
    const path = "sample/guarded.json";
    const row = await storage.insertEntry({
      scope,
      path,
      fileId: "guarded",
      collectedAt: "2026-01-01T00:00:00Z",
      sizeBytes: 1,
      version: 4,
      casRevision: 2,
    });
    expect(storage.updateDataPointId(path, "published", row.id + 1)).toBe(false);
    expect(storage.updateEntryVersion(path, 9, row.id + 1)).toBe(false);
    expect(storage.findEntry({ scope })).toMatchObject({
      dataPointId: null,
      version: 4,
      casRevision: 2,
    });

    expect(storage.updateDataPointId(path, "published", row.id)).toBe(true);
    expect(storage.updateEntryVersion(path, 9, row.id)).toBe(true);
    expect(storage.findEntry({ scope })).toMatchObject({
      dataPointId: "published",
      version: 9,
      casRevision: 2,
    });
    expect(storage.countUnsynced()).toBe(0);
  });
});

describe("memory data storage first-seen ledgers", () => {
  it("isolates nested saved values from callers and from other scopes", async () => {
    const storage = createMemoryDataStorage();
    const scope = "sample.records";
    const other = "sample.other";
    const ledger = { records: [{ id: "first" }] };
    await storage.writeFirstSeenLedger(scope, ledger);
    await storage.writeFirstSeenLedger(other, { records: [{ id: "other" }] });

    ledger.records[0]!.id = "changed after write";
    const read = (await storage.readFirstSeenLedger(scope)) as typeof ledger;
    expect(read).toEqual({ records: [{ id: "first" }] });
    read.records[0]!.id = "changed after read";
    expect(await storage.readFirstSeenLedger(scope)).toEqual({
      records: [{ id: "first" }],
    });

    await storage.deleteFirstSeenLedger(scope);
    expect(await storage.readFirstSeenLedger(scope)).toBeNull();
    expect(await storage.readFirstSeenLedger(other)).toEqual({
      records: [{ id: "other" }],
    });
  });
});
