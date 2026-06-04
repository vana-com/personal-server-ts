import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type Database from "better-sqlite3";
import { initializeDatabase } from "./index-schema.js";
import { createIndexManager } from "./index-manager.js";
import { createNodeDataStorage } from "./node-data-storage.js";
import { createDataFileEnvelope } from "@opendatalabs/vana-sdk/node";
import type { DataStoragePort } from "@opendatalabs/personal-server-ts-core/ports";

describe("createNodeDataStorage.deleteByFileId", () => {
  let db: Database.Database;
  let dataDir: string;
  let storage: DataStoragePort;

  beforeEach(async () => {
    db = initializeDatabase(":memory:");
    dataDir = await mkdtemp(join(tmpdir(), "node-data-storage-test-"));
    storage = createNodeDataStorage({
      indexManager: createIndexManager(db),
      hierarchyOptions: { dataDir },
    });
  });

  afterEach(async () => {
    db.close();
    await rm(dataDir, { recursive: true, force: true });
  });

  async function seed(fileId: string, collectedAt: string) {
    const envelope = createDataFileEnvelope("instagram.profile", collectedAt, {
      username: fileId,
    });
    const write = await storage.writeEnvelope(envelope);
    await storage.insertEntry({
      fileId,
      path: write.relativePath,
      scope: envelope.scope,
      collectedAt: envelope.collectedAt,
      sizeBytes: write.sizeBytes,
    });
  }

  it("removes the index row and the blob for the matching version only", async () => {
    await seed("file-1", "2026-05-08T00:00:00Z");
    await seed("file-2", "2026-05-09T00:00:00Z");

    expect(await storage.deleteByFileId("file-2")).toBe(true);

    expect(storage.countVersions("instagram.profile")).toBe(1);
    expect(storage.findByFileId("file-2")).toBeUndefined();
    // The other version's index row and blob survive.
    expect(storage.findByFileId("file-1")).toBeDefined();
    await expect(
      storage.readEnvelope("instagram.profile", "2026-05-08T00:00:00Z"),
    ).resolves.toBeDefined();
    // The deleted version's blob is gone.
    await expect(
      storage.readEnvelope("instagram.profile", "2026-05-09T00:00:00Z"),
    ).rejects.toThrow();
  });

  it("returns false (no-op) for an unknown fileId", async () => {
    expect(await storage.deleteByFileId("nope")).toBe(false);
  });

  it("is idempotent when the blob is already gone (no throw)", async () => {
    await seed("file-1", "2026-05-08T00:00:00Z");
    // First delete removes row + blob.
    expect(await storage.deleteByFileId("file-1")).toBe(true);
    // Re-seed the index row only, pointing at a now-missing blob, then delete again.
    await storage.insertEntry({
      fileId: "file-1",
      path: "instagram/profile/2026-05-08T00:00:00Z.json",
      scope: "instagram.profile",
      collectedAt: "2026-05-08T00:00:00Z",
      sizeBytes: 1,
    });
    await expect(storage.deleteByFileId("file-1")).resolves.toBe(true);
  });
});
