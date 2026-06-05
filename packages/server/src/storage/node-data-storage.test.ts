import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type Database from "better-sqlite3";
import { initializeDatabase } from "./index-schema.js";
import { createIndexManager } from "./index-manager.js";
import { createNodeDataStorage } from "./node-data-storage.js";
import { createDataFileEnvelope } from "@opendatalabs/vana-sdk/node";
import type { DataStoragePort } from "@opendatalabs/personal-server-ts-core/ports";
import { buildDataFilePath } from "@opendatalabs/personal-server-ts-core/storage/hierarchy";
import { buildDataBlocks } from "@opendatalabs/personal-server-ts-core/storage/blocks/build";
import type * as Hierarchy from "./hierarchy.js";

// Wrap the real hierarchy module so deleteDataFile can be forced to fail in one test.
// By default the spy delegates to the real implementation (happy paths unaffected).
vi.mock("./hierarchy.js", async (importOriginal) => {
  const actual = await importOriginal<typeof Hierarchy>();
  return { ...actual, deleteDataFile: vi.fn(actual.deleteDataFile) };
});
import { deleteDataFile } from "./hierarchy.js";

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

  it("preserves the index row when blob deletion fails (so a retry re-attempts)", async () => {
    await seed("file-1", "2026-05-08T00:00:00Z");
    // Force a real (non-ENOENT) blob-deletion failure for this call only.
    (deleteDataFile as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      new Error("EIO: disk failure"),
    );

    await expect(storage.deleteByFileId("file-1")).rejects.toThrow("EIO");

    // Row must survive so the next sync cycle re-attempts the delete rather than
    // advancing the cursor past an orphaned local blob.
    expect(storage.findByFileId("file-1")).toBeDefined();
    // A subsequent retry (real deleteDataFile) succeeds and removes the row.
    expect(await storage.deleteByFileId("file-1")).toBe(true);
    expect(storage.findByFileId("file-1")).toBeUndefined();
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

describe("createNodeDataStorage block sidecars", () => {
  let db: Database.Database;
  let dataDir: string;
  let storage: DataStoragePort;

  beforeEach(async () => {
    db = initializeDatabase(":memory:");
    dataDir = await mkdtemp(join(tmpdir(), "node-data-storage-block-test-"));
    storage = createNodeDataStorage({
      indexManager: createIndexManager(db),
      hierarchyOptions: { dataDir },
    });
  });

  afterEach(async () => {
    db.close();
    await rm(dataDir, { recursive: true, force: true });
  });

  const scope = "instagram.profile";
  const collectedAt = "2026-05-09T00:00:00Z";

  async function writeBlocks() {
    const built = buildDataBlocks({
      scope,
      collectedAt,
      content: Array.from({ length: 12 }, (_, index) => ({
        id: index,
        value: `value-${index}-${"x".repeat(160)}`,
      })),
      blockTargetBytes: 450,
    });

    await storage.writeBlockManifest!(
      scope,
      collectedAt,
      built.manifest,
      built.blocks,
    );

    return built;
  }

  it("writes manifest and payload files, then reads all blocks by cursor", async () => {
    const built = await writeBlocks();
    expect(built.blocks.length).toBeGreaterThan(1);

    const manifestPath = join(
      dataDir,
      "blocks",
      "instagram",
      "profile",
      collectedAt,
      "manifest.json",
    );
    expect(JSON.parse(await readFile(manifestPath, "utf-8"))).toMatchObject({
      scope,
      collectedAt,
    });

    const seen: string[] = [];
    let cursor: string | undefined;

    do {
      const page = await storage.readScopeBlocks!(scope, collectedAt, {
        cursor,
        maxBytes: 700,
      });
      seen.push(...page.blocks.map((block) => block.id));
      cursor = page.nextCursor;
    } while (cursor);

    expect(seen).toEqual(built.blocks.map((block) => block.id));
  });

  it("returns a typed not-found error when the manifest is missing", async () => {
    await expect(
      storage.readScopeBlocks!(scope, collectedAt, { maxBytes: 1024 }),
    ).rejects.toMatchObject({ code: "block_manifest_not_found" });
  });

  it("respects maxBytes approximately and does not read or parse the raw envelope", async () => {
    const built = await writeBlocks();
    await storage.writeEnvelope(
      createDataFileEnvelope(scope, collectedAt, { raw: "source" }),
    );
    await writeFile(
      buildDataFilePath(dataDir, scope, collectedAt),
      "{ this is not a valid raw envelope",
      "utf-8",
    );

    const page = await storage.readScopeBlocks!(scope, collectedAt, {
      maxBytes: 700,
    });

    expect(page.blocks.length).toBeGreaterThan(0);
    expect(page.blocks.length).toBeLessThan(built.blocks.length);
    expect(
      page.blocks.reduce((sum, block) => sum + block.sizeBytes, 0),
    ).toBeLessThan(1200);
    expect(page.nextCursor).toBeDefined();
  });
});
