import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import type Database from "better-sqlite3";
import { initializeDatabase } from "./index-schema.js";
import { createIndexManager } from "./index-manager.js";
import { createNodeDataStorage } from "./node-data-storage.js";
import { createDataFileEnvelope } from "@opendatalabs/vana-sdk/node";
import type { DataStoragePort } from "@opendatalabs/personal-server-ts-core/ports";
import { buildDataFilePath } from "@opendatalabs/personal-server-ts-core/storage/hierarchy";
import { buildDataBlocks } from "@opendatalabs/personal-server-ts-core/storage/blocks/build";

describe("owner import deletion ordering", () => {
  it("preserves a new import accepted after scope retirement committed", async () => {
    const root = await mkdtemp(join(tmpdir(), "import-scope-delete-"));
    const dataDir = join(root, "data");
    const db = initializeDatabase(join(root, "index.db"));
    const index = createIndexManager(db);
    const storage = createNodeDataStorage({
      indexManager: index,
      hierarchyOptions: { dataDir },
    });
    const db2 = initializeDatabase(join(root, "index.db"));
    const index2 = createIndexManager(db2);
    const concurrent = createNodeDataStorage({
      indexManager: index2,
      hierarchyOptions: { dataDir },
    });
    const scope = "github.events";
    const command = (value: string) => ({
      kind: "append" as const,
      envelope: createDataFileEnvelope(scope, "2026-10-11T00:00:00Z", {
        value,
      }),
      metadata: {},
      import: {
        authority: "local",
        owner: "owner",
        operation: value.repeat(64),
        bodySha256: value.repeat(64),
      },
    });
    try {
      const first = await storage.commitVersion!(command("a"));
      expect(first.kind).toBe("stored");
      if (first.kind !== "stored") throw new Error("Import was not stored");
      const orphan = join(dirname(first.writeResult.path), "orphan.json");
      await writeFile(orphan, "orphan");
      await storage.writeFirstSeenLedger!(scope, { accepted: "a" });
      const original = db.transaction.bind(db);
      let injected = false;
      let accepted: ReturnType<NonNullable<DataStoragePort["commitVersion"]>>;
      db.transaction = (run) => {
        const transaction = original(run);
        const wrapped = (...args: Parameters<typeof transaction>) =>
          transaction(...args);
        return Object.assign(wrapped, {
          default: transaction.default,
          deferred: transaction.deferred,
          exclusive: transaction.exclusive,
          immediate: (...args: Parameters<typeof transaction>) => {
            const result = transaction.immediate(...args);
            if (
              !injected &&
              db
                .prepare<[string], { state: string }>(
                  "SELECT state FROM owner_import_operations WHERE operation = ?",
                )
                .get("a".repeat(64))?.state === "deleted"
            ) {
              injected = true;
              accepted = concurrent.commitVersion!(command("b"));
              writeFileSync(
                join(dataDir, "first-seen", `${scope}.json`),
                JSON.stringify({ accepted: "b" }),
              );
            }
            return result;
          },
        });
      };
      expect(await storage.deleteScope(scope)).toBe(1);
      db.transaction = original;
      const added = await accepted!;
      expect(added.kind).toBe("stored");
      expect(storage.countVersions(scope)).toBe(1);
      if (added.kind !== "stored") throw new Error("Import was not stored");
      expect(
        await storage.readEnvelope(scope, added.envelope.collectedAt),
      ).toMatchObject({ data: { value: "b" } });
      await expect(readFile(orphan)).rejects.toThrow("ENOENT");
      expect(await storage.readFirstSeenLedger!(scope)).toEqual({
        accepted: "b",
      });
      expect(await storage.commitVersion!(command("b"))).toMatchObject({
        kind: "replay",
        receipt: added.receipt,
      });
      await expect(storage.commitVersion!(command("a"))).rejects.toMatchObject({
        code: 410,
      });
    } finally {
      index2.close();
      index.close();
      await rm(root, { recursive: true, force: true });
    }
  });
});

describe("owner imports beside the revision-guarded index", () => {
  const scope = "github.events";
  const command = (collectedAt: string) => ({
    kind: "append" as const,
    envelope: createDataFileEnvelope(scope, collectedAt, { value: "a" }),
    metadata: {},
    import: {
      authority: "local",
      owner: "owner",
      operation: "a".repeat(64),
      bodySha256: "b".repeat(64),
    },
  });
  let root: string;
  let db: Database.Database;
  let index: ReturnType<typeof createIndexManager>;
  let storage: DataStoragePort;

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "import-revision-index-"));
    db = initializeDatabase(join(root, "index.db"));
    index = createIndexManager(db);
    storage = createNodeDataStorage({
      indexManager: index,
      hierarchyOptions: { dataDir: join(root, "data") },
    });
  });

  afterEach(async () => {
    index.close();
    await rm(root, { recursive: true, force: true });
  });

  it("lands after the scope's current head, as an ordinary write would", async () => {
    const head = createDataFileEnvelope(scope, "2026-10-11T00:00:30.500Z", {
      value: "head",
    });
    const written = await storage.writeEnvelope(head);
    index.insert({
      fileId: null,
      path: written.relativePath,
      scope,
      collectedAt: head.collectedAt,
      sizeBytes: written.sizeBytes,
    });

    const result = await storage.commitVersion!(
      command("2026-10-11T00:00:00Z"),
    );

    expect(result.kind).toBe("stored");
    if (result.kind !== "stored") throw new Error("Import was not stored");
    expect(Date.parse(result.envelope.collectedAt)).toBeGreaterThan(
      Date.parse(head.collectedAt),
    );
    expect(index.findLatestByScope(scope)?.path).toBe(
      result.writeResult.relativePath,
    );
    expect(result.entry.casRevision).toBe(2);
  });

  it("refuses a scope the index closed for writes and keeps no operation", async () => {
    index.insert({
      fileId: null,
      path: "github/events/seed.json",
      scope,
      collectedAt: "2026-10-11T00:00:00Z",
      sizeBytes: 1,
    });
    index.closeScopeForWrites(scope);

    await expect(
      storage.commitVersion!(command("2026-10-11T00:01:00Z")),
    ).rejects.toMatchObject({
      code: 409,
      errorCode: "SCOPE_CLOSED_FOR_WRITES",
    });

    expect(
      db.prepare("SELECT COUNT(*) AS n FROM owner_import_operations").get(),
    ).toEqual({ n: 0 });
    expect(index.countByScope(scope)).toBe(1);
    await expect(
      readFile(
        buildDataFilePath(join(root, "data"), scope, "2026-10-11T00:01:00Z"),
      ),
    ).rejects.toThrow("ENOENT");
  });
});

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

  it("preserves a newly synced import when dropping a previously unsynced row", async () => {
    const command = {
      kind: "append" as const,
      envelope: createDataFileEnvelope(
        "instagram.profile",
        "2026-05-08T00:00:00Z",
        {
          username: "owner",
        },
      ),
      metadata: {},
      import: {
        authority: "local",
        owner: "owner",
        operation: "c".repeat(64),
        bodySha256: "c".repeat(64),
      },
    };
    const accepted = await storage.commitVersion!(command);
    if (accepted.kind !== "stored") throw new Error("Import was not stored");
    const path = accepted.writeResult.relativePath;
    const original = db.transaction.bind(db);
    let injected = false;
    db.transaction = (run) => {
      const transaction = original(run);
      const wrapped = (...args: Parameters<typeof transaction>) =>
        transaction(...args);
      return Object.assign(wrapped, {
        default: transaction.default,
        deferred: transaction.deferred,
        exclusive: transaction.exclusive,
        immediate: (...args: Parameters<typeof transaction>) => {
          if (!injected) {
            injected = true;
            db.prepare(
              "UPDATE data_files SET data_point_id = ? WHERE path = ?",
            ).run("synced", path);
          }
          return transaction.immediate(...args);
        },
      });
    };
    expect(await storage.dropUnsyncedEntry!(path)).toBe(false);
    db.transaction = original;
    await storage.commitVersion!({
      kind: "append",
      envelope: createDataFileEnvelope(
        "other.events",
        "2026-05-08T00:00:00Z",
        {},
      ),
      metadata: {},
    });
    expect(storage.findByDataPointId!("synced")).toMatchObject({ path });
    expect(
      await storage.readEnvelope(
        command.envelope.scope,
        accepted.envelope.collectedAt,
      ),
    ).toMatchObject({ data: { username: "owner" } });
    expect(await storage.commitVersion!(command)).toMatchObject({
      kind: "replay",
      receipt: accepted.receipt,
    });
  });

  it("preserves the index row when blob deletion fails (so a retry re-attempts)", async () => {
    await seed("file-1", "2026-05-08T00:00:00Z");
    const path = buildDataFilePath(
      dataDir,
      "instagram.profile",
      "2026-05-08T00:00:00Z",
    );
    const bytes = await readFile(path);
    await rm(path);
    await mkdir(path);
    await writeFile(join(path, "child"), "nonempty");
    try {
      await expect(storage.deleteByFileId("file-1")).rejects.toMatchObject({
        code: "ERR_FS_EISDIR",
      });
    } finally {
      await rm(path, { recursive: true, force: true });
      await writeFile(path, bytes);
    }

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
    await expect(storage.hasScopeBlocks?.(scope, collectedAt)).resolves.toBe(
      false,
    );
    await expect(
      storage.readScopeBlocks!(scope, collectedAt, { maxBytes: 1024 }),
    ).rejects.toMatchObject({ code: "block_manifest_not_found" });
  });

  it("respects maxBytes approximately and does not read or parse the raw envelope", async () => {
    const built = await writeBlocks();
    await expect(storage.hasScopeBlocks?.(scope, collectedAt)).resolves.toBe(
      true,
    );
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

describe("createNodeDataStorage.writeEnvelopeAndIndex", () => {
  const scope = "github.events";
  let root: string;
  let storage: DataStoragePort;
  let index: ReturnType<typeof createIndexManager>;

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "write-envelope-and-index-"));
    index = createIndexManager(initializeDatabase(join(root, "index.db")));
    storage = createNodeDataStorage({
      indexManager: index,
      hierarchyOptions: { dataDir: join(root, "data") },
    });
  });

  afterEach(async () => {
    index.close();
    await rm(root, { recursive: true, force: true });
  });

  it("writes the file and its row together and returns the row", async () => {
    const envelope = createDataFileEnvelope(scope, "2026-10-11T00:00:00.000Z", {
      value: "a",
    });

    const row = await storage.writeEnvelopeAndIndex!(envelope, {
      fileId: null,
      scope,
      collectedAt: envelope.collectedAt,
      dataPointId: "dp-1",
      version: 3,
    });

    expect(row).toMatchObject({ scope, dataPointId: "dp-1", version: 3 });
    expect(index.findByPath(row.path)).toEqual(row);
    expect(
      await readFile(
        buildDataFilePath(join(root, "data"), scope, envelope.collectedAt),
        "utf-8",
      ),
    ).toContain('"value"');
    expect(
      (await storage.readEnvelope(scope, envelope.collectedAt)).data,
    ).toEqual({ value: "a" });
  });

  it("never leaves a row without its file when a scope erase runs beside it", async () => {
    const envelope = createDataFileEnvelope(scope, "2026-10-11T00:00:00.000Z", {
      value: "a",
    });
    const entry = {
      fileId: null,
      scope,
      collectedAt: envelope.collectedAt,
    };

    await Promise.all([
      storage.writeEnvelopeAndIndex!(envelope, entry),
      storage.deleteScope(scope),
    ]);

    const rows = index.findByScope({ scope });
    const file = await readFile(
      buildDataFilePath(join(root, "data"), scope, envelope.collectedAt),
      "utf-8",
    ).then(
      () => true,
      () => false,
    );
    expect(rows.length > 0).toBe(file);
  });
});

describe("createNodeDataStorage.deleteVersionIfEnvelopeMissing", () => {
  const scope = "github.events";
  const collectedAt = "2026-10-11T00:00:00.000Z";
  let root: string;
  let dataDir: string;
  let storage: DataStoragePort;
  let index: ReturnType<typeof createIndexManager>;

  const replica = () => ({
    kind: "replica" as const,
    envelope: createDataFileEnvelope(scope, collectedAt, { value: "a" }),
    metadata: { schemaId: null, dataPointId: "dp-1", version: 1 },
  });

  async function storeReplica() {
    const stored = await storage.commitVersion!(replica());
    if (stored.kind !== "stored") throw new Error("not stored");
    return {
      filePath: stored.writeResult.path,
      fence: { id: stored.entry.id, path: stored.entry.path },
    };
  }

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "delete-if-missing-"));
    dataDir = join(root, "data");
    index = createIndexManager(initializeDatabase(join(root, "index.db")));
    storage = createNodeDataStorage({
      indexManager: index,
      hierarchyOptions: { dataDir },
    });
  });

  afterEach(async () => {
    index.close();
    await rm(root, { recursive: true, force: true });
  });

  it("removes the row when the envelope file is absent", async () => {
    const { filePath, fence } = await storeReplica();
    await rm(filePath);

    await expect(
      storage.deleteVersionIfEnvelopeMissing!(scope, collectedAt, fence),
    ).resolves.toBe(true);
    expect(index.findByPath(fence.path)).toBeUndefined();
  });

  it("keeps the row when the envelope file is present", async () => {
    const { fence } = await storeReplica();

    await expect(
      storage.deleteVersionIfEnvelopeMissing!(scope, collectedAt, fence),
    ).resolves.toBe(false);
    expect(index.findByPath(fence.path)).toBeDefined();
  });

  it("keeps the row when the file cannot be checked, which is not absence", async () => {
    const { filePath, fence } = await storeReplica();
    // A file where the directory should be: stat fails with ENOTDIR, not ENOENT.
    await rm(dirname(filePath), { recursive: true });
    await writeFile(dirname(filePath), "not a directory");

    await expect(
      storage.deleteVersionIfEnvelopeMissing!(scope, collectedAt, fence),
    ).rejects.toMatchObject({ code: "ENOTDIR" });
    expect(index.findByPath(fence.path)).toBeDefined();
  });

  it("keeps a version a replica write restored after the absence was seen", async () => {
    const { filePath, fence } = await storeReplica();
    await rm(filePath);
    // The caller has seen the file missing. A replica write restores it and
    // keeps the same row id, then the caller's erase runs.
    const restored = await storage.commitVersion!(replica());
    if (restored.kind !== "stored") throw new Error("not stored");
    expect(restored.entry.id).toBe(fence.id);

    await expect(
      storage.deleteVersionIfEnvelopeMissing!(scope, collectedAt, fence),
    ).resolves.toBe(false);
    expect(index.findByPath(fence.path)).toBeDefined();
    await expect(
      storage.readEnvelope(scope, collectedAt),
    ).resolves.toMatchObject({ data: { value: "a" } });
  });
});
