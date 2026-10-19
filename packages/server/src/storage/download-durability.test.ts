import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type * as FsPromises from "node:fs/promises";
import type * as Fs from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import type Database from "better-sqlite3";
import {
  decryptWithPassword,
  deriveScopeKey,
  type DataPointRecord,
} from "@opendatalabs/vana-sdk/browser";
import {
  downloadOne,
  type DownloadWorkerDeps,
} from "@opendatalabs/personal-server-ts-core/sync";
import { initializeDatabase } from "./index-schema.js";
import { createIndexManager, type IndexManager } from "./index-manager.js";
import { createNodeDataStorage } from "./node-data-storage.js";

const syncTrace = vi.hoisted(() => ({
  beforePublish: undefined as (() => Promise<void>) | undefined,
  events: [] as Array<
    | { kind: "file-sync"; path: string }
    | { kind: "dir-sync"; path: string }
    | { kind: "index-insert"; path: string }
  >,
}));

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof FsPromises>();
  return {
    ...actual,
    rename: async (...args: Parameters<typeof actual.rename>) => {
      await syncTrace.beforePublish?.();
      return actual.rename(...args);
    },
    open: async (...args: Parameters<typeof actual.open>) => {
      const handle = await actual.open(...args);
      const openedPath = resolve(String(args[0]));
      const stat = await handle.stat().catch(() => null);
      const isDirectory = stat?.isDirectory() ?? false;
      const originalSync = handle.sync.bind(handle);
      handle.sync = async () => {
        syncTrace.events.push({
          kind: isDirectory ? "dir-sync" : "file-sync",
          path: openedPath,
        });
        return originalSync();
      };
      return handle;
    },
  };
});

vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof Fs>();
  const paths = new Map<number, string>();
  return {
    ...actual,
    openSync: (...args: Parameters<typeof actual.openSync>) => {
      const fd = actual.openSync(...args);
      paths.set(fd, resolve(String(args[0])));
      return fd;
    },
    fsyncSync: (fd: number) => {
      const path = paths.get(fd);
      if (path) {
        syncTrace.events.push({
          kind: actual.fstatSync(fd).isDirectory() ? "dir-sync" : "file-sync",
          path,
        });
      }
      return actual.fsyncSync(fd);
    },
    closeSync: (fd: number) => {
      paths.delete(fd);
      return actual.closeSync(fd);
    },
  };
});

vi.mock("@opendatalabs/vana-sdk/browser", async (importOriginal) => ({
  ...(await importOriginal()),
  deriveScopeKey: vi.fn(),
  decryptWithPassword: vi.fn(),
}));

const scope = "instagram.profile";
const collectedAt = "2026-01-21T10:00:00Z";
const owner = "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12";
const dataPointId =
  "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

describe("sync download durability", () => {
  let db: Database.Database;
  let root: string;
  let indexManager: IndexManager;

  beforeEach(async () => {
    vi.clearAllMocks();
    syncTrace.events = [];
    syncTrace.beforePublish = undefined;
    root = await mkdtemp(join(tmpdir(), "download-durability-"));
    db = initializeDatabase(join(root, "index.db"));
    indexManager = createIndexManager(db, {
      revisionJournalDir: join(root, "cas-revisions"),
    });
    vi.mocked(deriveScopeKey).mockReturnValue(new Uint8Array(32).fill(0xbb));
  });

  afterEach(async () => {
    indexManager.close();
    await rm(root, { recursive: true, force: true });
  });

  it.each([false, true])(
    "preserves an import accepted while replica publication is paused (matching bytes: %s)",
    async (matching) => {
      const dataDir = join(root, "data");
      const storage = createNodeDataStorage({
        indexManager,
        hierarchyOptions: { dataDir },
      });
      const imported = {
        version: "1.0",
        scope,
        collectedAt,
        data: { username: "owner" },
      };
      const replica = matching
        ? imported
        : { ...imported, data: { username: "replica" } };
      vi.mocked(decryptWithPassword).mockResolvedValue(
        new TextEncoder().encode(JSON.stringify(replica)),
      );
      let reached!: () => void;
      let resume!: () => void;
      const paused = new Promise<void>((resolve) => {
        reached = resolve;
      });
      const released = new Promise<void>((resolve) => {
        resume = resolve;
      });
      syncTrace.beforePublish = async () => {
        reached();
        await released;
      };
      // On the old path the hook pauses rename after staging and lookup.
      // On the atomic path it pauses before entering the publication gate.
      const replicaStorage = {
        ...storage,
        async commitVersion(
          command: Parameters<NonNullable<typeof storage.commitVersion>>[0],
        ) {
          await syncTrace.beforePublish?.();
          return storage.commitVersion!(command);
        },
      };
      const deps = {
        storage: replicaStorage,
        storageAdapter: {
          urlForKey: () => "https://storage.invalid/blob",
          download: async () => new Uint8Array([0xde, 0xad]),
        },
        gateway: {},
        cursor: { read: async () => null, write: async () => undefined },
        masterKey: new Uint8Array(65).fill(0xaa),
        serverOwner: owner,
        logger: {
          info: () => undefined,
          warn: () => undefined,
          error: () => undefined,
          debug: () => undefined,
        },
      } as unknown as DownloadWorkerDeps;
      const record = {
        id: dataPointId,
        ownerAddress: owner,
        scope,
        dataHash: `0x${"11".repeat(32)}`,
        metadataHash: `0x${"22".repeat(32)}`,
        expectedVersion: "7",
        addedAt: collectedAt,
      } as DataPointRecord;
      const downloading = downloadOne(deps, record).then(
        (result) => ({ result, error: undefined }),
        (error: unknown) => ({ result: undefined, error }),
      );
      await paused;
      const command = {
        kind: "append" as const,
        envelope: imported,
        metadata: {},
        import: {
          authority: "local",
          owner,
          operation: "a".repeat(64),
          bodySha256: "b".repeat(64),
        },
      };
      const accepted = await storage.commitVersion!(command);
      if (accepted.kind !== "stored") throw new Error("Import was not stored");
      const bytes = await readFile(accepted.writeResult.path);
      const entry = indexManager.findByPath(accepted.entry.path);
      expect(accepted.envelope.collectedAt).toBe(collectedAt);
      resume();
      const outcome = await downloading;
      syncTrace.beforePublish = undefined;
      expect(await readFile(accepted.writeResult.path)).toEqual(bytes);
      expect(storage.countVersions(scope)).toBe(1);
      if (matching) {
        expect(outcome.error).toBeUndefined();
        expect(indexManager.findByPath(accepted.entry.path)).toEqual({
          ...entry,
          dataPointId,
          version: 7,
        });
        await expect(downloadOne(deps, record)).resolves.toBeNull();
        // A pre-existing, byte-identical owner copy also keeps skip semantics.
        await storage.updateDataPointId(accepted.entry.path, null);
        await storage.updateEntryVersion(accepted.entry.path, 1);
        await expect(downloadOne(deps, record)).resolves.toBeNull();
        expect(indexManager.findByPath(accepted.entry.path)).toEqual({
          ...entry,
          dataPointId,
          version: 7,
        });
      } else {
        expect(outcome.error).toBeInstanceOf(Error);
        expect(indexManager.findByPath(accepted.entry.path)).toEqual(entry);
        // A later retry must also validate bytes before adopting metadata.
        await expect(downloadOne(deps, record)).rejects.toThrow(
          "Stored envelope conflicts",
        );
        expect(indexManager.findByPath(accepted.entry.path)).toEqual(entry);
      }
      expect(await storage.commitVersion!(command)).toMatchObject({
        kind: "replay",
        receipt: accepted.receipt,
      });
      expect(await readFile(accepted.writeResult.path)).toEqual(bytes);
    },
  );

  it("syncs the envelope and new data ancestors before committing the index row", async () => {
    const dataDir = join(root, "new", "nested", "data");
    const envelope = {
      version: "1.0",
      scope,
      collectedAt,
      schemaId: "instagram-profile-v1",
      producer: "pdpp-projector",
      producer_provenance: {
        projector_version: "1",
        declaration_digest: "sha256:declaration",
        inputs: [{ stream: "profile", changes_since_token: "opaque" }],
        payload_sha256: "a".repeat(64),
      },
      data: {
        username: "testuser",
        items: Array.from({ length: 80 }, (_, index) => ({
          id: index,
          text: `downloaded block payload ${index} ${"x".repeat(160)}`,
        })),
      },
    };
    vi.mocked(decryptWithPassword).mockResolvedValue(
      new TextEncoder().encode(JSON.stringify(envelope)),
    );

    const tracedIndexManager: IndexManager = {
      ...indexManager,
      insert(entry) {
        syncTrace.events.push({ kind: "index-insert", path: entry.path });
        return indexManager.insert(entry);
      },
    };
    const storage = createNodeDataStorage({
      indexManager: tracedIndexManager,
      hierarchyOptions: { dataDir, blockTargetBytes: 450 },
    });
    const deps = {
      storage,
      storageAdapter: {
        urlForKey: () => "https://storage.invalid/blob",
        download: async () => new Uint8Array([0xde, 0xad]),
      },
      gateway: {},
      cursor: { read: async () => null, write: async () => undefined },
      masterKey: new Uint8Array(65).fill(0xaa),
      serverOwner: owner,
      logger: {
        info: () => undefined,
        warn: () => undefined,
        error: () => undefined,
        debug: () => undefined,
      },
    } as unknown as DownloadWorkerDeps;
    const record = {
      id: dataPointId,
      ownerAddress: owner,
      scope,
      dataHash: `0x${"11".repeat(32)}`,
      metadataHash: `0x${"22".repeat(32)}`,
      expectedVersion: "7",
      addedAt: collectedAt,
    } as DataPointRecord;

    const result = await downloadOne(deps, record);
    const entry = indexManager.findByDataPointId(dataPointId);

    expect(result?.path).toBe("instagram/profile/2026-01-21T10-00-00Z.json");
    expect(entry).toMatchObject({
      dataPointId,
      version: 7,
      producer: "pdpp-projector",
      producerProvenance: JSON.stringify(envelope.producer_provenance),
    });
    await expect(
      storage.readEnvelope(scope, collectedAt),
    ).resolves.toMatchObject(envelope);
    await expect(
      storage.readScopeBlocks!(scope, collectedAt, { maxBytes: 900 }),
    ).resolves.toMatchObject({
      scope,
      collectedAt,
      blocks: expect.arrayContaining([
        expect.objectContaining({ id: "block-000001" }),
      ]),
    });

    const indexInsertAt = syncTrace.events.findIndex(
      (event) => event.kind === "index-insert",
    );
    expect(indexInsertAt).toBeGreaterThanOrEqual(0);
    const envelopePath = join(
      dataDir,
      "instagram",
      "profile",
      "2026-01-21T10-00-00Z.json",
    );
    const eventsBeforeInsert = syncTrace.events.slice(0, indexInsertAt);
    const syncedDirectoriesBeforeInsert = new Set(
      eventsBeforeInsert
        .filter((event) => event.kind === "dir-sync")
        .map((event) => event.path),
    );
    const envelopeFileSyncedBeforeInsert = eventsBeforeInsert.some(
      (event) =>
        event.kind === "file-sync" &&
        dirname(event.path) === dirname(envelopePath) &&
        event.path.includes("2026-01-21T10-00-00Z.json"),
    );
    const expectedSyncedDirectories = collectDataDirectoriesCreatedByDownload(
      root,
      dataDir,
      dirname(envelopePath),
    );

    expect(envelopeFileSyncedBeforeInsert).toBe(true);
    expect(
      expectedSyncedDirectories
        .filter((path) => !syncedDirectoriesBeforeInsert.has(path))
        .map((path) => relative(root, path)),
    ).toEqual([]);
  });
});

function collectDataDirectoriesCreatedByDownload(
  existingRoot: string,
  dataDir: string,
  envelopeDir: string,
): string[] {
  const paths: string[] = [];
  let current = resolve(dataDir);
  const stop = resolve(existingRoot);
  while (current !== stop) {
    paths.push(current);
    current = dirname(current);
  }
  paths.push(stop);
  current = resolve(join(dataDir, scope.split(".")[0]!));
  const finalDir = resolve(envelopeDir);
  while (true) {
    paths.push(current);
    if (current === finalDir) break;
    current = join(current, "profile");
  }
  return paths;
}
