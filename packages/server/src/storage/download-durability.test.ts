import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type * as FsPromises from "node:fs/promises";
import { mkdtemp, rm } from "node:fs/promises";
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
