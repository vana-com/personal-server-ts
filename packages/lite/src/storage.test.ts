import { describe, expect, it, vi } from "vitest";
import type {
  DataBlockManifest,
  DataScopeBlock,
} from "@opendatalabs/personal-server-ts-core/storage/blocks";
import { createDataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import {
  createMemoryPsLiteStorage,
  createMemoryPsLiteDataFileStore,
  createMemoryPsLitePersistence,
} from "./test-support/memory.js";
import {
  createPersistentPsLiteStorage,
  type PsLiteDataFileStore,
} from "./storage.js";
import { previewEnvelopeValue } from "./storage-utils.js";

describe("createPersistentPsLiteStorage", () => {
  it("bounds in-memory previews by traversal work for container-heavy envelopes", () => {
    const envelope = createDataFileEnvelope(
      "chatgpt.conversations",
      "2026-05-08T00:00:00.000Z",
      { items: Array.from({ length: 50_000 }, () => ({})) },
    );

    const preview = previewEnvelopeValue(envelope, 100_000);

    expect(preview.truncated).toBe(true);
    expect(preview.text.length).toBeLessThanOrEqual(100_000);
  });

  it("leaves custom file stores without bounded previews on the core fallback path", async () => {
    const persistence = createMemoryPsLitePersistence();
    const files = new Map<string, ReturnType<typeof createDataFileEnvelope>>();
    const readEnvelope = vi.fn(async (path: string) => files.get(path) ?? null);
    const dataFileStore: PsLiteDataFileStore = {
      kind: "opfs",
      readEnvelope,
      async writeEnvelope(path, envelope) {
        files.set(path, envelope);
        return new TextEncoder().encode(JSON.stringify(envelope)).byteLength;
      },
      async deleteEnvelope(path) {
        files.delete(path);
      },
    };
    const storage = await createPersistentPsLiteStorage(
      { kind: "custom" },
      persistence,
      dataFileStore,
    );
    const envelope = createDataFileEnvelope(
      "notes.profile",
      "2026-05-08T00:00:00.000Z",
      { text: "x".repeat(10_000) },
    );

    const write = await storage.writeEnvelope(envelope);
    expect(write.sizeBytes).toBeGreaterThan(1_000);
    await storage.insertEntry({
      fileId: "file-1",
      path: write.relativePath,
      scope: envelope.scope,
      collectedAt: envelope.collectedAt,
      sizeBytes: write.sizeBytes,
    });

    expect(storage.readEnvelopePreview).toBeUndefined();
    expect(readEnvelope).not.toHaveBeenCalled();
  });

  it("persists envelopes and index entries across storage reloads", async () => {
    const persistence = createMemoryPsLitePersistence();
    const storage = await createPersistentPsLiteStorage(
      { kind: "indexeddb" },
      persistence,
    );
    const envelope = createDataFileEnvelope(
      "instagram.profile",
      "2026-05-08T00:00:00.000Z",
      { username: "test_user" },
    );

    const write = await storage.writeEnvelope(envelope);
    await storage.insertEntry({
      fileId: "file-1",
      path: write.relativePath,
      scope: envelope.scope,
      collectedAt: envelope.collectedAt,
      sizeBytes: write.sizeBytes,
    });

    const reloaded = await createPersistentPsLiteStorage(
      { kind: "indexeddb" },
      persistence,
    );

    expect(reloaded.findEntry({ scope: "instagram.profile" })).toMatchObject({
      fileId: "file-1",
      scope: "instagram.profile",
      collectedAt: "2026-05-08T00:00:00.000Z",
    });
    await expect(
      reloaded.readEnvelope("instagram.profile", "2026-05-08T00:00:00.000Z"),
    ).resolves.toMatchObject({
      data: { username: "test_user" },
    });
  });

  it("persists scope deletion", async () => {
    const persistence = createMemoryPsLitePersistence();
    const storage = await createPersistentPsLiteStorage(
      { kind: "indexeddb" },
      persistence,
    );
    const envelope = createDataFileEnvelope(
      "instagram.profile",
      "2026-05-08T00:00:00.000Z",
      { username: "test_user" },
    );

    const write = await storage.writeEnvelope(envelope);
    await storage.insertEntry({
      fileId: null,
      path: write.relativePath,
      scope: envelope.scope,
      collectedAt: envelope.collectedAt,
      sizeBytes: write.sizeBytes,
    });
    await storage.deleteScope("instagram.profile");

    const reloaded = await createPersistentPsLiteStorage(
      { kind: "indexeddb" },
      persistence,
    );

    expect(reloaded.countVersions("instagram.profile")).toBe(0);
    expect(reloaded.findEntry({ scope: "instagram.profile" })).toBeUndefined();
  });

  it("deletes a single version by fileId (entry + blob) and no-ops on unknown id", async () => {
    const persistence = createMemoryPsLitePersistence();
    const storage = await createPersistentPsLiteStorage(
      { kind: "indexeddb" },
      persistence,
    );
    // Two versions of the same scope; only one is deleted.
    const keep = createDataFileEnvelope(
      "instagram.profile",
      "2026-05-08T00:00:00.000Z",
      { username: "keep" },
    );
    const drop = createDataFileEnvelope(
      "instagram.profile",
      "2026-05-09T00:00:00.000Z",
      { username: "drop" },
    );
    for (const [index, envelope] of [keep, drop].entries()) {
      const write = await storage.writeEnvelope(envelope);
      await storage.insertEntry({
        fileId: `file-${index + 1}`,
        path: write.relativePath,
        scope: envelope.scope,
        collectedAt: envelope.collectedAt,
        sizeBytes: write.sizeBytes,
      });
    }

    expect(await storage.deleteByFileId("file-2")).toBe(true);
    // Unknown fileId is a no-op.
    expect(await storage.deleteByFileId("file-unknown")).toBe(false);

    const reloaded = await createPersistentPsLiteStorage(
      { kind: "indexeddb" },
      persistence,
    );
    expect(reloaded.countVersions("instagram.profile")).toBe(1);
    expect(
      reloaded.findEntry({ scope: "instagram.profile", fileId: "file-2" }),
    ).toBeUndefined();
    // The other version (and its blob) survive.
    expect(
      reloaded.findEntry({ scope: "instagram.profile", fileId: "file-1" }),
    ).toBeDefined();
    await expect(
      reloaded.readEnvelope("instagram.profile", "2026-05-08T00:00:00.000Z"),
    ).resolves.toBeDefined();
  });

  it("summarizes persisted scopes with latest collection time and version count", async () => {
    const persistence = createMemoryPsLitePersistence();
    const storage = await createPersistentPsLiteStorage(
      { kind: "indexeddb" },
      persistence,
    );
    const envelopes = [
      createDataFileEnvelope("instagram.profile", "2026-05-08T00:00:00.000Z", {
        username: "first",
      }),
      createDataFileEnvelope("instagram.profile", "2026-05-09T00:00:00.000Z", {
        username: "second",
      }),
      createDataFileEnvelope("spotify.profile", "2026-05-07T00:00:00.000Z", {
        username: "music",
      }),
    ];

    for (const [index, envelope] of envelopes.entries()) {
      const write = await storage.writeEnvelope(envelope);
      await storage.insertEntry({
        fileId: `file-${index + 1}`,
        path: write.relativePath,
        scope: envelope.scope,
        collectedAt: envelope.collectedAt,
        sizeBytes: write.sizeBytes,
      });
    }

    const reloaded = await createPersistentPsLiteStorage(
      { kind: "indexeddb" },
      persistence,
    );

    expect(reloaded.listScopes({ scopePrefix: "instagram." })).toEqual({
      scopes: [
        {
          scope: "instagram.profile",
          latestCollectedAt: "2026-05-09T00:00:00.000Z",
          versionCount: 2,
        },
      ],
      total: 1,
    });
  });

  it("stores envelope JSON in the file store and metadata in persistence", async () => {
    const persistence = createMemoryPsLitePersistence();
    const fileStore = createMemoryPsLiteDataFileStore("opfs");
    const storage = await createPersistentPsLiteStorage(
      { kind: "indexeddb" },
      persistence,
      fileStore,
    );
    const envelope = createDataFileEnvelope(
      "instagram.profile",
      "2026-05-08T00:00:00.000Z",
      { username: "opfs_user" },
    );

    const write = await storage.writeEnvelope(envelope);
    await storage.insertEntry({
      fileId: "file-1",
      path: write.relativePath,
      scope: envelope.scope,
      collectedAt: envelope.collectedAt,
      sizeBytes: write.sizeBytes,
    });

    await expect(
      fileStore.readEnvelope(
        "data/instagram.profile/2026-05-08T00:00:00.000Z.json",
      ),
    ).resolves.toMatchObject({ data: { username: "opfs_user" } });
    await expect(persistence.read()).resolves.toMatchObject({
      envelopes: [],
      entries: [{ path: write.relativePath }],
    });
    expect(
      (
        storage as typeof storage & {
          capabilities?: { files: string; metadata: string };
        }
      ).capabilities,
    ).toMatchObject({ metadata: "indexeddb", files: "opfs" });
  });

  it("persists sync index updates", async () => {
    const persistence = createMemoryPsLitePersistence();
    const storage = await createPersistentPsLiteStorage(
      { kind: "indexeddb" },
      persistence,
    );
    const envelope = createDataFileEnvelope(
      "instagram.profile",
      "2026-05-08T00:00:00.000Z",
      { username: "unsynced_user" },
    );
    const write = await storage.writeEnvelope(envelope);
    await storage.insertEntry({
      fileId: null,
      path: write.relativePath,
      scope: envelope.scope,
      collectedAt: envelope.collectedAt,
      sizeBytes: write.sizeBytes,
    });

    expect(storage.findUnsynced()).toHaveLength(1);
    expect(
      await storage.updateFileId(write.relativePath, "file-synced-1"),
    ).toBe(true);

    const reloaded = await createPersistentPsLiteStorage(
      { kind: "indexeddb" },
      persistence,
    );

    expect(reloaded.findUnsynced()).toEqual([]);
    expect(reloaded.findByFileId("file-synced-1")).toMatchObject({
      scope: "instagram.profile",
      fileId: "file-synced-1",
    });
  });

  it("serializes overlapping index persistence so file id updates win", async () => {
    const persistence = createMemoryPsLitePersistence();
    const storage = await createPersistentPsLiteStorage(
      { kind: "indexeddb" },
      persistence,
    );
    const envelope = createDataFileEnvelope(
      "instagram.profile",
      "2026-05-08T00:00:00.000Z",
      { username: "race_user" },
    );
    const write = await storage.writeEnvelope(envelope);

    const inserted = storage.insertEntry({
      fileId: null,
      path: write.relativePath,
      scope: envelope.scope,
      collectedAt: envelope.collectedAt,
      sizeBytes: write.sizeBytes,
    });
    const updated = storage.updateFileId(write.relativePath, "file-synced-1");
    await inserted;
    await updated;

    const reloaded = await createPersistentPsLiteStorage(
      { kind: "indexeddb" },
      persistence,
    );

    expect(reloaded.findByFileId("file-synced-1")).toMatchObject({
      scope: "instagram.profile",
      fileId: "file-synced-1",
    });
    expect(reloaded.findUnsynced()).toEqual([]);
  });

  it("persists IndexedDB fallback block sidecars across storage reloads", async () => {
    const persistence = createMemoryPsLitePersistence();
    const storage = await createPersistentPsLiteStorage(
      { kind: "indexeddb" },
      persistence,
    );
    const { manifest, blocks } = blockFixture(
      "instagram.profile",
      "2026-05-08T00:00:00.000Z",
      2,
    );

    await storage.writeBlockManifest?.(
      manifest.scope,
      manifest.collectedAt,
      manifest,
      blocks,
    );

    const reloaded = await createPersistentPsLiteStorage(
      { kind: "indexeddb" },
      persistence,
    );
    await expect(
      reloaded.readScopeBlocks?.(
        "instagram.profile",
        "2026-05-08T00:00:00.000Z",
        { maxBytes: 1_000 },
      ),
    ).resolves.toMatchObject({
      scope: "instagram.profile",
      blocks: [{ value: { index: 0 } }, { value: { index: 1 } }],
    });
  });

  it("pages block sidecar reads by cursor until all blocks are reachable", async () => {
    const storage = await createPersistentPsLiteStorage(
      { kind: "indexeddb" },
      createMemoryPsLitePersistence(),
    );
    const { manifest, blocks } = blockFixture(
      "chatgpt.conversations",
      "2026-05-08T00:00:00.000Z",
      3,
    );
    await storage.writeBlockManifest?.(
      manifest.scope,
      manifest.collectedAt,
      manifest,
      blocks,
    );

    const seen: unknown[] = [];
    let cursor: string | undefined;
    do {
      const page = await storage.readScopeBlocks!(
        manifest.scope,
        manifest.collectedAt,
        { cursor, maxBytes: 1 },
      );
      seen.push(...page.blocks.map((block) => block.value));
      cursor = page.nextCursor;
    } while (cursor);

    expect(seen).toEqual([{ index: 0 }, { index: 1 }, { index: 2 }]);
  });

  it("reports missing block manifests without reading raw envelopes", async () => {
    const files = new Map<string, ReturnType<typeof createDataFileEnvelope>>();
    const readEnvelope = vi.fn(async (path: string) => files.get(path) ?? null);
    const dataFileStore: PsLiteDataFileStore = {
      kind: "opfs",
      readEnvelope,
      async writeEnvelope(path, envelope) {
        files.set(path, envelope);
        return new TextEncoder().encode(JSON.stringify(envelope)).byteLength;
      },
      async deleteEnvelope(path) {
        files.delete(path);
      },
      async readBlockManifest() {
        return null;
      },
      async readBlockPayload() {
        throw new Error("payload should not be read without a manifest");
      },
    };
    const storage = await createPersistentPsLiteStorage(
      { kind: "custom" },
      createMemoryPsLitePersistence(),
      dataFileStore,
    );

    await expect(
      storage.readScopeBlocks?.("notes.profile", "2026-05-08T00:00:00.000Z", {
        maxBytes: 1_000,
      }),
    ).rejects.toThrow("Block manifest not found");
    expect(readEnvelope).not.toHaveBeenCalled();
  });

  it("supports block sidecars in memory storage", async () => {
    const storage = createMemoryPsLiteStorage();
    const { manifest, blocks } = blockFixture(
      "spotify.profile",
      "2026-05-08T00:00:00.000Z",
      1,
    );

    await storage.writeBlockManifest?.(
      manifest.scope,
      manifest.collectedAt,
      manifest,
      blocks,
    );

    await expect(
      storage.readScopeBlocks?.(manifest.scope, manifest.collectedAt, {
        maxBytes: 1_000,
      }),
    ).resolves.toMatchObject({
      contentKind: "json",
      blocks: [{ value: { index: 0 } }],
    });
  });
});

function blockFixture(
  scope: string,
  collectedAt: string,
  count: number,
): { manifest: DataBlockManifest; blocks: DataScopeBlock[] } {
  const blocks = Array.from({ length: count }, (_, index) => ({
    id: `block-${index}`,
    path: `$.items[${index}]`,
    mediaType: "application/json",
    value: { index },
    sizeBytes: 10,
  }));
  return {
    manifest: {
      version: 1,
      scope,
      collectedAt,
      contentKind: "json",
      blocks: blocks.map(({ id, path, mediaType, sizeBytes }) => ({
        id,
        path,
        mediaType,
        sizeBytes,
      })),
      warnings: [],
    },
    blocks,
  };
}
