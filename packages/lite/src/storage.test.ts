import { describe, expect, it } from "vitest";
import { createDataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import {
  createMemoryPsLiteDataFileStore,
  createMemoryPsLitePersistence,
} from "./test-support/memory.js";
import { createPersistentPsLiteStorage } from "./storage.js";
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
});
