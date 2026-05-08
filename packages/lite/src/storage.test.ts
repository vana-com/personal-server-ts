import { describe, expect, it } from "vitest";
import { createDataFileEnvelope } from "@opendatalabs/personal-server-ts-core/schemas/data-file";
import {
  createMemoryPsLitePersistence,
  createPersistentPsLiteStorage,
} from "./storage.js";

describe("createPersistentPsLiteStorage", () => {
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
    storage.insertEntry({
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
    storage.insertEntry({
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
      storage.insertEntry({
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
});
