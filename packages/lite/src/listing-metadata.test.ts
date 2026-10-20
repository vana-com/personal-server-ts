import { afterEach, expect, it, vi } from "vitest";
import { createDataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import { listDataScopesContract } from "@opendatalabs/personal-server-ts-core/contracts";
import * as projections from "@opendatalabs/personal-server-ts-core/legacy-projection";
import { withLegacyProjection } from "@opendatalabs/personal-server-ts-core/storage/legacy-projection";
import { buildDataBlocksAsync } from "@opendatalabs/personal-server-ts-core/storage/blocks";
import { createPersistentPsLiteStorage } from "./storage.js";
import {
  createMemoryPsLiteDataFileStore,
  createMemoryPsLitePersistence,
} from "./test-support/memory.js";

afterEach(() => vi.restoreAllMocks());

it("lists large stored and same-name projected scopes without reading file bodies", async () => {
  const files = createMemoryPsLiteDataFileStore();
  const storage = await createPersistentPsLiteStorage(
    { kind: "custom" },
    createMemoryPsLitePersistence(),
    files,
  );
  const collectedAt = "2026-10-20T00:00:00.000Z";
  const envelopes = [
    createDataFileEnvelope("notes.documents", collectedAt, {
      text: "x".repeat(4 * 1024 * 1024),
    }),
    createDataFileEnvelope("chatgpt.conversations", collectedAt, {
      records: [
        {
          id: "c1",
          title: "Large conversation",
          create_time: "2026-10-20T00:00:00Z",
          content: "x".repeat(4 * 1024 * 1024),
        },
      ],
    }),
  ];
  for (const envelope of envelopes) {
    const write = await storage.writeEnvelope(envelope);
    await storage.insertEntry({
      fileId: envelope.scope,
      scope: envelope.scope,
      collectedAt,
      path: write.relativePath,
      sizeBytes: write.sizeBytes,
    });
  }
  const readEnvelope = vi.spyOn(files, "readEnvelope");
  const readManifest = vi.spyOn(files, "readBlockManifest");
  const readPayload = vi.spyOn(files, "readBlockPayload");
  const projection = vi.spyOn(projections, "projectPdppRecordsToLegacyPayload");
  const served = withLegacyProjection(storage);
  const started = performance.now();
  const result = await listDataScopesContract({ storage: served, limit: 100 });
  expect(performance.now() - started).toBeLessThan(1000);
  expect(result.response).toEqual({
    scopes: ["chatgpt.conversations", "notes.documents"].map((scope) => ({
      scope,
      latestCollectedAt: collectedAt,
      versionCount: 1,
      sizeBytes: storage.findEntry({ scope })!.sizeBytes,
      dataStatus: "indexing",
    })),
    total: 2,
    limit: 100,
    offset: 0,
  });
  expect(readEnvelope).not.toHaveBeenCalled();
  expect(readManifest).not.toHaveBeenCalled();
  expect(readPayload).not.toHaveBeenCalled();
  expect(projection).not.toHaveBeenCalled();
});

it("persists block readiness metadata across reload and removes it with deleted versions", async () => {
  const files = createMemoryPsLiteDataFileStore();
  const persistence = createMemoryPsLitePersistence();
  const create = () =>
    createPersistentPsLiteStorage({ kind: "custom" }, persistence, files);
  const storage = await create();
  const scope = "notes.documents";
  const collectedAt = "2026-10-20T00:00:00.000Z";
  const built = await buildDataBlocksAsync({
    scope,
    collectedAt,
    content: { text: "hello" },
  });
  const envelope = createDataFileEnvelope(scope, collectedAt, {
    text: "hello",
  });
  const write = await storage.writeEnvelope(envelope);
  await storage.insertEntry({
    fileId: "file",
    scope,
    collectedAt,
    path: write.relativePath,
    sizeBytes: write.sizeBytes,
  });
  await storage.writeBlockManifest!(
    scope,
    collectedAt,
    built.manifest,
    built.blocks,
  );
  const reloaded = await create();
  const read = vi.spyOn(files, "readBlockManifest");
  const result = await listDataScopesContract({
    storage: withLegacyProjection(reloaded),
  });
  expect(result.response.scopes).toEqual([
    {
      scope,
      latestCollectedAt: collectedAt,
      versionCount: 1,
      sizeBytes: write.sizeBytes,
      dataStatus: "ready",
    },
  ]);
  expect(read).not.toHaveBeenCalled();
  await reloaded.deleteVersion!(scope, collectedAt);
  expect(await (await create()).hasScopeBlocks!(scope, collectedAt)).toBe(
    false,
  );
});
