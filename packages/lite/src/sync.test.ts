import { afterEach, describe, expect, it, vi } from "vitest";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import {
  createDataFileEnvelope,
  recoverServerOwner,
} from "@opendatalabs/vana-sdk/browser";
import {
  createMemoryPsLiteStateStore,
  createMemoryPsLiteStorage,
} from "./test-support/memory.js";
import { loadOrCreatePsLiteServerIdentity } from "./state.js";
import {
  createPsLitePendingBlobDeletionStore,
  createPsLiteSyncManager,
} from "./sync.js";

const OWNER_SIGNATURE =
  "0xedbb7743cce459345238442dcfb291f234a321d253485eaa58251aa0f28ea8f1410ab988bae2657b689cd24417b41e315efc22ba333024f4a6269c424ded8d361b" as const;

const SCHEMA_ID =
  "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

describe("PS Lite sync", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
  });

  it("uploads unsynced browser-local data and persists the data-point id", async () => {
    const storage = createMemoryPsLiteStorage();
    const envelope = createDataFileEnvelope(
      "instagram.profile",
      "2026-05-08T00:00:00.000Z",
      { username: "browser_sync" },
      "https://schemas.example/instagram.profile.json",
      SCHEMA_ID,
    );
    const write = await storage.writeEnvelope(envelope);
    storage.insertEntry({
      fileId: null,
      schemaId: SCHEMA_ID,
      path: write.relativePath,
      scope: envelope.scope,
      collectedAt: envelope.collectedAt,
      sizeBytes: write.sizeBytes,
    });
    const stateStore = createMemoryPsLiteStateStore();
    const identity = await loadOrCreatePsLiteServerIdentity({
      store: stateStore,
      ownerSignature: OWNER_SIGNATURE,
    });
    const owner = (await recoverServerOwner(OWNER_SIGNATURE)).toLowerCase();
    const gateway = {
      getSchemaForScope: vi.fn().mockResolvedValue({
        id: SCHEMA_ID,
        ownerAddress: "0xowner",
        name: "instagram.profile",
        definitionUrl: "https://schemas.example/instagram.profile.json",
        scope: "instagram.profile",
        addedAt: "2026-05-08T00:00:00.000Z",
      }),
      registerServer: vi.fn().mockResolvedValue({ alreadyRegistered: false }),
      // DPv2 upload worker registers the data point (the synced marker) after
      // uploading the version-keyed blob. Mock returns the dataPointId.
      registerDataPoint: vi.fn().mockResolvedValue({
        dataPointId: "0xdp-browser-1",
        expectedVersion: "1",
      }),
      listDataPointsByOwner: vi
        .fn()
        .mockResolvedValue({ dataPoints: [], cursor: null }),
      isRegisteredBuilder: vi.fn().mockResolvedValue(false),
      getBuilder: vi.fn().mockResolvedValue(null),
      getGrant: vi.fn().mockResolvedValue(null),
      listGrantsByUser: vi.fn().mockResolvedValue([]),
      getServer: vi.fn().mockResolvedValue({
        id: "server-browser-1",
        ownerAddress: owner,
        serverAddress: identity.account.address,
        publicKey: identity.account.publicKey,
        serverUrl: "https://browser.example",
        addedAt: "2026-05-08T00:00:00.000Z",
      }),
      getDataPoint: vi.fn().mockResolvedValue(null),
      getSchema: vi.fn().mockResolvedValue(null),
      createGrant: vi.fn().mockResolvedValue({}),
      revokeGrant: vi.fn().mockResolvedValue(undefined),
    };
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          // Blobs are version-keyed `{scope}/{version}` (version 1 here).
          // Storage paths are scoped by the gateway chainId (default 14800), so
          // the provider uses chain-scoped `/v1/chains/{chainId}/blobs/...`.
          key: `${owner}/instagram.profile/1`,
          url: `https://storage.vana.org/v1/chains/14800/blobs/${owner}/instagram.profile/1`,
          etag: "etag-browser-1",
          size: 256,
        }),
        {
          status: 200,
          headers: { "content-type": "application/json" },
        },
      ),
    );
    vi.stubGlobal("fetch", fetchMock);

    const { syncManager } = await createPsLiteSyncManager({
      config: ServerConfigSchema.parse({ sync: { enabled: true } }),
      stateStore,
      storage,
      ownerSignature: OWNER_SIGNATURE,
      serverAccount: identity.account,
      gateway: gateway as never,
      // The deletion-aware feed is a separate REST client; stub it so the
      // single-shot fetch mock above only sees the storage upload.
      dataPointFeed: {
        getDataPoint: async () => null,
        listDataPointsByOwner: async () => ({ dataPoints: [], cursor: null }),
      },
    });

    await syncManager.trigger();
    await syncManager.stop();

    expect(storage.findUnsynced()).toEqual([]);
    expect(storage.findByDataPointId("0xdp-browser-1")).toMatchObject({
      scope: "instagram.profile",
      dataPointId: "0xdp-browser-1",
    });
    expect(fetchMock).toHaveBeenCalledWith(
      `https://storage.vana.org/v1/chains/14800/blobs/${owner}/instagram.profile/1`,
      expect.objectContaining({ method: "PUT" }),
    );
    expect(gateway.registerDataPoint).toHaveBeenCalledWith(
      expect.objectContaining({
        scope: "instagram.profile",
        expectedVersion: "1",
      }),
    );
  });

  it("uses the caller-provided logger for sync lifecycle logs", async () => {
    const stateStore = createMemoryPsLiteStateStore();
    const storage = createMemoryPsLiteStorage();
    const identity = await loadOrCreatePsLiteServerIdentity({
      store: stateStore,
      ownerSignature: OWNER_SIGNATURE,
    });
    const owner = (await recoverServerOwner(OWNER_SIGNATURE)).toLowerCase();
    const gateway = {
      getServer: vi.fn().mockResolvedValue({
        id: "server-browser-1",
        ownerAddress: owner,
        serverAddress: identity.account.address,
        publicKey: identity.account.publicKey,
        serverUrl: "https://browser.example",
        addedAt: "2026-05-08T00:00:00.000Z",
      }),
      listDataPointsByOwner: vi
        .fn()
        .mockResolvedValue({ dataPoints: [], cursor: null }),
    };
    const logger = {
      debug: vi.fn(),
      error: vi.fn(),
      info: vi.fn(),
      warn: vi.fn(),
    };

    const { syncManager } = await createPsLiteSyncManager({
      config: ServerConfigSchema.parse({ sync: { enabled: true } }),
      stateStore,
      storage,
      ownerSignature: OWNER_SIGNATURE,
      serverAccount: identity.account,
      gateway: gateway as never,
      // The deletion-aware feed is a separate REST client; stub it so the
      // single-shot fetch mock above only sees the storage upload.
      dataPointFeed: {
        getDataPoint: async () => null,
        listDataPointsByOwner: async () => ({ dataPoints: [], cursor: null }),
      },
      logger,
    });

    await syncManager.trigger();
    await syncManager.stop();

    expect(logger.debug).toHaveBeenCalledWith(
      { uploaded: 0 },
      "Upload cycle complete",
    );
    expect(logger.debug).toHaveBeenCalledWith(
      { downloaded: 0, fullReconcile: false },
      "Download cycle complete",
    );
  });
});

describe("PS Lite pending blob deletion store", () => {
  it("does not lose markers when a delete and a retry mutate the state key concurrently", async () => {
    const stateStore = createMemoryPsLiteStateStore();
    const store = createPsLitePendingBlobDeletionStore(stateStore);
    const retrying = { scope: "retrying.scope", version: "3" };
    const first = { scope: "first.scope", version: "1" };
    const second = { scope: "second.scope", version: "1" };
    await store.add([retrying]);

    await Promise.all([
      store.remove([retrying]),
      store.add([first]),
      store.add([second]),
      store.add([first]),
    ]);

    expect(await store.list()).toEqual([first, second]);
    // Survives a fresh store over the same state.
    expect(
      await createPsLitePendingBlobDeletionStore(stateStore).list(),
    ).toEqual([first, second]);

    // The pre-key state shape (whole scopes) reads as version-less markers.
    await stateStore.set("pending-blob-deletions-v1", {
      scopes: ["legacy.scope"],
    });
    expect(
      await createPsLitePendingBlobDeletionStore(stateStore).list(),
    ).toEqual([{ scope: "legacy.scope", version: null }]);
  });
});

describe("PS Lite read-side deletion memory", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("is fed by the sync feed so a tombstone listed on the next cycle is refused by reads", async () => {
    const stateStore = createMemoryPsLiteStateStore();
    const storage = createMemoryPsLiteStorage();
    const identity = await loadOrCreatePsLiteServerIdentity({
      store: stateStore,
      ownerSignature: OWNER_SIGNATURE,
    });
    const owner = (await recoverServerOwner(OWNER_SIGNATURE)).toLowerCase();
    const gateway = {
      getServer: vi.fn().mockResolvedValue({
        id: "server-browser-1",
        ownerAddress: owner,
        serverAddress: identity.account.address,
        publicKey: identity.account.publicKey,
        serverUrl: "https://browser.example",
        addedAt: "2026-05-08T00:00:00.000Z",
      }),
      listDataPointsByOwner: vi.fn(),
    };

    const { syncManager, scopeDeletions } = await createPsLiteSyncManager({
      config: ServerConfigSchema.parse({ sync: { enabled: true } }),
      stateStore,
      storage,
      ownerSignature: OWNER_SIGNATURE,
      serverAccount: identity.account,
      gateway: gateway as never,
      dataPointFeed: {
        getDataPoint: async () => null,
        listDataPointsByOwner: async () => ({
          dataPoints: [
            {
              id: "0xdp-deleted",
              ownerAddress: owner,
              scope: "instagram.profile",
              dataHash: "0x" + "11".repeat(32),
              metadataHash: "0x" + "22".repeat(32),
              expectedVersion: "2",
              addedAt: "2026-05-09T00:00:00.000Z",
              deletedAt: "2026-05-09T00:00:00.000Z",
            },
          ],
          cursor: null,
        }),
      },
    });

    await syncManager.trigger();
    await syncManager.stop();

    expect(scopeDeletions.knownDeletion("instagram.profile")).toEqual({
      deletedAt: "2026-05-09T00:00:00.000Z",
      version: "2",
    });
    expect(scopeDeletions.feedAgeMs()).not.toBeNull();
    await expect(
      scopeDeletions.resolve("instagram.profile"),
    ).resolves.toMatchObject({
      deleted: true,
      deletedAt: "2026-05-09T00:00:00.000Z",
    });
  });
});
