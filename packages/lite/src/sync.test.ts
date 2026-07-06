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
import { createPsLiteSyncManager } from "./sync.js";

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
});
