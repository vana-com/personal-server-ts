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

  it("uploads unsynced browser-local data and persists the file id", async () => {
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
      registerFile: vi.fn().mockResolvedValue({ fileId: "file-browser-1" }),
      listFilesSince: vi.fn().mockResolvedValue({ files: [], cursor: null }),
      isRegisteredBuilder: vi.fn().mockResolvedValue(false),
      getBuilder: vi.fn().mockResolvedValue(null),
      getGrant: vi.fn().mockResolvedValue(null),
      listGrantsByUser: vi.fn().mockResolvedValue([]),
      getServer: vi.fn().mockResolvedValue(null),
      getFile: vi.fn().mockResolvedValue(null),
      getSchema: vi.fn().mockResolvedValue(null),
      createGrant: vi.fn().mockResolvedValue({}),
      revokeGrant: vi.fn().mockResolvedValue(undefined),
    };
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          key: `${owner}/instagram.profile/2026-05-08T00:00:00.000Z`,
          url: `https://storage.vana.com/v1/blobs/${owner}/instagram.profile/2026-05-08T00:00:00.000Z`,
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
    expect(storage.findByFileId("file-browser-1")).toMatchObject({
      scope: "instagram.profile",
      fileId: "file-browser-1",
    });
    expect(fetchMock).toHaveBeenCalledWith(
      `https://storage.vana.com/v1/blobs/${owner}/instagram.profile/2026-05-08T00%3A00%3A00.000Z`,
      expect.objectContaining({ method: "PUT" }),
    );
    expect(gateway.registerFile).toHaveBeenCalledWith(
      expect.objectContaining({
        schemaId: SCHEMA_ID,
      }),
    );
  });
});
