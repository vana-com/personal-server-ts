import "fake-indexeddb/auto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { createMemoryStreamSyncReadFiles } from "@opendatalabs/personal-server-ts-core/stream-sync-read";
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
const SCOPES = ["acme.items", "acme.orders"];

/** Legacy rows already uploaded: a retire step must delete them, not upload. */
async function legacyStorage() {
  const storage = createMemoryPsLiteStorage();
  let n = 0;
  for (const scope of SCOPES) {
    const envelope = createDataFileEnvelope(
      scope,
      "2026-05-08T00:00:00.000Z",
      { n: (n += 1) },
      `https://schemas.example/${scope}.json`,
      SCHEMA_ID,
    );
    const write = await storage.writeEnvelope(envelope);
    storage.insertEntry({
      fileId: "file-" + scope,
      schemaId: SCHEMA_ID,
      path: write.relativePath,
      scope,
      collectedAt: envelope.collectedAt,
      sizeBytes: write.sizeBytes,
      dataPointId: "0xdp-" + scope,
      version: 1,
    } as never);
  }
  return storage;
}

async function open(opts: {
  write: boolean;
  complete: (scope: string) => boolean;
}) {
  const owner = (await recoverServerOwner(OWNER_SIGNATURE)).toLowerCase();
  const stateStore = Object.assign(createMemoryPsLiteStateStore(), {
    namespace: "indexeddb:retire-" + Math.random(),
  });
  const identity = await loadOrCreatePsLiteServerIdentity({
    store: stateStore,
    ownerSignature: OWNER_SIGNATURE,
  });
  const storage = await legacyStorage();
  const gateway = {
    getServer: vi.fn().mockResolvedValue({
      id: "server-1",
      ownerAddress: owner,
      serverAddress: identity.account.address,
      publicKey: identity.account.publicKey,
      serverUrl: "https://retire.example",
      addedAt: "2026-05-08T00:00:00.000Z",
    }),
    registerServer: vi.fn().mockResolvedValue({ alreadyRegistered: true }),
  };
  const lite = await createPsLiteSyncManager({
    config: ServerConfigSchema.parse({
      sync: { enabled: true },
      streamSync: { read: true, write: opts.write },
    }),
    stateStore,
    storage,
    ownerSignature: OWNER_SIGNATURE,
    serverAccount: identity.account,
    gateway: gateway as never,
    autoStartSync: false,
    streamSyncRead: { files: createMemoryStreamSyncReadFiles() },
    dataPointFeed: {
      getDataPoint: async () => null,
      listDataPointsByOwner: async () =>
        ({ dataPoints: [], cursor: null }) as never,
    },
  });
  const viewServes = vi
    .spyOn(lite.streamSyncRead!, "viewServes")
    .mockImplementation(opts.complete);
  return { lite, storage, viewServes };
}

/** Scopes of the gateway/storage requests a cycle made. */
function requestedScopes(fetchMock: ReturnType<typeof vi.fn>): string[] {
  return SCOPES.filter((scope) =>
    fetchMock.mock.calls.some((call) => String(call[0]).includes(scope)),
  );
}

describe("PS Lite: retire legacy scopes after the switch", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  async function cycle(o: Awaited<ReturnType<typeof open>>) {
    try {
      await o.lite.syncManager.trigger();
    } finally {
      await o.lite.syncManager.stop();
      await o.lite.closeStreamSync();
    }
  }

  it("writer off (switch off): the view is never consulted and nothing is requested", async () => {
    const fetchMock = vi.fn(async () => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const o = await open({ write: false, complete: () => true });
    await cycle(o);
    expect(o.viewServes).not.toHaveBeenCalled();
    expect(requestedScopes(fetchMock)).toEqual([]);
    expect(o.storage.listScopes({}).total).toBe(2);
  });

  it("writer on, view incomplete: the legacy rows stay and nothing is requested", async () => {
    const fetchMock = vi.fn(async () => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const o = await open({ write: true, complete: () => false });
    await cycle(o);
    expect(o.viewServes).toHaveBeenCalled();
    expect(requestedScopes(fetchMock)).toEqual([]);
    expect(o.storage.listScopes({}).total).toBe(2);
  });

  it("writer on, one view complete: only that scope is sent to the delete path", async () => {
    const fetchMock = vi.fn(async () => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const o = await open({ write: true, complete: (s) => s === "acme.items" });
    await cycle(o);
    expect(requestedScopes(fetchMock)).toContain("acme.items");
    expect(requestedScopes(fetchMock)).not.toContain("acme.orders");
    expect(
      o.storage.listScopes({}).scopes.map((s: { scope: string }) => s.scope),
    ).toContain("acme.orders");
  });
});
