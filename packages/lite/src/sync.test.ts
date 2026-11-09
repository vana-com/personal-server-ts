import { privateKeyToAccount } from "viem/accounts";
import { recoverTypedDataAddress } from "viem";
import {
  type AddDataMessage,
  ADD_DATA_TYPES,
  deriveMasterKey,
  deriveScopeKey,
  decryptWithPassword,
  dataRegistryDomain,
  parseWeb3SignedHeader,
  verifyWeb3Signed,
} from "@opendatalabs/vana-sdk/browser";
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
import {
  createUploadAttemptLedger,
  uploadAttemptKey,
} from "@opendatalabs/personal-server-ts-core/sync";
import type { IndexEntry } from "@opendatalabs/personal-server-ts-core/storage/index/types";
import {
  createIndexedDbPsLiteStateStore,
  loadOrCreatePsLiteServerIdentity,
} from "./state.js";
import {
  createPsLitePendingBlobDeletionStore,
  createPsLiteUploadAttemptStore,
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

  it("uploads with owner authority without a registered server", async () => {
    const owner = privateKeyToAccount(`0x${"12".repeat(32)}`);
    const ownerSignature = await owner.signMessage({
      message: "vana-master-key-v1",
    });
    const config = ServerConfigSchema.parse({ sync: { enabled: true } });
    const storage = createMemoryPsLiteStorage();
    const envelope = createDataFileEnvelope(
      "spotify.profile",
      "2026-09-08T00:00:00.000Z",
      { displayName: "Public Spotify" },
      "https://schemas.example/spotify.profile.json",
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
      ownerSignature,
    });
    const gateway = {
      getServer: vi.fn().mockResolvedValue(null),
      registerServer: vi.fn(),
      registerDataPoint: vi
        .fn()
        .mockResolvedValue({ dataPointId: "0xowner-dp", expectedVersion: "1" }),
    };
    const url = `https://storage.vana.org/v1/chains/14800/blobs/${owner.address.toLowerCase()}/spotify.profile/1`;
    const fetchMock = vi.fn().mockImplementation(
      async () =>
        new Response(
          JSON.stringify({
            url,
            key: "spotify.profile/1",
            size: 256,
            etag: "owner",
          }),
          { status: 200 },
        ),
    );
    vi.stubGlobal("fetch", fetchMock);
    const { syncManager } = await createPsLiteSyncManager({
      config,
      storage,
      stateStore,
      ownerSignature,
      serverAccount: identity.account,
      ownerSyncSigner: {
        address: owner.address,
        signMessage: (message: string) => owner.signMessage({ message }),
        signAddData: (message: AddDataMessage) =>
          owner.signTypedData({
            domain: dataRegistryDomain(config.gateway),
            types: ADD_DATA_TYPES,
            primaryType: "AddData",
            message,
          }),
        signLineageAttestation: vi.fn(),
      },
      gateway: gateway as never,
      dataPointFeed: {
        getDataPoint: async () => null,
        listDataPointsByOwner: async () => ({ dataPoints: [], cursor: null }),
      },
    });
    try {
      await syncManager.trigger();
    } finally {
      await syncManager.stop();
    }
    expect(storage.findUnsynced()).toEqual([]);
    expect(gateway.getServer).not.toHaveBeenCalled();
    expect(gateway.registerServer).not.toHaveBeenCalled();
    const registration = gateway.registerDataPoint.mock.calls[0][0];
    expect(
      await recoverTypedDataAddress({
        domain: dataRegistryDomain(config.gateway),
        types: ADD_DATA_TYPES,
        primaryType: "AddData",
        message: {
          ...registration,
          expectedVersion: BigInt(registration.expectedVersion),
        },
        signature: registration.signature,
      }),
    ).toBe(owner.address);
    const [uploadUrl, upload] = fetchMock.mock.calls.find(
      ([, request]) => request.method === "PUT",
    )!;
    const parsed = parseWeb3SignedHeader(upload.headers.authorization);
    const verified = await verifyWeb3Signed({
      headerValue: upload.headers.authorization,
      expectedOrigin: "https://storage.vana.org",
      expectedMethod: "PUT",
      expectedPath: new URL(uploadUrl).pathname,
      bodyBytes: upload.body,
    });
    expect(verified.signer.toLowerCase()).toBe(owner.address.toLowerCase());
    expect(parsed.payload.uri).toContain("/spotify.profile/1");
    const key = deriveScopeKey(
      deriveMasterKey(ownerSignature),
      "spotify.profile",
    );
    const password = Array.from(key, (byte) =>
      byte.toString(16).padStart(2, "0"),
    ).join("");
    const plaintext = await decryptWithPassword(upload.body, password);
    expect(JSON.parse(new TextDecoder().decode(plaintext))).toEqual(envelope);
    expect(new TextDecoder().decode(upload.body)).not.toContain(
      "Public Spotify",
    );
  });

  it("rejects an owner sync capability for a different owner", async () => {
    const stateStore = createMemoryPsLiteStateStore();
    const identity = await loadOrCreatePsLiteServerIdentity({
      store: stateStore,
      ownerSignature: OWNER_SIGNATURE,
    });
    await expect(
      createPsLiteSyncManager({
        config: ServerConfigSchema.parse({}),
        stateStore,
        storage: createMemoryPsLiteStorage(),
        ownerSignature: OWNER_SIGNATURE,
        serverAccount: identity.account,
        ownerSyncSigner: {
          address: identity.account.address,
          signAddData: vi.fn(),
          signLineageAttestation: vi.fn(),
          signMessage: vi.fn(),
        },
      }),
    ).rejects.toThrow("Owner sync signer must match the verified data owner");
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
      // The attempt's signal reaches the registry write.
      { signal: expect.any(AbortSignal) },
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

describe("createPsLiteUploadAttemptStore ownership", () => {
  afterEach(() => vi.unstubAllGlobals());
  const OWNER = "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12";
  const entry = {
    id: 1,
    scope: "chatgpt.conversations",
    path: "chatgpt.conversations/2026-11-07T10:00:00Z.json",
    collectedAt: "2026-11-07T10:00:00Z",
    version: 1,
    sizeBytes: 4096,
  } as IndexEntry;

  /** A state store over the named backing store. */
  const stateAt = (namespace: string) =>
    Object.assign(createMemoryPsLiteStateStore(), { namespace });
  /** Another wrapper object over the same backing store. */
  const wrapperOf = (store: ReturnType<typeof stateAt>) => ({ ...store });
  const ledgerOver = (store: ReturnType<typeof stateAt>) =>
    createUploadAttemptLedger(createPsLiteUploadAttemptStore(store), OWNER);

  /** Browser locks as one origin shares them: by name, held until released. */
  function stubBrowserLocks() {
    const held = new Set<string>();
    vi.stubGlobal("navigator", {
      locks: {
        request: async (
          name: string,
          _options: unknown,
          callback: (lock: object | null) => Promise<void> | undefined,
        ) => {
          if (held.has(name)) return callback(null);
          held.add(name);
          try {
            await callback({});
          } finally {
            held.delete(name);
          }
        },
      },
    });
  }

  it("excludes a second wrapper over the same store without browser locks, and loses no marker", async () => {
    vi.stubGlobal("navigator", {});
    const first = stateAt("indexeddb:personal-server-lite/state");
    const holder = ledgerOver(first);
    expect(await holder.recover()).toBe(true);
    const token = await holder.begin(entry);

    const rival = ledgerOver(wrapperOf(first));
    expect(await rival.recover()).toBe(false);

    // The holder's marker is intact: it was not counted as a crash, and it
    // settles normally.
    expect(
      (
        (await first.get("upload-attempts-v1")) as {
          records: Array<{ inFlight: boolean; interrupted: number }>;
        }
      ).records,
    ).toEqual([expect.objectContaining({ inFlight: true, interrupted: 0 })]);
    await holder.settle(token, "success");
    await holder.close();
    expect(await ledgerOver(wrapperOf(first)).recover()).toBe(true);
  });

  it("excludes a second wrapper over the same store with browser locks", async () => {
    stubBrowserLocks();
    const first = stateAt("indexeddb:personal-server-lite/state");
    expect(await ledgerOver(first).recover()).toBe(true);
    expect(await ledgerOver(wrapperOf(first)).recover()).toBe(false);
  });

  it.each([
    ["without browser locks", () => vi.stubGlobal("navigator", {})],
    ["with browser locks", stubBrowserLocks],
  ])(
    "does not starve a different store on the same origin (%s)",
    async (_name, setup) => {
      setup();
      const a = ledgerOver(stateAt("indexeddb:db-a/state"));
      const b = ledgerOver(stateAt("indexeddb:db-b/state"));
      expect(await a.recover()).toBe(true);
      expect(await b.recover()).toBe(true);
    },
  );

  it("names the backing store of an IndexedDB state store", () => {
    expect(
      createIndexedDbPsLiteStateStore({ dbName: "a", storeName: "s" })
        .namespace,
    ).toBe('indexeddb:["a","s"]');
  });

  it.each([
    ["without browser locks", () => vi.stubGlobal("navigator", {})],
    ["with browser locks", stubBrowserLocks],
  ])(
    "does not merge database/store names that concatenate alike (%s)",
    async (_name, setup) => {
      setup();
      const first = createIndexedDbPsLiteStateStore({
        dbName: "tenant/a",
        storeName: "state",
      });
      const second = createIndexedDbPsLiteStateStore({
        dbName: "tenant",
        storeName: "a/state",
      });
      expect(first.namespace).not.toBe(second.namespace);
      const a = ledgerOver(stateAt(first.namespace!));
      const b = ledgerOver(stateAt(second.namespace!));
      expect(await a.recover()).toBe(true);
      expect(await b.recover()).toBe(true);
    },
  );

  it("refuses to guess a lock identity when the host names no store", () => {
    expect(() =>
      createPsLiteUploadAttemptStore({
        ...createMemoryPsLiteStateStore(),
        namespace: undefined,
      }),
    ).toThrow(/namespace/);
  });
});

describe("createPsLiteUploadAttemptStore", () => {
  const OWNER = "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12";
  const entry = {
    id: 1,
    scope: "chatgpt.conversations",
    path: "chatgpt.conversations/2026-11-07T10:00:00Z.json",
    collectedAt: "2026-11-07T10:00:00Z",
    version: 1,
    sizeBytes: 4096,
  } as IndexEntry;

  it("keeps an unsettled attempt in the durable state store across rebuilds and quarantines at the second", async () => {
    const stateStore = Object.assign(createMemoryPsLiteStateStore(), {
      namespace: "indexeddb:personal-server-lite/state",
    });
    // Each boot is a new WebView: it holds no lock of its dead predecessor.
    const boot = (n: number) =>
      createUploadAttemptLedger(
        createPsLiteUploadAttemptStore(stateStore, {
          namespace: `${stateStore.namespace}#boot-${n}`,
        }),
        OWNER,
      );
    for (let n = 0; n < 2; n++) {
      const ledger = boot(n);
      await ledger.recover();
      expect(ledger.quarantined()).toEqual([]);
      await ledger.begin(entry); // the WebView dies here, never settles
    }
    const ledger = boot(2);
    await ledger.recover();
    expect(ledger.isQuarantined(uploadAttemptKey(OWNER, entry))).toBe(true);
  });

  it("preserves a malformed ledger under a side key, then starts a valid empty one", async () => {
    const stateStore = Object.assign(
      createMemoryPsLiteStateStore({
        "upload-attempts-v1": { version: 1, records: [{ key: 7 }] },
      }),
      { namespace: "indexeddb:corrupt-ledger-test/state" },
    );
    const writes: Array<[string, unknown]> = [];
    const set = stateStore.set.bind(stateStore);
    stateStore.set = async (key, value) => {
      writes.push([key, value]);
      await set(key, value);
    };
    const degraded: string[] = [];
    const ledger = createUploadAttemptLedger(
      createPsLiteUploadAttemptStore(stateStore),
      OWNER,
      { onDegraded: (message) => degraded.push(message) },
    );

    expect(await ledger.recover()).toBe(true);

    const side = writes.find(([key]) =>
      key.startsWith("upload-attempts-v1.corrupt-"),
    );
    expect(side?.[1]).toEqual({ version: 1, records: [{ key: 7 }] });
    // The copy is durable before the ledger is replaced.
    expect(writes.indexOf(side!)).toBeLessThan(
      writes.findIndex(([key]) => key === "upload-attempts-v1"),
    );
    expect(await stateStore.get("upload-attempts-v1")).toEqual({
      version: 1,
      records: [],
    });
    expect(degraded).toEqual([
      "Upload crash protection was reset; earlier interruption counts were lost",
    ]);
    // New attempts are protected again.
    await ledger.begin(entry);
    expect(
      (
        (await stateStore.get("upload-attempts-v1")) as {
          records: unknown[];
        }
      ).records,
    ).toHaveLength(1);
  });
});
