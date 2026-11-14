import type * as LocalDbModule from "@opendatalabs/personal-server-ts-core/localdb";
import type { OwnedAccountStorageMode } from "@opendatalabs/personal-server-ts-core/api";
import "fake-indexeddb/auto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  createLocalSync,
  localDatabaseName,
  openLocalDb,
  type LocalSync,
  type SqlDriver,
} from "@opendatalabs/personal-server-ts-core/localdb";
import { openLiteLocalDb, type LiteLocalDbOptions } from "./localdb-port.js";

// These composition tests isolate the host factory. Real database intake and
// cross-surface reads are covered by sync-stream-intake.test.ts.
vi.mock(
  "@opendatalabs/personal-server-ts-core/localdb",
  async (importOriginal) => {
    const actual = await importOriginal<typeof LocalDbModule>();
    return {
      ...actual,
      createLocalSync: vi.fn(),
      openLocalDb: vi.fn(async (driver: SqlDriver) => driver),
    };
  },
);
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { uploadAttemptKey } from "@opendatalabs/personal-server-ts-core/sync";
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
const UPLOAD_ATTEMPTS_KEY = "upload-attempts-v1";
/** A physical stream-sync name (`pdpp.<connector>~<16 hex ns>.<stream>`). */
const PHYSICAL_SCOPE = "pdpp.chatgpt~0123456789abcdef.messages";

type StateStore = ReturnType<typeof createMemoryPsLiteStateStore>;

/** A state store that names its backing store, as a browser host does. */
function namedState(namespace: string): StateStore {
  return Object.assign(createMemoryPsLiteStateStore(), { namespace });
}

/** Browser locks as one origin shares them: by name, held until released. */
function stubBrowserLocks() {
  const held = new Set<string>();
  const requested: string[] = [];
  vi.stubGlobal("navigator", {
    locks: {
      request: async (
        name: string,
        _options: unknown,
        callback: (lock: object | null) => Promise<void> | undefined,
      ) => {
        requested.push(name);
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
  return requested;
}

/** One unsynced legacy row, as the local index holds it. */
async function legacyStorage() {
  const storage = createMemoryPsLiteStorage();
  const envelope = createDataFileEnvelope(
    "instagram.profile",
    "2026-05-08T00:00:00.000Z",
    { username: "composition" },
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
  return { storage, entry: storage.findUnsynced()[0]! };
}

/** Upload and registry responses the real upload path needs. */
function uploadFetch(owner: string) {
  return vi.fn().mockImplementation(
    async () =>
      new Response(
        JSON.stringify({
          key: `${owner}/instagram.profile/1`,
          url: `https://storage.vana.org/v1/chains/14800/blobs/${owner}/instagram.profile/1`,
          etag: "etag-composition",
          size: 256,
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
  );
}

async function fixture(stateStore: StateStore, owner: string) {
  const identity = await loadOrCreatePsLiteServerIdentity({
    store: stateStore,
    ownerSignature: OWNER_SIGNATURE,
  });
  const gateway = {
    getServer: vi.fn().mockResolvedValue({
      id: "server-composition-1",
      ownerAddress: owner,
      serverAddress: identity.account.address,
      publicKey: identity.account.publicKey,
      serverUrl: "https://composition.example",
      addedAt: "2026-05-08T00:00:00.000Z",
    }),
    registerServer: vi.fn().mockResolvedValue({ alreadyRegistered: true }),
    registerDataPoint: vi.fn().mockResolvedValue({
      dataPointId: "0xdp-composition",
      expectedVersion: "1",
    }),
    getSchemaForScope: vi.fn().mockResolvedValue({
      id: SCHEMA_ID,
      ownerAddress: owner,
      name: "instagram.profile",
      definitionUrl: "https://schemas.example/instagram.profile.json",
      scope: "instagram.profile",
      addedAt: "2026-05-08T00:00:00.000Z",
    }),
  };
  return { identity, gateway };
}

/** The real manager factory; tests explicitly choose Account mode. */
async function openLite(opts: {
  stateStore: StateStore;
  storage: ReturnType<typeof createMemoryPsLiteStorage>;
  identity: Awaited<ReturnType<typeof loadOrCreatePsLiteServerIdentity>>;
  gateway: object;
  feed?: {
    dataPoints: unknown[];
    cursor: string | null;
  };
  localDb?: LiteLocalDbOptions;
  accountStorageMode?: OwnedAccountStorageMode;
}) {
  return createPsLiteSyncManager({
    streamSyncDeclaredStreams: () => [],
    config: ServerConfigSchema.parse({
      sync: { enabled: true },
      streamSync: { read: true, write: true },
    }),
    localDb: opts.localDb,
    accountStorageMode: opts.accountStorageMode ?? {
      owner: opts.identity.account.address,
      read: () => "unswitched",
    },
    stateStore: opts.stateStore,
    storage: opts.storage,
    ownerSignature: OWNER_SIGNATURE,
    serverAccount: opts.identity.account,
    gateway: opts.gateway as never,
    autoStartSync: false,
    dataPointFeed: {
      getDataPoint: async () => null,
      listDataPointsByOwner: async () =>
        (opts.feed ?? { dataPoints: [], cursor: null }) as never,
    },
  });
}

const physicalRow = {
  id: "0xdp-physical",
  ownerAddress: "0x0",
  scope: PHYSICAL_SCOPE,
  dataHash: "0x" + "11".repeat(32),
  metadataHash: "0x" + "22".repeat(32),
  expectedVersion: "1",
  addedAt: "2026-05-09T00:00:00.000Z",
};

describe("PS Lite composition: durable attempt store with stream sync on", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("explicit Off preserves a quarantined legacy row without opening database sync", async () => {
    stubBrowserLocks();
    const owner = (await recoverServerOwner(OWNER_SIGNATURE)).toLowerCase();
    const stateStore = namedState("indexeddb:composition-a/state");
    const { storage, entry } = await legacyStorage();
    // A prior boot left this row interrupted twice: it is quarantined.
    await stateStore.set(UPLOAD_ATTEMPTS_KEY, {
      version: 1,
      records: [
        {
          key: uploadAttemptKey(owner, entry),
          owner,
          scope: entry.scope,
          path: entry.path,
          rowId: entry.id,
          interrupted: 2,
          inFlight: false,
          quarantined: true,
        },
      ],
    });
    const fetchMock = uploadFetch(owner);
    vi.stubGlobal("fetch", fetchMock);
    const { identity, gateway } = await fixture(stateStore, owner);
    // Record where each body read comes from; call through unchanged.
    const bodyReadStacks: string[] = [];
    const readEnvelope = storage.readEnvelope.bind(storage);
    storage.readEnvelope = (scope, collectedAt) => {
      bodyReadStacks.push(new Error().stack ?? "");
      return readEnvelope(scope, collectedAt);
    };

    const lite = await openLite({
      stateStore,
      storage,
      identity,
      gateway,
      feed: { dataPoints: [physicalRow], cursor: null },
    });
    expect(lite.localSync).toBeNull();
    try {
      await lite.syncManager.trigger();
    } finally {
      await lite.syncManager.stop();
      await lite.closeStreamSync();
    }

    // The upload worker never reads the quarantined row's body. (The download
    // side's sidecar repair reads envelopes on its own; that is not upload.)
    expect(
      bodyReadStacks.filter((stack) => stack.includes("/workers/upload")),
    ).toEqual([]);
    // Nor does it reach the network.
    expect(fetchMock).not.toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({ method: "PUT" }),
    );
    expect(gateway.registerDataPoint).not.toHaveBeenCalled();
    // Explicit Off keeps database sync unopened.
    expect(lite.localSync).toBeNull();
    // The quarantine itself is kept, not reset by the cycle.
    expect(
      (
        (await stateStore.get(UPLOAD_ATTEMPTS_KEY)) as {
          records: Array<{ quarantined: boolean }>;
        }
      ).records,
    ).toEqual([expect.objectContaining({ quarantined: true })]);
  });

  it("explicit Off shares the attempt-store lock only within its state namespace", async () => {
    const requested = stubBrowserLocks();
    const fetchMock = uploadFetch("0x0");
    vi.stubGlobal("fetch", fetchMock);
    const owner = (await recoverServerOwner(OWNER_SIGNATURE)).toLowerCase();
    const shared = namedState("indexeddb:composition-b/state");
    const first = await fixture(shared, owner);
    const holder = await openLite({
      stateStore: shared,
      storage: (await legacyStorage()).storage,
      identity: first.identity,
      gateway: first.gateway,
    });
    expect(holder.localSync).toBeNull();
    await holder.syncManager.trigger(); // the holder recovers and owns its store

    try {
      // Same namespace, another wrapper object: the attempt store is excluded.
      const sameStore = { ...shared };
      const rival = await openLite({
        stateStore: sameStore as StateStore,
        storage: (await legacyStorage()).storage,
        identity: first.identity,
        gateway: first.gateway,
      });
      // Explicit Off has no stream database.
      expect(rival.localSync).toBeNull();
      const putsBefore = fetchMock.mock.calls.length;
      await rival.syncManager.trigger();
      await rival.syncManager.stop();
      expect(
        fetchMock.mock.calls
          .slice(putsBefore)
          .filter(([, init]) => init?.method === "PUT"),
      ).toEqual([]);

      // Another namespace has its own attempt store, so its legacy row uploads.
      const other = namedState("indexeddb:composition-b-other/state");
      const otherFixture = await fixture(other, owner);
      const elsewhere = await openLite({
        stateStore: other,
        storage: (await legacyStorage()).storage,
        identity: otherFixture.identity,
        gateway: otherFixture.gateway,
      });
      expect(elsewhere.localSync).toBeNull();
      const before = fetchMock.mock.calls.length;
      await elsewhere.syncManager.trigger();
      await elsewhere.syncManager.stop();
      expect(
        fetchMock.mock.calls
          .slice(before)
          .some(([, init]) => init?.method === "PUT"),
      ).toBe(true);
      await elsewhere.closeStreamSync();
      await rival.closeStreamSync();
    } finally {
      await holder.syncManager.stop();
      await holder.closeStreamSync();
    }
    // Explicit Off takes the attempt lock and never a retired stream-home lock.
    const attemptLock =
      "upload-attempts:indexeddb:composition-b/state/upload-attempts-v1";
    const homeLocks = requested.filter((name) =>
      name.startsWith("ps-lite-stream-sync-"),
    );
    expect(requested).toContain(attemptLock);
    expect(homeLocks).toEqual([]);
    expect(homeLocks).not.toContain(attemptLock);
  });
});

describe("PS Lite local database composition", () => {
  beforeEach(() => {
    vi.mocked(createLocalSync).mockReset();
    vi.mocked(openLocalDb).mockReset();
    vi.mocked(openLocalDb).mockImplementation(async (driver) => driver);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  function driver(): SqlDriver {
    return {
      info: { sqliteVersion: "3.22.0", host: "web", persistent: true },
      query: vi.fn().mockResolvedValue([]),
      batch: vi.fn().mockResolvedValue({ changes: [] }),
      close: vi.fn().mockResolvedValue(undefined),
    };
  }

  function facade(db: SqlDriver) {
    const intake = { begin: vi.fn().mockResolvedValue({ ok: false }) };
    const localSync = {
      intake,
      cycle: vi.fn().mockResolvedValue({ connections: [] }),
      apply: vi.fn().mockResolvedValue(undefined),
      close: vi.fn(() => db.close()),
    } as unknown as LocalSync;
    vi.mocked(createLocalSync).mockReturnValue(localSync);
    return { localSync, intake };
  }

  async function setup(
    localDb: LiteLocalDbOptions,
    readMode: () => "switched" | "unswitched" | "unknown" = () => "switched",
  ) {
    const owner = (await recoverServerOwner(OWNER_SIGNATURE)).toLowerCase();
    const stateStore = namedState("indexeddb:localdb-composition/state");
    const { identity, gateway } = await fixture(stateStore, owner);
    const lite = await openLite({
      stateStore,
      storage: createMemoryPsLiteStorage(),
      identity,
      gateway,
      localDb,
      accountStorageMode: { owner, read: readMode },
    });
    return { lite, owner };
  }

  it("opens Lite's database through the host factory and shared initializer", async () => {
    const db = driver();
    const openDriver = vi.fn().mockResolvedValue(db);
    const identity = {
      owner: "0xABCD",
      network: "test-network",
      deviceId: "device-one",
    };
    expect(await openLiteLocalDb({ openDriver }, identity)).toBe(db);
    expect(openDriver).toHaveBeenCalledTimes(1);
    expect(openDriver).toHaveBeenCalledWith({
      name: localDatabaseName(identity.owner, identity.network),
      owner: identity.owner.toLowerCase(),
      network: identity.network,
    });
    expect(openLocalDb).toHaveBeenCalledTimes(1);
    expect(openLocalDb).toHaveBeenCalledWith(db, {
      ...identity,
      owner: identity.owner.toLowerCase(),
    });
    expect(db.close).not.toHaveBeenCalled();

    const failure = new Error("database identity mismatch");
    vi.mocked(openLocalDb).mockRejectedValueOnce(failure);
    await expect(openLiteLocalDb({ openDriver }, identity)).rejects.toBe(
      failure,
    );
    expect(db.close).toHaveBeenCalledTimes(1);
  });

  it("treats a null host driver as stream sync unavailable in this process", async () => {
    const locks = stubBrowserLocks();
    const openDriver = vi.fn().mockResolvedValue(null);
    const { lite } = await setup({ openDriver });
    try {
      expect(openDriver).toHaveBeenCalledTimes(1);
      expect(openLocalDb).not.toHaveBeenCalled();
      expect(createLocalSync).not.toHaveBeenCalled();
      expect(lite.localSync).toBeNull();
      expect(lite.streamSyncIntake).not.toBeNull();
      expect("streamSyncWriter" in lite).toBe(false);
      await expect(
        lite.streamSyncRead!.resolve({} as never),
      ).rejects.toMatchObject({
        code: 503,
        errorCode: "STREAM_READ_UNAVAILABLE",
      });
      expect(locks).toEqual([]);
    } finally {
      await lite.syncManager.stop();
      await lite.closeStreamSync();
    }
  });

  it("routes Lite intake through createLocalSync over the opened database", async () => {
    const db = driver();
    const { localSync, intake } = facade(db);
    const { lite, owner } = await setup({
      openDriver: vi.fn().mockResolvedValue(db),
    });
    try {
      expect(createLocalSync).toHaveBeenCalledTimes(1);
      expect(createLocalSync).toHaveBeenCalledWith(
        expect.objectContaining({
          db,
          ownerAddress: owner,
          queue: { run: expect.any(Function) },
        }),
        expect.objectContaining({
          resolveArtifact: expect.any(Function),
          declaredStreams: expect.any(Function),
          olderVersionReads: expect.any(Function),
        }),
      );
      expect(lite.localSync).toBe(localSync);
      expect(lite.streamSyncIntake).not.toBeNull();
      const request = {} as Parameters<
        NonNullable<typeof lite.streamSyncIntake>["begin"]
      >[0];
      await lite.streamSyncIntake!.begin(request);
      expect(intake.begin).toHaveBeenCalledTimes(1);
      expect(intake.begin).toHaveBeenCalledWith(request);
    } finally {
      await lite.syncManager.stop();
      await lite.closeStreamSync();
    }
    expect(localSync.close).toHaveBeenCalledTimes(1);
    expect(db.close).toHaveBeenCalledTimes(1);
  });

  it("opens no database until Account is On, then uses its cycle and pauses again on unknown", async () => {
    const db = driver();
    const { localSync } = facade(db);
    let mode: "unknown" | "switched" = "unknown";
    const openDriver = vi.fn().mockResolvedValue(db);
    const { lite } = await setup({ openDriver }, () => mode);
    try {
      expect(openDriver).not.toHaveBeenCalled();
      await expect(lite.getLocalSync()).rejects.toMatchObject({
        errorCode: "ACCOUNT_MODE_UNKNOWN",
      });
      mode = "switched";
      await lite.syncManager.trigger();
      expect(openDriver).toHaveBeenCalledTimes(1);
      expect(localSync.cycle).toHaveBeenCalledTimes(1);
      mode = "unknown";
      await lite.syncManager.trigger();
      expect(localSync.cycle).toHaveBeenCalledTimes(1);
    } finally {
      await lite.syncManager.stop();
      await lite.closeStreamSync();
    }
  });

  it("keeps the sync manager's sixty-second interval and adds only the change probe's", async () => {
    const db = driver();
    facade(db);
    const interval = vi.spyOn(globalThis, "setInterval");
    const { lite } = await setup({
      openDriver: vi.fn().mockResolvedValue(db),
    });
    try {
      expect(interval).not.toHaveBeenCalled();
      lite.syncManager.start();
      // The cycle timer is the fallback; the probe timer is the only other.
      expect(interval).toHaveBeenCalledTimes(2);
      expect(interval).toHaveBeenCalledWith(expect.any(Function), 60_000);
      expect(interval).toHaveBeenCalledWith(expect.any(Function), 5_000);
    } finally {
      await lite.syncManager.stop();
      await lite.closeStreamSync();
    }
  });
});
