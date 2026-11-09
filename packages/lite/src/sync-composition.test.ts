import "fake-indexeddb/auto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { uploadAttemptKey } from "@opendatalabs/personal-server-ts-core/sync";
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
const UPLOAD_ATTEMPTS_KEY = "upload-attempts-v1";
const SYNC_CURSOR_KEY = "sync-cursor-v1";
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

/** The real factory, stream sync on, read files injectable for a fault. */
async function openLite(opts: {
  stateStore: StateStore;
  storage: ReturnType<typeof createMemoryPsLiteStorage>;
  identity: Awaited<ReturnType<typeof loadOrCreatePsLiteServerIdentity>>;
  gateway: object;
  feed?: {
    dataPoints: unknown[];
    cursor: string | null;
  };
  readFiles?: ReturnType<typeof createMemoryStreamSyncReadFiles>;
}) {
  return createPsLiteSyncManager({
    config: ServerConfigSchema.parse({
      sync: { enabled: true },
      streamSync: { read: true, write: true },
    }),
    stateStore: opts.stateStore,
    storage: opts.storage,
    ownerSignature: OWNER_SIGNATURE,
    serverAccount: opts.identity.account,
    gateway: opts.gateway as never,
    autoStartSync: false,
    streamSyncRead: {
      files: opts.readFiles ?? createMemoryStreamSyncReadFiles(),
    },
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

  it("(a) skips the body of a quarantined legacy row while publish and read still run in the cycle", async () => {
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
    expect(lite.streamSyncWriter).not.toBeNull();
    const publish = vi.spyOn(lite.streamSyncWriter!, "cycle");
    const observe = vi.spyOn(lite.streamSyncRead!, "observe");
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
    // The same cycle still publishes the stream and reads the physical row.
    expect(publish).toHaveBeenCalledTimes(1);
    expect(observe).toHaveBeenCalledWith(
      [expect.objectContaining({ scope: PHYSICAL_SCOPE })],
      expect.objectContaining({ fromStart: true, lastPage: true }),
    );
    // The quarantine itself is kept, not reset by the cycle.
    expect(
      (
        (await stateStore.get(UPLOAD_ATTEMPTS_KEY)) as {
          records: Array<{ quarantined: boolean }>;
        }
      ).records,
    ).toEqual([expect.objectContaining({ quarantined: true })]);
  });

  it("(b) two managers over one state namespace exclude each other on the attempt store and the stream home; another namespace only shares the home", async () => {
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
    expect(holder.streamSyncWriter).not.toBeNull();
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
      // The stream home is keyed by owner and network, so it is excluded too.
      expect(rival.streamSyncWriter).toBeNull();
      const putsBefore = fetchMock.mock.calls.length;
      await rival.syncManager.trigger();
      await rival.syncManager.stop();
      expect(
        fetchMock.mock.calls
          .slice(putsBefore)
          .filter(([, init]) => init?.method === "PUT"),
      ).toEqual([]);

      // Another namespace, same owner: the attempt store is not excluded, so
      // its legacy row uploads, while the stream home stays excluded.
      const other = namedState("indexeddb:composition-b-other/state");
      const otherFixture = await fixture(other, owner);
      const elsewhere = await openLite({
        stateStore: other,
        storage: (await legacyStorage()).storage,
        identity: otherFixture.identity,
        gateway: otherFixture.gateway,
      });
      expect(elsewhere.streamSyncWriter).toBeNull();
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
    // The attempt store and the stream home take distinct lock names.
    const attemptLock =
      "upload-attempts:indexeddb:composition-b/state/upload-attempts-v1";
    const homeLocks = requested.filter((name) =>
      name.startsWith("ps-lite-stream-sync-"),
    );
    expect(requested).toContain(attemptLock);
    expect(homeLocks.length).toBeGreaterThan(0);
    expect(homeLocks).not.toContain(attemptLock);
  });

  it("(c) a stop repairs the attempt ledger while the stream writer is in flight, and the repair is persisted before the writer is released", async () => {
    stubBrowserLocks();
    const owner = (await recoverServerOwner(OWNER_SIGNATURE)).toLowerCase();
    const stateStore = namedState("indexeddb:composition-c/state");
    // The settle of the upload's successful attempt fails once: the in-memory
    // ledger is clean, storage still holds the in-flight marker.
    let attemptWrites = 0;
    const set = stateStore.set.bind(stateStore);
    stateStore.set = async (key, value) => {
      if (key === UPLOAD_ATTEMPTS_KEY && ++attemptWrites === 2)
        throw new Error("storage refused the settle");
      await set(key, value);
    };
    vi.stubGlobal("fetch", uploadFetch(owner));
    const { storage } = await legacyStorage();
    const { identity, gateway } = await fixture(stateStore, owner);
    const lite = await openLite({ stateStore, storage, identity, gateway });
    const writer = lite.streamSyncWriter!;
    const realCycle = writer.cycle.bind(writer);
    let enteredWriter = false;
    let writerDone = false;
    let releaseWriter!: () => void;
    const gate = new Promise<void>((resolve) => (releaseWriter = resolve));
    vi.spyOn(writer, "cycle").mockImplementation(async () => {
      enteredWriter = true;
      await gate;
      try {
        return await realCycle();
      } finally {
        writerDone = true;
      }
    });

    const cycle = lite.syncManager.trigger();
    await vi.waitFor(
      () => {
        if (!enteredWriter) throw new Error("stream writer never entered");
      },
      { timeout: 4000 },
    );
    // Before the stop: storage still shows the marker of the unsettled attempt.
    expect(
      (
        (await stateStore.get(UPLOAD_ATTEMPTS_KEY)) as {
          records: Array<{ inFlight: boolean }>;
        }
      ).records,
    ).toEqual([expect.objectContaining({ inFlight: true })]);

    const stopping = lite.syncManager.stop();
    await vi.waitFor(
      async () => {
        const state = (await stateStore.get(UPLOAD_ATTEMPTS_KEY)) as {
          records: unknown[];
        };
        if (state.records.length !== 0)
          throw new Error("the stop has not repaired the ledger yet");
      },
      { timeout: 4000 },
    );
    // The repair reached storage while the writer was still held.
    expect(writerDone).toBe(false);
    expect(attemptWrites).toBeGreaterThanOrEqual(3);

    releaseWriter();
    await stopping;
    await cycle;
    await lite.closeStreamSync();
    expect(writerDone).toBe(true);
  });

  it("(d) a failed stream observation leaves the legacy download cursor unset; a clean one sets it", async () => {
    stubBrowserLocks();
    const owner = (await recoverServerOwner(OWNER_SIGNATURE)).toLowerCase();
    vi.stubGlobal("fetch", uploadFetch(owner));
    const readFiles = createMemoryStreamSyncReadFiles();
    let armed = false;
    let refused = 0;
    const flakyFiles = {
      ...readFiles,
      async write(path: string, bytes: Uint8Array) {
        if (armed) {
          refused += 1;
          throw new Error("read-side storage refused the write");
        }
        return readFiles.write(path, bytes);
      },
    };
    const stateStore = namedState("indexeddb:composition-d/state");
    const { identity, gateway } = await fixture(stateStore, owner);
    const { storage } = await legacyStorage();
    // A two-page listing: the cursor would move to "page-2" if nothing failed.
    const lite = await openLite({
      stateStore,
      storage,
      identity,
      gateway,
      readFiles: flakyFiles as never,
      feed: { dataPoints: [physicalRow], cursor: "page-2" },
    });
    try {
      armed = true;
      await lite.syncManager.trigger();
      // The injected write failure fired, and the cursor did not move.
      expect(refused).toBeGreaterThan(0);
      expect(await stateStore.get(SYNC_CURSOR_KEY)).toBeNull();

      // The same listing with the stream side healthy moves the cursor.
      armed = false;
      await lite.syncManager.trigger();
      expect(await stateStore.get(SYNC_CURSOR_KEY)).toEqual({
        lastProcessedTimestamp: "page-2",
      });
    } finally {
      await lite.syncManager.stop();
      await lite.closeStreamSync();
    }
  });
});
