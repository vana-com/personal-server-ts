import { IDBFactory, IDBKeyRange } from "fake-indexeddb";
import { privateKeyToAccount } from "viem/accounts";
import { afterEach, describe, expect, it, vi } from "vitest";
import { StreamSyncReadService } from "@opendatalabs/personal-server-ts-core/stream-sync-read";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import {
  createMemoryPsLiteStateStore,
  createMemoryPsLiteStorage,
} from "./test-support/memory.js";
import { loadOrCreatePsLiteServerIdentity } from "./state.js";
import { createPsLiteSyncManager } from "./sync.js";

/** Exclusive Web Locks that answer `ifAvailable` with null while held. */
function fakeLocks() {
  const held = new Set<string>();
  return {
    held,
    locks: {
      async request(
        name: string,
        _options: unknown,
        callback: (lock: unknown) => Promise<unknown>,
      ) {
        if (held.has(name)) return callback(null);
        held.add(name);
        try {
          return await callback({ name });
        } finally {
          held.delete(name);
        }
      },
    },
  };
}

// The default home: no injected `streamSyncFiles`, so the real IndexedDB home
// and Web Lock are used (an injected home has a no-op close).
async function startManager() {
  const owner = privateKeyToAccount(`0x${"12".repeat(32)}`);
  const ownerSignature = await owner.signMessage({
    message: "vana-master-key-v1",
  });
  const stateStore = createMemoryPsLiteStateStore();
  const identity = await loadOrCreatePsLiteServerIdentity({
    store: stateStore,
    ownerSignature,
  });
  return createPsLiteSyncManager({
    streamSyncDeclaredStreams: () => [],
    config: ServerConfigSchema.parse({
      sync: { enabled: true },
      streamSync: { write: true, read: true },
    }),
    storage: createMemoryPsLiteStorage(),
    stateStore,
    ownerSignature,
    serverAccount: identity.account,
    ownerSyncSigner: {
      address: owner.address,
      signMessage: (message: string) => owner.signMessage({ message }),
      signAddData: vi.fn(),
      signLineageAttestation: vi.fn(),
    },
    gateway: { getServer: vi.fn().mockResolvedValue(null) } as never,
    dataPointFeed: {
      getDataPoint: async () => null,
      listDataPointsByOwner: async () => ({ dataPoints: [], cursor: null }),
    },
    autoStartSync: false,
    streamSyncRead: {},
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("PS Lite stream-sync startup failure", () => {
  it("releases the writer home when the reader fails to open", async () => {
    const { locks, held } = fakeLocks();
    vi.stubGlobal("indexedDB", new IDBFactory());
    vi.stubGlobal("IDBKeyRange", IDBKeyRange);
    vi.stubGlobal("navigator", { locks });
    const failure = new Error("reader open failed");
    const open = vi
      .spyOn(StreamSyncReadService, "open")
      .mockRejectedValueOnce(failure);

    await expect(startManager()).rejects.toBe(failure);
    expect(held.size).toBe(0);

    // A retry in the same context acquires the home and writes are enabled.
    open.mockRestore();
    const retry = await startManager();
    expect(retry.streamSyncWriter).not.toBeNull();
    expect(held.size).toBe(1);
    await retry.closeStreamSync();
    expect(held.size).toBe(0);
  });
});
