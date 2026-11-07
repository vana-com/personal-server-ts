import { IDBFactory, IDBKeyRange } from "fake-indexeddb";
import { privateKeyToAccount } from "viem/accounts";
import { describe, expect, it, vi } from "vitest";
import { StreamSyncReadService } from "@opendatalabs/personal-server-ts-core/stream-sync-read";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import {
  createMemoryPsLiteStateStore,
  createMemoryPsLiteStorage,
} from "./test-support/memory.js";
import { loadOrCreatePsLiteServerIdentity } from "./state.js";
import { createIndexedDbStreamSyncFiles } from "./stream-sync-files.js";
import { createPsLiteSyncManager } from "./sync.js";

/** PS-Lite hands a run intake to its host only when `streamSync.write` is on. */
async function manager(
  streamSync: { write?: boolean; read?: boolean } | undefined,
  streamSyncRead?: Record<string, never>,
) {
  const owner = privateKeyToAccount(`0x${"12".repeat(32)}`);
  const OWNER_SIGNATURE = await owner.signMessage({
    message: "vana-master-key-v1",
  });
  const stateStore = createMemoryPsLiteStateStore();
  const identity = await loadOrCreatePsLiteServerIdentity({
    store: stateStore,
    ownerSignature: OWNER_SIGNATURE,
  });
  const result = await createPsLiteSyncManager({
    config: ServerConfigSchema.parse({
      sync: { enabled: true },
      ...(streamSync ? { streamSync } : {}),
    }),
    storage: createMemoryPsLiteStorage(),
    stateStore,
    ownerSignature: OWNER_SIGNATURE,
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
    ...(streamSyncRead ? { streamSyncRead } : {}),
    streamSyncFiles: (id) =>
      createIndexedDbStreamSyncFiles({
        dbName: id,
        factory: new IDBFactory(),
        keyRange: IDBKeyRange,
      }),
  });
  await result.syncManager.stop();
  return { ...result, owner: owner.address };
}

describe("PS Lite run intake", () => {
  it("is absent with streamSync.write off", async () => {
    expect((await manager(undefined)).streamSyncIntake).toBeNull();
    expect((await manager({ write: false })).streamSyncIntake).toBeNull();
  });

  it("is the in-process API when streamSync.write is on", async () => {
    const result = await manager({ write: true });
    expect(result.streamSyncWriter).not.toBeNull();
    // No connector artifact is resolvable by default: begin says so.
    await expect(
      result.streamSyncIntake!.begin("r1", {
        connector: "c",
        artifactDigest: "sha256:" + "ab".repeat(32),
        owner: { address: result.owner, leaseId: null },
        observedAt: Date.now(),
      } as never),
    ).rejects.toMatchObject({ code: "unknown_artifact" });
  });
});

describe("PS Lite stream-sync reader", () => {
  it("is opened with an overlay backed by its own writer", async () => {
    const open = vi.spyOn(StreamSyncReadService, "open");
    try {
      const result = await manager({ write: true, read: true }, {});
      expect(result.streamSyncWriter).not.toBeNull();
      // A device must read what it collected itself while its publish is
      // pending, so the reader needs a source of the writer's pending rows.
      expect(open).toHaveBeenCalledTimes(1);
      expect(open.mock.calls[0]![0].overlay).toBeDefined();
    } finally {
      open.mockRestore();
    }
  });

  it("keeps its default read files across a restart", async () => {
    // Default files are in memory: after an offline restart an own stream
    // that was readable is gone until a full online listing.
    const open = vi.spyOn(StreamSyncReadService, "open");
    const idb = globalThis as { indexedDB?: unknown; IDBKeyRange?: unknown };
    const saved = { db: idb.indexedDB, range: idb.IDBKeyRange };
    idb.indexedDB = new IDBFactory();
    idb.IDBKeyRange = IDBKeyRange;
    try {
      await manager({ read: true }, {});
      const probe = new TextEncoder().encode("imported view");
      await open.mock.calls[0]![0].files.write("views/probe", probe);
      await manager({ read: true }, {}); // the restart
      const restarted = open.mock.calls[1]![0].files;
      expect(await restarted.read("views/probe")).toEqual(probe);
    } finally {
      open.mockRestore();
      idb.indexedDB = saved.db;
      idb.IDBKeyRange = saved.range;
    }
  });
});
