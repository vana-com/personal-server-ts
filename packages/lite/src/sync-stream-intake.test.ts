import { IDBFactory, IDBKeyRange } from "fake-indexeddb";
import { privateKeyToAccount } from "viem/accounts";
import { describe, expect, it, vi } from "vitest";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import {
  createMemoryPsLiteStateStore,
  createMemoryPsLiteStorage,
} from "./test-support/memory.js";
import { loadOrCreatePsLiteServerIdentity } from "./state.js";
import { createIndexedDbStreamSyncFiles } from "./stream-sync-files.js";
import { createPsLiteSyncManager } from "./sync.js";

/** PS-Lite hands a run intake to its host only when `streamSync.write` is on. */
async function manager(streamSync: { write: boolean } | undefined) {
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
    streamSyncFiles: createIndexedDbStreamSyncFiles({
      dbName: `intake-${Math.random()}`,
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
