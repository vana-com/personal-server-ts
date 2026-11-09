import "fake-indexeddb/auto";
import { describe, expect, it, vi } from "vitest";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { createMemoryStreamSyncReadFiles } from "@opendatalabs/personal-server-ts-core/stream-sync-read";
import {
  createMemoryPsLiteStateStore,
  createMemoryPsLiteStorage,
} from "./test-support/memory.js";
import { loadOrCreatePsLiteServerIdentity } from "./state.js";
import { createPsLiteSyncManager } from "./sync.js";

const OWNER_SIGNATURE =
  "0xedbb7743cce459345238442dcfb291f234a321d253485eaa58251aa0f28ea8f1410ab988bae2657b689cd24417b41e315efc22ba333024f4a6269c424ded8d361b" as const;

/** The real Lite factory with a mode: the manager it builds must obey the mode. */
async function open(value: "switched" | "unswitched" | undefined) {
  const stateStore = createMemoryPsLiteStateStore();
  const storage = createMemoryPsLiteStorage();
  const findUnsynced = vi.spyOn(storage, "findUnsynced");
  const identity = await loadOrCreatePsLiteServerIdentity({
    store: stateStore,
    ownerSignature: OWNER_SIGNATURE,
  });
  const gateway = {
    getServer: vi.fn().mockResolvedValue({ id: "server-1" }),
  };
  const sync = await createPsLiteSyncManager({
    config: ServerConfigSchema.parse({ sync: { enabled: true } }),
    stateStore,
    storage,
    ownerSignature: OWNER_SIGNATURE,
    serverAccount: identity.account,
    gateway: gateway as never,
    autoStartSync: false,
    streamSyncRead: { files: createMemoryStreamSyncReadFiles() },
    dataPointFeed: {
      getDataPoint: async () => null,
      listDataPointsByOwner: async () => ({ dataPoints: [], cursor: null }),
    } as never,
    ...(value === undefined
      ? {}
      : { accountStorageMode: { read: () => value } }),
  });
  return { sync, findUnsynced, gateway };
}

describe("LITE_SYNC_MANAGER_MODE_DROPPED: the Lite sync manager follows the account mode", () => {
  it("a switched account's trigger reads no legacy storage", async () => {
    const h = await open("switched");
    await h.sync.syncManager.trigger();
    expect(h.findUnsynced).not.toHaveBeenCalled();
    expect(h.sync.syncManager.getStatus().blocked?.reason).toBe("stream_sync");
  });

  it.each(["unswitched", undefined] as const)(
    "UNSWITCHED_PARITY (%s): the legacy cycle runs",
    async (value) => {
      const h = await open(value);
      await h.sync.syncManager.trigger();
      expect(h.findUnsynced).toHaveBeenCalled();
      expect(h.sync.syncManager.getStatus().blocked?.reason).not.toBe(
        "stream_sync",
      );
    },
  );
});
