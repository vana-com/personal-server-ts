import { expect, it, vi } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { openBetterSqlite3 } from "../../server/src/localdb/better-sqlite3-driver.js";
import {
  createMemoryPsLiteStateStore,
  createMemoryPsLitePersistence,
} from "./test-support/memory.js";
import { loadOrCreatePsLiteServerIdentity } from "./state.js";
import { createOpenPersistentPsLiteStorage } from "./test-support/open-storage.js";
import { createPsLiteSyncManager } from "./sync.js";

it("with no registrationReady callback and an unregistered gateway response, the retirement captures nothing and sends no delete", async () => {
  const owner = privateKeyToAccount(`0x${"11".repeat(32)}`);
  const ownerSignature = await owner.signMessage({
    message: "Retirement fixture",
  });
  const stateStore = createMemoryPsLiteStateStore();
  const identity = await loadOrCreatePsLiteServerIdentity({
    store: stateStore,
    ownerSignature,
  });
  const storage = await createOpenPersistentPsLiteStorage(
    { kind: "custom" },
    createMemoryPsLitePersistence(),
  );
  const capture = vi.spyOn(storage.retirementRows!, "capture");
  const fetch = vi.spyOn(globalThis, "fetch");
  const db = openBetterSqlite3(":memory:");
  const getServer = vi.fn().mockResolvedValue(null);
  const lite = await createPsLiteSyncManager({
    config: ServerConfigSchema.parse({ sync: { enabled: true } }),
    autoStartSync: false,
    localDb: { openDriver: async () => db },
    accountStorageMode: { owner: owner.address, read: () => "switched" },
    stateStore,
    storage,
    ownerSignature,
    serverAccount: identity.account,
    gateway: { getServer } as never,
    dataPointFeed: {
      getDataPoint: async () => null,
      listDataPointsByOwner: async () => ({ dataPoints: [], cursor: null }),
    },
  });
  try {
    await expect(
      lite.localSync!.legacyRetirer.request("github"),
    ).rejects.toThrow("write authority");
    await lite.syncManager.trigger();
    expect(getServer).toHaveBeenCalled();
    await expect(
      lite.localSync!.legacyRetirer.request("github"),
    ).rejects.toThrow("write authority");
    expect(capture).not.toHaveBeenCalled();
    expect(await db.query("SELECT * FROM legacy_retirements")).toEqual([]);
    expect(
      fetch.mock.calls.filter(([, init]) => init?.method === "DELETE"),
    ).toEqual([]);
  } finally {
    await lite.syncManager.stop();
    await lite.closeStreamSync();
    fetch.mockRestore();
  }
});
