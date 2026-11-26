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

it.each([undefined, () => true])(
  "an unregistered gateway response captures nothing and sends no delete (callback=%s)",
  async (registrationReady) => {
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
      registrationReady,
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
  },
);

it.each([false, true])(
  "switched Lite startup opens the database without waiting for the registration lookup (later confirmed=%s)",
  async (confirmLater) => {
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
    let confirmRegistration: (value: { id: string }) => void = () => {};
    const getServer = vi.fn(
      () =>
        new Promise<{ id: string }>((resolve) => {
          confirmRegistration = resolve;
        }),
    );
    const starting = createPsLiteSyncManager({
      config: ServerConfigSchema.parse({ sync: { enabled: true } }),
      autoStartSync: false,
      registrationReady: () => true,
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
    let lite: Awaited<typeof starting> | undefined;
    let timeout: ReturnType<typeof setTimeout> | undefined;
    try {
      lite = await Promise.race([
        starting,
        new Promise<never>((_, reject) => {
          timeout = setTimeout(
            () => reject(new Error("startup waited for registration")),
            2000,
          );
        }),
      ]);
      expect(getServer).toHaveBeenCalledOnce();
      expect(
        await lite.localSync!.query.listRecords({
          connectionId: "missing",
          stream: "items",
        }),
      ).toEqual({ records: [], nextCursor: null });
      await expect(
        lite.localSync!.legacyRetirer.request("github"),
      ).rejects.toThrow("write authority");
      expect(capture).not.toHaveBeenCalled();
      const resume = vi.spyOn(lite.localSync!.legacyRetirer, "resume");
      if (confirmLater) {
        confirmRegistration({ id: "registered" });
        await vi.waitFor(() => expect(resume).toHaveBeenCalledOnce());
      } else {
        expect(resume).not.toHaveBeenCalled();
      }
    } finally {
      clearTimeout(timeout);
      await lite?.syncManager.stop();
      if (lite) await lite.closeStreamSync();
      else await db.close();
      fetch.mockRestore();
    }
  },
);
