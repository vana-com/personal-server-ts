import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import { signOwnerMasterKey } from "@opendatalabs/personal-server-ts-core/keys";
import {
  createLocalSync,
  openLocalDb,
  connectionQueue,
  type SqlDriver,
} from "@opendatalabs/personal-server-ts-core/localdb";
import {
  createMemoryStreamSyncRegistry,
  createMemoryStreamSyncBlobs,
  createStreamSyncKeyPorts,
  streamSyncNetwork,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { openBetterSqlite3 } from "../../server/src/localdb/better-sqlite3-driver.js";
import {
  createMemoryPsLiteStateStore,
  createMemoryPsLiteStorage,
} from "./test-support/memory.js";
import { loadOrCreatePsLiteServerIdentity } from "./state.js";
import { createPsLiteSyncManager } from "./sync.js";
const account = privateKeyToAccount(`0x${"12".repeat(32)}`);
let signature: `0x${string}`;
beforeAll(async () => {
  signature = await signOwnerMasterKey(account);
});
const managers: Awaited<ReturnType<typeof createPsLiteSyncManager>>[] = [];
const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const manager of managers.splice(0)) {
    await manager.syncManager.stop();
    await manager.closeStreamSync();
  }
  for (const db of drivers.splice(0)) await db.close();
  vi.unstubAllGlobals();
});
const declaration = {
  connector: "fixture",
  version: "1",
  streams: [
    {
      name: "items",
      semantics: "mutable_state" as const,
      primaryKey: ["id"],
      coverageStrategy: "full_inventory" as const,
    },
  ],
};
const id = "pdpp.fixture~";
async function fixture(
  mode: () => "unknown" | "unswitched" | "switched" = () => "switched",
  available = true,
) {
  const registry = createMemoryStreamSyncRegistry(),
    blobs = createMemoryStreamSyncBlobs();
  const stateStore = createMemoryPsLiteStateStore();
  const identity = await loadOrCreatePsLiteServerIdentity({
    store: stateStore,
    ownerSignature: signature,
  });
  const openDriver = vi.fn(async () =>
    available ? openBetterSqlite3(":memory:") : null,
  );
  const config = ServerConfigSchema.parse({
    streamSync: { write: false, read: false },
  });
  const lite = await createPsLiteSyncManager({
    config,
    autoStartSync: false,
    localDb: { openDriver },
    accountStorageMode: { owner: account.address, read: mode },
    streamSyncRegistry: registry,
    streamSyncBlobs: blobs,
    streamSyncDeclarations: () => declaration,
    streamSyncDeclaredStreams: () => ["items"],
    stateStore,
    storage: createMemoryPsLiteStorage(),
    ownerSignature: signature,
    serverAccount: identity.account,
    ownerSyncSigner: {
      address: account.address,
      signMessage: (message) => account.signMessage({ message }),
      signAddData: async () => "0x00",
      signLineageAttestation: async () => "0x00",
    },
    gateway: { getServer: vi.fn() } as never,
    dataPointFeed: {
      getDataPoint: async () => null,
      listDataPointsByOwner: async () => ({ dataPoints: [], cursor: null }),
    },
  });
  managers.push(lite);
  const db = await openLocalDb(openBetterSqlite3(":memory:"), {
    owner: account.address,
    network: streamSyncNetwork(config.gateway),
    deviceId: "node",
  });
  drivers.push(db);
  const node = createLocalSync(
    {
      db,
      queue: connectionQueue(),
      ownerAddress: account.address,
      registry,
      blobs,
      keys: createStreamSyncKeyPorts(signature),
      signer: { signAddData: async () => "0x00" },
      logger: { info: vi.fn(), warn: vi.fn() },
      now: () => 2000,
      newOp: () => crypto.randomUUID(),
    },
    {
      resolveArtifact: () => declaration,
      declaredStreams: () => ["items"],
      olderVersionReads: () => true,
    },
  );
  return { lite, node, openDriver };
}
const request = (observedAt: number) => ({
  connector: "fixture",
  artifactDigest: "fixture",
  owner: { address: account.address, leaseId: null },
  observedAt,
});
async function collect(
  intake: NonNullable<
    Awaited<ReturnType<typeof createPsLiteSyncManager>>["streamSyncIntake"]
  >,
  run: string,
  key: string,
  o: number,
) {
  await intake.begin(run, request(o));
  await intake.batch(run, {
    batch: 0,
    records: [{ stream: "items", data: { id: key, value: o } }],
  });
  await intake.end(run, {
    outcome: "succeeded",
    coveredStreams: ["items"],
    provenFullStreams: ["items"],
    lastBatch: 0,
  });
}
describe("Lite database intake", () => {
  it("uses the same model in both directions across Lite and Node", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() => {
        throw new Error("unexpected legacy or gateway fetch");
      }),
    );
    const { lite, node } = await fixture();
    await collect(lite.streamSyncIntake!, "lite-run", "from-lite", 1000);
    await lite.syncManager.trigger();
    await node.apply();
    expect(
      (
        await node.query.listRecords({ connectionId: id, stream: "items" })
      ).records.map((r) => JSON.parse(r.body)),
    ).toEqual([{ id: "from-lite", value: 1000 }]);
    await collect(node.intake, "node-run", "from-node", 2000);
    await node.cycle();
    await (await lite.getLocalSync()).apply();
    const decision = await lite.streamSyncRead!.resolve({
      scope: "pdpp.fixture.items",
      connection: null,
      cursor: null,
      legacyFile: false,
      isOwnerView: true,
    } as never);
    expect(decision.kind).toBe("view");
    expect(
      (
        await (
          await lite.getLocalSync()
        ).query.listRecords({ connectionId: id, stream: "items" })
      ).records.map((r) => JSON.parse(r.body)),
    ).toEqual([{ id: "from-node", value: 2000 }]);
  });
  it("a run that ends wakes the sync manager so publish does not wait for the poll", async () => {
    const { lite } = await fixture();
    const wake = vi.spyOn(lite.syncManager, "notifyNewData");
    await collect(lite.streamSyncIntake!, "lite-wake", "item", 1000);
    expect(wake).toHaveBeenCalledTimes(1);
  });
  it("unknown and explicit Off never open a database or fall back to writer files", async () => {
    let mode: "unknown" | "unswitched" | "switched" = "unknown";
    const { lite, openDriver } = await fixture(() => mode);
    await expect(
      lite.streamSyncIntake!.begin("blocked", request(1000)),
    ).rejects.toMatchObject({ errorCode: "ACCOUNT_MODE_UNKNOWN" });
    expect(openDriver).not.toHaveBeenCalled();
    mode = "unswitched";
    await expect(lite.getLocalSync()).rejects.toMatchObject({
      errorCode: "STREAM_SYNC_NOT_ENABLED",
    });
    expect(openDriver).not.toHaveBeenCalled();
    mode = "switched";
    await expect(lite.getLocalSync()).resolves.toBeDefined();
    expect(openDriver).toHaveBeenCalledTimes(1);
    expect("streamSyncWriter" in lite).toBe(false);
  });
  it("fails closed when the host has no SQLite driver", async () => {
    const { lite, openDriver } = await fixture(() => "switched", false);
    expect(openDriver).toHaveBeenCalledTimes(1);
    await expect(
      lite.streamSyncRead!.resolve({} as never),
    ).rejects.toMatchObject({ errorCode: "STREAM_READ_UNAVAILABLE" });
  });
});
