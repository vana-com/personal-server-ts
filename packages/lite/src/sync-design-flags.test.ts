/**
 * The stream-sync design flags a host passes to PS-Lite reach `LocalSyncDeps`,
 * the one place the sync engine reads them. Default off.
 */
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import { signOwnerMasterKey } from "@opendatalabs/personal-server-ts-core/keys";
import type * as LocalDbModule from "@opendatalabs/personal-server-ts-core/localdb";
import {
  createMemoryStreamSyncRegistry,
  createMemoryStreamSyncBlobs,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { openBetterSqlite3 } from "../../server/src/localdb/better-sqlite3-driver.js";
import {
  createMemoryPsLiteStateStore,
  createMemoryPsLiteStorage,
} from "./test-support/memory.js";
import { loadOrCreatePsLiteServerIdentity } from "./state.js";
import { createPsLiteSyncManager } from "./sync.js";
import { IDBFactory } from "fake-indexeddb";
import { createMockPsLiteGateway } from "./test-support/gateway.js";
import { createSwitchedIndexedDbPsLiteRuntime } from "./test-support/unswitched-runtime.js";
import { createBearerTokenPsLiteAuth } from "./runtime.js";

const engineDeps = vi.hoisted(() => [] as Array<Record<string, unknown>>);
vi.mock(
  "@opendatalabs/personal-server-ts-core/localdb",
  async (importOriginal) => {
    const actual = await importOriginal<typeof LocalDbModule>();
    return {
      ...actual,
      createLocalSync: (...args: Parameters<typeof actual.createLocalSync>) => {
        engineDeps.push(args[0] as unknown as Record<string, unknown>);
        return actual.createLocalSync(...args);
      },
    };
  },
);

const account = privateKeyToAccount(`0x${"13".repeat(32)}`);
let signature: `0x${string}`;
beforeAll(async () => {
  signature = await signOwnerMasterKey(account);
});
const managers: Awaited<ReturnType<typeof createPsLiteSyncManager>>[] = [];
afterEach(async () => {
  for (const manager of managers.splice(0)) {
    await manager.syncManager.stop();
    await manager.closeStreamSync();
  }
  engineDeps.length = 0;
});

type Flags = {
  streamSyncFlags?: string;
  streamSyncPublishWhileCollecting?: boolean;
  streamSyncLogProtocol?: boolean;
  streamSyncProgressiveFirstLoad?: boolean;
};

async function depsFor(flags: Flags) {
  const stateStore = createMemoryPsLiteStateStore();
  const identity = await loadOrCreatePsLiteServerIdentity({
    store: stateStore,
    ownerSignature: signature,
  });
  const lite = await createPsLiteSyncManager({
    config: ServerConfigSchema.parse({}),
    autoStartSync: false,
    localDb: { openDriver: async () => openBetterSqlite3(":memory:") },
    accountStorageMode: { owner: account.address, read: () => "switched" },
    streamSyncRegistry: createMemoryStreamSyncRegistry(),
    streamSyncBlobs: createMemoryStreamSyncBlobs(),
    streamSyncDeclarations: () => null,
    streamSyncDeclaredStreams: () => [],
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
    ...flags,
  });
  managers.push(lite);
  await lite.getLocalSync();
  expect(engineDeps).toHaveLength(1);
  return engineDeps[0]!;
}

const FLAGS = [
  ["publishWhileCollecting", "streamSyncPublishWhileCollecting"],
  ["logProtocol", "streamSyncLogProtocol"],
  ["progressiveFirstLoad", "streamSyncProgressiveFirstLoad"],
] as const;

describe("PS-Lite stream-sync design flags", () => {
  it.each(FLAGS)(
    "%s is off by default and on when the sync manager gets %s",
    async (flag, option) => {
      expect((await depsFor({}))[flag] ?? false).toBe(false);
      engineDeps.length = 0;
      expect(await depsFor({ [option]: true })).toMatchObject({
        [flag]: true,
      });
    },
  );

  it.each(FLAGS)(
    "the list naming only %s turns that flag on and no other",
    async (flag) => {
      const deps = await depsFor({ streamSyncFlags: `${flag}, nonsense` });
      for (const [other] of FLAGS) {
        expect(deps[other] ?? false).toBe(other === flag);
      }
    },
  );

  it.each(FLAGS)(
    "lets the own option of %s win over a list that names it",
    async (flag, option) => {
      const deps = await depsFor({
        streamSyncFlags: flag,
        [option]: false,
      });
      expect(deps[flag] ?? false).toBe(false);
    },
  );

  // `startPersonalServer` (what the Web host calls) spreads its options into
  // `createIndexedDbPsLiteRuntime`; the option must survive that hop too.
  it.each(FLAGS)(
    "%s reaches the sync deps from the runtime option %s",
    async (flag, option) => {
      for (const on of [false, true]) {
        vi.stubGlobal("indexedDB", new IDBFactory());
        engineDeps.length = 0;
        const context = await createSwitchedIndexedDbPsLiteRuntime({
          ownerAddress: account.address,
          ownerSignature: signature,
          dbName: `ps-lite-flags-${Math.random()}`,
          storageDbName: `ps-lite-flags-storage-${Math.random()}`,
          gateway: createMockPsLiteGateway(),
          auth: createBearerTokenPsLiteAuth({
            ownerToken: "owner-token",
            builderToken: "builder-token",
          }),
          active: true,
          streamSyncDeclaredStreams: () => [],
          localDb: { openDriver: async () => openBetterSqlite3(":memory:") },
          configDefaults: {
            gateway: { url: "https://gateway.local" },
            sync: { enabled: false },
          },
          ...(on ? { [option]: true } : {}),
        });
        try {
          await context.getLocalSync!();
          expect(engineDeps).toHaveLength(1);
          if (on) expect(engineDeps[0]).toMatchObject({ [flag]: true });
          else expect(engineDeps[0]![flag] ?? false).toBe(false);
        } finally {
          await context.syncManager?.stop();
          await context.closeStreamSync?.();
        }
      }
    },
  );
});
