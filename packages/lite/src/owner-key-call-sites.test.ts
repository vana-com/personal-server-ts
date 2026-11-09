/**
 * Call-site pins for the legacy owner key in PS Lite.
 *
 * The legacy key is the raw 65 signature bytes; the stream key is the same
 * signature in normal form. They differ for a non-canonical signature. The
 * existing suites sign canonical signatures, so a swap of one key for the other
 * at these sites passes them.
 *
 * Each test wraps the real factory (it still runs) and compares the key it
 * receives with the SDK's `deriveMasterKey`, which is independent of the owner
 * module. The signature is the high-s vector (v = 0x1c).
 */

import { createUnswitchedIndexedDbPsLiteRuntime } from "./test-support/unswitched-runtime.js";
import { IDBFactory } from "fake-indexeddb";
import { afterEach, expect, it, vi } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import { bytesToHex, type Hex } from "viem";
import { deriveMasterKey } from "@opendatalabs/vana-sdk/browser";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import * as SyncManagerModule from "@opendatalabs/personal-server-ts-core/sync/manager";
import * as HostPortsModule from "@opendatalabs/personal-server-ts-core/replication/host-ports";
import * as ReplicationHostModule from "./replication-host.js";
import { createPsLiteSyncManager } from "./sync.js";
import { createIndexedDbPsLiteStateStore } from "./state.js";
import { recoverOwnerAddress } from "@opendatalabs/personal-server-ts-core/keys";
import { createBearerTokenPsLiteAuth } from "./runtime.js";
import {
  createMemoryPsLiteAccessLogStore,
  createMemoryPsLiteStateStore,
  createMemoryPsLiteStorage,
  createMemoryPsLiteTokenStore,
} from "./test-support/memory.js";
import { createMockPsLiteGateway } from "./test-support/gateway.js";
import {
  createInMemoryMcpConnectionStore,
  createInMemoryMcpOAuthAuthorizationStore,
} from "@opendatalabs/personal-server-ts-core/mcp";

vi.mock(
  "@opendatalabs/personal-server-ts-core/sync/manager",
  async (importOriginal) => {
    const actual = await importOriginal<typeof SyncManagerModule>();
    return {
      ...actual,
      createSyncManager: vi.fn(actual.createSyncManager),
    };
  },
);

vi.mock(
  "@opendatalabs/personal-server-ts-core/replication/host-ports",
  async (importOriginal) => {
    const actual = await importOriginal<typeof HostPortsModule>();
    return {
      ...actual,
      createReplicationNetworkPorts: vi.fn(
        actual.createReplicationNetworkPorts,
      ),
    };
  },
);

vi.mock("./replication-host.js", async (importOriginal) => {
  const actual = await importOriginal<typeof ReplicationHostModule>();
  return {
    ...actual,
    createLiteReplication: vi.fn(actual.createLiteReplication),
  };
});

/** High-s signature (v = 0x1c). Its legacy key is the raw bytes. */
const HIGH_S_SIGNATURE =
  "0x1f5c9b3bafc291e8ea7aa4e0c5700a109e68aa2431fdbea08b49f9bf91b5c7dbd555e6d21a3207991a060a0c6afd5992e4183bad14f5218f2fd6dc20cf515f6c1c" as Hex;

/** The SDK's legacy key for that signature. Independent of the owner module. */
const SDK_LEGACY_KEY = bytesToHex(deriveMasterKey(HIGH_S_SIGNATURE));

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

it("gives the Lite sync manager the legacy master key for upload and download", async () => {
  vi.stubGlobal("indexedDB", new IDBFactory());
  vi.stubGlobal("navigator", {
    locks: {
      request: async (_name: string, _options: unknown, run: () => unknown) =>
        run(),
    },
  });
  const account = privateKeyToAccount(`0x${"12".repeat(32)}`);
  await createPsLiteSyncManager({
    config: ServerConfigSchema.parse({}),
    storage: createMemoryPsLiteStorage(),
    stateStore: createIndexedDbPsLiteStateStore({
      dbName: crypto.randomUUID(),
    }),
    ownerSignature: HIGH_S_SIGNATURE,
    serverAccount: account,
  });
  const calls = vi.mocked(SyncManagerModule.createSyncManager).mock.calls;
  expect(calls.length).toBeGreaterThan(0);
  const [uploadDeps, downloadDeps] = calls.at(-1)!;
  expect(bytesToHex(uploadDeps.masterKey)).toBe(SDK_LEGACY_KEY);
  expect(bytesToHex(downloadDeps.masterKey)).toBe(SDK_LEGACY_KEY);
});

it("gives the Lite replication network ports the legacy master key", async () => {
  const owner = await recoverOwnerAddress(HIGH_S_SIGNATURE);
  const memory = {
    storage: createMemoryPsLiteStorage(),
    state: createMemoryPsLiteStateStore(),
    tokens: createMemoryPsLiteTokenStore(),
    accessLog: createMemoryPsLiteAccessLogStore(),
    mcpConnections: createInMemoryMcpConnectionStore(),
    mcpOAuthAuthorizations: createInMemoryMcpOAuthAuthorizationStore(),
    relayTlsIdentity: { read: () => null, write: () => {} },
  };
  await createUnswitchedIndexedDbPsLiteRuntime({
    ownerAddress: owner,
    ownerSignature: HIGH_S_SIGNATURE,
    persistence: memory,
    gateway: createMockPsLiteGateway(),
    auth: createBearerTokenPsLiteAuth({
      ownerToken: "owner-token",
      builderToken: "builder-token",
    }),
    active: true,
    configDefaults: {
      gateway: { url: "https://gateway.local" },
      sync: { enabled: false },
    },
    // Replication stays off, so createLiteReplication builds no network. The
    // input still carries the `network` callback, which is the call site.
    replicaHost: {
      config: { enabled: false } as never,
      persistence: {} as never,
      transfers: {} as never,
      declarations: [],
    },
  });
  const input = vi
    .mocked(ReplicationHostModule.createLiteReplication)
    .mock.calls.at(-1)?.[0];
  expect(input).toBeDefined();
  // Run the callback as replication would. The port factory may throw on the
  // placeholder storage; the spy has recorded the key by then.
  try {
    input!.network(owner, {} as never);
  } catch {
    // Expected with placeholder storage.
  }
  const calls = vi.mocked(HostPortsModule.createReplicationNetworkPorts).mock
    .calls;
  expect(calls.length).toBeGreaterThan(0);
  expect(bytesToHex(calls.at(-1)![0].masterKey)).toBe(SDK_LEGACY_KEY);
});
