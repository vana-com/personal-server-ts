/**
 * The sync manager must be the LAST thing `startPersonalServer` starts: a throw
 * anywhere earlier (auth, runtime construction) must leave no sync cycle
 * running, because the caller never receives a handle to stop it.
 */
import { IDBFactory } from "fake-indexeddb";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import { signOwnerMasterKey } from "@opendatalabs/personal-server-ts-core/keys";

const mocks = vi.hoisted(() => ({
  managers: [] as Array<{ running: boolean; stop: () => Promise<void> }>,
  runtimeThrows: true,
}));

vi.mock("./runtime.js", async () => {
  const actual = await vi.importActual<Record<string, unknown>>("./runtime.js");
  return {
    ...actual,
    createPsLiteRuntime: (...args: unknown[]) => {
      if (mocks.runtimeThrows) throw new Error("runtime construction failed");
      return (actual.createPsLiteRuntime as (...a: unknown[]) => unknown)(
        ...args,
      );
    },
  };
});

vi.mock("./sync.js", async () => {
  const actual = await vi.importActual<Record<string, unknown>>("./sync.js");
  return {
    ...actual,
    createPsLiteSyncManager: async (...args: unknown[]) => {
      const result = await (
        actual.createPsLiteSyncManager as (...a: unknown[]) => Promise<{
          syncManager: { running: boolean; stop: () => Promise<void> };
        }>
      )(...args);
      mocks.managers.push(result.syncManager);
      return result;
    },
  };
});

import { startPersonalServer } from "./client.js";
import { createBearerTokenPsLiteAuth } from "./runtime.js";
import type { PsLitePersistenceBundle } from "./persistence.js";
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

let ownerAddress: `0x${string}`;
let ownerSignature: `0x${string}`;

beforeAll(async () => {
  const account = privateKeyToAccount(`0x${"11".repeat(32)}`);
  ownerAddress = account.address;
  ownerSignature = await signOwnerMasterKey(account);
});

afterEach(async () => {
  await Promise.all(mocks.managers.map((m) => m.stop()));
  mocks.managers.length = 0;
  vi.unstubAllGlobals();
});

function memoryBundle(): PsLitePersistenceBundle {
  return {
    storage: createMemoryPsLiteStorage(),
    state: createMemoryPsLiteStateStore(),
    tokens: createMemoryPsLiteTokenStore(),
    accessLog: createMemoryPsLiteAccessLogStore(),
    mcpConnections: createInMemoryMcpConnectionStore(),
    mcpOAuthAuthorizations: createInMemoryMcpOAuthAuthorizationStore(),
    relayTlsIdentity: { read: () => null, write: () => {} },
  };
}

function start(extra: Record<string, unknown> = {}) {
  vi.stubGlobal("indexedDB", new IDBFactory());
  return startPersonalServer({
    ownerAddress,
    ownerSignature,
    persistence: memoryBundle(),
    gateway: createMockPsLiteGateway(),
    auth: createBearerTokenPsLiteAuth({
      ownerToken: "owner-token",
      builderToken: "builder-token",
    }),
    configDefaults: {
      gateway: { url: "https://gateway.local" },
      sync: { enabled: true },
    },
    ...extra,
  } as Parameters<typeof startPersonalServer>[0]);
}

describe("startPersonalServer starts sync last", () => {
  it("throw_after_sync_built_stops_sync: a runtime construction throw leaves no sync cycle running", async () => {
    mocks.runtimeThrows = true;
    await expect(start()).rejects.toThrow("runtime construction failed");

    expect(mocks.managers).toHaveLength(1);
    expect(mocks.managers[0]!.running).toBe(false);
  });

  it("starts the sync manager once the start has succeeded", async () => {
    mocks.runtimeThrows = false;
    const handle = await start();
    try {
      expect(mocks.managers).toHaveLength(1);
      expect(mocks.managers[0]!.running).toBe(true);
    } finally {
      await handle.stop();
    }
  });
});
