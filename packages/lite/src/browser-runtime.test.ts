/**
 * Proves `createIndexedDbPsLiteRuntime` composes its identity/config/sync/auth
 * over INJECTED persistence ports (the Mobile native path) instead of the
 * browser IndexedDB defaults — without a browser storage dependency in the test
 * environment. Browser defaults remain exercised by the existing suite.
 */

import { beforeAll, describe, expect, it } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import { buildPersonalServerLiteOwnerBindingMessage } from "@opendatalabs/vana-sdk/protocol/personal-server-lite-owner-binding";
import { createIndexedDbPsLiteRuntime } from "./browser-runtime.js";
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
  ownerSignature = await account.signMessage({
    message: buildPersonalServerLiteOwnerBindingMessage(account.address),
  });
});

function memoryBundle(): PsLitePersistenceBundle {
  const accessLog = createMemoryPsLiteAccessLogStore();
  return {
    storage: createMemoryPsLiteStorage(),
    state: createMemoryPsLiteStateStore(),
    tokens: createMemoryPsLiteTokenStore(),
    accessLog,
    mcpConnections: createInMemoryMcpConnectionStore(),
    mcpOAuthAuthorizations: createInMemoryMcpOAuthAuthorizationStore(),
    relayTlsIdentity: {
      read: () => null,
      write: () => {},
    },
  };
}

function build(bundle: PsLitePersistenceBundle) {
  return createIndexedDbPsLiteRuntime({
    ownerAddress,
    ownerSignature,
    persistence: bundle,
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
  });
}

describe("createIndexedDbPsLiteRuntime persistence injection", () => {
  it("rejects a partial bundle instead of mixing native and IndexedDB stores", async () => {
    await expect(
      createIndexedDbPsLiteRuntime({
        ownerAddress,
        ownerSignature,
        persistence: {} as PsLitePersistenceBundle,
      }),
    ).rejects.toThrow(
      "PS Lite persistence bundle must be complete; missing storage, state, tokens, accessLog, mcpConnections, mcpOAuthAuthorizations, relayTlsIdentity",
    );
  });

  it("uses the injected ports and persists identity into the injected state store", async () => {
    const bundle = memoryBundle();
    const built = await build(bundle);

    // The factory returned the injected instances, not IndexedDB defaults.
    expect(built.stateStore).toBe(bundle.state);
    expect(built.storage).toBe(bundle.storage);
    expect(built.tokenStore).toBe(bundle.tokens);
    expect(built.accessLogStore).toBe(bundle.accessLog);

    // Identity was created + persisted through the injected state store, with
    // the existing AES-GCM record shape (byte-compatible, no app-level crypto).
    const persisted = await bundle.state.get<{
      encryptedPrivateKey: { algorithm: string };
      address: string;
    }>("server-identity-v1");
    expect(persisted?.encryptedPrivateKey.algorithm).toBe("AES-GCM");
    expect(persisted?.address).toBe(built.identity.account.address);
  });

  it("serves data through the injected storage across a runtime restart", async () => {
    const bundle = memoryBundle();

    const first = await build(bundle);
    const write = await first.runtime.fetch(
      new Request("https://ps.local/v1/data/instagram.profile", {
        method: "POST",
        headers: {
          Authorization: "Bearer owner-token",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ username: "native_user" }),
      }),
    );
    expect(write.status).toBe(201);

    // A second runtime over the SAME injected bundle sees the persisted data:
    // durability comes from the native store, not the runtime instance.
    const rebooted = await build(bundle);
    const list = await rebooted.runtime.fetch(
      new Request("https://ps.local/v1/data", {
        headers: { Authorization: "Bearer owner-token" },
      }),
    );
    expect(list.status).toBe(200);
    await expect(list.json()).resolves.toMatchObject({
      scopes: [{ scope: "instagram.profile" }],
      total: 1,
    });
  });
});
