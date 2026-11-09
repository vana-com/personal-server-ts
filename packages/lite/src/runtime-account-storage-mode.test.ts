/**
 * The Lite runtime hands one account storage mode to every consumer: the
 * legacy write gate, the data handler and the MCP engine. The mode is a
 * counting stand-in that reports a switched account, and the requests go
 * through the real runtime.
 */
import { describe, it, expect, vi } from "vitest";
import { createPsLiteRuntime, createWeb3SignedPsLiteAuth } from "./runtime.js";
import {
  createMemoryPsLiteStorage,
  createMemoryPsLiteTokenStore,
} from "./test-support/memory.js";
import {
  approveMcpConnection,
  createInMemoryMcpConnectionStore,
  createMcpConnection,
} from "@opendatalabs/personal-server-ts-core/mcp";
import {
  buildWeb3SignedHeader,
  createTestWallet,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import type {
  Builder,
  GatewayClient,
  GatewayGrantResponse,
} from "@opendatalabs/vana-sdk/browser";
import type {
  AccountStorageMode,
  AccountStorageModeValue,
  StreamSyncReadPort,
} from "@opendatalabs/personal-server-ts-core/api";

const SERVER_ORIGIN = "https://ps-lite.local";
const SCOPE = "instagram.profile";
const owner = createTestWallet(7);

function gatewayFor(granteeAddress: `0x${string}`): GatewayClient {
  const grant = {
    id: "grant-mode-1",
    grantorAddress: owner.address,
    granteeId: granteeAddress,
    scopes: [SCOPE],
    status: "confirmed",
    addedAt: "2026-01-21T10:00:00.000Z",
    expiresAt: null,
    expired: false,
    revokedAt: null,
    revocationSignature: null,
    paymentStatus: "paid",
    paidAt: null,
    paidBy: null,
    grantVersion: "1",
  } as unknown as GatewayGrantResponse;
  const builder: Builder = {
    id: granteeAddress,
    ownerAddress: owner.address,
    granteeAddress,
    publicKey: "0x04",
    appUrl: "https://claude.test",
    addedAt: "2026-01-21T10:00:00.000Z",
  };
  return {
    isRegisteredBuilder: vi.fn().mockResolvedValue(true),
    getBuilder: vi.fn().mockResolvedValue(builder),
    getGrant: vi.fn().mockResolvedValue(grant),
    listGrantsByUser: vi.fn().mockResolvedValue([]),
    getSchemaForScope: vi.fn().mockResolvedValue(null),
  } as unknown as GatewayClient;
}

const emptyReader: StreamSyncReadPort = {
  resolve: async () => ({ kind: "pass" }),
};

async function ownerSigned(
  method: "GET" | "POST",
  path: string,
  body?: unknown,
): Promise<Request> {
  const rawBody = body === undefined ? undefined : JSON.stringify(body);
  const auth = await buildWeb3SignedHeader({
    wallet: owner,
    aud: SERVER_ORIGIN,
    method,
    uri: path,
    body: rawBody === undefined ? undefined : new TextEncoder().encode(rawBody),
  });
  return new Request(`${SERVER_ORIGIN}${path}`, {
    method,
    headers: rawBody
      ? { "Content-Type": "application/json", Authorization: auth }
      : { Authorization: auth },
    body: rawBody,
  });
}

async function harness(value: AccountStorageModeValue) {
  const store = createInMemoryMcpConnectionStore();
  const created = await createMcpConnection(
    { displayName: "Claude" },
    { store, publicOrigin: SERVER_ORIGIN },
  );
  const gateway = gatewayFor(created.granteeAddress);
  const mode: AccountStorageMode & { read: ReturnType<typeof vi.fn> } = {
    read: vi.fn(() => value),
  };
  const sink = {
    async write() {},
    async read() {
      return { logs: [], total: 0, limit: 50, offset: 0 };
    },
  };
  const runtime = createPsLiteRuntime({
    active: true,
    storage: createMemoryPsLiteStorage(),
    gateway,
    accessLogReader: sink,
    accessLogWriter: sink,
    tokenStore: createMemoryPsLiteTokenStore(),
    saveConfig: async () => {},
    stateCapabilities: { config: "memory" },
    serverOwner: owner.address,
    mcpConnectionStore: store,
    streamSyncRead: emptyReader,
    accountStorageMode: mode,
    auth: createWeb3SignedPsLiteAuth({
      origin: SERVER_ORIGIN,
      ownerAddress: owner.address,
      dataReadPolicyPorts: {
        authSessionVerifier: gateway,
        grantVerifier: gateway,
      },
    }),
  });
  await approveMcpConnection(
    {
      connectionId: created.connectionId,
      grants: [{ grantId: "grant-mode-1", scopes: [SCOPE] }],
    },
    { store },
  );
  return { runtime, mode, token: created.connectionToken };
}

describe("Lite consumes one account storage mode", () => {
  it("the data handler reads it", async () => {
    const h = await harness("unswitched");
    await h.runtime.fetch(await ownerSigned("GET", `/v1/data/${SCOPE}`));
    expect(h.mode.read).toHaveBeenCalled();
  });

  it("the MCP engine reads it", async () => {
    const h = await harness("unswitched");
    const res = await h.runtime.fetch(
      new Request(`${SERVER_ORIGIN}/mcp/${encodeURIComponent(h.token)}`, {
        method: "POST",
        headers: {
          Accept: "application/json, text/event-stream",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: "call",
          method: "tools/call",
          params: { name: "read_scope", arguments: { scope: SCOPE } },
        }),
      }),
    );
    expect(res.status).toBe(200);
    expect(h.mode.read).toHaveBeenCalled();
  });

  it("the legacy write gate refuses a switched account and lets an unswitched one write", async () => {
    const switched = await harness("switched");
    const refused = await switched.runtime.fetch(
      await ownerSigned("POST", `/v1/data/${SCOPE}`, { records: [] }),
    );
    expect(refused.status).toBe(426);
    expect(switched.mode.read).toHaveBeenCalled();

    const unswitched = await harness("unswitched");
    const accepted = await unswitched.runtime.fetch(
      await ownerSigned("POST", `/v1/data/${SCOPE}`, { records: [] }),
    );
    expect(accepted.status).not.toBe(426);
  });
});
