/**
 * The Lite runtime hands one account storage mode to every consumer: the
 * legacy write gate, scope-upload append, Oura, the data handler and the MCP
 * engine. It binds the mode to its own owner once, so each consumer asks about
 * that owner and no other. The mode is a real latched mode wrapped in a spy,
 * bound to this runtime's owner or to another account, and the requests go
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
import {
  createAccountStorageMode,
  type AccountStorageMode,
  type AccountStorageModeValue,
  type StreamSyncReadPort,
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

const OTHER = "0x2222222222222222222222222222222222222222";

interface Call {
  owner: string;
  answer: AccountStorageModeValue;
}

async function harness(bound: string, latched: boolean) {
  const store = createInMemoryMcpConnectionStore();
  const created = await createMcpConnection(
    { displayName: "Claude" },
    { store, publicOrigin: SERVER_ORIGIN },
  );
  const gateway = gatewayFor(created.granteeAddress);
  const calls: Call[] = [];
  const inner = createAccountStorageMode({
    owner: bound,
    source: () => latched,
  });
  if (latched) expect(inner.read(bound)).toBe("switched");
  const mode: AccountStorageMode = {
    read: (requestOwner) => {
      const answer = inner.read(requestOwner);
      calls.push({ owner: requestOwner, answer });
      return answer;
    },
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
  return { runtime, calls, token: created.connectionToken };
}

function expectOnlyThisRuntimesOwnerWasAsked(
  calls: Call[],
  answer: AccountStorageModeValue,
) {
  expect(calls.length).toBeGreaterThan(0);
  expect(new Set(calls.map((c) => c.owner))).toEqual(new Set([owner.address]));
  expect(new Set(calls.map((c) => c.answer))).toEqual(new Set([answer]));
}

const mcpReadScope = (token: string) =>
  new Request(`${SERVER_ORIGIN}/mcp/${encodeURIComponent(token)}`, {
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
  });

describe.each([
  {
    name: "own latched switched mode",
    bound: owner.address,
    answer: "switched",
    refused: true,
  },
  {
    name: "latched switched mode of another account",
    bound: OTHER,
    answer: "unknown",
    refused: false,
  },
] as const)("Lite binds $name to its own owner", (c) => {
  // DROP_REQUEST_OWNER
  it("the data handler asks about this owner only", async () => {
    const h = await harness(c.bound, true);
    await h.runtime.fetch(await ownerSigned("GET", `/v1/data/${SCOPE}`));
    expectOnlyThisRuntimesOwnerWasAsked(h.calls, c.answer);
  });

  // MCP_REQUEST_OWNER_DROPPED
  it("the MCP engine asks about this owner only", async () => {
    const h = await harness(c.bound, true);
    const res = await h.runtime.fetch(mcpReadScope(h.token));
    expect(res.status).toBe(200);
    expectOnlyThisRuntimesOwnerWasAsked(h.calls, c.answer);
  });

  // DROP_REQUEST_OWNER
  it("the legacy write gate asks about this owner only", async () => {
    const h = await harness(c.bound, true);
    const res = await h.runtime.fetch(
      await ownerSigned("POST", `/v1/data/${SCOPE}`, { records: [] }),
    );
    expect(res.status === 426).toBe(c.refused);
    expectOnlyThisRuntimesOwnerWasAsked(h.calls, c.answer);
  });

  // DROP_REQUEST_OWNER
  it("the Oura import asks about this owner only", async () => {
    const h = await harness(c.bound, true);
    const res = await h.runtime.fetch(
      await ownerSigned("POST", "/v1/import/oura-browser", { streams: [] }),
    );
    expect(res.status === 426).toBe(c.refused);
    expectOnlyThisRuntimesOwnerWasAsked(h.calls, c.answer);
  });

  // LITE_APPEND_OWNER_DROPPED
  it("scope-upload append asks about this owner only", async () => {
    const h = await harness(c.bound, true);
    const path = `/v1/data/${SCOPE}/uploads/u1/batches/0`;
    const authorization = await buildWeb3SignedHeader({
      wallet: owner,
      aud: SERVER_ORIGIN,
      method: "PUT",
      uri: path,
      body: new TextEncoder().encode("{}"),
    });
    const res = await h.runtime.appendScopeUpload!(
      new Request(`${SERVER_ORIGIN}${path}`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          Authorization: authorization,
        },
        body: "{}",
      }),
      // A refused append never reads the batch. An unknown mode lets it
      // through, and the placeholder batch then fails: only the gate's
      // question is under test here.
      {} as never,
    ).catch(() => undefined);
    if (c.refused) expect(res?.status).toBe(426);
    expectOnlyThisRuntimesOwnerWasAsked(h.calls, c.answer);
  });
});

describe("Lite with an unswitched account", () => {
  it("lets legacy writes through and never refuses them", async () => {
    const h = await harness(owner.address, false);
    const res = await h.runtime.fetch(
      await ownerSigned("POST", `/v1/data/${SCOPE}`, { records: [] }),
    );
    expect(res.status).not.toBe(426);
    expectOnlyThisRuntimesOwnerWasAsked(h.calls, "unswitched");
  });
});
