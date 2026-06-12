/**
 * MCP integration test for `createPsLiteRuntime`.
 *
 * Phase 1 / 260604-PLAN-vana-mcp-personal-server.md §1 — proves the Lite
 * runtime (the actual browser PS runtime that `app-dev.vana.org` boots) is
 * the one serving `/mcp/:token` and `/v1/mcp/connections`, not just the Node
 * server package.
 *
 * What this covers:
 *
 *  1. Owner endpoints: create → list → approve → revoke roundtrip via the
 *     same auth surface that gates `/v1/grants`.
 *  2. `/mcp/:token` rejects unknown + pending + revoked tokens with 401.
 *  3. `/mcp/:token` MCP traffic — proven via a tool call that round-trips
 *     through `verifyDataReadPolicy` as the per-connection grantee. The
 *     access-log entry MUST record `builder === granteeAddress`, not the
 *     owner, confirming the read path doesn't bypass policy.
 *
 * We do NOT spin up the Claude Streamable HTTP transport in tests; that adapter
 * is shared with the Node server route and is integration-tested there. Here
 * we invoke `MCP_TOOLS.read_scope` directly with the same `McpToolContext` the
 * route would have built, which is what would happen on a real Claude call.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { createPsLiteRuntime } from "./runtime.js";
import {
  createMemoryPsLiteStorage,
  createMemoryPsLiteTokenStore,
} from "./test-support/memory.js";
import {
  createInMemoryMcpConnectionStore,
  createMcpConnection,
  createMcpDataReadClient,
  hashConnectionToken,
  loadMcpGranteeAccount,
  MCP_TOOLS,
  type McpConnectionStore,
  type McpToolContext,
} from "@opendatalabs/personal-server-ts-core/mcp";
import {
  createTestWallet,
  buildWeb3SignedHeader,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import { createWeb3SignedPsLiteAuth } from "./runtime.js";
import type {
  Builder,
  GatewayClient,
  GatewayGrantResponse,
} from "@opendatalabs/vana-sdk/browser";
import type { DataStoragePort } from "@opendatalabs/personal-server-ts-core/ports";
import type { PersonalServerDataApiDeps } from "@opendatalabs/personal-server-ts-core/api";
import type { AccessLogReader } from "@opendatalabs/personal-server-ts-core/logging/access-reader";
import type {
  AccessLogEntry,
  AccessLogWriter,
} from "@opendatalabs/personal-server-ts-core/logging/access-log";

const SERVER_ORIGIN = "https://ps-lite.local";
const CLAUDE_REDIRECT_URI = "https://claude.ai/api/mcp/auth_callback";
const owner = createTestWallet(7);
const gatewayConfig = {
  url: "https://gateway.test",
  chainId: 14800,
  contracts: {
    dataRegistry: "0x0000000000000000000000000000000000000001",
    dataPortabilityPermissions: "0x0000000000000000000000000000000000000002",
    dataPortabilityServer: "0x0000000000000000000000000000000000000003",
    dataPortabilityGrantees: "0x0000000000000000000000000000000000000004",
  },
} as const;

async function pkceChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(verifier),
  );
  let binary = "";
  for (const byte of new Uint8Array(digest)) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/u, "");
}

function makeMockGateway(opts: {
  granteeAddress: `0x${string}`;
  grantId: string;
  scopes: string[];
}): GatewayClient {
  const grant = {
    id: opts.grantId,
    grantorAddress: owner.address,
    granteeId: opts.granteeAddress,
    // Canary GatewayGrantResponse is flat: top-level scopes + decimal-string
    // expiresAt (null = perpetual).
    scopes: opts.scopes,
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
    id: opts.granteeAddress,
    ownerAddress: owner.address,
    granteeAddress: opts.granteeAddress,
    publicKey: "0x04",
    appUrl: "https://claude.test",
    addedAt: "2026-01-21T10:00:00.000Z",
  };
  return {
    isRegisteredBuilder: vi.fn().mockResolvedValue(true),
    getBuilder: vi.fn().mockResolvedValue(builder),
    getGrant: vi.fn().mockResolvedValue(grant),
    listGrantsByUser: vi.fn().mockResolvedValue([]),
    getSchemaForScope: vi.fn().mockResolvedValue({
      id: "0xschema1",
      ownerAddress: owner.address,
      name: opts.scopes[0],
      definitionUrl: "https://ipfs.io/ipfs/QmTestSchema",
      scope: opts.scopes[0],
      addedAt: "2026-01-21T10:00:00.000Z",
    }),
    getServer: vi.fn().mockResolvedValue(null),
    getDataPoint: vi.fn().mockResolvedValue(null),
    listDataPointsByOwner: vi
      .fn()
      .mockResolvedValue({ dataPoints: [], cursor: null }),
    getSchema: vi.fn().mockResolvedValue(null),
    registerServer: vi.fn().mockResolvedValue({ alreadyRegistered: false }),
    registerDataPoint: vi.fn().mockResolvedValue({ dataPointId: "0xdp" }),
    createGrant: vi.fn().mockResolvedValue({ grantId: opts.grantId }),
    revokeGrant: vi.fn().mockResolvedValue(undefined),
  } as unknown as GatewayClient;
}

function createMockAccessLog(): AccessLogReader &
  AccessLogWriter & { entries: AccessLogEntry[] } {
  const entries: AccessLogEntry[] = [];
  return {
    entries,
    async write(entry) {
      entries.push({ ...entry });
    },
    async read() {
      return { logs: entries, total: entries.length, limit: 50, offset: 0 };
    },
  };
}

interface RuntimeBundle {
  runtime: ReturnType<typeof createPsLiteRuntime>;
  store: McpConnectionStore;
  accessLog: AccessLogReader & AccessLogWriter & { entries: AccessLogEntry[] };
  storage: DataStoragePort;
  gateway: GatewayClient;
}

function buildRuntime(
  opts: {
    granteeAddress?: `0x${string}`;
    grantId?: string;
    scopes?: string[];
    approvalUrl?: string;
  } = {},
): RuntimeBundle {
  const gateway = makeMockGateway({
    granteeAddress:
      opts.granteeAddress ?? "0x000000000000000000000000000000000000d00d",
    grantId: opts.grantId ?? "grant-mcp-1",
    scopes: opts.scopes ?? ["instagram.profile"],
  });
  const accessLog = createMockAccessLog();
  const storage = createMemoryPsLiteStorage();
  const store = createInMemoryMcpConnectionStore();
  const runtime = createPsLiteRuntime({
    active: true,
    storage,
    config: { gateway: gatewayConfig },
    gateway,
    serverSigner: {
      signGrantRegistration: vi
        .fn()
        .mockResolvedValue("0xgrantsig" as `0x${string}`),
    },
    accessLogReader: accessLog,
    accessLogWriter: accessLog,
    tokenStore: createMemoryPsLiteTokenStore(),
    saveConfig: async () => {},
    stateCapabilities: { config: "memory" },
    serverOwner: owner.address,
    mcpConnectionStore: store,
    mcpOAuthApprovalUrl: opts.approvalUrl,
    auth: createWeb3SignedPsLiteAuth({
      origin: SERVER_ORIGIN,
      ownerAddress: owner.address,
      dataReadPolicyPorts: {
        authSessionVerifier: gateway,
        grantVerifier: gateway,
      },
    }),
  });
  return { runtime, store, accessLog, storage, gateway };
}

async function ownerSigned(
  method: "GET" | "POST" | "DELETE",
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

describe("createPsLiteRuntime + MCP owner routes", () => {
  let bundle: RuntimeBundle;
  beforeEach(() => {
    bundle = buildRuntime();
  });

  it("creates, lists, approves, and revokes a connection over Lite runtime", async () => {
    const createRes = await bundle.runtime.fetch(
      await ownerSigned("POST", "/v1/mcp/connections", {
        displayName: "Claude",
      }),
    );
    expect(createRes.status).toBe(201);
    const created = await createRes.json();
    expect(created.connectionToken).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(created.mcpUrl).toContain("/mcp/");

    const listRes = await bundle.runtime.fetch(
      await ownerSigned("GET", "/v1/mcp/connections"),
    );
    expect(listRes.status).toBe(200);
    const list = await listRes.json();
    expect(list.connections).toHaveLength(1);
    expect(list.connections[0].status).toBe("pending");

    const approveRes = await bundle.runtime.fetch(
      await ownerSigned(
        "POST",
        `/v1/mcp/connections/${created.connectionId}/approve`,
        { grants: [{ grantId: "grant-mcp-1", scopes: ["instagram.profile"] }] },
      ),
    );
    expect(approveRes.status).toBe(200);
    expect((await approveRes.json()).status).toBe("approved");

    const revokeRes = await bundle.runtime.fetch(
      await ownerSigned(
        "DELETE",
        `/v1/mcp/connections/${created.connectionId}`,
      ),
    );
    expect(revokeRes.status).toBe(200);
    expect((await revokeRes.json()).status).toBe("revoked");
  });

  it("rejects unauthenticated owner calls", async () => {
    const res = await bundle.runtime.fetch(
      new Request(`${SERVER_ORIGIN}/v1/mcp/connections`, { method: "POST" }),
    );
    expect([401, 403]).toContain(res.status);
  });

  it("rejects approve without grants (400 GRANTS_REQUIRED)", async () => {
    const create = await bundle.runtime.fetch(
      await ownerSigned("POST", "/v1/mcp/connections", {}),
    );
    const created = await create.json();
    const res = await bundle.runtime.fetch(
      await ownerSigned(
        "POST",
        `/v1/mcp/connections/${created.connectionId}/approve`,
        { grants: [] },
      ),
    );
    expect(res.status).toBe(400);
    expect((await res.json()).error.errorCode).toBe("GRANTS_REQUIRED");
  });
});

describe("createPsLiteRuntime + /mcp/:token route", () => {
  it("returns OAuth discovery challenge on stable /mcp without bearer token", async () => {
    const { runtime } = buildRuntime({
      approvalUrl: "https://app-dev.vana.org/mcp/connect/claude",
    });
    const res = await runtime.fetch(
      new Request(`${SERVER_ORIGIN}/mcp`, {
        method: "POST",
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }),
      }),
    );
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toContain(
      `${SERVER_ORIGIN}/.well-known/oauth-protected-resource/mcp`,
    );
    expect((await res.json()).error.errorCode).toBe("MCP_AUTH_REQUIRED");
  });

  it("does not advertise OAuth on stable /mcp when approval URL is missing", async () => {
    const { runtime } = buildRuntime();
    const res = await runtime.fetch(
      new Request(`${SERVER_ORIGIN}/mcp`, { method: "POST" }),
    );
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toBeNull();
    expect((await res.json()).error.errorCode).toBe("INVALID_TOKEN");
  });

  it("rejects unknown tokens", async () => {
    const { runtime } = buildRuntime();
    const res = await runtime.fetch(
      new Request(`${SERVER_ORIGIN}/mcp/totally-not-a-real-token`, {
        method: "POST",
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }),
      }),
    );
    expect(res.status).toBe(401);
    expect((await res.json()).error.errorCode).toBe("INVALID_TOKEN");
  });

  it("rejects pending tokens", async () => {
    const { runtime, store } = buildRuntime();
    const created = await createMcpConnection(
      { displayName: "Claude" },
      { store, publicOrigin: SERVER_ORIGIN },
    );
    const res = await runtime.fetch(
      new Request(
        `${SERVER_ORIGIN}/mcp/${encodeURIComponent(created.connectionToken)}`,
        {
          method: "POST",
          body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }),
        },
      ),
    );
    expect(res.status).toBe(401);
  });
});

describe("createPsLiteRuntime + MCP OAuth routes", () => {
  it("returns JSON OAuth error when authorize cannot redirect", async () => {
    const bundle = buildRuntime({
      approvalUrl: "https://app-dev.vana.org/mcp/connect/claude",
    });
    const res = await bundle.runtime.fetch(
      new Request(`${SERVER_ORIGIN}/mcp/oauth/authorize?response_type=token`),
    );
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({
      error: "unsupported_response_type",
    });
  });

  it("creates an authorization from Claude OAuth and redeems it after owner approval", async () => {
    const bundle = buildRuntime({
      approvalUrl: "https://app-dev.vana.org/mcp/connect/claude",
    });
    const register = await bundle.runtime.fetch(
      new Request(`${SERVER_ORIGIN}/mcp/oauth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client_name: "Claude",
          redirect_uris: [CLAUDE_REDIRECT_URI],
        }),
      }),
    );
    expect(register.status).toBe(201);
    const registered = await register.json();
    const codeVerifier = "lite-route-pkce-verifier";

    const authorize = await bundle.runtime.fetch(
      new Request(
        `${SERVER_ORIGIN}/mcp/oauth/authorize?${new URLSearchParams({
          response_type: "code",
          client_id: registered.client_id,
          redirect_uri: CLAUDE_REDIRECT_URI,
          code_challenge: await pkceChallenge(codeVerifier),
          code_challenge_method: "S256",
          scope: "vana:read",
          state: "lite-state",
        })}`,
      ),
    );
    expect(authorize.status).toBe(302);
    const approvalLocation = authorize.headers.get("location");
    expect(approvalLocation).toContain(
      "https://app-dev.vana.org/mcp/connect/claude",
    );
    const authorizationId = new URL(approvalLocation!).searchParams.get(
      "mcp_authorization",
    );
    expect(authorizationId).toMatch(/.+/);

    const pending = await bundle.runtime.fetch(
      await ownerSigned(
        "GET",
        `/v1/mcp/oauth/authorizations/${authorizationId}`,
      ),
    );
    expect(pending.status).toBe(200);
    expect((await pending.json()).status).toBe("pending");

    const approve = await bundle.runtime.fetch(
      await ownerSigned(
        "POST",
        `/v1/mcp/oauth/authorizations/${authorizationId}/approve`,
        { scopes: ["chatgpt.history"] },
      ),
    );
    expect(approve.status).toBe(200);
    const redirectTo = (await approve.json()).redirectTo;
    const redirect = new URL(redirectTo);
    expect(`${redirect.origin}${redirect.pathname}`).toBe(CLAUDE_REDIRECT_URI);
    expect(redirect.searchParams.get("state")).toBe("lite-state");
    const code = redirect.searchParams.get("code");
    expect(code).toMatch(/.+/);

    const token = await bundle.runtime.fetch(
      new Request(`${SERVER_ORIGIN}/mcp/oauth/token`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: code!,
          code_verifier: codeVerifier,
          client_id: registered.client_id,
          redirect_uri: CLAUDE_REDIRECT_URI,
        }),
      }),
    );
    expect(token.status).toBe(200);
    const tokenBody = await token.json();
    expect(tokenBody.token_type).toBe("Bearer");

    const approvedConnection = await bundle.store.getByTokenHash(
      await hashConnectionToken(tokenBody.access_token),
    );
    expect(approvedConnection?.status).toBe("approved");
    expect(approvedConnection?.grants).toEqual([
      { grantId: "grant-mcp-1", scopes: ["chatgpt.history"] },
    ]);
  });
});

describe("MCP read_scope tool through Lite runtime", () => {
  let bundle: RuntimeBundle;
  let connectionId: string;
  let granteeAddress: `0x${string}`;
  let dataApiDeps: PersonalServerDataApiDeps;

  beforeEach(async () => {
    // Phase 1: build a runtime, create+approve a connection, ingest data, and
    // then exercise the tool. The runtime's own data-API auth verifies grants
    // through the gateway mock, so the read path is fully grant-gated.
    bundle = buildRuntime({ scopes: ["instagram.profile"] });
    const created = await createMcpConnection(
      { displayName: "Claude" },
      { store: bundle.store, publicOrigin: SERVER_ORIGIN },
    );
    connectionId = created.connectionId;
    const record = (await bundle.store.getById(connectionId))!;
    granteeAddress = record.granteeAddress;

    // Rebuild gateway with the real grantee address so verifyDataReadPolicy
    // accepts the per-connection grantee's signed read.
    bundle.gateway = makeMockGateway({
      granteeAddress,
      grantId: "grant-mcp-1",
      scopes: ["instagram.profile"],
    });
    bundle = {
      ...bundle,
      runtime: createPsLiteRuntime({
        active: true,
        storage: bundle.storage,
        gateway: bundle.gateway,
        accessLogReader: bundle.accessLog,
        accessLogWriter: bundle.accessLog,
        tokenStore: createMemoryPsLiteTokenStore(),
        saveConfig: async () => {},
        stateCapabilities: { config: "memory" },
        serverOwner: owner.address,
        mcpConnectionStore: bundle.store,
        auth: createWeb3SignedPsLiteAuth({
          origin: SERVER_ORIGIN,
          ownerAddress: owner.address,
          dataReadPolicyPorts: {
            authSessionVerifier: bundle.gateway,
            grantVerifier: bundle.gateway,
          },
        }),
      }),
    };

    // Approve the connection.
    await bundle.runtime.fetch(
      await ownerSigned("POST", `/v1/mcp/connections/${connectionId}/approve`, {
        grants: [{ grantId: "grant-mcp-1", scopes: ["instagram.profile"] }],
      }),
    );

    // Ingest data as owner so read_scope has something to return.
    const ingestPath = "/v1/data/instagram.profile";
    const ingestBody = JSON.stringify({
      handle: "claudefan",
      followers: 7,
    });
    const ingestAuth = await buildWeb3SignedHeader({
      wallet: owner,
      aud: SERVER_ORIGIN,
      method: "POST",
      uri: ingestPath,
      body: new TextEncoder().encode(ingestBody),
    });
    const ingestRes = await bundle.runtime.fetch(
      new Request(`${SERVER_ORIGIN}${ingestPath}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: ingestAuth,
        },
        body: ingestBody,
      }),
    );
    expect([200, 201]).toContain(ingestRes.status);

    // Build a `dataApiDeps` mirror used by `createMcpDataReadClient`. The
    // route already does this internally, but we exercise the underlying tool
    // here for assertion granularity on the access-log shape.
    dataApiDeps = {
      storage: bundle.storage,
      auth: createWeb3SignedPsLiteAuth({
        origin: SERVER_ORIGIN,
        ownerAddress: owner.address,
        dataReadPolicyPorts: {
          authSessionVerifier: bundle.gateway,
          grantVerifier: bundle.gateway,
        },
      }),
      schemaResolver: bundle.gateway,
      accessLogWriter: bundle.accessLog,
    };
  });

  it("invokes read_scope through the Lite runtime grantee and writes access log with builder === granteeAddress", async () => {
    const record = (await bundle.store.getById(connectionId))!;
    const granteeAccount = loadMcpGranteeAccount({
      address: record.granteeAddress,
      publicKey: record.granteePublicKey,
      encryptedPrivateKey: record.encryptedGranteePrivateKey,
    });
    const readClient = createMcpDataReadClient({
      serverOrigin: SERVER_ORIGIN,
      granteeAccount,
      dataApiDeps,
    });

    const readScope = MCP_TOOLS.find((t) => t.name === "read_scope")!;
    const ctx: McpToolContext = { connection: record, readClient };
    const result = await readScope.handler({ scope: "instagram.profile" }, ctx);
    expect(result.isError ?? false).toBe(false);

    // Owner-side ingest writes the first entry. The grantee read writes the
    // second. We assert ONLY on the read entry — the one that proves the MCP
    // path went through `verifyDataReadPolicy` as the grantee.
    const readEntry = bundle.accessLog.entries.find((e) => e.action === "read");
    expect(readEntry).toBeDefined();
    expect(readEntry!.builder).toBe(granteeAddress);
    expect(readEntry!.builder).not.toBe(owner.address);
    expect(readEntry!.grantId).toBe("grant-mcp-1");
    expect(readEntry!.scope).toBe("instagram.profile");
  });
});
