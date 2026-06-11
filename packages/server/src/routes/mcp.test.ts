/**
 * Integration tests for the MCP routes.
 *
 * We exercise two layers without booting the SDK transport:
 *
 *  1. The owner endpoints (`/v1/mcp/connections` create/list/approve/revoke)
 *     end-to-end through Hono.
 *  2. The tool surface — directly via `createMcpServerForConnection`'s
 *     underlying `MCP_TOOLS` array — so we can prove `read_scope` flows
 *     through the per-connection grantee, hits `verifyDataReadPolicy`, and
 *     writes an access-log entry.
 *
 * We do NOT spin up Claude's transport here; that's a Phase-1 manual smoke
 * concern and the SDK transport itself is well-tested upstream. The
 * server.ts `handleMcpStreamableHttpRequest` adapter is exercised by hand in
 * `app-dev` smoke tests.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { pino } from "pino";
import { Hono } from "hono";
import {
  approveMcpConnection,
  createInMemoryMcpConnectionStore,
  createInMemoryMcpOAuthAuthorizationStore,
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
import type {
  Builder,
  GatewayClient,
  GatewayGrantResponse,
} from "@opendatalabs/vana-sdk/node";
import type { AccessLogWriter } from "@opendatalabs/personal-server-ts-core/logging/access-log";
import type { HierarchyManagerOptions } from "@opendatalabs/personal-server-ts-core/storage/hierarchy";
import { initializeDatabase } from "../storage/index-schema.js";
import { createIndexManager } from "../storage/index-manager.js";
import type { IndexManager } from "@opendatalabs/personal-server-ts-core/storage/index";
import { dataRoutes } from "./data.js";
import {
  mcpConnectionsRoutes,
  mcpOAuthRoutes,
  mcpStreamableHttpRoutes,
} from "./mcp.js";
import { createServerApiAuth } from "../api-auth.js";
import { createNodeDataStorage } from "../storage/node-data-storage.js";
import type { PersonalServerDataApiDeps } from "@opendatalabs/personal-server-ts-core/api";

const SERVER_ORIGIN = "http://localhost:8080";
const ownerWallet = createTestWallet(9);
const CLAUDE_REDIRECT_URI = "https://claude.ai/api/mcp/auth_callback";
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

const logger = pino({ level: "silent" });

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

function makeGatewayForGrantee(opts: {
  granteeAddress: `0x${string}`;
  grantId?: string;
  scopes?: string[];
}): { gateway: GatewayClient; grant: GatewayGrantResponse } {
  const grant = {
    id: opts.grantId ?? "grant-mcp-1",
    grantorAddress: ownerWallet.address,
    granteeId: opts.granteeAddress,
    // Canary GatewayGrantResponse is flat: scopes is a top-level string[] and
    // expiresAt is a decimal-string uint256 (null = perpetual).
    scopes: opts.scopes ?? ["instagram.*"],
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
    ownerAddress: ownerWallet.address,
    granteeAddress: opts.granteeAddress,
    publicKey: "0x04",
    appUrl: "https://claude.test",
    addedAt: "2026-01-21T10:00:00.000Z",
  };
  const gateway: GatewayClient = {
    isRegisteredBuilder: vi.fn().mockResolvedValue(true),
    getBuilder: vi.fn().mockResolvedValue(builder),
    getGrant: vi.fn().mockResolvedValue(grant),
    listGrantsByUser: vi.fn().mockResolvedValue([]),
    getSchemaForScope: vi.fn().mockResolvedValue({
      id: "0xschema1",
      ownerAddress: ownerWallet.address,
      name: "instagram.profile",
      definitionUrl: "https://ipfs.io/ipfs/QmTestSchema",
      scope: "instagram.profile",
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
    createGrant: vi.fn().mockResolvedValue({
      grantId: opts.grantId ?? "grant-mcp-1",
    }),
    revokeGrant: vi.fn().mockResolvedValue(undefined),
  };
  return { gateway, grant };
}

function createMockAccessLogWriter(): AccessLogWriter & {
  entries: unknown[];
} {
  const entries: unknown[] = [];
  return {
    entries,
    write: vi.fn(async (entry) => {
      entries.push(entry);
    }),
  };
}

function blockReadResult(opts: {
  scope: string;
  value: unknown;
  collectedAt?: string;
  nextCursor?: string;
}) {
  return {
    status: 200,
    scope: opts.scope,
    collectedAt: opts.collectedAt ?? "2026-06-01T12:00:00.000Z",
    contentKind: "json" as const,
    blocks: [
      {
        id: "block-1",
        path: "$.data",
        mediaType: "application/json",
        value: opts.value,
        sizeBytes: JSON.stringify(opts.value).length,
      },
    ],
    ...(opts.nextCursor ? { nextCursor: opts.nextCursor } : {}),
    warnings: [],
  };
}

async function ingestScope(opts: {
  scope: string;
  data: Record<string, unknown>;
  indexManager: IndexManager;
  hierarchyOptions: HierarchyManagerOptions;
  gateway: GatewayClient;
  accessLogWriter: AccessLogWriter;
}) {
  const subApp = dataRoutes({
    indexManager: opts.indexManager,
    hierarchyOptions: opts.hierarchyOptions,
    logger,
    serverOrigin: SERVER_ORIGIN,
    serverOwner: ownerWallet.address,
    gateway: opts.gateway,
    accessLogWriter: opts.accessLogWriter,
  });
  const body = JSON.stringify(opts.data);
  const auth = await buildWeb3SignedHeader({
    wallet: ownerWallet,
    aud: SERVER_ORIGIN,
    method: "POST",
    uri: `/${opts.scope}`,
    body: new TextEncoder().encode(body),
  });
  const res = await subApp.request(`/${opts.scope}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: auth },
    body,
  });
  if (!res.ok) {
    throw new Error(`ingest failed: ${res.status} ${await res.text()}`);
  }
}

describe("MCP owner connection routes", () => {
  let app: Hono;
  let store: McpConnectionStore;
  let gateway: GatewayClient;

  beforeEach(() => {
    store = createInMemoryMcpConnectionStore();
    const grantee = "0x0000000000000000000000000000000000000001" as const;
    gateway = makeGatewayForGrantee({ granteeAddress: grantee }).gateway;
    const root = new Hono();
    root.route(
      "/v1/mcp/connections",
      mcpConnectionsRoutes({
        logger,
        serverOrigin: SERVER_ORIGIN,
        serverOwner: ownerWallet.address,
        gateway,
        gatewayConfig,
        serverSigner: {
          signGrantRegistration: vi
            .fn()
            .mockResolvedValue("0xgrantsig" as `0x${string}`),
        },
        accessLogWriter: createMockAccessLogWriter(),
        connectionStore: store,
      }),
    );
    app = root;
  });

  async function postOwner(path: string, body: unknown) {
    const rawBody = JSON.stringify(body);
    const auth = await buildWeb3SignedHeader({
      wallet: ownerWallet,
      aud: SERVER_ORIGIN,
      method: "POST",
      uri: path,
      body: new TextEncoder().encode(rawBody),
    });
    return app.request(path, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: auth },
      body: rawBody,
    });
  }

  async function getOwner(path: string) {
    const auth = await buildWeb3SignedHeader({
      wallet: ownerWallet,
      aud: SERVER_ORIGIN,
      method: "GET",
      uri: path,
    });
    return app.request(path, {
      headers: { Authorization: auth },
    });
  }

  async function delOwner(path: string) {
    const auth = await buildWeb3SignedHeader({
      wallet: ownerWallet,
      aud: SERVER_ORIGIN,
      method: "DELETE",
      uri: path,
    });
    return app.request(path, {
      method: "DELETE",
      headers: { Authorization: auth },
    });
  }

  it("creates, lists, approves, and revokes a connection", async () => {
    const create = await postOwner("/v1/mcp/connections", {
      displayName: "Claude",
    });
    expect(create.status).toBe(201);
    const created = await create.json();
    expect(created.connectionToken).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(created.mcpUrl).toContain("/mcp/");

    const list = await getOwner("/v1/mcp/connections");
    expect(list.status).toBe(200);
    const listJson = await list.json();
    expect(listJson.connections).toHaveLength(1);
    expect(listJson.connections[0].status).toBe("pending");

    const approve = await postOwner(
      `/v1/mcp/connections/${created.connectionId}/approve`,
      {
        grants: [{ grantId: "grant-mcp-1", scopes: ["instagram.*"] }],
      },
    );
    expect(approve.status).toBe(200);
    const approved = await approve.json();
    expect(approved.status).toBe("approved");
    expect(approved.grants).toEqual([
      { grantId: "grant-mcp-1", scopes: ["instagram.*"] },
    ]);

    const revoke = await delOwner(
      `/v1/mcp/connections/${created.connectionId}`,
    );
    expect(revoke.status).toBe(200);
    expect((await revoke.json()).status).toBe("revoked");
  });

  it("rejects unauthenticated requests with 401", async () => {
    const res = await app.request("/v1/mcp/connections", { method: "POST" });
    expect([401, 500]).toContain(res.status);
    const body = await res.json();
    expect(body.error).toBeDefined();
  });

  it("rejects approve with no grants (400 GRANTS_REQUIRED)", async () => {
    const create = await postOwner("/v1/mcp/connections", {});
    const created = await create.json();
    const res = await postOwner(
      `/v1/mcp/connections/${created.connectionId}/approve`,
      { grants: [] },
    );
    expect(res.status).toBe(400);
    expect((await res.json()).error.errorCode).toBe("GRANTS_REQUIRED");
  });
});

describe("MCP /mcp/:token route", () => {
  let app: Hono;
  let store: McpConnectionStore;
  let gateway: GatewayClient;

  beforeEach(() => {
    store = createInMemoryMcpConnectionStore();
    gateway = makeGatewayForGrantee({
      granteeAddress: "0x0000000000000000000000000000000000000002",
    }).gateway;
    const root = new Hono();
    root.route(
      "/mcp",
      mcpStreamableHttpRoutes({
        logger,
        serverOrigin: SERVER_ORIGIN,
        serverOwner: ownerWallet.address,
        gateway,
        gatewayConfig,
        serverSigner: {
          signGrantRegistration: vi
            .fn()
            .mockResolvedValue("0xgrantsig" as `0x${string}`),
        },
        accessLogWriter: createMockAccessLogWriter(),
        connectionStore: store,
        indexManager: createIndexManager(initializeDatabase(":memory:")),
        hierarchyOptions: { dataDir: "/tmp" },
        oauthApprovalUrl: "https://app-dev.vana.org/mcp/connect/claude",
      }),
    );
    app = root;
  });

  it("returns OAuth discovery challenge on stable /mcp without bearer token", async () => {
    const res = await app.request("/mcp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }),
    });
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toContain(
      `${SERVER_ORIGIN}/.well-known/oauth-protected-resource/mcp`,
    );
    expect((await res.json()).error.errorCode).toBe("MCP_AUTH_REQUIRED");
  });

  it("does not advertise OAuth on stable /mcp when approval URL is missing", async () => {
    const root = new Hono();
    root.route(
      "/mcp",
      mcpStreamableHttpRoutes({
        logger,
        serverOrigin: SERVER_ORIGIN,
        serverOwner: ownerWallet.address,
        gateway,
        accessLogWriter: createMockAccessLogWriter(),
        connectionStore: store,
        indexManager: createIndexManager(initializeDatabase(":memory:")),
        hierarchyOptions: { dataDir: "/tmp" },
      }),
    );
    const res = await root.request("/mcp", { method: "POST" });
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toBeNull();
    expect((await res.json()).error.errorCode).toBe("INVALID_TOKEN");
  });

  it("returns 401 INVALID_TOKEN for unknown tokens", async () => {
    const res = await app.request("/mcp/totally-not-a-real-token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }),
    });
    expect(res.status).toBe(401);
    expect((await res.json()).error.errorCode).toBe("INVALID_TOKEN");
  });

  it("returns 401 for a pending (not-yet-approved) token", async () => {
    const created = await createMcpConnection(
      { displayName: "Claude" },
      { store, publicOrigin: SERVER_ORIGIN },
    );
    const res = await app.request(
      `/mcp/${encodeURIComponent(created.connectionToken)}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }),
      },
    );
    expect(res.status).toBe(401);
    expect((await res.json()).error.errorCode).toBe("INVALID_TOKEN");
  });
});

describe("MCP OAuth routes", () => {
  let app: Hono;
  let store: McpConnectionStore;

  beforeEach(() => {
    store = createInMemoryMcpConnectionStore();
    const authorizationStore = createInMemoryMcpOAuthAuthorizationStore();
    const grantee = "0x0000000000000000000000000000000000000003" as const;
    const gateway = makeGatewayForGrantee({ granteeAddress: grantee }).gateway;
    const root = new Hono();
    root.route(
      "/",
      mcpOAuthRoutes({
        logger,
        serverOrigin: SERVER_ORIGIN,
        serverOwner: ownerWallet.address,
        gateway,
        gatewayConfig,
        serverSigner: {
          signGrantRegistration: vi
            .fn()
            .mockResolvedValue("0xgrantsig" as `0x${string}`),
        },
        accessLogWriter: createMockAccessLogWriter(),
        connectionStore: store,
        oauthAuthorizationStore: authorizationStore,
        oauthApprovalUrl: "https://app-dev.vana.org/mcp/connect/claude",
      }),
    );
    app = root;
  });

  async function ownerRequest(
    method: "GET" | "POST",
    path: string,
    body?: unknown,
  ) {
    const rawBody = body === undefined ? undefined : JSON.stringify(body);
    const auth = await buildWeb3SignedHeader({
      wallet: ownerWallet,
      aud: SERVER_ORIGIN,
      method,
      uri: path,
      body:
        rawBody === undefined ? undefined : new TextEncoder().encode(rawBody),
    });
    return app.request(path, {
      method,
      headers: rawBody
        ? { "Content-Type": "application/json", Authorization: auth }
        : { Authorization: auth },
      body: rawBody,
    });
  }

  it("serves OAuth metadata", async () => {
    const resource = await app.request(
      "/.well-known/oauth-protected-resource/mcp",
    );
    expect(resource.status).toBe(200);
    expect((await resource.json()).resource).toBe(`${SERVER_ORIGIN}/mcp`);

    const authServer = await app.request(
      "/.well-known/oauth-authorization-server",
    );
    expect(authServer.status).toBe(200);
    expect((await authServer.json()).authorization_endpoint).toBe(
      `${SERVER_ORIGIN}/mcp/oauth/authorize`,
    );
  });

  it("returns 404 for OAuth metadata when approval URL is missing", async () => {
    const root = new Hono();
    root.route(
      "/",
      mcpOAuthRoutes({
        logger,
        serverOrigin: SERVER_ORIGIN,
        serverOwner: ownerWallet.address,
        gateway: makeGatewayForGrantee({
          granteeAddress: "0x0000000000000000000000000000000000000003",
        }).gateway,
        accessLogWriter: createMockAccessLogWriter(),
        connectionStore: createInMemoryMcpConnectionStore(),
        oauthAuthorizationStore: createInMemoryMcpOAuthAuthorizationStore(),
      }),
    );
    const res = await root.request("/.well-known/oauth-protected-resource/mcp");
    expect(res.status).toBe(404);
    expect((await res.json()).error.errorCode).toBe("MCP_OAUTH_NOT_CONFIGURED");
  });

  it("returns JSON OAuth error when authorize cannot redirect", async () => {
    const res = await app.request("/mcp/oauth/authorize?response_type=token");
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({
      error: "unsupported_response_type",
    });
  });

  it("creates an authorization from Claude OAuth and redeems it after owner approval", async () => {
    const register = await app.request("/mcp/oauth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_name: "Claude",
        redirect_uris: [CLAUDE_REDIRECT_URI],
      }),
    });
    expect(register.status).toBe(201);
    const registered = await register.json();
    const codeVerifier = "server-route-pkce-verifier";

    const authorize = await app.request(
      `/mcp/oauth/authorize?${new URLSearchParams({
        response_type: "code",
        client_id: registered.client_id,
        redirect_uri: CLAUDE_REDIRECT_URI,
        code_challenge: await pkceChallenge(codeVerifier),
        code_challenge_method: "S256",
        scope: "vana:read",
        state: "route-state",
      })}`,
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

    const pending = await ownerRequest(
      "GET",
      `/v1/mcp/oauth/authorizations/${authorizationId}`,
    );
    expect(pending.status).toBe(200);
    const pendingBody = await pending.json();
    expect(pendingBody.status).toBe("pending");

    const approve = await ownerRequest(
      "POST",
      `/v1/mcp/oauth/authorizations/${authorizationId}/approve`,
      { scopes: ["chatgpt.history"] },
    );
    expect(approve.status).toBe(200);
    const redirectTo = (await approve.json()).redirectTo;
    const redirect = new URL(redirectTo);
    expect(`${redirect.origin}${redirect.pathname}`).toBe(CLAUDE_REDIRECT_URI);
    expect(redirect.searchParams.get("state")).toBe("route-state");
    const code = redirect.searchParams.get("code");
    expect(code).toMatch(/.+/);

    const token = await app.request("/mcp/oauth/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: code!,
        code_verifier: codeVerifier,
        client_id: registered.client_id,
        redirect_uri: CLAUDE_REDIRECT_URI,
      }),
    });
    expect(token.status).toBe(200);
    const tokenBody = await token.json();
    expect(tokenBody.token_type).toBe("Bearer");

    const approvedConnection = await store.getByTokenHash(
      await hashConnectionToken(tokenBody.access_token),
    );
    expect(approvedConnection?.status).toBe("approved");
    expect(approvedConnection?.grants).toEqual([
      { grantId: "grant-mcp-1", scopes: ["chatgpt.history"] },
    ]);
  });
});

describe("MCP read_scope tool (grant-gated + access-logged)", () => {
  let dataDir: string;
  let hierarchyOptions: HierarchyManagerOptions;
  let indexManager: IndexManager;
  let store: McpConnectionStore;

  beforeEach(async () => {
    dataDir = await mkdtemp(join(tmpdir(), "mcp-tool-test-"));
    hierarchyOptions = { dataDir };
    indexManager = createIndexManager(initializeDatabase(":memory:"));
    store = createInMemoryMcpConnectionStore();
  });

  afterEach(async () => {
    indexManager.close();
    await rm(dataDir, { recursive: true, force: true });
  });

  function buildDataApiDeps(
    gateway: GatewayClient,
    accessLogWriter: AccessLogWriter,
  ): PersonalServerDataApiDeps {
    const dataStorage = createNodeDataStorage({
      indexManager,
      hierarchyOptions,
    });
    return {
      storage: dataStorage,
      auth: createServerApiAuth({
        serverOrigin: SERVER_ORIGIN,
        serverOwner: ownerWallet.address,
        gateway,
        dataStorage,
      }),
      schemaResolver: gateway,
      accessLogWriter,
      logger,
    };
  }

  it("read_scope reads through the grant-gated path and writes an access log", async () => {
    // 1. Create + approve an MCP connection.
    const created = await createMcpConnection(
      { displayName: "Claude" },
      { store, publicOrigin: SERVER_ORIGIN },
    );
    const record = (await store.getById(created.connectionId))!;
    const granteeAddress = record.granteeAddress;
    const { gateway } = makeGatewayForGrantee({
      granteeAddress,
      grantId: "grant-mcp-1",
      scopes: ["instagram.*"],
    });
    const accessLogWriter = createMockAccessLogWriter();
    await approveMcpConnection(
      {
        connectionId: created.connectionId,
        grants: [{ grantId: "grant-mcp-1", scopes: ["instagram.*"] }],
      },
      { store },
    );

    // 2. Owner ingests a scope.
    await ingestScope({
      scope: "instagram.profile",
      data: { username: "mcp_user" },
      indexManager,
      hierarchyOptions,
      gateway,
      accessLogWriter,
    });

    // 3. Build the read client + tool context and invoke `read_scope`.
    const approved = (await store.getById(created.connectionId))!;
    const granteeAccount = loadMcpGranteeAccount({
      address: approved.granteeAddress,
      publicKey: approved.granteePublicKey,
      encryptedPrivateKey: approved.encryptedGranteePrivateKey,
    });
    const dataApiDeps = buildDataApiDeps(gateway, accessLogWriter);
    const readClient = createMcpDataReadClient({
      serverOrigin: SERVER_ORIGIN,
      granteeAccount,
      dataApiDeps,
    });
    const tool = MCP_TOOLS.find((t) => t.name === "read_scope")!;
    const ctx: McpToolContext = { connection: approved, readClient };
    const ingestEntriesBefore = accessLogWriter.entries.length;

    const result = await tool.handler({ scope: "instagram.profile" }, ctx);

    expect(result.isError).not.toBe(true);
    const payload = JSON.parse(result.content[0].text);
    expect(payload.scope).toBe("instagram.profile");
    expect(payload.grantId).toBe("grant-mcp-1");
    expect(payload.blocks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: "$.data",
          value: { username: "mcp_user" },
        }),
      ]),
    );

    // Access log: the read added a new entry.
    expect(accessLogWriter.entries.length).toBeGreaterThan(ingestEntriesBefore);
    const last = accessLogWriter.entries.at(-1) as {
      builder: string;
      scope: string;
      action: string;
      grantId: string;
    };
    expect(last.action).toBe("read");
    expect(last.scope).toBe("instagram.profile");
    expect(last.grantId).toBe("grant-mcp-1");
    // CRITICAL: log records the per-connection grantee, NOT the owner.
    expect(last.builder.toLowerCase()).toBe(granteeAddress.toLowerCase());
    expect(last.builder.toLowerCase()).not.toBe(
      ownerWallet.address.toLowerCase(),
    );
  });

  it("local MCP route returns embedded raw files without hanging", async () => {
    const created = await createMcpConnection(
      { displayName: "Codex route repro" },
      { store, publicOrigin: SERVER_ORIGIN },
    );
    const record = (await store.getById(created.connectionId))!;
    const { gateway } = makeGatewayForGrantee({
      granteeAddress: record.granteeAddress,
      grantId: "grant-file-1",
      scopes: ["manual.document"],
    });
    const accessLogWriter = createMockAccessLogWriter();
    await approveMcpConnection(
      {
        connectionId: created.connectionId,
        grants: [{ grantId: "grant-file-1", scopes: ["manual.document"] }],
      },
      { store },
    );

    const dataApp = dataRoutes({
      indexManager,
      hierarchyOptions,
      logger,
      serverOrigin: SERVER_ORIGIN,
      serverOwner: ownerWallet.address,
      gateway,
      accessLogWriter,
    });
    const pdf = new Uint8Array(154_453);
    pdf.set(new TextEncoder().encode("%PDF-1.4\n"));
    const writeAuth = await buildWeb3SignedHeader({
      wallet: ownerWallet,
      aud: SERVER_ORIGIN,
      method: "POST",
      uri: "/manual.document",
      body: pdf,
    });
    const write = await dataApp.request("/manual.document", {
      method: "POST",
      headers: {
        "Content-Type": "application/pdf",
        "X-Filename": "scan.pdf",
        Authorization: writeAuth,
      },
      body: pdf,
    });
    expect(write.status).toBe(201);

    const root = new Hono();
    root.route(
      "/mcp",
      mcpStreamableHttpRoutes({
        logger,
        serverOrigin: SERVER_ORIGIN,
        serverOwner: ownerWallet.address,
        gateway,
        gatewayConfig,
        serverSigner: {
          signGrantRegistration: vi
            .fn()
            .mockResolvedValue("0xgrantsig" as `0x${string}`),
        },
        accessLogWriter,
        connectionStore: store,
        indexManager,
        hierarchyOptions,
        oauthApprovalUrl: "https://app-dev.vana.org/mcp",
      }),
    );

    async function rpc(
      id: string,
      method: string,
      params: Record<string, unknown>,
    ) {
      const res = await root.request(
        `/mcp/${encodeURIComponent(created.connectionToken)}`,
        {
          method: "POST",
          headers: {
            Accept: "application/json, text/event-stream",
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
        },
      );
      const text = await res.text();
      return {
        status: res.status,
        bytes: new TextEncoder().encode(text).byteLength,
        body: JSON.parse(text),
      };
    }

    async function withHangTimeout<T>(
      label: string,
      promise: Promise<T>,
    ): Promise<T> {
      let timer: ReturnType<typeof setTimeout> | undefined;
      try {
        return await Promise.race([
          promise,
          new Promise<never>((_, reject) => {
            timer = setTimeout(
              () => reject(new Error(`${label} hung for 5000ms`)),
              5000,
            );
          }),
        ]);
      } finally {
        if (timer) clearTimeout(timer);
      }
    }

    const inline = await withHangTimeout(
      "inline file tool response",
      rpc("inline", "tools/call", {
        name: "get_scope_file",
        arguments: { scope: "manual.document", includeContent: true },
      }),
    );
    expect(inline.status).toBe(200);
    expect(inline.bytes).toBeGreaterThan(200_000);
    expect(
      inline.body.result.content.map((item: { type: string }) => item.type),
    ).toEqual(["text", "resource"]);

    const resource = await withHangTimeout(
      "raw file resource read response",
      rpc("resource", "resources/read", {
        uri: "vana://scope/manual.document/raw",
      }),
    );
    expect(resource.status).toBe(200);
    expect(resource.bytes).toBeGreaterThan(200_000);
    expect(resource.body.result.contents[0].blob).toMatch(/^JVBERi0xLjQK/u);
  });

  it("read_scope rejects top-level source ids even when a wildcard grant exists", async () => {
    const created = await createMcpConnection(
      { displayName: "Claude" },
      { store, publicOrigin: SERVER_ORIGIN },
    );
    await approveMcpConnection(
      {
        connectionId: created.connectionId,
        grants: [{ grantId: "grant-mcp-1", scopes: ["instagram.*"] }],
      },
      { store },
    );
    const readScopeBlocks = vi
      .fn()
      .mockResolvedValue(blockReadResult({ scope: "instagram", value: {} }));
    const tool = MCP_TOOLS.find((t) => t.name === "read_scope")!;

    const result = await tool.handler(
      { scope: "instagram" },
      {
        connection: (await store.getById(created.connectionId))!,
        readClient: {
          listScopes: vi.fn(),
          readScopeBlocks,
        },
      },
    );

    expect(result.isError).toBe(true);
    expect(JSON.parse(result.content[0].text)).toMatchObject({
      error: "scope_not_granted",
      grantedScopes: ["instagram.*"],
    });
    expect(readScopeBlocks).not.toHaveBeenCalled();
  });

  it("search_personal_context expands wildcard scopes through the real read client", async () => {
    const created = await createMcpConnection(
      { displayName: "Claude" },
      { store, publicOrigin: SERVER_ORIGIN },
    );
    const record = (await store.getById(created.connectionId))!;
    const { gateway } = makeGatewayForGrantee({
      granteeAddress: record.granteeAddress,
      grantId: "grant-mcp-1",
      scopes: ["instagram.*"],
    });
    const accessLogWriter = createMockAccessLogWriter();
    await approveMcpConnection(
      {
        connectionId: created.connectionId,
        grants: [{ grantId: "grant-mcp-1", scopes: ["instagram.*"] }],
      },
      { store },
    );

    await ingestScope({
      scope: "instagram.profile",
      data: { username: "mcp_user" },
      indexManager,
      hierarchyOptions,
      gateway,
      accessLogWriter,
    });
    await ingestScope({
      scope: "instagram.ads",
      data: { advertisers: [{ name: "Acme" }] },
      indexManager,
      hierarchyOptions,
      gateway,
      accessLogWriter,
    });

    const approved = (await store.getById(created.connectionId))!;
    const readClient = createMcpDataReadClient({
      serverOrigin: SERVER_ORIGIN,
      granteeAccount: loadMcpGranteeAccount({
        address: approved.granteeAddress,
        publicKey: approved.granteePublicKey,
        encryptedPrivateKey: approved.encryptedGranteePrivateKey,
      }),
      dataApiDeps: buildDataApiDeps(gateway, accessLogWriter),
    });
    const tool = MCP_TOOLS.find((t) => t.name === "search_personal_context")!;

    const result = await tool.handler(
      { query: "mcp_user", scopes: ["instagram.*"], maxScopes: 2 },
      { connection: approved, readClient },
    );

    expect(result.isError).not.toBe(true);
    const payload = JSON.parse(result.content[0].text) as {
      matches: Array<{ scope: string; preview: string }>;
      searchedScopes: string[];
      skippedScopes: string[];
      errors: unknown[];
    };
    expect(payload.errors).toEqual([]);
    expect(payload.searchedScopes).toEqual([
      "instagram.ads",
      "instagram.profile",
    ]);
    expect(payload.skippedScopes).toEqual([]);
    expect(payload.matches).toEqual([
      expect.objectContaining({
        scope: "instagram.profile",
        preview: expect.stringContaining("mcp_user"),
      }),
    ]);
  });

  it("search_personal_context searches bounded storage blocks without full envelope parsing", async () => {
    const created = await createMcpConnection(
      { displayName: "Claude" },
      { store, publicOrigin: SERVER_ORIGIN },
    );
    const record = (await store.getById(created.connectionId))!;
    const { gateway } = makeGatewayForGrantee({
      granteeAddress: record.granteeAddress,
      grantId: "grant-mcp-1",
      scopes: ["chatgpt.conversations"],
    });
    const accessLogWriter = createMockAccessLogWriter();
    await approveMcpConnection(
      {
        connectionId: created.connectionId,
        grants: [{ grantId: "grant-mcp-1", scopes: ["chatgpt.conversations"] }],
      },
      { store },
    );

    await ingestScope({
      scope: "chatgpt.conversations",
      data: {
        text: `needle ${"x".repeat(250_000)}`,
      },
      indexManager,
      hierarchyOptions,
      gateway,
      accessLogWriter,
    });

    const approved = (await store.getById(created.connectionId))!;
    const dataApiDeps = buildDataApiDeps(gateway, accessLogWriter);
    const fullRead = vi
      .spyOn(dataApiDeps.storage, "readEnvelope")
      .mockRejectedValue(new Error("search must not parse the full envelope"));
    const readClient = createMcpDataReadClient({
      serverOrigin: SERVER_ORIGIN,
      granteeAccount: loadMcpGranteeAccount({
        address: approved.granteeAddress,
        publicKey: approved.granteePublicKey,
        encryptedPrivateKey: approved.encryptedGranteePrivateKey,
      }),
      dataApiDeps,
    });
    const tool = MCP_TOOLS.find((t) => t.name === "search_personal_context")!;

    const result = await tool.handler(
      { query: "needle", scopes: ["chatgpt.conversations"] },
      { connection: approved, readClient },
    );

    expect(result.isError).not.toBe(true);
    const payload = JSON.parse(result.content[0].text) as {
      matches: Array<{ scope: string; searchedChars: number }>;
      truncatedScopes: string[];
      errors: unknown[];
    };
    expect(payload.errors).toEqual([]);
    expect(payload.matches).toEqual([
      expect.objectContaining({
        scope: "chatgpt.conversations",
      }),
    ]);
    expect(payload.matches[0]!.searchedChars).toBeLessThanOrEqual(70_000);
    expect(payload.matches[0]!.searchedChars).toBeGreaterThan(45_000);
    expect(payload.truncatedScopes).toEqual([]);
    expect(fullRead).not.toHaveBeenCalled();
    expect(accessLogWriter.entries).toContainEqual(
      expect.objectContaining({
        action: "read",
        builder: approved.granteeAddress,
        grantId: "grant-mcp-1",
        scope: "chatgpt.conversations",
      }),
    );
  });

  it("search_personal_context searches decoded escaped text through server storage blocks", async () => {
    const created = await createMcpConnection(
      { displayName: "Claude" },
      { store, publicOrigin: SERVER_ORIGIN },
    );
    const record = (await store.getById(created.connectionId))!;
    const { gateway } = makeGatewayForGrantee({
      granteeAddress: record.granteeAddress,
      grantId: "grant-mcp-1",
      scopes: ["notes.profile"],
    });
    const accessLogWriter = createMockAccessLogWriter();
    await approveMcpConnection(
      {
        connectionId: created.connectionId,
        grants: [{ grantId: "grant-mcp-1", scopes: ["notes.profile"] }],
      },
      { store },
    );

    await ingestScope({
      scope: "notes.profile",
      data: {
        text: 'line one\nline "two" uses C:\\tmp',
      },
      indexManager,
      hierarchyOptions,
      gateway,
      accessLogWriter,
    });

    const approved = (await store.getById(created.connectionId))!;
    const dataApiDeps = buildDataApiDeps(gateway, accessLogWriter);
    const readClient = createMcpDataReadClient({
      serverOrigin: SERVER_ORIGIN,
      granteeAccount: loadMcpGranteeAccount({
        address: approved.granteeAddress,
        publicKey: approved.granteePublicKey,
        encryptedPrivateKey: approved.encryptedGranteePrivateKey,
      }),
      dataApiDeps,
    });
    const tool = MCP_TOOLS.find((t) => t.name === "search_personal_context")!;

    const result = await tool.handler(
      { query: 'one\nline "two" uses C:\\tmp', scopes: ["notes.profile"] },
      { connection: approved, readClient },
    );

    expect(result.isError).not.toBe(true);
    const payload = JSON.parse(result.content[0].text) as {
      matches: Array<{ scope: string; preview: string }>;
      errors: unknown[];
    };
    expect(payload.errors).toEqual([]);
    expect(payload.matches).toEqual([
      expect.objectContaining({
        scope: "notes.profile",
        preview: expect.stringContaining('line "two" uses C:\\tmp'),
      }),
    ]);
  });

  it("search_personal_context hides unexpected bounded storage errors", async () => {
    const created = await createMcpConnection(
      { displayName: "Claude" },
      { store, publicOrigin: SERVER_ORIGIN },
    );
    const record = (await store.getById(created.connectionId))!;
    const { gateway } = makeGatewayForGrantee({
      granteeAddress: record.granteeAddress,
      grantId: "grant-mcp-1",
      scopes: ["github.profile"],
    });
    const accessLogWriter = createMockAccessLogWriter();
    await approveMcpConnection(
      {
        connectionId: created.connectionId,
        grants: [{ grantId: "grant-mcp-1", scopes: ["github.profile"] }],
      },
      { store },
    );

    await ingestScope({
      scope: "github.profile",
      data: { username: "octo" },
      indexManager,
      hierarchyOptions,
      gateway,
      accessLogWriter,
    });

    const approved = (await store.getById(created.connectionId))!;
    const dataApiDeps = buildDataApiDeps(gateway, accessLogWriter);
    dataApiDeps.storage.readScopeBlocks = vi
      .fn()
      .mockRejectedValue(
        new Error("ENOENT: /home/tim/personal-server/data/github.profile.json"),
      );
    const readClient = createMcpDataReadClient({
      serverOrigin: SERVER_ORIGIN,
      granteeAccount: loadMcpGranteeAccount({
        address: approved.granteeAddress,
        publicKey: approved.granteePublicKey,
        encryptedPrivateKey: approved.encryptedGranteePrivateKey,
      }),
      dataApiDeps,
    });
    const tool = MCP_TOOLS.find((t) => t.name === "search_personal_context")!;

    const result = await tool.handler(
      { query: "octo", scopes: ["github.profile"] },
      { connection: approved, readClient },
    );

    expect(result.isError).not.toBe(true);
    const payload = JSON.parse(result.content[0].text) as {
      errors: Array<{ scope: string; status?: number; bodyPreview: string }>;
    };
    expect(payload.errors).toEqual([
      expect.objectContaining({
        scope: "github.profile",
        error: "scope_read_failed",
        status: 503,
        bodyPreview: expect.stringContaining("BOUNDED_DATA_UNAVAILABLE"),
      }),
    ]);
    expect(result.content[0].text).not.toContain("/home/tim");
  });

  it("read_scope returns scope_not_granted for scopes outside the grant", async () => {
    const created = await createMcpConnection(
      {},
      { store, publicOrigin: SERVER_ORIGIN },
    );
    const record = (await store.getById(created.connectionId))!;
    const { gateway } = makeGatewayForGrantee({
      granteeAddress: record.granteeAddress,
      scopes: ["instagram.profile"],
    });
    await approveMcpConnection(
      {
        connectionId: created.connectionId,
        grants: [{ grantId: "grant-mcp-1", scopes: ["instagram.profile"] }],
      },
      { store },
    );
    const accessLogWriter = createMockAccessLogWriter();
    const approved = (await store.getById(created.connectionId))!;
    const readClient = createMcpDataReadClient({
      serverOrigin: SERVER_ORIGIN,
      granteeAccount: loadMcpGranteeAccount({
        address: approved.granteeAddress,
        publicKey: approved.granteePublicKey,
        encryptedPrivateKey: approved.encryptedGranteePrivateKey,
      }),
      dataApiDeps: buildDataApiDeps(gateway, accessLogWriter),
    });
    const tool = MCP_TOOLS.find((t) => t.name === "read_scope")!;
    const result = await tool.handler(
      { scope: "chatgpt.history" },
      { connection: approved, readClient },
    );
    expect(result.isError).toBe(true);
    const payload = JSON.parse(result.content[0].text);
    expect(payload.error).toBe("scope_not_granted");
    // No access log entry on tool-side rejection.
    expect(accessLogWriter.entries).toHaveLength(0);
  });

  it("list_granted_scopes only exposes scopes from this connection's grants", async () => {
    const created = await createMcpConnection(
      {},
      { store, publicOrigin: SERVER_ORIGIN },
    );
    await approveMcpConnection(
      {
        connectionId: created.connectionId,
        grants: [
          { grantId: "g1", scopes: ["instagram.*"], sourceId: "instagram" },
          { grantId: "g2", scopes: ["chatgpt.history"], sourceId: "chatgpt" },
        ],
      },
      { store },
    );
    const approved = (await store.getById(created.connectionId))!;
    const tool = MCP_TOOLS.find((t) => t.name === "list_granted_scopes")!;
    const result = await tool.handler(
      {},
      {
        connection: approved,
        readClient: {} as never,
      },
    );
    expect(result.isError).not.toBe(true);
    const payload = JSON.parse(result.content[0].text);
    expect(payload.scopes).toEqual([
      expect.objectContaining({ scope: "chatgpt.history" }),
      expect.objectContaining({ scope: "instagram.*" }),
    ]);
  });

  it("list_granted_sources derives source ids from scope-only grants", async () => {
    const created = await createMcpConnection(
      {},
      { store, publicOrigin: SERVER_ORIGIN },
    );
    await approveMcpConnection(
      {
        connectionId: created.connectionId,
        grants: [
          { grantId: "g1", scopes: ["instagram.profile", "instagram.posts"] },
          { grantId: "g2", scopes: ["chatgpt.history"] },
        ],
      },
      { store },
    );
    const approved = (await store.getById(created.connectionId))!;
    const tool = MCP_TOOLS.find((t) => t.name === "list_granted_sources")!;
    const result = await tool.handler(
      {},
      {
        connection: approved,
        readClient: {} as never,
      },
    );
    expect(result.isError).not.toBe(true);
    const payload = JSON.parse(result.content[0].text);
    expect(payload.sources).toEqual(["chatgpt", "instagram"]);
  });

  it("search_personal_context returns bounded previews instead of full envelopes", async () => {
    const created = await createMcpConnection(
      {},
      { store, publicOrigin: SERVER_ORIGIN },
    );
    await approveMcpConnection(
      {
        connectionId: created.connectionId,
        grants: [{ grantId: "g1", scopes: ["chatgpt.conversations"] }],
      },
      { store },
    );
    const approved = (await store.getById(created.connectionId))!;
    const tool = MCP_TOOLS.find((t) => t.name === "search_personal_context")!;
    const largePrefix = "x".repeat(5_000);
    const largeSuffix = "y".repeat(5_000);

    const result = await tool.handler(
      {
        query: "unique-match",
        scopes: ["chatgpt.conversations"],
        limit: 5,
      },
      {
        connection: approved,
        readClient: {
          listScopes: vi.fn(),
          readScopeBlocks: vi.fn().mockResolvedValue(
            blockReadResult({
              scope: "chatgpt.conversations",
              value: `${largePrefix} unique-match ${largeSuffix}`,
            }),
          ),
        },
      },
    );

    expect(result.isError).not.toBe(true);
    const payload = JSON.parse(result.content[0].text) as {
      matches: Array<{
        scope: string;
        collectedAt?: string;
        preview: string;
        searchedChars: number;
      }>;
      errors: unknown[];
      searchedScopes: string[];
      skippedScopes: string[];
    };
    expect(payload.errors).toEqual([]);
    expect(payload.searchedScopes).toEqual(["chatgpt.conversations"]);
    expect(payload.skippedScopes).toEqual([]);
    expect(payload.matches).toHaveLength(1);
    expect(payload.matches[0]).toMatchObject({
      scope: "chatgpt.conversations",
      collectedAt: "2026-06-01T12:00:00.000Z",
    });
    expect(payload.matches[0].preview).toContain("unique-match");
    expect(payload.matches[0].preview.length).toBeLessThan(700);
    expect(payload.matches[0].searchedChars).toBeGreaterThan(10_000);
    expect(result.content[0].text).not.toContain(largePrefix);
    expect(result.content[0].text).not.toContain(largeSuffix);
  });

  it("search_personal_context expands wildcard grants but caps searched scopes", async () => {
    const created = await createMcpConnection(
      {},
      { store, publicOrigin: SERVER_ORIGIN },
    );
    await approveMcpConnection(
      {
        connectionId: created.connectionId,
        grants: [{ grantId: "g1", scopes: ["instagram.*"] }],
      },
      { store },
    );
    const approved = (await store.getById(created.connectionId))!;
    const readScopeBlocks = vi
      .fn()
      .mockResolvedValue(
        blockReadResult({ scope: "instagram.ads", value: "needle_user" }),
      );
    const tool = MCP_TOOLS.find((t) => t.name === "search_personal_context")!;

    const result = await tool.handler(
      { query: "needle", scopes: ["instagram.*"], maxScopes: 1 },
      {
        connection: approved,
        readClient: {
          listScopes: vi.fn().mockResolvedValue({
            status: 200,
            scopes: [
              {
                scope: "instagram.ads",
                latestCollectedAt: "2026-06-01T12:00:00.000Z",
                versionCount: 1,
              },
              {
                scope: "instagram.posts",
                latestCollectedAt: "2026-06-01T12:00:00.000Z",
                versionCount: 1,
              },
              {
                scope: "instagram.profile",
                latestCollectedAt: "2026-06-01T12:00:00.000Z",
                versionCount: 1,
              },
            ],
            total: 3,
            limit: 200,
            offset: 0,
          }),
          readScopeBlocks,
        },
      },
    );

    expect(result.isError).not.toBe(true);
    const payload = JSON.parse(result.content[0].text) as {
      matches: Array<{ scope: string; preview: string }>;
      searchedScopes: string[];
      skippedScopes: string[];
      errors: unknown[];
    };
    expect(payload.errors).toEqual([]);
    expect(payload.searchedScopes).toEqual(["instagram.ads"]);
    expect(payload.skippedScopes).toEqual([
      "instagram.posts",
      "instagram.profile",
    ]);
    expect(payload.matches).toHaveLength(1);
    expect(payload.matches[0].scope).toBe("instagram.ads");
    expect(payload.matches[0].preview).toContain("needle_user");
    expect(readScopeBlocks).toHaveBeenCalledTimes(1);
  });

  it("search_personal_context stops wildcard discovery once the scope cap is filled", async () => {
    const created = await createMcpConnection(
      {},
      { store, publicOrigin: SERVER_ORIGIN },
    );
    await approveMcpConnection(
      {
        connectionId: created.connectionId,
        grants: [
          { grantId: "g1", scopes: ["instagram.*"] },
          { grantId: "g2", scopes: ["youtube.*"] },
        ],
      },
      { store },
    );
    const approved = (await store.getById(created.connectionId))!;
    const listScopes = vi.fn().mockResolvedValue({
      status: 200,
      scopes: [
        {
          scope: "instagram.profile",
          latestCollectedAt: "2026-06-01T12:00:00.000Z",
          versionCount: 1,
        },
        {
          scope: "instagram.posts",
          latestCollectedAt: "2026-06-01T12:00:00.000Z",
          versionCount: 1,
        },
      ],
      total: 2,
      limit: 200,
      offset: 0,
    });
    const tool = MCP_TOOLS.find((t) => t.name === "search_personal_context")!;

    const result = await tool.handler(
      {
        query: "needle",
        scopes: ["instagram.*", "youtube.*"],
        maxScopes: 1,
      },
      {
        connection: approved,
        readClient: {
          listScopes,
          readScopeBlocks: vi.fn().mockResolvedValue(
            blockReadResult({
              scope: "instagram.profile",
              value: "needle_user",
            }),
          ),
        },
      },
    );

    expect(result.isError).not.toBe(true);
    const payload = JSON.parse(result.content[0].text) as {
      searchedScopes: string[];
      skippedScopes: string[];
      errors: unknown[];
    };
    expect(listScopes).toHaveBeenCalledTimes(1);
    expect(payload.errors).toEqual([]);
    expect(payload.searchedScopes).toEqual(["instagram.profile"]);
    expect(payload.skippedScopes).toEqual(["instagram.posts", "youtube.*"]);
  });

  it("search_personal_context does not treat wildcard grants as covering top-level source ids", async () => {
    const created = await createMcpConnection(
      {},
      { store, publicOrigin: SERVER_ORIGIN },
    );
    await approveMcpConnection(
      {
        connectionId: created.connectionId,
        grants: [{ grantId: "g1", scopes: ["instagram.*"] }],
      },
      { store },
    );
    const approved = (await store.getById(created.connectionId))!;
    const listScopes = vi.fn();
    const readScopeBlocks = vi.fn();
    const tool = MCP_TOOLS.find((t) => t.name === "search_personal_context")!;

    const result = await tool.handler(
      { query: "needle", scopes: ["instagram"] },
      {
        connection: approved,
        readClient: { listScopes, readScopeBlocks },
      },
    );

    expect(result.isError).not.toBe(true);
    const payload = JSON.parse(result.content[0].text) as {
      searchedScopes: string[];
      errors: Array<{ scope: string; error: string }>;
    };
    expect(payload.searchedScopes).toEqual([]);
    expect(payload.errors).toEqual([
      { scope: "instagram", error: "scope_not_granted" },
    ]);
    expect(listScopes).not.toHaveBeenCalled();
    expect(readScopeBlocks).not.toHaveBeenCalled();
  });

  it("search_personal_context rejects oversized queries without echoing them", async () => {
    const created = await createMcpConnection(
      {},
      { store, publicOrigin: SERVER_ORIGIN },
    );
    await approveMcpConnection(
      {
        connectionId: created.connectionId,
        grants: [{ grantId: "g1", scopes: ["github.profile"] }],
      },
      { store },
    );
    const approved = (await store.getById(created.connectionId))!;
    const tool = MCP_TOOLS.find((t) => t.name === "search_personal_context")!;
    const oversizedQuery = "q".repeat(1_000);

    const result = await tool.handler(
      { query: oversizedQuery, scopes: ["github.profile"] },
      {
        connection: approved,
        readClient: {
          listScopes: vi.fn(),
          readScopeBlocks: vi.fn(),
        },
      },
    );

    expect(result.isError).toBe(true);
    const payload = JSON.parse(result.content[0].text);
    expect(payload).toEqual({
      error: "query_too_long",
      maxQueryChars: 256,
    });
    expect(result.content[0].text).not.toContain(oversizedQuery);
  });

  it("search_personal_context caps requested scope input and summarizes overflow", async () => {
    const created = await createMcpConnection(
      {},
      { store, publicOrigin: SERVER_ORIGIN },
    );
    await approveMcpConnection(
      {
        connectionId: created.connectionId,
        grants: [{ grantId: "g1", scopes: ["github.profile"] }],
      },
      { store },
    );
    const approved = (await store.getById(created.connectionId))!;
    const tool = MCP_TOOLS.find((t) => t.name === "search_personal_context")!;
    const oversizedScope = "x".repeat(1_000);
    const requestedScopes = [
      oversizedScope,
      ...Array.from({ length: 420 }, (_value, index) => `unknown.${index}`),
    ];

    const result = await tool.handler(
      { query: "needle", scopes: requestedScopes },
      {
        connection: approved,
        readClient: {
          listScopes: vi.fn(),
          readScopeBlocks: vi.fn(),
        },
      },
    );

    expect(result.isError).not.toBe(true);
    const payload = JSON.parse(result.content[0].text) as {
      errors: Array<{ scope: string; error: string }>;
      skippedScopes: string[];
      limits: { maxRequestedScopes: number; scopeChars: number };
    };
    expect(payload.errors).toHaveLength(399);
    expect(
      payload.errors.every((entry) => entry.error === "scope_not_granted"),
    ).toBe(true);
    expect(payload.skippedScopes).toEqual([
      "21 requested scopes omitted by input cap",
      "1 invalid requested scopes omitted",
    ]);
    expect(payload.limits).toMatchObject({
      maxRequestedScopes: 400,
      scopeChars: 128,
    });
    expect(result.content[0].text).not.toContain(oversizedScope);
  });

  it("search_personal_context reports wildcard discovery timeout without hanging", async () => {
    const created = await createMcpConnection(
      {},
      { store, publicOrigin: SERVER_ORIGIN },
    );
    await approveMcpConnection(
      {
        connectionId: created.connectionId,
        grants: [{ grantId: "g1", scopes: ["instagram.*"] }],
      },
      { store },
    );
    const approved = (await store.getById(created.connectionId))!;
    const readScopeBlocks = vi.fn();
    const tool = MCP_TOOLS.find((t) => t.name === "search_personal_context")!;

    const result = await tool.handler(
      { query: "needle", scopes: ["instagram.*"], timeoutMs: 50 },
      {
        connection: approved,
        readClient: {
          listScopes: vi.fn().mockReturnValue(new Promise(() => undefined)),
          readScopeBlocks,
        },
      },
    );

    expect(result.isError).not.toBe(true);
    const payload = JSON.parse(result.content[0].text) as {
      searchedScopes: string[];
      errors: Array<{ scope: string; error: string; bodyPreview?: string }>;
    };
    expect(payload.searchedScopes).toEqual([]);
    expect(payload.errors).toEqual([
      expect.objectContaining({
        scope: "instagram.*",
        error: "scope_list_timeout",
        bodyPreview: expect.stringContaining(
          "list scopes for instagram.* timed out after 1000ms",
        ),
      }),
    ]);
    expect(readScopeBlocks).not.toHaveBeenCalled();
  });

  it("search_personal_context reports per-scope timeout without failing the whole search", async () => {
    const created = await createMcpConnection(
      {},
      { store, publicOrigin: SERVER_ORIGIN },
    );
    await approveMcpConnection(
      {
        connectionId: created.connectionId,
        grants: [
          { grantId: "g1", scopes: ["chatgpt.conversations"] },
          { grantId: "g2", scopes: ["github.profile"] },
        ],
      },
      { store },
    );
    const approved = (await store.getById(created.connectionId))!;
    const tool = MCP_TOOLS.find((t) => t.name === "search_personal_context")!;

    const result = await tool.handler(
      {
        query: "needle",
        scopes: ["chatgpt.conversations", "github.profile"],
        timeoutMs: 50,
      },
      {
        connection: approved,
        readClient: {
          listScopes: vi.fn(),
          readScopeBlocks: vi
            .fn()
            .mockImplementation(({ scope }: { scope: string }) =>
              scope === "chatgpt.conversations"
                ? new Promise(() => undefined)
                : Promise.resolve(
                    blockReadResult({ scope, value: "needle_user" }),
                  ),
            ),
        },
      },
    );

    expect(result.isError).not.toBe(true);
    const payload = JSON.parse(result.content[0].text) as {
      matches: Array<{ scope: string }>;
      errors: Array<{ scope: string; error: string }>;
    };
    expect(payload.matches).toEqual([
      expect.objectContaining({ scope: "github.profile" }),
    ]);
    expect(payload.errors).toContainEqual({
      scope: "chatgpt.conversations",
      error: "scope_search_timeout",
      bodyPreview: expect.stringContaining(
        "read blocks for chatgpt.conversations timed out after 500ms",
      ),
    });
  });

  it("search_personal_context stops after match output is capped", async () => {
    const created = await createMcpConnection(
      {},
      { store, publicOrigin: SERVER_ORIGIN },
    );
    await approveMcpConnection(
      {
        connectionId: created.connectionId,
        grants: [
          { grantId: "g1", scopes: ["github.profile"] },
          { grantId: "g2", scopes: ["linkedin.profile"] },
        ],
      },
      { store },
    );
    const approved = (await store.getById(created.connectionId))!;
    const tool = MCP_TOOLS.find((t) => t.name === "search_personal_context")!;
    const largeSuffix = "x".repeat(120_000);

    const result = await tool.handler(
      {
        query: "needle",
        scopes: ["github.profile", "linkedin.profile"],
        limit: 1,
      },
      {
        connection: approved,
        readClient: {
          listScopes: vi.fn(),
          readScopeBlocks: vi
            .fn()
            .mockImplementation(({ scope }: { scope: string }) =>
              Promise.resolve(
                blockReadResult({
                  scope,
                  value:
                    scope === "github.profile"
                      ? `needle ${largeSuffix}`
                      : largeSuffix,
                  nextCursor: "cursor-2",
                }),
              ),
            ),
        },
      },
    );

    expect(result.isError).not.toBe(true);
    const payload = JSON.parse(result.content[0].text) as {
      matches: Array<{ scope: string }>;
      searchedScopes: string[];
      truncatedScopes: string[];
    };
    expect(payload.matches).toEqual([
      expect.objectContaining({ scope: "github.profile" }),
    ]);
    expect(payload.searchedScopes).toEqual(["github.profile"]);
    expect(payload.truncatedScopes).toEqual(["github.profile"]);
  });

  it("exposes stable list/read/search MCP tools", () => {
    expect(MCP_TOOLS.map((tool) => tool.name)).toEqual([
      "list_granted_sources",
      "list_granted_scopes",
      "request_scope_access",
      "read_scope",
      "get_scope_file",
      "search_personal_context",
    ]);
  });
});

describe("revoked connection cannot be resolved by token", () => {
  it("revoked record returns null on getByTokenHash even with a known token", async () => {
    const store = createInMemoryMcpConnectionStore();
    const created = await createMcpConnection(
      {},
      { store, publicOrigin: SERVER_ORIGIN },
    );
    await approveMcpConnection(
      {
        connectionId: created.connectionId,
        grants: [{ grantId: "g1", scopes: ["instagram.*"] }],
      },
      { store },
    );
    const hash = await hashConnectionToken(created.connectionToken);
    expect(await store.getByTokenHash(hash)).not.toBeNull();
    await store.update(created.connectionId, { status: "revoked" });
    expect(await store.getByTokenHash(hash)).toBeNull();
  });
});
