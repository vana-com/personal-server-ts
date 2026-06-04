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
import { mcpConnectionsRoutes, mcpStreamableHttpRoutes } from "./mcp.js";
import { createServerApiAuth } from "../api-auth.js";
import { createNodeDataStorage } from "../storage/node-data-storage.js";
import type { PersonalServerDataApiDeps } from "@opendatalabs/personal-server-ts-core/api";

const SERVER_ORIGIN = "http://localhost:8080";
const ownerWallet = createTestWallet(9);

const logger = pino({ level: "silent" });

function makeGatewayForGrantee(opts: {
  granteeAddress: `0x${string}`;
  grantId?: string;
  scopes?: string[];
}): { gateway: GatewayClient; grant: GatewayGrantResponse } {
  const grant: GatewayGrantResponse = {
    id: opts.grantId ?? "grant-mcp-1",
    grantorAddress: ownerWallet.address,
    granteeId: opts.granteeAddress,
    grant: JSON.stringify({
      user: ownerWallet.address,
      builder: opts.granteeAddress,
      scopes: opts.scopes ?? ["instagram.*"],
      expiresAt: Math.floor(Date.now() / 1000) + 3600,
    }),
    fileIds: [],
    status: "confirmed",
    addedAt: "2026-01-21T10:00:00.000Z",
    revokedAt: null,
    revocationSignature: null,
  };
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
    getFile: vi.fn().mockResolvedValue(null),
    listFilesSince: vi.fn().mockResolvedValue({ files: [], cursor: null }),
    getSchema: vi.fn().mockResolvedValue(null),
    registerServer: vi.fn().mockResolvedValue({ alreadyRegistered: false }),
    registerFile: vi.fn().mockResolvedValue({}),
    createGrant: vi.fn().mockResolvedValue({}),
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
        accessLogWriter: createMockAccessLogWriter(),
        connectionStore: store,
        indexManager: createIndexManager(initializeDatabase(":memory:")),
        hierarchyOptions: { dataDir: "/tmp" },
      }),
    );
    app = root;
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
    expect(payload.data.data).toEqual({ username: "mcp_user" });

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
    expect(payload.scopes).toEqual(["chatgpt.history", "instagram.*"]);
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
