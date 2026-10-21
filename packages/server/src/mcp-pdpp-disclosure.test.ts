/**
 * MCP reads by a legacy chain grant reach actual legacy files only.
 *
 * Real Node routes end to end: owner writes through `/v1/data`, MCP reads
 * through `/mcp/:token` (owner's-Claude connection) and `/mcp` (self-signing
 * session), each a JSON-RPC tool call over the streamable HTTP route.
 *
 * Each scope here holds the same data in two forms: an older legacy file and
 * a newer version a PDPP producer stamped. A live chain grant must not read
 * the PDPP version through any MCP tool, while the owner reads it through
 * `/v1/data` and the same grant still reads the legacy file.
 */
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Hono } from "hono";
import pino from "pino";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type {
  Builder,
  GatewayClient,
  GatewayGrantResponse,
} from "@opendatalabs/vana-sdk/browser";
import {
  approveMcpConnection,
  createInMemoryMcpConnectionStore,
  createMcpConnection,
  type McpConnectionStore,
} from "@opendatalabs/personal-server-ts-core/mcp";
import {
  buildWeb3SignedHeader,
  createTestWallet,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import { encodeDataBlockCursor } from "@opendatalabs/personal-server-ts-core/storage/blocks";
import { createScopeDeletionTracker } from "@opendatalabs/personal-server-ts-core/sync";
import type { IndexManager } from "@opendatalabs/personal-server-ts-core/storage/index";
import type { AccessLogWriter } from "@opendatalabs/personal-server-ts-core/logging/access-log";
import { initializeDatabase } from "./storage/index-schema.js";
import { createIndexManager } from "./storage/index-manager.js";
import { dataRoutes } from "./routes/data.js";
import { mcpStreamableHttpRoutes } from "./routes/mcp.js";

const logger = pino({ level: "silent" });
const SERVER_ORIGIN = "http://localhost:8080";
const owner = createTestWallet(0);
const appWallet = createTestWallet(21);
const gatewayConfig = {
  chainId: 14800,
  contracts: {
    dataRegistry: "0x0000000000000000000000000000000000000001",
    dataPortabilityPermissions: "0x0000000000000000000000000000000000000002",
    dataPortabilityServer: "0x0000000000000000000000000000000000000003",
    dataPortabilityGrantees: "0x0000000000000000000000000000000000000004",
  },
} as const;
const GRANT_ID = "grant-mcp-1";
const SECRET = "pdpp-only-score-99";
const LEGACY = "legacy-file-row";

function gatewayFor(granteeAddress: `0x${string}`): GatewayClient {
  const grant = {
    id: GRANT_ID,
    grantorAddress: owner.address,
    granteeId: granteeAddress,
    scopes: ["instagram.*"],
    status: "confirmed",
    addedAt: "2026-01-21T10:00:00.000Z",
    expiresAt: null,
    expired: false,
    revokedAt: null,
    paymentStatus: "paid",
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
    getServer: vi.fn().mockResolvedValue(null),
    getDataPoint: vi.fn().mockResolvedValue(null),
    listDataPointsByOwner: vi
      .fn()
      .mockResolvedValue({ dataPoints: [], cursor: null }),
    getSchema: vi.fn().mockResolvedValue(null),
    registerServer: vi.fn().mockResolvedValue({ alreadyRegistered: false }),
    registerDataPoint: vi.fn().mockResolvedValue({ dataPointId: "0xdp" }),
    createGrant: vi.fn().mockResolvedValue({ grantId: GRANT_ID }),
    revokeGrant: vi.fn().mockResolvedValue(undefined),
  } as unknown as GatewayClient;
}

const accessLogWriter: AccessLogWriter = { write: async () => undefined };

let dataDir: string;
let indexManager: IndexManager;
let connections: McpConnectionStore;

beforeEach(async () => {
  dataDir = await mkdtemp(join(tmpdir(), "mcp-pdpp-disclosure-"));
  indexManager = createIndexManager(initializeDatabase(":memory:"));
  connections = createInMemoryMcpConnectionStore();
});

afterEach(async () => {
  indexManager.close();
  await rm(dataDir, { recursive: true, force: true });
});

function data(gateway: GatewayClient) {
  return dataRoutes({
    indexManager,
    hierarchyOptions: { dataDir },
    logger,
    serverOrigin: SERVER_ORIGIN,
    serverOwner: owner.address,
    gateway,
    accessLogWriter,
  });
}

/** Owner write; a `producer` stamps the version as PDPP data. */
async function ownerWrite(
  gateway: GatewayClient,
  scope: string,
  body: Record<string, unknown>,
  producer?: "pdpp-projector",
): Promise<string> {
  const raw = JSON.stringify(body);
  const response = await data(gateway).request(`/${scope}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: await buildWeb3SignedHeader({
        wallet: owner,
        aud: SERVER_ORIGIN,
        method: "POST",
        uri: `/${scope}`,
        body: new TextEncoder().encode(raw),
      }),
      ...(producer ? { "Vana-Producer": producer } : {}),
    },
    body: raw,
  });
  expect(response.status, await response.clone().text()).toBe(201);
  return indexManager.findLatestByScope(scope)!.collectedAt;
}

async function ownerRead(gateway: GatewayClient, scope: string) {
  return data(gateway).request(`/${scope}`, {
    headers: {
      Authorization: await buildWeb3SignedHeader({
        wallet: owner,
        aud: SERVER_ORIGIN,
        method: "GET",
        uri: `/${scope}`,
      }),
    },
  });
}

/**
 * `instagram.profile`: a legacy file, then a PDPP-stamped version of the same
 * data. `instagram.posts`: a legacy file only.
 */
async function seed(gateway: GatewayClient) {
  const legacyAt = await ownerWrite(gateway, "instagram.profile", {
    rows: [{ id: LEGACY }],
  });
  await ownerWrite(
    gateway,
    "instagram.profile",
    { rows: [{ id: LEGACY, score: SECRET, note: "zebracorn" }] },
    "pdpp-projector",
  );
  await ownerWrite(gateway, "instagram.posts", { rows: [{ id: LEGACY }] });
  return { legacyAt };
}

function mcpApp(gateway: GatewayClient, extra: Record<string, unknown> = {}) {
  const root = new Hono();
  root.route(
    "/mcp",
    mcpStreamableHttpRoutes({
      logger,
      serverOrigin: SERVER_ORIGIN,
      serverOwner: owner.address,
      gateway,
      gatewayConfig,
      serverSigner: {
        signGrantRegistration: vi
          .fn()
          .mockResolvedValue("0xgrantsig" as `0x${string}`),
      },
      accessLogWriter,
      connectionStore: connections,
      indexManager,
      hierarchyOptions: { dataDir },
      ...extra,
    }),
  );
  return root;
}

async function toolCall(
  app: Hono,
  path: string,
  headers: Record<string, string>,
  name: string,
  args: Record<string, unknown>,
): Promise<string> {
  const response = await app.request(path, {
    method: "POST",
    headers: {
      Accept: "application/json, text/event-stream",
      "Content-Type": "application/json",
      ...headers,
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name, arguments: args },
    }),
  });
  expect(response.status).toBe(200);
  return response.text();
}

function matchesOf(rpcText: string): unknown[] {
  return JSON.parse(rpcText).result.structuredContent.matches;
}

async function connection() {
  const created = await createMcpConnection(
    { displayName: "Claude" },
    { store: connections, publicOrigin: SERVER_ORIGIN },
  );
  const record = (await connections.getById(created.connectionId))!;
  const gateway = gatewayFor(record.granteeAddress);
  await approveMcpConnection(
    {
      connectionId: created.connectionId,
      grants: [{ grantId: GRANT_ID, scopes: ["instagram.*"] }],
    },
    { store: connections },
  );
  return {
    gateway,
    path: `/mcp/${encodeURIComponent(created.connectionToken)}`,
  };
}

describe("owner's-Claude MCP connection with a live chain grant", () => {
  it("read_scope refuses the PDPP version and still reads the legacy file", async () => {
    const { gateway, path } = await connection();
    const { legacyAt } = await seed(gateway);
    const app = mcpApp(gateway);

    const latest = await toolCall(app, path, {}, "read_scope", {
      scope: "instagram.profile",
    });
    expect(latest).not.toContain(SECRET);
    expect(latest).toContain("GRANT_REQUIRED");

    // Positive controls on the same data.
    const owned = await ownerRead(gateway, "instagram.profile");
    expect(owned.status).toBe(200);
    expect(await owned.text()).toContain(SECRET);
    const legacy = await toolCall(app, path, {}, "read_scope", {
      scope: "instagram.profile",
      cursor: encodeDataBlockCursor({
        scope: "instagram.profile",
        collectedAt: legacyAt,
        blockIndex: 0,
      }),
    });
    expect(legacy).toContain(LEGACY);
    expect(legacy).not.toContain(SECRET);
  });

  it("search previews never quote the PDPP version", async () => {
    const { gateway, path } = await connection();
    await seed(gateway);
    const app = mcpApp(gateway);

    // "zebracorn" occurs only in the PDPP version.
    const pdpp = await toolCall(app, path, {}, "search_personal_context", {
      query: "zebracorn",
      scopes: ["instagram.profile"],
    });
    expect(pdpp).not.toContain(SECRET);
    expect(matchesOf(pdpp)).toEqual([]);

    // The same tool still searches a legacy file under the same grant.
    const legacy = await toolCall(app, path, {}, "search_personal_context", {
      query: LEGACY,
      scopes: ["instagram.posts"],
    });
    expect(matchesOf(legacy).length).toBeGreaterThan(0);
    expect(JSON.stringify(matchesOf(legacy))).toContain(LEGACY);
  });

  it("list_scope_blocks refuses the PDPP version's block table", async () => {
    const { gateway, path } = await connection();
    await seed(gateway);
    const app = mcpApp(gateway);

    const pdpp = await toolCall(app, path, {}, "list_scope_blocks", {
      scope: "instagram.profile",
    });
    expect(pdpp).toContain("GRANT_REQUIRED");
    expect(pdpp).not.toContain('"blocks"');

    const legacy = await toolCall(app, path, {}, "list_scope_blocks", {
      scope: "instagram.posts",
    });
    expect(legacy).toContain('"blocks"');
    expect(legacy).not.toContain("GRANT_REQUIRED");
  });

  it("refuses a read of a scope the owner deleted, like /v1/data", async () => {
    const { gateway, path } = await connection();
    await seed(gateway);
    const scopeDeletions = createScopeDeletionTracker({
      serverOwner: owner.address,
    });
    scopeDeletions.markDeleted("instagram.posts", {
      deletedAt: "2099-01-01T00:00:00.000Z",
      version: "9",
    });
    const app = mcpApp(gateway, { scopeDeletions });

    const read = await toolCall(app, path, {}, "read_scope", {
      scope: "instagram.posts",
    });
    expect(read).toContain("DATA_DELETED");
    expect(read).not.toContain(LEGACY);
    const blocks = await toolCall(app, path, {}, "list_scope_blocks", {
      scope: "instagram.posts",
    });
    expect(blocks).toContain("DATA_DELETED");
  });
});

describe("self-signing MCP session with a live chain grant", () => {
  async function session(gateway: GatewayClient, app: Hono) {
    const minted = await app.request("/mcp/session", {
      method: "POST",
      headers: {
        Authorization: await buildWeb3SignedHeader({
          wallet: appWallet,
          aud: SERVER_ORIGIN,
          method: "POST",
          uri: "/mcp/session",
          grantId: GRANT_ID,
        }),
      },
    });
    expect(minted.status).toBe(200);
    const { access_token } = (await minted.json()) as { access_token: string };
    return { Authorization: `Bearer ${access_token}` };
  }

  it("read_scope refuses the PDPP version and still reads the legacy file", async () => {
    const gateway = gatewayFor(appWallet.address);
    const { legacyAt } = await seed(gateway);
    const app = mcpApp(gateway);
    const headers = await session(gateway, app);

    const latest = await toolCall(app, "/mcp", headers, "read_scope", {
      scope: "instagram.profile",
    });
    expect(latest).not.toContain(SECRET);
    expect(latest).toContain("GRANT_REQUIRED");

    const owned = await ownerRead(gateway, "instagram.profile");
    expect(owned.status).toBe(200);
    expect(await owned.text()).toContain(SECRET);
    const legacy = await toolCall(app, "/mcp", headers, "read_scope", {
      scope: "instagram.profile",
      cursor: encodeDataBlockCursor({
        scope: "instagram.profile",
        collectedAt: legacyAt,
        blockIndex: 0,
      }),
    });
    expect(legacy).toContain(LEGACY);
    expect(legacy).not.toContain(SECRET);
  });
});
