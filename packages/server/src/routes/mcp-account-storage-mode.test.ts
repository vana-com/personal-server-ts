/**
 * Every Node MCP engine reads the account's storage mode from the one
 * instance the host passes: the connection path, TEE dispatch, and free and
 * paid self-signing sessions. Each tool call below goes through the real MCP
 * route and its in-process read client into the data handler, which asks the
 * mode before anything else. The mode is a counting stand-in.
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
  type McpConnectionStore,
} from "@opendatalabs/personal-server-ts-core/mcp";
import {
  buildWeb3SignedHeader,
  createTestWallet,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import type {
  Builder,
  GatewayClient,
  GatewayGrantResponse,
} from "@opendatalabs/vana-sdk/node";
import type {
  AccountStorageMode,
  StreamSyncReadPort,
} from "@opendatalabs/personal-server-ts-core/api";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { createApp } from "../app.js";
import { initializeDatabase } from "../storage/index-schema.js";
import { createIndexManager } from "../storage/index-manager.js";
import {
  executeMcpConnectionRequest,
  mcpStreamableHttpRoutes,
  type McpRouteDeps,
} from "./mcp.js";
import { openLegacyWriteSealForTests } from "@opendatalabs/personal-server-ts-core/test-utils/legacy-write-seal";

const SERVER_ORIGIN = "http://localhost:8080";
const SCOPE = "instagram.profile";
const GRANT_ID = "grant-mode-1";
const ownerWallet = createTestWallet(9);
const appWallet = createTestWallet(21);
const logger = pino({ level: "silent" });
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

function gatewayFor(granteeAddress: `0x${string}`): GatewayClient {
  const grant = {
    id: GRANT_ID,
    grantorAddress: ownerWallet.address,
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
    ownerAddress: ownerWallet.address,
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

/** A reader that serves nothing: enough to send an MCP read into the handler. */
const emptyReader: StreamSyncReadPort = {
  resolve: async () => ({ kind: "pass" }),
};

const readScope = JSON.stringify({
  jsonrpc: "2.0",
  id: "call",
  method: "tools/call",
  params: { name: "read_scope", arguments: { scope: SCOPE } },
});

describe("the MCP engines share the host's account storage mode", () => {
  let dataDir: string;
  let mode: AccountStorageMode & { read: ReturnType<typeof vi.fn> };
  let store: McpConnectionStore;

  beforeEach(async () => {
    dataDir = await mkdtemp(join(tmpdir(), "mcp-account-mode-"));
    mode = { read: vi.fn(() => "unswitched" as const) };
    store = createInMemoryMcpConnectionStore();
  });

  afterEach(async () => {
    await rm(dataDir, { recursive: true, force: true });
  });

  function routeDeps(gateway: GatewayClient): McpRouteDeps {
    return {
      logger,
      serverOrigin: SERVER_ORIGIN,
      serverOwner: ownerWallet.address,
      gateway,
      gatewayConfig,
      accessLogWriter: { write: vi.fn(async () => undefined) },
      connectionStore: store,
      indexManager: createIndexManager(initializeDatabase(":memory:"), {
        legacyWriteSeal: openLegacyWriteSealForTests(),
      }),
      hierarchyOptions: { dataDir },
      streamSyncRead: emptyReader,
      accountStorageMode: mode,
    } as McpRouteDeps;
  }

  async function approvedConnection() {
    const created = await createMcpConnection(
      { displayName: "Claude" },
      { store, publicOrigin: SERVER_ORIGIN },
    );
    await approveMcpConnection(
      {
        connectionId: created.connectionId,
        grants: [{ grantId: GRANT_ID, scopes: [SCOPE] }],
      },
      { store },
    );
    return created;
  }

  const headers = {
    Accept: "application/json, text/event-stream",
    "Content-Type": "application/json",
  };

  it("the connection path reads it", async () => {
    const created = await approvedConnection();
    const app = new Hono();
    app.route(
      "/mcp",
      mcpStreamableHttpRoutes(routeDeps(gatewayFor(created.granteeAddress))),
    );
    const res = await app.request(
      `/mcp/${encodeURIComponent(created.connectionToken)}`,
      { method: "POST", headers, body: readScope },
    );
    expect(res.status).toBe(200);
    expect(mode.read).toHaveBeenCalled();
  });

  it("TEE dispatch reads it", async () => {
    const created = await approvedConnection();
    const connection = await store.getById(created.connectionId);
    const res = await executeMcpConnectionRequest(
      new Request("https://worker.local/mcp", {
        method: "POST",
        headers,
        body: readScope,
      }),
      connection!,
      routeDeps(gatewayFor(created.granteeAddress)),
    );
    expect(res.status).toBe(200);
    expect(mode.read).toHaveBeenCalled();
  });

  it("the mounted app hands its mode to the MCP engine", async () => {
    const created = await approvedConnection();
    const app = createApp({
      logger,
      version: "0.0.1",
      startedAt: new Date(),
      indexManager: createIndexManager(initializeDatabase(":memory:"), {
        legacyWriteSeal: openLegacyWriteSealForTests(),
      }),
      hierarchyOptions: { dataDir },
      serverOrigin: SERVER_ORIGIN,
      serverOwner: ownerWallet.address,
      gateway: gatewayFor(created.granteeAddress),
      gatewayConfig,
      accessLogWriter: { write: vi.fn(async () => undefined) },
      mcpConnectionStore: store,
      streamSyncRead: emptyReader,
      accountStorageMode: mode,
      config: ServerConfigSchema.parse({}),
    });
    const res = await app.request(
      `/mcp/${encodeURIComponent(created.connectionToken)}`,
      { method: "POST", headers, body: readScope },
    );
    expect(res.status).toBe(200);
    expect(mode.read).toHaveBeenCalled();
  });

  for (const paid of [false, true]) {
    it(`a ${paid ? "paid" : "free"} self-signing session reads it`, async () => {
      const app = new Hono();
      app.route(
        "/mcp",
        mcpStreamableHttpRoutes({
          ...routeDeps(gatewayFor(appWallet.address)),
          ...(paid
            ? {
                paymentEnabled: true,
                serverAddress: ownerWallet.address,
                serverSigner: {
                  signGrantRegistration: vi.fn(),
                  signRecordDataAccess: vi.fn(),
                },
              }
            : {}),
        } as McpRouteDeps),
      );
      const minted = (await (
        await app.request("/mcp/session", {
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
        })
      ).json()) as { access_token: string };
      expect(minted.access_token).toBeTruthy();
      await app.request("/mcp", {
        method: "POST",
        headers: { ...headers, Authorization: `Bearer ${minted.access_token}` },
        body: readScope,
      });
      expect(mode.read).toHaveBeenCalled();
    });
  }
});
