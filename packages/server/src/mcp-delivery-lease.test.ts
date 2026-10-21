/**
 * MCP reads release blocks only through the read's delivery lease, the same
 * as GET /v1/data. A scope deleted while the grant check is in flight (a
 * gateway round trip) must not be served over MCP when /v1/data refuses it.
 *
 * Real Node storage, MCP route and data route; the gateway is a stub whose
 * grant lookup lets the test act while it is in flight.
 */
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Hono } from "hono";
import pino from "pino";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type {
  Builder,
  DataFileEnvelope,
  GatewayClient,
  GatewayGrantResponse,
} from "@opendatalabs/vana-sdk/browser";
import {
  approveMcpConnection,
  createInMemoryMcpConnectionStore,
  createMcpConnection,
} from "@opendatalabs/personal-server-ts-core/mcp";
import {
  buildWeb3SignedHeader,
  createTestWallet,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import { buildDataBlocksAsync } from "@opendatalabs/personal-server-ts-core/storage/blocks";
import type { IndexManager } from "@opendatalabs/personal-server-ts-core/storage/index";
import type { DataStoragePort } from "@opendatalabs/personal-server-ts-core/ports";
import {
  createScopeDeletionTracker,
  type ScopeDeletionTracker,
} from "@opendatalabs/personal-server-ts-core/sync";
import { initializeDatabase } from "./storage/index-schema.js";
import { createIndexManager } from "./storage/index-manager.js";
import { createNodeDataStorage } from "./storage/node-data-storage.js";
import { dataRoutes } from "./routes/data.js";
import { mcpStreamableHttpRoutes } from "./routes/mcp.js";

const logger = pino({ level: "silent" });
const ORIGIN = "http://localhost:8080";
const owner = createTestWallet(0);
const builder = createTestWallet(5);
const GRANT_ID = "grant-lease";
const AT = "2026-09-01T00:00:00.000Z";
const SCOPE = "oura.activity";
const gatewayConfig = {
  chainId: 14800,
  contracts: {
    dataRegistry: "0x0000000000000000000000000000000000000001",
    dataPortabilityPermissions: "0x0000000000000000000000000000000000000002",
    dataPortabilityServer: "0x0000000000000000000000000000000000000003",
    dataPortabilityGrantees: "0x0000000000000000000000000000000000000004",
  },
} as const;

let dataDir: string;
let indexManager: IndexManager;
let storage: DataStoragePort;
let duringGrantLookup: (() => void) | undefined;

function gatewayFor(granteeAddress: `0x${string}`): GatewayClient {
  const grant = {
    id: GRANT_ID,
    grantorAddress: owner.address,
    granteeId: granteeAddress,
    scopes: ["oura.*"],
    status: "confirmed",
    addedAt: "2026-01-21T10:00:00.000Z",
    expiresAt: null,
    expired: false,
    revokedAt: null,
    paymentStatus: "paid",
    grantVersion: "1",
  } as unknown as GatewayGrantResponse;
  const registered: Builder = {
    id: granteeAddress,
    ownerAddress: owner.address,
    granteeAddress,
    publicKey: "0x04",
    appUrl: "https://app.test",
    addedAt: "2026-01-21T10:00:00.000Z",
  };
  return {
    isRegisteredBuilder: vi.fn().mockResolvedValue(true),
    getBuilder: vi.fn().mockResolvedValue(registered),
    getGrant: vi.fn(async () => {
      const hook = duringGrantLookup;
      duringGrantLookup = undefined;
      hook?.();
      return grant;
    }),
    listGrantsByUser: vi.fn().mockResolvedValue([]),
    getSchemaForScope: vi.fn().mockResolvedValue(null),
    getServer: vi.fn().mockResolvedValue(null),
    getDataPoint: vi.fn().mockResolvedValue(null),
    listDataPointsByOwner: vi
      .fn()
      .mockResolvedValue({ dataPoints: [], cursor: null }),
    getSchema: vi.fn().mockResolvedValue(null),
  } as unknown as GatewayClient;
}

async function putLegacyVersion() {
  const envelope = {
    version: "1.0",
    scope: SCOPE,
    collectedAt: AT,
    data: { id: "legacy-row" },
  } as DataFileEnvelope;
  const written = await storage.writeEnvelope(envelope);
  const built = await buildDataBlocksAsync({
    scope: SCOPE,
    collectedAt: AT,
    content: envelope,
  });
  await storage.writeBlockManifest?.(SCOPE, AT, built.manifest, built.blocks);
  await storage.insertEntry({
    fileId: null,
    path: written.relativePath,
    scope: SCOPE,
    collectedAt: AT,
    sizeBytes: written.sizeBytes,
  });
}

beforeEach(async () => {
  dataDir = await mkdtemp(join(tmpdir(), "mcp-delivery-lease-"));
  indexManager = createIndexManager(initializeDatabase(":memory:"));
  storage = createNodeDataStorage({
    indexManager,
    hierarchyOptions: { dataDir },
  });
  duringGrantLookup = undefined;
  await putLegacyVersion();
});

afterEach(async () => {
  indexManager.close();
  await rm(dataDir, { recursive: true, force: true });
});

async function mcpClient(scopeDeletions: ScopeDeletionTracker) {
  const connections = createInMemoryMcpConnectionStore();
  const created = await createMcpConnection(
    { displayName: "Lease" },
    { store: connections, publicOrigin: ORIGIN },
  );
  const record = (await connections.getById(created.connectionId))!;
  await approveMcpConnection(
    {
      connectionId: created.connectionId,
      grants: [{ grantId: GRANT_ID, scopes: ["oura.*"] }],
    },
    { store: connections },
  );
  const root = new Hono();
  root.route(
    "/mcp",
    mcpStreamableHttpRoutes({
      logger,
      scopeDeletions,
      serverOrigin: ORIGIN,
      serverOwner: owner.address,
      gateway: gatewayFor(record.granteeAddress),
      gatewayConfig,
      accessLogWriter: { write: async () => undefined },
      connectionStore: connections,
      indexManager,
      hierarchyOptions: { dataDir },
    }),
  );
  return async (name: string, args: Record<string, unknown>) => {
    const response = await root.request(
      `/mcp/${encodeURIComponent(created.connectionToken)}`,
      {
        method: "POST",
        headers: {
          Accept: "application/json, text/event-stream",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: { name, arguments: args },
        }),
      },
    );
    return response.text();
  };
}

async function v1DataRead(scopeDeletions: ScopeDeletionTracker) {
  return dataRoutes({
    indexManager,
    hierarchyOptions: { dataDir },
    logger,
    scopeDeletions,
    serverOrigin: ORIGIN,
    serverOwner: owner.address,
    gateway: gatewayFor(builder.address),
    accessLogWriter: { write: async () => undefined },
  }).request(`/${SCOPE}`, {
    headers: {
      Authorization: await buildWeb3SignedHeader({
        wallet: builder,
        aud: ORIGIN,
        method: "GET",
        uri: `/${SCOPE}`,
        grantId: GRANT_ID,
      }),
    },
  });
}

describe("MCP delivery when the scope is deleted during the grant check", () => {
  for (const [tool, args] of [
    ["read_scope", { scope: SCOPE }],
    ["list_scope_blocks", { scope: SCOPE }],
  ] as const) {
    it(`${tool} refuses like /v1/data`, async () => {
      const tracker = createScopeDeletionTracker({
        serverOwner: owner.address,
      });
      const call = await mcpClient(tracker);
      duringGrantLookup = () => {
        tracker.markDeleted(SCOPE, {
          deletedAt: "2099-01-01T00:00:00Z",
          version: "9",
        });
      };
      const text = await call(tool, args);
      // The deletion reached the tracker during the MCP read's grant lookup.
      expect(duringGrantLookup).toBeUndefined();
      expect((await v1DataRead(tracker)).status).toBe(410);
      expect(text).toContain("DATA_DELETED");
      expect(text).not.toContain("legacy-row");
      expect(text).not.toContain("block-000002");
    });
  }

  it("serves the scope when nothing changes (positive control)", async () => {
    const tracker = createScopeDeletionTracker({ serverOwner: owner.address });
    const call = await mcpClient(tracker);
    const text = await call("read_scope", { scope: SCOPE });
    expect(text).toContain("legacy-row");
  });
});
