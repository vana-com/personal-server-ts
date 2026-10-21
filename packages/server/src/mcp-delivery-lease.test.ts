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
import { REMOTE_GRANT_REVERIFY_AFTER_MS } from "@opendatalabs/personal-server-ts-core/policy";
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
let revokedRemotely = false;

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
      return revokedRemotely
        ? { ...grant, revokedAt: "2026-10-21T00:00:00.000Z" }
        : grant;
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

async function putLegacyVersion(
  scope = SCOPE,
  data: Record<string, unknown> = { id: "legacy-row" },
) {
  const envelope = {
    version: "1.0",
    scope,
    collectedAt: AT,
    data,
  } as DataFileEnvelope;
  const written = await storage.writeEnvelope(envelope);
  const built = await buildDataBlocksAsync({
    scope,
    collectedAt: AT,
    content: envelope,
  });
  await storage.writeBlockManifest?.(scope, AT, built.manifest, built.blocks);
  await storage.insertEntry({
    fileId: null,
    path: written.relativePath,
    scope,
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
  revokedRemotely = false;
  await putLegacyVersion();
});

afterEach(async () => {
  vi.useRealTimers();
  indexManager.close();
  await rm(dataDir, { recursive: true, force: true });
});

async function mcpClient(
  scopeDeletions: ScopeDeletionTracker,
  onAccessLog: (scope: string) => void = () => undefined,
) {
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
      accessLogWriter: {
        write: async (entry) => {
          onAccessLog(entry.scope);
        },
      },
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

describe("MCP search across scopes when one is deleted during another's read", () => {
  it("does not release the deleted scope's preview", async () => {
    const A = "oura.sleep";
    const B = "oura.readiness";
    await putLegacyVersion(A, { note: "needle alpha-private" });
    await putLegacyVersion(B, { note: "needle beta" });
    const tracker = createScopeDeletionTracker({ serverOwner: owner.address });
    let deletedDuringB = false;
    const call = await mcpClient(tracker, (scope) => {
      // A has already been read and gated; B is being read now.
      if (scope === B && !deletedDuringB) {
        deletedDuringB = true;
        tracker.markDeleted(A, {
          deletedAt: "2099-01-01T00:00:00Z",
          version: "9",
        });
      }
    });
    const text = await call("search_personal_context", {
      query: "needle",
      scopes: [A, B],
    });
    expect(deletedDuringB).toBe(true);
    expect(text).not.toContain("alpha-private");
    expect(text).toContain("DATA_DELETED");
  });

  it("releases both previews when nothing changes (positive control)", async () => {
    const A = "oura.sleep";
    const B = "oura.readiness";
    await putLegacyVersion(A, { note: "needle alpha-private" });
    await putLegacyVersion(B, { note: "needle beta" });
    const tracker = createScopeDeletionTracker({ serverOwner: owner.address });
    const call = await mcpClient(tracker);
    const text = await call("search_personal_context", {
      query: "needle",
      scopes: [A, B],
    });
    expect(text).toContain("alpha-private");
    expect(text).toContain("beta");
  });
});

/**
 * The remote revocation policy for a composed MCP call: the gateway revokes
 * the grant while a search is still reading its second scope. A result
 * released before REMOTE_GRANT_REVERIFY_AFTER_MS may succeed on the admitting
 * answers; the first release after it asks the gateway again and is refused.
 */
describe("remote revocation stops a composed MCP call within REMOTE_GRANT_REVERIFY_AFTER_MS", () => {
  async function searchRevokedDuringSecondScope(elapsedMs: number) {
    vi.useFakeTimers({ toFake: ["Date"] });
    const A = "oura.sleep";
    const B = "oura.readiness";
    await putLegacyVersion(A, { note: "needle alpha-private" });
    await putLegacyVersion(B, { note: "needle beta-private" });
    const tracker = createScopeDeletionTracker({ serverOwner: owner.address });
    const call = await mcpClient(tracker, (scope) => {
      if (scope === B && !revokedRemotely) {
        revokedRemotely = true;
        vi.setSystemTime(Date.now() + elapsedMs);
      }
    });
    return call("search_personal_context", { query: "needle", scopes: [A, B] });
  }

  it("a release before the bound may succeed", async () => {
    const text = await searchRevokedDuringSecondScope(
      REMOTE_GRANT_REVERIFY_AFTER_MS - 1_000,
    );
    expect(revokedRemotely).toBe(true);
    expect(text).toContain("alpha-private");
  });

  it("the first release after the bound is refused", async () => {
    const text = await searchRevokedDuringSecondScope(
      REMOTE_GRANT_REVERIFY_AFTER_MS,
    );
    expect(revokedRemotely).toBe(true);
    expect(text).not.toContain("alpha-private");
    expect(text).not.toContain("beta-private");
    expect(text).toContain("GRANT_REVOKED");
  });
});
