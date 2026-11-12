/**
 * The MCP read and the HTTP data read serve the same stream-sync view.
 *
 * Real: the SQLite composition (heads, parts, apply and resolver), the data route, the MCP route and its in-process
 * read client, the connection store and grant checks. Stubbed: the gateway
 * (grant lookup only) and the access log, as in the existing route tests.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
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
  fixedLegacyWriteSeal,
  createTestWallet,
  buildWeb3SignedHeader,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import type {
  GatewayClient,
  GatewayGrantResponse,
} from "@opendatalabs/vana-sdk/node";
import type { AccessLogWriter } from "@opendatalabs/personal-server-ts-core/logging/access-log";
import type { StreamSyncReadPort } from "@opendatalabs/personal-server-ts-core/api";
import { databaseReadFixture } from "../localdb/read-fixture.test-utils.js";
import { initializeDatabase } from "../storage/index-schema.js";
import { createIndexManager } from "../storage/index-manager.js";
import { dataRoutes } from "./data.js";
import { mcpStreamableHttpRoutes } from "./mcp.js";

const SERVER_ORIGIN = "http://localhost:8080";
const MAIN_PORT = 8080;
const LOOPBACK_PORT = 8081;
/** A legacy binding name: its stream view is connector `meta`, streams `posts` and `post_likes`. */
const SCOPE = "instagram.posts";
const ownerWallet = createTestWallet(9);
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

function gatewayWithGrant(
  granteeAddress: `0x${string}`,
  grantedScope: string = SCOPE,
): GatewayClient {
  const grant = {
    id: "grant-mcp-1",
    grantorAddress: ownerWallet.address,
    granteeId: granteeAddress,
    scopes: [grantedScope],
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
  // The MCP connection's grantee is a registered builder, as in mcp.test.ts.
  const builder = {
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
    getServer: vi.fn().mockResolvedValue(null),
    getDataPoint: vi.fn().mockResolvedValue(null),
    listDataPointsByOwner: vi
      .fn()
      .mockResolvedValue({ dataPoints: [], cursor: null }),
    getSchema: vi.fn().mockResolvedValue(null),
    registerServer: vi.fn().mockResolvedValue({ alreadyRegistered: false }),
    registerDataPoint: vi.fn().mockResolvedValue({ dataPointId: "0xdp" }),
    createGrant: vi.fn().mockResolvedValue({ grantId: "grant-mcp-1" }),
    revokeGrant: vi.fn().mockResolvedValue(undefined),
  } as unknown as GatewayClient;
}

function accessLog(): AccessLogWriter {
  return { write: vi.fn(async () => undefined) } as unknown as AccessLogWriter;
}

/**
 * The stream view for SCOPE: a completed `posts` row with one post, `p1`,
 * and its `post_likes` row, read through the real service.
 */
async function streamView(): Promise<StreamSyncReadPort> {
  const { remote, local } = await databaseReadFixture("meta");
  await remote.head(
    "posts",
    [
      {
        id: "p1",
        media_url: "https://media.test/p1.jpg",
        caption: "from the stream view",
        like_count: 1,
        taken_at: "2026-11-01T00:00:00Z",
      },
    ],
    { profile: { key: "meta", version: "1" } },
  );
  await remote.head(
    "post_likes",
    [{ post_id: "p1", liker_ordinal: 0, user_id: "u1", username: "liker" }],
    {
      profile: { key: "meta", version: "1" },
      primaryKey: ["post_id", "liker_ordinal"],
    },
  );
  await local.apply();
  return {
    resolve: (input) => local.resolver.resolve(input),
    listScopes: (input) => local.listing.listScopes(input),
    olderVersions: local.olderVersions,
  };
}

/** Every `caption` string in a parsed read payload, in order. */
function captionsIn(value: unknown): string[] {
  const found: string[] = [];
  const walk = (node: unknown): void => {
    if (Array.isArray(node)) node.forEach(walk);
    else if (node !== null && typeof node === "object") {
      for (const [key, inner] of Object.entries(node)) {
        if (key === "caption" && typeof inner === "string") found.push(inner);
        else walk(inner);
      }
    }
  };
  walk(value);
  return found;
}

/** The first object in a payload whose `scope` is `scope`. */
function findScopeEntry(
  value: unknown,
  scope: string,
): { sizeBytes?: number; dataStatus?: string } | undefined {
  if (Array.isArray(value)) {
    for (const item of value) {
      const found = findScopeEntry(item, scope);
      if (found) return found;
    }
  } else if (value !== null && typeof value === "object") {
    if ((value as { scope?: unknown }).scope === scope) {
      return value as { sizeBytes?: number; dataStatus?: string };
    }
    for (const inner of Object.values(value)) {
      const found = findScopeEntry(inner, scope);
      if (found) return found;
    }
  }
  return undefined;
}

describe("MCP and HTTP reads serve the same stream-sync view", () => {
  let dataDir: string;
  let store: McpConnectionStore;
  let http: Hono;
  let mcp: Hono;
  let token: string;
  let mode: "switched" | "unswitched";

  beforeEach(async () => {
    mode = "switched";
    dataDir = await mkdtemp(join(tmpdir(), "mcp-stream-sync-read-"));
    const indexManager = createIndexManager(initializeDatabase(":memory:"));
    store = createInMemoryMcpConnectionStore();
    const view = Object.assign(await streamView(), {
      listScopes: async ({
        canRead,
      }: {
        canRead: (scope: string) => boolean | Promise<boolean>;
      }) =>
        (await canRead(SCOPE))
          ? [
              {
                scope: SCOPE,
                connector: "fixture",
                ns: "",
                records: 1,
                updatedAt: Date.parse("2026-11-01T00:00:00Z"),
              },
            ]
          : [],
    });
    const created = await createMcpConnection(
      { displayName: "Claude" },
      { store, publicOrigin: SERVER_ORIGIN },
    );
    const gateway = gatewayWithGrant(created.granteeAddress);
    const accessLogWriter = accessLog();
    const hierarchyOptions = { dataDir };

    http = dataRoutes({
      accountStorageMode: { owner: ownerWallet.address, read: () => mode },
      legacyWriteSeal: fixedLegacyWriteSeal("unswitched"),
      indexManager,
      hierarchyOptions,
      logger,
      serverOrigin: SERVER_ORIGIN,
      serverOwner: ownerWallet.address,
      gateway,
      accessLogWriter,
      streamSyncRead: view,
    });

    mcp = new Hono();
    mcp.route(
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
        accountStorageMode: { owner: ownerWallet.address, read: () => mode },
        streamSyncRead: view,
        oauthApprovalUrl: "https://app-dev.vana.org/mcp/connect/claude",
        localApprovalPort: LOOPBACK_PORT,
        serverPort: MAIN_PORT,
      }),
    );
    await approveMcpConnection(
      {
        connectionId: created.connectionId,
        grants: [{ grantId: "grant-mcp-1", scopes: [SCOPE] }],
      },
      { store },
    );
    token = created.connectionToken;
  });

  afterEach(async () => {
    await rm(dataDir, { recursive: true, force: true });
  });

  async function httpRead(): Promise<unknown> {
    const auth = await buildWeb3SignedHeader({
      wallet: ownerWallet,
      aud: SERVER_ORIGIN,
      method: "GET",
      uri: `/${SCOPE}`,
    });
    const res = await http.request(`/${SCOPE}`, {
      headers: { Authorization: auth },
    });
    expect(res.status, await res.clone().text()).toBe(200);
    return res.json();
  }

  /** One MCP tool call over the real route; the tool's text and error flag. */
  async function mcpCall(
    name: string,
    args: Record<string, unknown>,
  ): Promise<{ text: string; isError: boolean }> {
    const res = await mcp.request(`/mcp/${encodeURIComponent(token)}`, {
      method: "POST",
      headers: {
        Accept: "application/json, text/event-stream",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: "call",
        method: "tools/call",
        params: { name, arguments: args },
      }),
    });
    expect(res.status).toBe(200);
    const payload = (await res.json()) as {
      result: { content: { text: string }[]; isError?: boolean };
    };
    return {
      text: payload.result.content[0]!.text,
      isError: payload.result.isError === true,
    };
  }

  async function mcpRead(): Promise<string> {
    return (await mcpCall("read_scope", { scope: SCOPE })).text;
  }

  it("returns a stream-only completed row on MCP just as on HTTP", async () => {
    // No legacy file exists for SCOPE: the stream view is the only source.
    const httpCaptions = captionsIn(await httpRead());
    expect(httpCaptions).toEqual(["from the stream view"]);
    const mcpCaptions = captionsIn(JSON.parse(await mcpRead()));
    expect(mcpCaptions).toEqual(httpCaptions);
  });

  it("reports the view's size and readiness in list_granted_scopes", async () => {
    const list = await mcpCall("list_granted_scopes", {});
    expect(list.isError).toBe(false);
    const entry = findScopeEntry(JSON.parse(list.text), SCOPE);
    expect(entry).toBeDefined();
    expect(entry?.sizeBytes).toBeGreaterThan(0);
    expect(entry?.dataStatus).not.toBe("needs_refresh");
  });

  it("lists, pages and raw-reads a view-served name without legacy bytes", async () => {
    await ingestStaleLegacy();
    const manifest = await mcpCall("list_scope_blocks", { scope: SCOPE });
    expect(manifest.isError).toBe(false);
    expect(manifest.text).toContain('"path":"$.data"');
    expect(manifest.text).not.toContain("stale legacy");

    const page = await mcpCall("read_scope", { scope: SCOPE });
    expect(page.isError).toBe(false);
    expect(page.text).toContain("from the stream view");
    expect(page.text).not.toContain("stale legacy");

    const raw = await mcpCall("get_scope_file", { scope: SCOPE });
    expect(raw.isError).toBe(true);
    expect(raw.text).toContain("STREAM_VIEW_NOT_RAW");
    expect(raw.text).not.toContain("stale legacy");
  });

  async function ingestStaleLegacy(): Promise<void> {
    const bodyText = JSON.stringify({
      records: [{ id: "legacy", caption: "stale legacy" }],
    });
    const auth = await buildWeb3SignedHeader({
      wallet: ownerWallet,
      aud: SERVER_ORIGIN,
      method: "POST",
      uri: `/${SCOPE}`,
      body: new TextEncoder().encode(bodyText),
    });
    mode = "unswitched";
    const ingest = await http.request(`/${SCOPE}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: auth },
      body: bodyText,
    });
    mode = "switched";
    expect(ingest.ok).toBe(true);
  }

  it("serves the stream view over a stale legacy file on MCP just as on HTTP", async () => {
    // A legacy file under the same scope name, holding an older post.
    const bodyText = JSON.stringify({
      records: [{ id: "legacy", caption: "stale legacy" }],
    });
    const auth = await buildWeb3SignedHeader({
      wallet: ownerWallet,
      aud: SERVER_ORIGIN,
      method: "POST",
      uri: `/${SCOPE}`,
      body: new TextEncoder().encode(bodyText),
    });
    mode = "unswitched";
    const ingest = await http.request(`/${SCOPE}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: auth },
      body: bodyText,
    });
    mode = "switched";
    expect(ingest.ok).toBe(true);

    const httpCaptions = captionsIn(await httpRead());
    expect(httpCaptions).toEqual(["from the stream view"]);
    const mcpCaptions = captionsIn(JSON.parse(await mcpRead()));
    expect(mcpCaptions).toEqual(httpCaptions);
  });
});

/**
 * `notShared` owner-wide discovery for a switched account. The grant covers
 * `other.thing`. The stream listing holds `youtube.history` (live, ungranted)
 * and omits every other scope. No legacy storage exists to read from.
 */
describe("MCP notShared lists from the stream listing for a switched account", () => {
  let dataDir: string;

  beforeEach(async () => {
    dataDir = await mkdtemp(join(tmpdir(), "mcp-notshared-stream-"));
  });
  afterEach(async () => {
    await rm(dataDir, { recursive: true, force: true });
  });

  async function setup(mode: "switched" | "unknown", listing: boolean) {
    const indexManager = createIndexManager(initializeDatabase(":memory:"));
    const store = createInMemoryMcpConnectionStore();
    const created = await createMcpConnection(
      { displayName: "Claude" },
      { store, publicOrigin: SERVER_ORIGIN },
    );
    const gateway = gatewayWithGrant(created.granteeAddress, "other.thing");
    const listScopes = vi.fn(
      async ({
        canRead,
      }: {
        canRead: (scope: string) => boolean | Promise<boolean>;
      }) =>
        (await canRead("youtube.history"))
          ? [
              {
                scope: "youtube.history",
                connector: "youtube",
                ns: "",
                records: 3,
                updatedAt: Date.parse("2026-11-01T00:00:00Z"),
                latestCollectedAt: "2026-11-01T00:00:00.000Z",
              },
            ]
          : [],
    );
    const view = {
      resolve: async () => {
        throw new Error("unexpected resolve");
      },
      ...(listing && { listScopes }),
    } as unknown as StreamSyncReadPort;
    const mcp = new Hono();
    mcp.route(
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
        accessLogWriter: accessLog(),
        connectionStore: store,
        indexManager,
        hierarchyOptions: { dataDir },
        mcpExposeUnsharedScopes: true,
        accountStorageMode: {
          owner: ownerWallet.address,
          read: () => mode,
        },
        streamSyncRead: view,
        oauthApprovalUrl: "https://app-dev.vana.org/mcp/connect/claude",
        localApprovalPort: LOOPBACK_PORT,
        serverPort: MAIN_PORT,
      }),
    );
    await approveMcpConnection(
      {
        connectionId: created.connectionId,
        grants: [{ grantId: "grant-mcp-1", scopes: ["other.thing"] }],
      },
      { store },
    );
    const listGranted = async () => {
      const res = await mcp.request(
        `/mcp/${encodeURIComponent(created.connectionToken)}`,
        {
          method: "POST",
          headers: {
            Accept: "application/json, text/event-stream",
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            jsonrpc: "2.0",
            id: "call",
            method: "tools/call",
            params: { name: "list_granted_scopes", arguments: {} },
          }),
        },
      );
      expect(res.status).toBe(200);
      const payload = (await res.json()) as {
        result: { content: { text: string }[] };
      };
      return JSON.parse(payload.result.content[0]!.text) as {
        notShared?: { scope: string; dataStatus: string }[];
        notSharedUnavailable?: boolean;
      };
    };
    return { listGranted, listScopes };
  }

  it("lists a live ungranted stream-only scope as ready, and no legacy-only scope", async () => {
    const { listGranted } = await setup("switched", true);
    const body = await listGranted();
    expect(body.notShared).toEqual([
      expect.objectContaining({
        scope: "youtube.history",
        source: "youtube",
        collectedAt: "2026-11-01T00:00:00.000Z",
        dataStatus: "ready",
      }),
    ]);
    expect(body.notSharedUnavailable).toBeUndefined();
  });

  it("reports discovery unavailable, not empty, when a switched account has no stream listing", async () => {
    const { listGranted } = await setup("switched", false);
    const body = await listGranted();
    expect(body.notShared).toBeUndefined();
    expect(body.notSharedUnavailable).toBe(true);
  });

  it("reports discovery unavailable, not empty, for an unknown account, and never lists", async () => {
    const { listGranted, listScopes } = await setup("unknown", true);
    const body = await listGranted();
    expect(body.notShared).toBeUndefined();
    expect(body.notSharedUnavailable).toBe(true);
    expect(listScopes).not.toHaveBeenCalled();
  });
});
