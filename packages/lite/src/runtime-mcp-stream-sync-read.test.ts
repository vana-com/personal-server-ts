import {
  createModeAuthority,
  createMemoryModeRecordStore,
} from "@opendatalabs/personal-server-ts-core/sync/account-mode";
/**
 * The MCP read and the HTTP data read serve the same stream-sync view in the
 * Lite runtime (the browser Personal Server).
 *
 * Real: the Lite runtime (`createPsLiteRuntime`), its `/v1/data` and `/mcp/:token`
 * routes, the connection store, grant checks, and the database composition
 * (real heads, parts, SQLite apply and resolver). Stubbed: the
 * gateway (grant and builder lookup only) and the access-log sink.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createPsLiteRuntime } from "./runtime.js";
import {
  createMemoryPsLiteStorage,
  createMemoryPsLiteTokenStore,
} from "./test-support/memory.js";
import {
  approveMcpConnection,
  createInMemoryMcpConnectionStore,
  createMcpConnection,
  type McpConnectionStore,
} from "@opendatalabs/personal-server-ts-core/mcp";
import {
  createTestWallet,
  buildWeb3SignedHeader,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import type {
  Builder,
  GatewayClient,
  GatewayGrantResponse,
} from "@opendatalabs/vana-sdk/browser";
import type { AccessLogEntry } from "@opendatalabs/personal-server-ts-core/logging/access-log";
import type { StreamSyncReadPort } from "@opendatalabs/personal-server-ts-core/api";
import {
  openLocalDb,
  connectionQueue,
  type SqlDriver,
} from "@opendatalabs/personal-server-ts-core/localdb";
import { openBetterSqlite3 } from "../../server/src/localdb/better-sqlite3-driver.js";
import { remoteFixture } from "../../server/src/localdb/apply-fixture.js";
import { createServerLocalSync } from "../../server/src/localdb/sync.js";
const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
});
import { createWeb3SignedPsLiteAuth } from "./runtime.js";

const SERVER_ORIGIN = "https://ps-lite.local";
/** A legacy binding name: its stream view is connector `meta`, streams `posts` and `post_likes`. */
const SCOPE = "instagram.posts";
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

function gatewayFor(
  granteeAddress: `0x${string}`,
  grantedScopes: string[] = [SCOPE],
): GatewayClient {
  const grant = {
    id: "grant-mcp-1",
    grantorAddress: owner.address,
    granteeId: granteeAddress,
    scopes: grantedScopes,
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

/**
 * The stream view for SCOPE: a completed `posts` row with one post, `p1`,
 * and its `post_likes` row, read through the real database resolver.
 */
async function streamView(): Promise<StreamSyncReadPort> {
  const keys = {
    namespaceHmac: async () => new Uint8Array(32),
    encrypt: async (_s: string, b: Uint8Array) => b,
    encryptPart: async (_s: string, b: Uint8Array) => b,
    decrypt: async (_s: string, b: Uint8Array) => b,
  };
  const remote = await remoteFixture(keys, "meta");
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
  const db = await openLocalDb(openBetterSqlite3(":memory:"), {
    owner: owner.address,
    network: "test",
    deviceId: "lite-mcp",
  });
  drivers.push(db);
  let op = 0;
  const local = createServerLocalSync(
    {
      db,
      queue: connectionQueue(),
      ownerAddress: owner.address,
      registry: remote.registry,
      blobs: remote.storage,
      keys,
      signer: { signAddData: async () => "0x00" },
      logger: { info() {}, warn() {} },
      now: () => 100,
      newOp: () => String(++op),
    },
    {
      resolveArtifact: () => undefined,
      declaredStreams: () => ["posts", "post_likes"],
      olderVersionReads: () => true,
    },
  );
  await local.apply();
  return {
    resolve: (input) => local.resolver.resolve(input),
    listScopes: (input) => local.listing.listScopes(input),
    olderVersions: local.olderVersions,
  };
}

function ownerSigned(
  method: "GET" | "POST",
  path: string,
  body?: unknown,
): Promise<Request> {
  const rawBody = body === undefined ? undefined : JSON.stringify(body);
  return buildWeb3SignedHeader({
    wallet: owner,
    aud: SERVER_ORIGIN,
    method,
    uri: path,
    body: rawBody === undefined ? undefined : new TextEncoder().encode(rawBody),
  }).then(
    (auth) =>
      new Request(`${SERVER_ORIGIN}${path}`, {
        method,
        headers: rawBody
          ? { "Content-Type": "application/json", Authorization: auth }
          : { Authorization: auth },
        body: rawBody,
      }),
  );
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

describe("Lite MCP and HTTP reads serve the same stream-sync view", () => {
  let store: McpConnectionStore;
  let runtime: ReturnType<typeof createPsLiteRuntime>;
  let accessLog: AccessLogEntry[];
  let token: string;
  let authority: ReturnType<typeof createModeAuthority>;

  beforeEach(async () => {
    authority = createModeAuthority({ store: createMemoryModeRecordStore() });
    await authority.ready;
    await authority.submitEvidence({ owner: owner.address, state: "off" });
    store = createInMemoryMcpConnectionStore();
    const created = await createMcpConnection(
      { displayName: "Claude" },
      { store, publicOrigin: SERVER_ORIGIN },
    );
    token = created.connectionToken;
    const gateway = gatewayFor(created.granteeAddress);
    accessLog = [];
    const accessLogSink = {
      async write(entry: AccessLogEntry) {
        accessLog.push({ ...entry });
      },
      async read() {
        return {
          logs: accessLog,
          total: accessLog.length,
          limit: 50,
          offset: 0,
        };
      },
    };
    const gatewayPorts = {
      authSessionVerifier: gateway,
      grantVerifier: gateway,
    };
    runtime = createPsLiteRuntime({
      accountModeAuthority: authority,
      active: true,
      storage: createMemoryPsLiteStorage(),
      config: { gateway: gatewayConfig },
      gateway,
      serverSigner: {
        signGrantRegistration: vi
          .fn()
          .mockResolvedValue("0xgrantsig" as `0x${string}`),
      },
      accessLogReader: accessLogSink,
      accessLogWriter: accessLogSink,
      tokenStore: createMemoryPsLiteTokenStore(),
      saveConfig: async () => {},
      stateCapabilities: { config: "memory" },
      serverOwner: owner.address,
      mcpConnectionStore: store,
      streamSyncRead: await streamView(),
      auth: createWeb3SignedPsLiteAuth({
        origin: SERVER_ORIGIN,
        ownerAddress: owner.address,
        dataReadPolicyPorts: gatewayPorts,
      }),
    });
    await approveMcpConnection(
      {
        connectionId: created.connectionId,
        grants: [{ grantId: "grant-mcp-1", scopes: [SCOPE] }],
      },
      { store },
    );
  });

  async function httpRead(): Promise<unknown> {
    await authority.submitEvidence({ owner: owner.address, state: "on" });
    const res = await runtime.fetch(
      await ownerSigned("GET", `/v1/data/${SCOPE}`),
    );
    expect(res.status, await res.clone().text()).toBe(200);
    return res.json();
  }

  /** One MCP tool call over the real Lite route; the tool's text and error flag. */
  async function mcpCall(
    name: string,
    args: Record<string, unknown>,
  ): Promise<{ text: string; isError: boolean }> {
    await authority.submitEvidence({ owner: owner.address, state: "on" });
    const res = await runtime.fetch(
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
          params: { name, arguments: args },
        }),
      }),
    );
    expect(res.status).toBe(200);
    const payload = (await res.json()) as {
      result: { content: { text: string }[]; isError?: boolean };
    };
    return {
      text: payload.result.content[0]!.text,
      isError: payload.result.isError === true,
    };
  }

  async function mcpRead(): Promise<unknown> {
    const call = await mcpCall("read_scope", { scope: SCOPE });
    expect(call.isError).toBe(false);
    return JSON.parse(call.text);
  }

  async function ingestStaleLegacy(): Promise<void> {
    const bodyText = JSON.stringify({
      records: [{ id: "legacy", caption: "stale legacy" }],
    });
    const res = await runtime.fetch(
      await ownerSigned("POST", `/v1/data/${SCOPE}`, JSON.parse(bodyText)),
    );
    expect(res.ok).toBe(true);
  }

  it("returns a stream-only completed row on MCP just as on HTTP", async () => {
    const httpCaptions = captionsIn(await httpRead());
    expect(httpCaptions).toEqual(["from the stream view"]);
    expect(captionsIn(await mcpRead())).toEqual(httpCaptions);
  });

  it("serves the stream view over a stale legacy file on MCP just as on HTTP", async () => {
    await ingestStaleLegacy();
    const httpCaptions = captionsIn(await httpRead());
    expect(httpCaptions).toEqual(["from the stream view"]);
    expect(captionsIn(await mcpRead())).toEqual(httpCaptions);
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
});

/**
 * `notShared` owner-wide discovery for a switched account. The grant covers
 * `other.thing`; the stream view holds `instagram.posts`, which no grant
 * covers. The legacy store holds a stale scope the stream view does not.
 */
describe("Lite MCP notShared lists from the stream view for a switched account", () => {
  async function setup(mode: "off" | "unknown") {
    const authority = createModeAuthority({
      store: createMemoryModeRecordStore(),
    });
    await authority.ready;
    if (mode !== "unknown") {
      await authority.submitEvidence({ owner: owner.address, state: mode });
    }
    const store = createInMemoryMcpConnectionStore();
    const created = await createMcpConnection(
      { displayName: "Claude" },
      { store, publicOrigin: SERVER_ORIGIN },
    );
    const gateway = gatewayFor(created.granteeAddress, ["other.thing"]);
    const accessLogSink = {
      async write() {},
      async read() {
        return { logs: [], total: 0, limit: 50, offset: 0 };
      },
    };
    const gatewayPorts = {
      authSessionVerifier: gateway,
      grantVerifier: gateway,
    };
    const memory = createMemoryPsLiteStorage();
    // Every legacy-storage operation is recorded: a switched or unknown
    // account must make none, not even a read that returns nothing.
    const legacyCalls: string[] = [];
    const legacy = new Proxy(memory, {
      get(target, prop, receiver) {
        const value = Reflect.get(target, prop, receiver);
        return typeof value === "function"
          ? (...args: unknown[]) => {
              legacyCalls.push(String(prop));
              return value.apply(target, args);
            }
          : value;
      },
    });
    const runtime = createPsLiteRuntime({
      accountModeAuthority: authority,
      active: true,
      storage: legacy,
      config: { gateway: gatewayConfig },
      gateway,
      serverSigner: {
        signGrantRegistration: vi
          .fn()
          .mockResolvedValue("0xgrantsig" as `0x${string}`),
      },
      accessLogReader: accessLogSink,
      accessLogWriter: accessLogSink,
      tokenStore: createMemoryPsLiteTokenStore(),
      saveConfig: async () => {},
      stateCapabilities: { config: "memory" },
      serverOwner: owner.address,
      mcpConnectionStore: store,
      mcpExposeUnsharedScopes: true,
      streamSyncRead: await streamView(),
      auth: createWeb3SignedPsLiteAuth({
        origin: SERVER_ORIGIN,
        ownerAddress: owner.address,
        dataReadPolicyPorts: gatewayPorts,
      }),
    });
    await approveMcpConnection(
      {
        connectionId: created.connectionId,
        grants: [{ grantId: "grant-mcp-1", scopes: ["other.thing"] }],
      },
      { store },
    );
    const listGranted = async () => {
      const res = await runtime.fetch(
        new Request(
          `${SERVER_ORIGIN}/mcp/${encodeURIComponent(created.connectionToken)}`,
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
        ),
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
    const ingestLegacy = async (scope: string) => {
      const res = await runtime.fetch(
        await ownerSigned("POST", `/v1/data/${scope}`, {
          records: [{ id: "legacy" }],
        }),
      );
      expect(res.ok, await res.clone().text()).toBe(true);
    };
    return { listGranted, authority, legacyCalls, ingestLegacy };
  }

  it("lists a live ungranted stream scope, not a stale legacy one, with no legacy storage call", async () => {
    const { listGranted, authority, legacyCalls, ingestLegacy } =
      await setup("off");
    await ingestLegacy("stale.legacy");
    await authority.submitEvidence({ owner: owner.address, state: "on" });
    legacyCalls.length = 0;
    const body = await listGranted();
    expect(body.notShared?.map((s) => s.scope)).toContain("instagram.posts");
    expect(body.notShared?.map((s) => s.scope)).not.toContain("stale.legacy");
    expect(body.notShared?.every((s) => s.dataStatus === "ready")).toBe(true);
    expect(body.notSharedUnavailable).toBeUndefined();
    expect(legacyCalls).toEqual([]);
  });

  it("an unknown account mode reports discovery unavailable, not empty, with no legacy storage call", async () => {
    const { listGranted, legacyCalls } = await setup("unknown");
    const body = await listGranted();
    expect(body.notShared).toBeUndefined();
    expect(body.notSharedUnavailable).toBe(true);
    expect(legacyCalls).toEqual([]);
  });
});
