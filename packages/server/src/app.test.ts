import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { createApp } from "./app.js";
import { MissingAuthError } from "@opendatalabs/personal-server-ts-core/errors";
import {
  initializeDatabase,
  createIndexManager,
  type IndexManager,
} from "@opendatalabs/personal-server-ts-core/storage/index";
import type { GatewayClient } from "@opendatalabs/personal-server-ts-core/gateway";
import type { AccessLogWriter } from "@opendatalabs/personal-server-ts-core/logging/access-log";
import type { AccessLogReader } from "@opendatalabs/personal-server-ts-core/logging/access-reader";
import {
  createTestWallet,
  buildWeb3SignedHeader,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import type { SyncManager } from "@opendatalabs/personal-server-ts-core/sync";
import pino from "pino";
import type { TokenStore } from "./token-store.js";

const SERVER_ORIGIN = "http://localhost:8080";
const ownerWallet = createTestWallet(0);
const nonOwnerWallet = createTestWallet(1);
const CONTROL_PLANE_TOKEN = "vana_ps_control_plane";

function createMockSyncManager(): SyncManager {
  return {
    start: vi.fn(),
    stop: vi.fn().mockResolvedValue(undefined),
    trigger: vi.fn().mockResolvedValue(undefined),
    getStatus: vi.fn().mockReturnValue({
      enabled: true,
      running: true,
      lastSync: null,
      lastProcessedTimestamp: null,
      pendingFiles: 0,
      errors: [],
    }),
    notifyNewData: vi.fn(),
    running: true,
  };
}

function createMockGateway(): GatewayClient {
  return {
    isRegisteredBuilder: vi.fn().mockResolvedValue(true),
    getBuilder: vi.fn().mockResolvedValue(null),
    getGrant: vi.fn().mockResolvedValue(null),
    listGrantsByUser: vi.fn().mockResolvedValue([]),
    getSchemaForScope: vi.fn().mockResolvedValue({
      id: "0xschema1",
      ownerAddress: "0xOwner",
      name: "test.scope",
      definitionUrl: "https://ipfs.io/ipfs/QmTestSchema",
      scope: "test.scope",
      addedAt: "2026-01-21T10:00:00.000Z",
    }),
    getServer: vi.fn().mockResolvedValue(null),
  };
}

function createMockAccessLogWriter(): AccessLogWriter {
  return {
    write: vi.fn().mockResolvedValue(undefined),
  };
}

function createMockAccessLogReader(): AccessLogReader {
  return {
    read: vi.fn().mockResolvedValue({
      logs: [],
      total: 0,
      limit: 50,
      offset: 0,
    }),
  };
}

function createMockTokenStore(tokens: string[] = []): TokenStore {
  const storedTokens = new Set(tokens);
  return {
    getTokens: vi.fn(async () => Array.from(storedTokens)),
    isValid: vi.fn(async (token: string) => storedTokens.has(token)),
    addToken: vi.fn(async (token: string) => {
      storedTokens.add(token);
    }),
    removeToken: vi.fn(async (token: string) => {
      storedTokens.delete(token);
    }),
  };
}

describe("createApp", () => {
  let tempDir: string;
  let indexManager: IndexManager;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "app-test-"));
    const db = initializeDatabase(":memory:");
    indexManager = createIndexManager(db);
  });

  afterEach(async () => {
    indexManager.close();
    await rm(tempDir, { recursive: true, force: true });
  });

  function makeApp() {
    const logger = pino({ level: "silent" });
    return createApp({
      logger,
      version: "0.0.1",
      startedAt: new Date(),
      indexManager,
      hierarchyOptions: { dataDir: join(tempDir, "data") },
      serverOrigin: SERVER_ORIGIN,
      serverOwner: ownerWallet.address,
      gateway: createMockGateway(),
      accessLogWriter: createMockAccessLogWriter(),
      accessLogReader: createMockAccessLogReader(),
    });
  }

  function makeAppWithControlPlaneToken() {
    const logger = pino({ level: "silent" });
    return createApp({
      logger,
      version: "0.0.1",
      startedAt: new Date(),
      indexManager,
      hierarchyOptions: { dataDir: join(tempDir, "data") },
      serverOrigin: SERVER_ORIGIN,
      serverOwner: ownerWallet.address,
      gateway: createMockGateway(),
      accessLogWriter: createMockAccessLogWriter(),
      accessLogReader: createMockAccessLogReader(),
      accessToken: CONTROL_PLANE_TOKEN,
    });
  }

  function makeAppWithTokenStore(
    tokenStore: TokenStore = createMockTokenStore(),
    options?: { cloudMode?: boolean; accessToken?: string },
  ) {
    const logger = pino({ level: "silent" });
    return createApp({
      logger,
      version: "0.0.1",
      startedAt: new Date(),
      indexManager,
      hierarchyOptions: { dataDir: join(tempDir, "data") },
      serverOrigin: SERVER_ORIGIN,
      serverOwner: ownerWallet.address,
      gateway: createMockGateway(),
      accessLogWriter: createMockAccessLogWriter(),
      accessLogReader: createMockAccessLogReader(),
      cloudMode: options?.cloudMode,
      accessToken: options?.accessToken,
      tokenStore,
    });
  }

  it("GET /health returns 200", async () => {
    const app = makeApp();
    const res = await app.request("/health");
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.status).toBe("healthy");
  });

  it("ProtocolError returns correct status and JSON body", async () => {
    const app = makeApp();

    app.get("/test-protocol-error", () => {
      throw new MissingAuthError({ reason: "no token" });
    });

    const res = await app.request("/test-protocol-error");
    expect(res.status).toBe(401);

    const body = await res.json();
    expect(body.error.code).toBe(401);
    expect(body.error.errorCode).toBe("MISSING_AUTH");
    expect(body.error.message).toBe("Missing authentication");
    expect(body.error.details).toEqual({ reason: "no token" });
  });

  it("unknown error returns 500 INTERNAL_ERROR", async () => {
    const app = makeApp();

    app.get("/test-unknown-error", () => {
      throw new Error("something broke");
    });

    const res = await app.request("/test-unknown-error");
    expect(res.status).toBe(500);

    const body = await res.json();
    expect(body.error.code).toBe(500);
    expect(body.error.errorCode).toBe("INTERNAL_ERROR");
    expect(body.error.message).toBe("Internal server error");
  });

  it("unknown route returns 404", async () => {
    const app = makeApp();
    const res = await app.request("/nonexistent");
    expect(res.status).toBe(404);

    const body = await res.json();
    expect(body.error.code).toBe(404);
    expect(body.error.errorCode).toBe("NOT_FOUND");
  });

  // --- Phase 3: Auth integration tests for owner-only routes ---

  it("DELETE /v1/data/:scope without auth → 401 MISSING_AUTH", async () => {
    const app = makeApp();
    const res = await app.request("/v1/data/test.scope", { method: "DELETE" });
    expect(res.status).toBe(401);

    const body = await res.json();
    expect(body.error.errorCode).toBe("MISSING_AUTH");
  });

  it("DELETE /v1/data/:scope with non-owner auth → 401 NOT_OWNER", async () => {
    const app = makeApp();
    const auth = await buildWeb3SignedHeader({
      wallet: nonOwnerWallet,
      aud: SERVER_ORIGIN,
      method: "DELETE",
      uri: "/v1/data/test.scope",
    });
    const res = await app.request("/v1/data/test.scope", {
      method: "DELETE",
      headers: { authorization: auth },
    });
    expect(res.status).toBe(401);

    const body = await res.json();
    expect(body.error.errorCode).toBe("NOT_OWNER");
  });

  it("DELETE /v1/data/:scope with owner auth → 204", async () => {
    const app = makeApp();
    const auth = await buildWeb3SignedHeader({
      wallet: ownerWallet,
      aud: SERVER_ORIGIN,
      method: "DELETE",
      uri: "/v1/data/test.scope",
    });
    const res = await app.request("/v1/data/test.scope", {
      method: "DELETE",
      headers: { authorization: auth },
    });
    expect(res.status).toBe(204);
  });

  it("GET /v1/grants without auth → 401", async () => {
    const app = makeApp();
    const res = await app.request("/v1/grants");
    expect(res.status).toBe(401);

    const body = await res.json();
    expect(body.error.errorCode).toBe("MISSING_AUTH");
  });

  it("GET /v1/access-logs without auth → 401", async () => {
    const app = makeApp();
    const res = await app.request("/v1/access-logs");
    expect(res.status).toBe(401);

    const body = await res.json();
    expect(body.error.errorCode).toBe("MISSING_AUTH");
  });

  it("POST /v1/sync/trigger without auth → 401", async () => {
    const app = makeApp();
    const res = await app.request("/v1/sync/trigger", { method: "POST" });
    expect(res.status).toBe(401);

    const body = await res.json();
    expect(body.error.errorCode).toBe("MISSING_AUTH");
  });

  it("control-plane token cannot read owner grants routes", async () => {
    const app = makeAppWithControlPlaneToken();
    const res = await app.request("/v1/grants", {
      headers: { authorization: `Bearer ${CONTROL_PLANE_TOKEN}` },
    });

    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body.error.errorCode).toBe("INVALID_SIGNATURE");
  });

  it("control-plane token cannot write owner data routes", async () => {
    const app = makeAppWithControlPlaneToken();
    const res = await app.request("/v1/data/test.scope", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        authorization: `Bearer ${CONTROL_PLANE_TOKEN}`,
      },
      body: JSON.stringify({ data: "value" }),
    });

    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body.error.errorCode).toBe("INVALID_SIGNATURE");
  });

  it("control-plane token cannot trigger sync routes", async () => {
    const app = makeAppWithControlPlaneToken();
    const res = await app.request("/v1/sync/trigger", {
      method: "POST",
      headers: { authorization: `Bearer ${CONTROL_PLANE_TOKEN}` },
    });

    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body.error.errorCode).toBe("INVALID_SIGNATURE");
  });

  it("POST /v1/grants/verify without auth → 400 (public endpoint, no auth wall)", async () => {
    const app = makeApp();
    const res = await app.request("/v1/grants/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    // 400 means it reached the handler (no auth wall) — body validation fails
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toBe("INVALID_BODY");
  });

  it("POST /auth/device returns approval URLs on the request origin", async () => {
    const app = makeAppWithTokenStore();
    const res = await app.request(
      new Request("https://ps.alice.com/auth/device", { method: "POST" }),
    );

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.login).toMatch(
      /^https:\/\/ps\.alice\.com\/auth\/device\/approve\?session=.+$/,
    );
    expect(body.poll.endpoint).toBe("/auth/device/poll");
  });

  it("remote owner-signed /auth/device/approve succeeds on the mounted app path", async () => {
    const app = makeAppWithTokenStore();

    const initRes = await app.request(
      new Request("https://ps.alice.com/auth/device", { method: "POST" }),
    );
    const initBody = await initRes.json();
    const sessionId = new URL(initBody.login).searchParams.get("session")!;
    const auth = await buildWeb3SignedHeader({
      wallet: ownerWallet,
      aud: "https://ps.alice.com",
      method: "POST",
      uri: "/auth/device/approve",
    });

    const approveRes = await app.request(
      new Request(
        `https://ps.alice.com/auth/device/approve?session=${sessionId}`,
        {
          method: "POST",
          headers: { authorization: auth },
        },
      ),
    );

    expect(approveRes.status).toBe(200);
    expect(await approveRes.json()).toEqual({ status: "approved" });
  });

  it("cloud mode disables interactive /auth/device login flow", async () => {
    const app = makeAppWithTokenStore(createMockTokenStore(), {
      cloudMode: true,
      accessToken: CONTROL_PLANE_TOKEN,
    });

    const initRes = await app.request(
      new Request("https://0xabc.myvana.app/auth/device", { method: "POST" }),
    );

    expect(initRes.status).toBe(404);

    const approveRes = await app.request(
      new Request("https://0xabc.myvana.app/auth/device/approve?session=test", {
        method: "POST",
      }),
    );

    expect(approveRes.status).toBe(404);
  });

  it("cloud mode still allows control-plane token provisioning", async () => {
    const tokenStore = createMockTokenStore();
    const app = makeAppWithTokenStore(tokenStore, {
      cloudMode: true,
      accessToken: CONTROL_PLANE_TOKEN,
    });

    const res = await app.request("/auth/device/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        authorization: `Bearer ${CONTROL_PLANE_TOKEN}`,
      },
      body: JSON.stringify({ token: "vana_ps_cli_token" }),
    });

    expect(res.status).toBe(201);
    expect(await res.json()).toEqual({ status: "created" });
    expect(tokenStore.addToken).toHaveBeenCalledWith("vana_ps_cli_token", {
      expiresAt: null,
    });
  });

  // --- Phase 4: Sync manager wiring tests ---

  it("syncManager passed to sync routes — GET /v1/sync/status returns enabled status", async () => {
    const mockSyncManager = createMockSyncManager();
    const logger = pino({ level: "silent" });
    const app = createApp({
      logger,
      version: "0.0.1",
      startedAt: new Date(),
      indexManager,
      hierarchyOptions: { dataDir: join(tempDir, "data") },
      serverOrigin: SERVER_ORIGIN,
      serverOwner: ownerWallet.address,
      gateway: createMockGateway(),
      accessLogWriter: createMockAccessLogWriter(),
      accessLogReader: createMockAccessLogReader(),
      syncManager: mockSyncManager,
    });

    const auth = await buildWeb3SignedHeader({
      wallet: ownerWallet,
      aud: SERVER_ORIGIN,
      method: "GET",
      uri: "/v1/sync/status",
    });
    const res = await app.request("/v1/sync/status", {
      headers: { authorization: auth },
    });
    expect(res.status).toBe(200);

    const body = await res.json();
    expect(body.enabled).toBe(true);
    expect(body.running).toBe(true);
    expect(mockSyncManager.getStatus).toHaveBeenCalled();
  });

  it("syncManager passed to data routes — POST /v1/data/:scope calls notifyNewData", async () => {
    const mockSyncManager = createMockSyncManager();
    const logger = pino({ level: "silent" });
    const app = createApp({
      logger,
      version: "0.0.1",
      startedAt: new Date(),
      indexManager,
      hierarchyOptions: { dataDir: join(tempDir, "data") },
      serverOrigin: SERVER_ORIGIN,
      serverOwner: ownerWallet.address,
      gateway: createMockGateway(),
      accessLogWriter: createMockAccessLogWriter(),
      accessLogReader: createMockAccessLogReader(),
      syncManager: mockSyncManager,
    });

    const auth = await buildWeb3SignedHeader({
      wallet: ownerWallet,
      aud: SERVER_ORIGIN,
      method: "POST",
      uri: "/v1/data/test.scope",
    });
    const res = await app.request("/v1/data/test.scope", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        authorization: auth,
      },
      body: JSON.stringify({ data: "value" }),
    });
    expect(res.status).toBe(201);

    const body = await res.json();
    expect(body.status).toBe("syncing");
    expect(mockSyncManager.notifyNewData).toHaveBeenCalled();
  });

  it("without syncManager — GET /v1/sync/status returns disabled", async () => {
    const logger = pino({ level: "silent" });
    const app = createApp({
      logger,
      version: "0.0.1",
      startedAt: new Date(),
      indexManager,
      hierarchyOptions: { dataDir: join(tempDir, "data") },
      serverOrigin: SERVER_ORIGIN,
      serverOwner: ownerWallet.address,
      gateway: createMockGateway(),
      accessLogWriter: createMockAccessLogWriter(),
      accessLogReader: createMockAccessLogReader(),
      syncManager: null,
    });

    const auth = await buildWeb3SignedHeader({
      wallet: ownerWallet,
      aud: SERVER_ORIGIN,
      method: "GET",
      uri: "/v1/sync/status",
    });
    const res = await app.request("/v1/sync/status", {
      headers: { authorization: auth },
    });
    expect(res.status).toBe(200);

    const body = await res.json();
    expect(body.enabled).toBe(false);
  });

  it("without syncManager — POST /v1/data/:scope returns stored status", async () => {
    const app = makeApp(); // makeApp doesn't pass syncManager
    const auth = await buildWeb3SignedHeader({
      wallet: ownerWallet,
      aud: SERVER_ORIGIN,
      method: "POST",
      uri: "/v1/data/test.scope",
    });
    const res = await app.request("/v1/data/test.scope", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        authorization: auth,
      },
      body: JSON.stringify({ data: "value" }),
    });
    expect(res.status).toBe(201);

    const body = await res.json();
    expect(body.status).toBe("stored");
  });
});
