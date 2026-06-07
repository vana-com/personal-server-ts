import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { createApp } from "./app.js";
import { MissingAuthError } from "@opendatalabs/personal-server-ts-core/errors";
import { initializeDatabase } from "./storage/index-schema.js";
import {
  createIndexManager,
  type IndexManager,
} from "./storage/index-manager.js";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import type { AccessLogWriter } from "@opendatalabs/personal-server-ts-core/logging/access-log";
import type { AccessLogReader } from "@opendatalabs/personal-server-ts-core/logging/access-reader";
import {
  createTestWallet,
  buildWeb3SignedHeader,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import type { SyncManager } from "@opendatalabs/personal-server-ts-core/sync";
import type { ServerSigner } from "@opendatalabs/personal-server-ts-core/signing";
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
      syncing: false,
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
    registerServer: vi.fn().mockResolvedValue({ alreadyRegistered: false }),
    getFile: vi.fn().mockResolvedValue(null),
    listFilesSince: vi.fn().mockResolvedValue({ files: [], cursor: null }),
    getSchema: vi.fn().mockResolvedValue(null),
    registerFile: vi.fn().mockResolvedValue({}),
    createGrant: vi.fn().mockResolvedValue({}),
    revokeGrant: vi.fn().mockResolvedValue(undefined),
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
    options?: {
      cloudMode?: boolean;
      accessToken?: string;
      localApprovalOrigin?: string | (() => string | undefined);
    },
  ) {
    const logger = pino({ level: "silent" });
    return createApp({
      logger,
      version: "0.0.1",
      startedAt: new Date(),
      indexManager,
      hierarchyOptions: { dataDir: join(tempDir, "data") },
      serverOrigin: SERVER_ORIGIN,
      localApprovalOrigin: options?.localApprovalOrigin,
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

  it("control-plane token can read owner grants routes", async () => {
    const app = makeAppWithControlPlaneToken();
    const res = await app.request("/v1/grants", {
      headers: { authorization: `Bearer ${CONTROL_PLANE_TOKEN}` },
    });

    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toEqual({ grants: [] });
  });

  it("control-plane token can write owner data routes", async () => {
    const app = makeAppWithControlPlaneToken();
    const res = await app.request("/v1/data/test.scope", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        authorization: `Bearer ${CONTROL_PLANE_TOKEN}`,
      },
      body: JSON.stringify({ data: "value" }),
    });

    expect(res.status).toBe(201);
  });

  it("control-plane token can read owner data routes (owner-exempt read)", async () => {
    // The parent-host control-plane token is owner-identified and never
    // crosses an interactive surface, so it gets the same owner-exempt
    // read treatment as web3-signed owner requests. CLI session tokens
    // (issued via /auth/device) are intentionally NOT exempted — they
    // travel through terminals and copy-paste, so we keep them on the
    // grant path. See data.test.ts > "does not let CLI session tokens
    // bypass grant checks on raw reads".
    const app = makeAppWithControlPlaneToken();
    // Seed a file via the same control-plane-authenticated write path.
    const writeRes = await app.request("/v1/data/test.scope", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        authorization: `Bearer ${CONTROL_PLANE_TOKEN}`,
      },
      body: JSON.stringify({ data: "value" }),
    });
    expect(writeRes.status).toBe(201);

    const readRes = await app.request("/v1/data/test.scope", {
      headers: { authorization: `Bearer ${CONTROL_PLANE_TOKEN}` },
    });
    expect(readRes.status).toBe(200);
  });

  it("control-plane token can trigger sync routes", async () => {
    const app = makeAppWithControlPlaneToken();
    const res = await app.request("/v1/sync/trigger", {
      method: "POST",
      headers: { authorization: `Bearer ${CONTROL_PLANE_TOKEN}` },
    });

    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toEqual({
      status: "disabled",
      message: "Sync is not enabled",
    });
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

  it("POST /auth/device returns loopback approval URLs for localhost login initiation", async () => {
    const app = makeAppWithTokenStore(createMockTokenStore(), {
      localApprovalOrigin: "http://127.0.0.1:34127",
    });

    const res = await app.request(
      new Request("http://localhost:8080/auth/device", { method: "POST" }),
    );

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.login).toMatch(
      /^http:\/\/127\.0\.0\.1:34127\/auth\/device\/approve\?session=.+$/,
    );
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

  it("public localhost /auth/device/approve requires owner auth when a loopback auth channel is configured", async () => {
    const app = makeAppWithTokenStore(createMockTokenStore(), {
      localApprovalOrigin: "http://127.0.0.1:34127",
    });

    const initRes = await app.request(
      new Request("http://localhost:8080/auth/device", { method: "POST" }),
    );
    const initBody = await initRes.json();
    const sessionId = new URL(initBody.login).searchParams.get("session")!;

    const approveRes = await app.request(
      new Request(
        `http://localhost:8080/auth/device/approve?session=${sessionId}`,
        {
          method: "POST",
        },
      ),
    );

    expect(approveRes.status).toBe(403);
    expect((await approveRes.json()).error.message).toContain(
      "Remote approval requires owner wallet authentication",
    );
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

    const requestBody = JSON.stringify({ data: "value" });
    const auth = await buildWeb3SignedHeader({
      wallet: ownerWallet,
      aud: SERVER_ORIGIN,
      method: "POST",
      uri: "/v1/data/test.scope",
      body: new TextEncoder().encode(requestBody),
    });
    const res = await app.request("/v1/data/test.scope", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        authorization: auth,
      },
      body: requestBody,
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

  // --- Binary / unstructured data ingestion ---

  it("POST /v1/data/:scope with a binary body stores it and serves it back raw", async () => {
    const app = makeApp();
    const pdf = new Uint8Array([
      0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x34,
    ]); // %PDF-1.4
    const auth = await buildWeb3SignedHeader({
      wallet: ownerWallet,
      aud: SERVER_ORIGIN,
      method: "POST",
      uri: "/v1/data/documents.pdf",
      body: pdf,
    });
    const res = await app.request("/v1/data/documents.pdf", {
      method: "POST",
      headers: {
        "Content-Type": "application/pdf",
        "X-Filename": "report.pdf",
        "X-Vana-Metadata": "Quarterly earnings report",
        authorization: auth,
      },
      body: pdf,
    });
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.scope).toBe("documents.pdf");

    // Default GET returns the envelope (binary marker + base64 inside `data`).
    const readAuth = await buildWeb3SignedHeader({
      wallet: ownerWallet,
      aud: SERVER_ORIGIN,
      method: "GET",
      uri: "/v1/data/documents.pdf",
    });
    const envRes = await app.request("/v1/data/documents.pdf", {
      headers: { authorization: readAuth },
    });
    expect(envRes.status).toBe(200);
    const envelope = await envRes.json();
    expect(envelope.data.$binary).toBe(true);
    expect(envelope.data.metadata).toBe("Quarterly earnings report");

    // `?content=raw` returns the original bytes with the original media type.
    const rawAuth = await buildWeb3SignedHeader({
      wallet: ownerWallet,
      aud: SERVER_ORIGIN,
      method: "GET",
      uri: "/v1/data/documents.pdf",
    });
    const rawRes = await app.request("/v1/data/documents.pdf?content=raw", {
      headers: { authorization: rawAuth },
    });
    expect(rawRes.status).toBe(200);
    expect(rawRes.headers.get("content-type")).toBe("application/pdf");
    expect(rawRes.headers.get("content-disposition")).toContain("report.pdf");
    expect(rawRes.headers.get("x-vana-metadata")).toBe(
      "Quarterly earnings report",
    );
    const received = new Uint8Array(await rawRes.arrayBuffer());
    expect(Array.from(received)).toEqual(Array.from(pdf));
  });

  it("POST binary auto-registers a no-schema schema when the scope has none", async () => {
    const logger = pino({ level: "silent" });
    const gateway = createMockGateway();
    // No schema exists for this scope → triggers auto-registration.
    (gateway.getSchemaForScope as ReturnType<typeof vi.fn>).mockResolvedValue(
      null,
    );
    const signer: ServerSigner = {
      address: "0x2222222222222222222222222222222222222222",
      signFileRegistration: vi.fn(),
      signGrantRegistration: vi.fn(),
      signGrantRevocation: vi.fn(),
      signSchemaRegistration: vi.fn().mockResolvedValue("0xschemasig"),
    };
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ data: { schemaId: "0xnoschema" } }), {
        status: 200,
      }),
    );

    const app = createApp({
      logger,
      version: "0.0.1",
      startedAt: new Date(),
      indexManager,
      hierarchyOptions: { dataDir: join(tempDir, "data") },
      serverOrigin: SERVER_ORIGIN,
      serverOwner: ownerWallet.address,
      gateway,
      gatewayConfig: {
        url: "https://gw.example",
        chainId: 14800,
        contracts: {
          dataRegistry: "0x0",
          dataPortabilityPermissions: "0x0",
          dataPortabilityServer: "0x0",
          dataPortabilityGrantees: "0x0",
          dataPortabilityEscrow: "0x0",
          feeRegistry: "0x0",
        },
      },
      serverSigner: signer,
      accessLogWriter: createMockAccessLogWriter(),
      accessLogReader: createMockAccessLogReader(),
    });

    const blob = new Uint8Array([1, 2, 3, 4]);
    const auth = await buildWeb3SignedHeader({
      wallet: ownerWallet,
      aud: SERVER_ORIGIN,
      method: "POST",
      uri: "/v1/data/random.blob",
      body: blob,
    });
    const res = await app.request("/v1/data/random.blob", {
      method: "POST",
      headers: {
        "Content-Type": "application/octet-stream",
        authorization: auth,
      },
      body: blob,
    });

    expect(res.status).toBe(201);
    expect(signer.signSchemaRegistration).toHaveBeenCalledWith(
      expect.objectContaining({ scope: "random.blob" }),
    );
    expect(fetchMock).toHaveBeenCalledWith(
      "https://gw.example/v1/schemas",
      expect.objectContaining({ method: "POST" }),
    );

    vi.restoreAllMocks();
  });

  it("without syncManager — POST /v1/data/:scope returns stored status", async () => {
    const app = makeApp(); // makeApp doesn't pass syncManager
    const requestBody = JSON.stringify({ data: "value" });
    const auth = await buildWeb3SignedHeader({
      wallet: ownerWallet,
      aud: SERVER_ORIGIN,
      method: "POST",
      uri: "/v1/data/test.scope",
      body: new TextEncoder().encode(requestBody),
    });
    const res = await app.request("/v1/data/test.scope", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        authorization: auth,
      },
      body: requestBody,
    });
    expect(res.status).toBe(201);

    const body = await res.json();
    expect(body.status).toBe("stored");
  });
});
