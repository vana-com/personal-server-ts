import { describe, expect, it, vi } from "vitest";
import {
  createBearerTokenPsLiteAuth,
  createPsLiteRuntime,
  createWeb3SignedPsLiteAuth,
} from "./runtime.js";
import {
  createMemoryPsLiteAccessLogStore,
  createMemoryPsLiteStorage,
  createMemoryPsLiteTokenStore,
} from "./test-support/memory.js";
import { createMockPsLiteGateway } from "./test-support/gateway.js";
import {
  buildWeb3SignedHeader,
  createTestWallet,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import {
  createDataFileEnvelope,
  RECORD_DATA_ACCESS_TYPES,
} from "@opendatalabs/vana-sdk/browser";
import { privateKeyToAccount } from "viem/accounts";

type PsLiteRuntimeOptions = Parameters<typeof createPsLiteRuntime>[0];

function createTestRuntime(options: Partial<PsLiteRuntimeOptions> = {}) {
  const accessLogStore = createMemoryPsLiteAccessLogStore();
  const defaults: PsLiteRuntimeOptions = {
    storage: createMemoryPsLiteStorage(),
    gateway: createMockPsLiteGateway(),
    accessLogReader: accessLogStore,
    accessLogWriter: accessLogStore,
    tokenStore: createMemoryPsLiteTokenStore(),
    saveConfig: async () => {},
    stateCapabilities: { config: "memory" },
  };
  return createPsLiteRuntime({
    ...defaults,
    ...options,
    storage: options.storage ?? defaults.storage,
    gateway: "gateway" in options ? options.gateway : defaults.gateway,
    accessLogReader: options.accessLogReader ?? defaults.accessLogReader,
    accessLogWriter: options.accessLogWriter ?? defaults.accessLogWriter,
    tokenStore: options.tokenStore ?? defaults.tokenStore,
    saveConfig: options.saveConfig ?? defaults.saveConfig,
    stateCapabilities: {
      ...defaults.stateCapabilities,
      ...options.stateCapabilities,
    },
  });
}

describe("createPsLiteRuntime", () => {
  it("rejects storage adapters instead of falling back to memory", () => {
    expect(() =>
      createPsLiteRuntime({ storage: { kind: "indexeddb" } }),
    ).toThrow(
      "PS Lite runtime requires a persistent DataStoragePort. Use createIndexedDbPsLiteRuntime() or createPersistentPsLiteStorage().",
    );
  });

  it("requires explicit stores instead of memory fallbacks without IndexedDB", () => {
    const accessLogStore = createMemoryPsLiteAccessLogStore();

    expect(() =>
      createPsLiteRuntime({ storage: createMemoryPsLiteStorage() }),
    ).toThrow(
      "IndexedDB is required for default PS Lite access log persistence.",
    );

    expect(() =>
      createPsLiteRuntime({
        storage: createMemoryPsLiteStorage(),
        accessLogReader: accessLogStore,
        accessLogWriter: accessLogStore,
      }),
    ).toThrow("IndexedDB is required for default PS Lite token storage.");

    expect(() =>
      createPsLiteRuntime({
        storage: createMemoryPsLiteStorage(),
        accessLogReader: accessLogStore,
        accessLogWriter: accessLogStore,
        tokenStore: createMemoryPsLiteTokenStore(),
      }),
    ).toThrow("IndexedDB is required for default PS Lite config persistence.");
  });

  it("reports ps-lite availability through health", async () => {
    const runtime = createTestRuntime({
      active: true,
      now: () => new Date("2026-05-08T00:00:00.000Z"),
    });

    const res = await runtime.fetch(new Request("https://ps.local/health"));

    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toEqual({
      status: "healthy",
      runtime: "ps-lite",
      storage: "browser-indexeddb-opfs",
      capabilities: {
        metadata: "memory",
        files: "memory",
        opfsAvailable: false,
      },
      stateCapabilities: {
        tokens: "memory",
        accessLogs: "memory",
        config: "memory",
      },
      owner: null,
      apiOrigin: "https://ps.local",
      gatewayUrl: null,
      gatewayConfig: null,
      identity: null,
      registration: null,
      active: true,
      checkedAt: "2026-05-08T00:00:00.000Z",
    });
  });

  it("reports the request origin as the browser API origin", async () => {
    const runtime = createTestRuntime({
      active: true,
      config: { server: { origin: "https://configured.local" } },
    });

    const res = await runtime.fetch(new Request("https://relay.local/health"));

    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toMatchObject({
      apiOrigin: "https://relay.local",
    });
  });

  it("starts and stops the sync manager with runtime activation", () => {
    const syncManager = {
      start: vi.fn(),
      stop: vi.fn().mockResolvedValue(undefined),
      trigger: vi.fn().mockResolvedValue(undefined),
      getStatus: vi.fn(),
    };
    const runtime = createTestRuntime({
      active: false,
      syncManager,
    });

    runtime.activate();
    runtime.deactivate();

    expect(syncManager.start).toHaveBeenCalledTimes(1);
    expect(syncManager.stop).toHaveBeenCalledTimes(1);
  });

  it("returns PS_UNAVAILABLE while the browser runtime is inactive", async () => {
    const runtime = createTestRuntime({
      active: false,
    });

    const res = await runtime.fetch(
      new Request("https://ps.local/v1/data/instagram.profile"),
    );

    expect(res.status).toBe(503);
    const body = await res.json();
    expect(body.error.errorCode).toBe("PS_UNAVAILABLE");
  });

  it("does not allow unauthenticated writes while active", async () => {
    const runtime = createTestRuntime({
      storage: createMemoryPsLiteStorage(),
      auth: createBearerTokenPsLiteAuth({
        ownerToken: "owner-token",
        builderToken: "builder-token",
      }),
      active: true,
    });

    const res = await runtime.fetch(
      new Request("https://ps.local/v1/data/instagram.profile", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "test_user" }),
      }),
    );

    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body.error.errorCode).toBe("MISSING_AUTH");
  });

  it("ingests successfully even without a gateway schema resolver", async () => {
    // Schema is best-effort in the canary flow. When the runtime is wired
    // without a gateway (no resolver), ingestion proceeds with schemaId
    // unset rather than failing closed. Sync-worker registerFile (if
    // enabled) would surface its own error there.
    const storage = createMemoryPsLiteStorage();
    const runtime = createTestRuntime({
      storage,
      gateway: undefined,
      auth: createBearerTokenPsLiteAuth({
        ownerToken: "owner-token",
        builderToken: "builder-token",
      }),
      active: true,
    });

    const res = await runtime.fetch(
      new Request("https://ps.local/v1/data/instagram.profile", {
        method: "POST",
        headers: {
          Authorization: "Bearer owner-token",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ username: "test_user" }),
      }),
    );

    expect(res.status).toBe(201);
    expect(storage.listScopes({ limit: 20, offset: 0 }).total).toBe(1);
  });

  it("accepts owner writes even when no schema is registered for the scope", async () => {
    // Schema is optional in the canary flow — registerDataPoint (DPv2)
    // doesn't take schemaId, and X402 reads don't consult it. The ingest
    // path proceeds with schemaId=undefined; only the sync worker's
    // legacy registerFile call would later need one (and surface its own
    // error there).
    const storage = createMemoryPsLiteStorage();
    const runtime = createTestRuntime({
      storage,
      gateway: {
        ...createMockPsLiteGateway(),
        async getSchemaForScope() {
          return null;
        },
      },
      auth: createBearerTokenPsLiteAuth({
        ownerToken: "owner-token",
        builderToken: "builder-token",
      }),
      active: true,
    });

    const res = await runtime.fetch(
      new Request("https://ps.local/v1/data/instagram.profile", {
        method: "POST",
        headers: {
          Authorization: "Bearer owner-token",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ username: "test_user" }),
      }),
    );

    expect(res.status).toBe(201);
    expect(storage.listScopes({ limit: 20, offset: 0 }).total).toBe(1);
  });

  it("ingests binary uploads schemaless on DPv2 (no no-schema registration)", async () => {
    // DPv2 data points are scope-addressed and carry no schemaId, so binary
    // uploads to a novel scope must NOT register a "no schema" — the upload
    // worker no longer needs one.
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ data: { schemaId: "0xnoschema" } }), {
        headers: { "Content-Type": "application/json" },
        status: 200,
      }),
    );

    try {
      const runtime = createTestRuntime({
        active: true,
        auth: createBearerTokenPsLiteAuth({
          builderToken: "builder-token",
          ownerToken: "owner-token",
        }),
        config: { gateway: { url: "https://gw.test" } },
        gateway: {
          ...createMockPsLiteGateway(),
          async getSchemaForScope() {
            return null;
          },
        },
        serverSigner: {
          address: "0x1111111111111111111111111111111111111111",
          signGrantRegistration: vi.fn(),
        },
        storage: createMemoryPsLiteStorage(),
      });

      const res = await runtime.fetch(
        new Request("https://ps.local/v1/data/dexa.scan", {
          body: new Uint8Array([1, 2, 3]),
          headers: {
            Authorization: "Bearer owner-token",
            "Content-Type": "application/octet-stream",
            "X-Filename": "scan.bin",
          },
          method: "POST",
        }),
      );

      expect(res.status).toBe(201);
      expect(fetchMock).not.toHaveBeenCalledWith(
        "https://gw.test/v1/schemas",
        expect.anything(),
      );
    } finally {
      fetchMock.mockRestore();
    }
  });

  it("stores and reads data through the ps-lite data contract", async () => {
    const runtime = createTestRuntime({
      storage: createMemoryPsLiteStorage(),
      auth: createBearerTokenPsLiteAuth({
        ownerToken: "owner-token",
        builderToken: "builder-token",
      }),
      active: true,
      now: () => new Date("2026-05-08T00:00:00.000Z"),
    });

    const write = await runtime.fetch(
      new Request("https://ps.local/v1/data/instagram.profile", {
        method: "POST",
        headers: {
          Authorization: "Bearer owner-token",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ username: "test_user" }),
      }),
    );
    expect(write.status).toBe(201);
    await expect(write.json()).resolves.toEqual({
      scope: "instagram.profile",
      collectedAt: "2026-05-08T00:00:00Z",
      status: "stored",
    });

    const read = await runtime.fetch(
      new Request(
        "https://ps.local/v1/data/instagram.profile?grantId=grant-1",
        {
          headers: { Authorization: "Bearer builder-token" },
        },
      ),
    );

    expect(read.status).toBe(200);
    await expect(read.json()).resolves.toMatchObject({
      version: "1.0",
      scope: "instagram.profile",
      collectedAt: "2026-05-08T00:00:00Z",
      data: { username: "test_user" },
    });
  });

  it("requires grantId for builder reads", async () => {
    const runtime = createTestRuntime({
      storage: createMemoryPsLiteStorage(),
      auth: createBearerTokenPsLiteAuth({
        ownerToken: "owner-token",
        builderToken: "builder-token",
      }),
      active: true,
    });

    const res = await runtime.fetch(
      new Request("https://ps.local/v1/data/instagram.profile", {
        headers: { Authorization: "Bearer builder-token" },
      }),
    );

    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.error.errorCode).toBe("GRANT_REQUIRED");
  });

  it("lists scopes and versions from browser-local storage", async () => {
    const runtime = createTestRuntime({
      storage: createMemoryPsLiteStorage(),
      auth: createBearerTokenPsLiteAuth({
        ownerToken: "owner-token",
        builderToken: "builder-token",
      }),
      active: true,
      now: () => new Date("2026-05-08T00:00:00.000Z"),
    });

    await runtime.fetch(
      new Request("https://ps.local/v1/data/instagram.profile", {
        method: "POST",
        headers: {
          Authorization: "Bearer owner-token",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ username: "test_user" }),
      }),
    );

    const scopes = await runtime.fetch(
      new Request("https://ps.local/v1/data", {
        headers: { Authorization: "Bearer builder-token" },
      }),
    );
    const ownerScopes = await runtime.fetch(
      new Request("https://ps.local/v1/data", {
        headers: { Authorization: "Bearer owner-token" },
      }),
    );
    const versions = await runtime.fetch(
      new Request("https://ps.local/v1/data/instagram.profile/versions", {
        headers: { Authorization: "Bearer builder-token" },
      }),
    );

    expect(scopes.status).toBe(200);
    await expect(scopes.json()).resolves.toMatchObject({
      scopes: [
        {
          scope: "instagram.profile",
          latestCollectedAt: "2026-05-08T00:00:00Z",
          versionCount: 1,
        },
      ],
      total: 1,
    });
    expect(ownerScopes.status).toBe(200);
    await expect(ownerScopes.json()).resolves.toMatchObject({
      scopes: [{ scope: "instagram.profile" }],
      total: 1,
    });

    expect(versions.status).toBe(200);
    await expect(versions.json()).resolves.toMatchObject({
      scope: "instagram.profile",
      versions: [{ collectedAt: "2026-05-08T00:00:00Z" }],
      total: 1,
    });
  });

  it("deletes a scope with owner auth", async () => {
    const runtime = createTestRuntime({
      storage: createMemoryPsLiteStorage(),
      auth: createBearerTokenPsLiteAuth({
        ownerToken: "owner-token",
        builderToken: "builder-token",
      }),
      active: true,
      now: () => new Date("2026-05-08T00:00:00.000Z"),
    });

    await runtime.fetch(
      new Request("https://ps.local/v1/data/instagram.profile", {
        method: "POST",
        headers: {
          Authorization: "Bearer owner-token",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ username: "test_user" }),
      }),
    );

    const deleted = await runtime.fetch(
      new Request("https://ps.local/v1/data/instagram.profile", {
        method: "DELETE",
        headers: { Authorization: "Bearer owner-token" },
      }),
    );
    expect(deleted.status).toBe(204);

    const read = await runtime.fetch(
      new Request(
        "https://ps.local/v1/data/instagram.profile?grantId=grant-1",
        {
          headers: { Authorization: "Bearer builder-token" },
        },
      ),
    );
    expect(read.status).toBe(404);
  });

  it("exposes grants, sync, access logs, and config routes through ps-lite", async () => {
    const runtime = createTestRuntime({
      storage: createMemoryPsLiteStorage(),
      auth: createBearerTokenPsLiteAuth({
        ownerToken: "owner-token",
        builderToken: "builder-token",
      }),
      active: true,
      config: {
        server: { origin: "https://ps.local" },
        gateway: { url: "https://gateway.local" },
      },
      serverOwner: "0x0000000000000000000000000000000000000001",
      gateway: {
        async listGrantsByUser() {
          return [];
        },
        async getBuilder() {
          return null;
        },
        async createGrant() {
          return { grantId: "grant-1" };
        },
        async isRegisteredBuilder() {
          return false;
        },
        async getGrant() {
          return null;
        },
        async getSchemaForScope() {
          return null;
        },
        async getServer() {
          return null;
        },
        async getFile() {
          return null;
        },
        async listFilesSince() {
          return { files: [], nextCursor: null };
        },
        async getSchema() {
          return null;
        },
        async registerServer() {
          return { alreadyRegistered: false };
        },
        async registerFile() {
          return { fileId: "file-1" };
        },
        async revokeGrant() {},
      },
    });

    const ownerHeaders = { Authorization: "Bearer owner-token" };
    const grants = await runtime.fetch(
      new Request("https://ps.local/v1/grants", { headers: ownerHeaders }),
    );
    const syncStatus = await runtime.fetch(
      new Request("https://ps.local/v1/sync/status", {
        headers: ownerHeaders,
      }),
    );
    const syncTrigger = await runtime.fetch(
      new Request("https://ps.local/v1/sync/trigger", {
        method: "POST",
        headers: ownerHeaders,
      }),
    );
    const accessLogs = await runtime.fetch(
      new Request("https://ps.local/v1/access-logs", {
        headers: ownerHeaders,
      }),
    );
    const config = await runtime.fetch(
      new Request("https://ps.local/ui/api/config", {
        headers: ownerHeaders,
      }),
    );

    expect(grants.status).toBe(200);
    await expect(grants.json()).resolves.toEqual({ grants: [] });
    expect(syncStatus.status).toBe(200);
    await expect(syncStatus.json()).resolves.toMatchObject({
      enabled: false,
      running: false,
    });
    expect(syncTrigger.status).toBe(200);
    await expect(syncTrigger.json()).resolves.toMatchObject({
      status: "disabled",
    });
    expect(accessLogs.status).toBe(200);
    await expect(accessLogs.json()).resolves.toMatchObject({
      logs: [],
      total: 0,
    });
    expect(config.status).toBe(200);
    await expect(config.json()).resolves.toMatchObject({
      server: { origin: "https://ps.local" },
    });
  });

  it("supports browser-local device auth and oauth token routes", async () => {
    const tokenStore = {
      tokens: new Set<string>(),
      async getTokens() {
        return Array.from(this.tokens);
      },
      async isValid(token: string) {
        return this.tokens.has(token);
      },
      async addToken(token: string) {
        this.tokens.add(token);
      },
      async removeToken(token: string) {
        this.tokens.delete(token);
      },
    };
    const runtime = createTestRuntime({
      storage: createMemoryPsLiteStorage(),
      auth: createBearerTokenPsLiteAuth({
        ownerToken: "owner-token",
        builderToken: "builder-token",
      }),
      active: true,
      serverOwner: "0x0000000000000000000000000000000000000001",
      accessToken: "control-plane-secret",
      tokenStore,
      now: () => new Date("2026-05-08T00:00:00.000Z"),
    });

    const init = await runtime.fetch(
      new Request("https://ps.local/auth/device", { method: "POST" }),
    );
    expect(init.status).toBe(200);
    const initBody = (await init.json()) as {
      login: string;
      poll: { token: string };
    };

    const firstPoll = await runtime.fetch(
      new Request(
        `https://ps.local/auth/device/poll?token=${initBody.poll.token}`,
      ),
    );
    expect(firstPoll.status).toBe(404);
    await expect(firstPoll.json()).resolves.toEqual({ status: "pending" });

    const approve = await runtime.fetch(
      new Request(initBody.login, {
        method: "POST",
        headers: { Authorization: "Bearer owner-token" },
      }),
    );
    expect(approve.status).toBe(200);
    await expect(approve.json()).resolves.toEqual({ status: "approved" });

    const redeem = await runtime.fetch(
      new Request("https://ps.local/oauth/token", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          grant_type: "urn:ietf:params:oauth:grant-type:device_code",
          device_code: initBody.poll.token,
        }),
      }),
    );
    expect(redeem.status).toBe(200);
    const redeemBody = (await redeem.json()) as { access_token: string };
    expect(redeemBody.access_token).toMatch(/^vana_ps_/);
    expect(await tokenStore.isValid(redeemBody.access_token)).toBe(true);

    const clientCredentials = await runtime.fetch(
      new Request("https://ps.local/oauth/token", {
        method: "POST",
        headers: {
          Authorization: `Basic ${btoa("control-plane:control-plane-secret")}`,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          grant_type: "client_credentials",
        }),
      }),
    );
    expect(clientCredentials.status).toBe(200);
    const clientCredentialsBody = (await clientCredentials.json()) as {
      access_token: string;
    };
    expect(clientCredentialsBody.access_token).toMatch(/^vana_ps_/);
    expect(await tokenStore.isValid(clientCredentialsBody.access_token)).toBe(
      true,
    );

    const provision = await runtime.fetch(
      new Request("https://ps.local/auth/device/token", {
        method: "POST",
        headers: {
          Authorization: "Bearer control-plane-secret",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ token: "vana_ps_control_plane" }),
      }),
    );
    expect(provision.status).toBe(201);
    expect(await tokenStore.isValid("vana_ps_control_plane")).toBe(true);

    const revoke = await runtime.fetch(
      new Request("https://ps.local/auth/device/token", {
        method: "DELETE",
        headers: { Authorization: "Bearer vana_ps_control_plane" },
      }),
    );
    expect(revoke.status).toBe(200);
    expect(await tokenStore.isValid("vana_ps_control_plane")).toBe(false);
  });

  it("supports Web3Signed owner writes and builder grant reads", async () => {
    const owner = createTestWallet(0);
    const builder = createTestWallet(1);
    const grantId = "grant-1";
    const runtime = createTestRuntime({
      storage: createMemoryPsLiteStorage(),
      auth: createWeb3SignedPsLiteAuth({
        origin: "https://ps.local",
        ownerAddress: owner.address,
        dataReadPolicyPorts: {
          authSessionVerifier: {
            async getBuilder(address) {
              return address.toLowerCase() === builder.address.toLowerCase()
                ? {
                    id: "builder-1",
                    ownerAddress: builder.address,
                    granteeAddress: builder.address,
                    publicKey: "0x04",
                    appUrl: "https://builder.local",
                    addedAt: "2026-05-08T00:00:00.000Z",
                  }
                : null;
            },
          },
          grantVerifier: {
            async getGrant(id) {
              return id === grantId
                ? {
                    id: grantId,
                    grantorAddress: owner.address,
                    granteeId: "builder-1",
                    scopes: ["instagram.*"],
                    status: "confirmed",
                    addedAt: "2026-05-08T00:00:00.000Z",
                    expiresAt: String(Math.floor(Date.now() / 1000) + 3600),
                    expired: false,
                    revokedAt: null,
                    revocationSignature: null,
                    paymentStatus: "paid",
                    paidAt: "2026-05-08T00:00:05.000Z",
                    paidBy: owner.address,
                    grantVersion: "1",
                    settleTxHash: null,
                    settleSubmittedAt: null,
                    revocationTxHash: null,
                    revocationSubmittedAt: null,
                    fee: {
                      asset: "0x0000000000000000000000000000000000000000",
                      registrationFee: "0",
                      dataAccessFee: "0",
                      totalDue: "0",
                    },
                  }
                : null;
            },
          },
        },
      }),
      active: true,
      now: () => new Date("2026-05-08T00:00:00.000Z"),
    });

    const writeBody = JSON.stringify({ username: "web3_user" });
    const writeAuth = await buildWeb3SignedHeader({
      wallet: owner,
      aud: "https://ps.local",
      method: "POST",
      uri: "/v1/data/instagram.profile",
      body: new TextEncoder().encode(writeBody),
    });
    const write = await runtime.fetch(
      new Request("https://ps.local/v1/data/instagram.profile", {
        method: "POST",
        headers: {
          Authorization: writeAuth,
          "Content-Type": "application/json",
        },
        body: writeBody,
      }),
    );
    expect(write.status).toBe(201);

    const readAuth = await buildWeb3SignedHeader({
      wallet: builder,
      aud: "https://ps.local",
      method: "GET",
      uri: "/v1/data/instagram.profile",
      grantId,
    });
    const read = await runtime.fetch(
      new Request("https://ps.local/v1/data/instagram.profile", {
        headers: { Authorization: readAuth },
      }),
    );

    expect(read.status).toBe(200);
    await expect(read.json()).resolves.toMatchObject({
      data: { username: "web3_user" },
    });
  });

  it("returns SERVER_NOT_CONFIGURED when Web3Signed reads lack policy ports", async () => {
    const owner = createTestWallet(0);
    const builder = createTestWallet(1);
    const runtime = createTestRuntime({
      storage: createMemoryPsLiteStorage(),
      auth: createWeb3SignedPsLiteAuth({
        origin: "https://ps.local",
        ownerAddress: owner.address,
      }),
      active: true,
    });

    const readAuth = await buildWeb3SignedHeader({
      wallet: builder,
      aud: "https://ps.local",
      method: "GET",
      uri: "/v1/data/instagram.profile",
      grantId: "grant-1",
    });
    const res = await runtime.fetch(
      new Request("https://ps.local/v1/data/instagram.profile", {
        headers: { Authorization: readAuth },
      }),
    );

    expect(res.status).toBe(500);
    const body = await res.json();
    expect(body.error.errorCode).toBe("SERVER_NOT_CONFIGURED");
  });

  it("returns SERVER_NOT_CONFIGURED when Web3Signed list auth lacks policy ports", async () => {
    const owner = createTestWallet(0);
    const builder = createTestWallet(1);
    const runtime = createTestRuntime({
      storage: createMemoryPsLiteStorage(),
      auth: createWeb3SignedPsLiteAuth({
        origin: "https://ps.local",
        ownerAddress: owner.address,
      }),
      active: true,
    });

    const listAuth = await buildWeb3SignedHeader({
      wallet: builder,
      aud: "https://ps.local",
      method: "GET",
      uri: "/v1/data",
    });
    const res = await runtime.fetch(
      new Request("https://ps.local/v1/data", {
        headers: { Authorization: listAuth },
      }),
    );

    expect(res.status).toBe(500);
    const body = await res.json();
    expect(body.error.errorCode).toBe("SERVER_NOT_CONFIGURED");
  });

  it("accepts Lite persisted session tokens through Web3Signed owner auth", async () => {
    const owner = createTestWallet(0);
    const tokenStore = createMemoryPsLiteTokenStore();
    await tokenStore.addToken("vana_ps_session");
    const runtime = createTestRuntime({
      storage: createMemoryPsLiteStorage(),
      tokenStore,
      auth: createWeb3SignedPsLiteAuth({
        origin: "https://ps.local",
        ownerAddress: owner.address,
        tokenStore,
      }),
      active: true,
    });

    const res = await runtime.fetch(
      new Request("https://ps.local/v1/data/instagram.profile", {
        method: "POST",
        headers: {
          Authorization: "Bearer vana_ps_session",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ username: "session_user" }),
      }),
    );

    expect(res.status).toBe(201);
  });

  it("can be activated for foreground handling", async () => {
    const runtime = createTestRuntime({
      active: false,
    });

    expect(await runtime.isAvailable()).toBe(false);
    runtime.activate();
    expect(await runtime.isAvailable()).toBe(true);
  });

  it("x402: unpaid read 402 embeds the server-signed accessRecord when the entry has a dataPointId", async () => {
    const ORIGIN = "https://ps.local";
    const COLLECTED_AT = "2026-05-08T00:00:00.000Z";
    const owner = createTestWallet(0);
    const builder = createTestWallet(1);
    const serverAccount = privateKeyToAccount(
      ("0x" + "33".repeat(32)) as `0x${string}`,
    );
    const BUILDER_ID = ("0x" + "bb".repeat(32)) as `0x${string}`;
    const GRANT_ID = ("0x" + "11".repeat(32)) as `0x${string}`;
    const DATA_POINT_ID = ("0x" + "dd".repeat(32)) as `0x${string}`;
    const chainId = 14800;
    const contracts = {
      dataRegistry: "0x0000000000000000000000000000000000000001",
      dataPortabilityPermissions: "0x0000000000000000000000000000000000000002",
      dataPortabilityServer: "0x0000000000000000000000000000000000000003",
      dataPortabilityGrantees: "0x0000000000000000000000000000000000000004",
      dataPortabilityEscrow: "0x0000000000000000000000000000000000000005",
      feeRegistry: "0x0000000000000000000000000000000000000006",
    };

    // Paid-eligible grant whose granteeId matches the builder (data-read policy
    // cross-check) and which carries a fee (x402 charges).
    const grant = {
      id: GRANT_ID,
      grantorAddress: owner.address,
      granteeId: BUILDER_ID,
      scopes: ["instagram.*"],
      status: "confirmed",
      addedAt: COLLECTED_AT,
      expiresAt: null,
      expired: false,
      revokedAt: null,
      revocationSignature: null,
      paymentStatus: "pending",
      paidAt: null,
      paidBy: null,
      grantVersion: "1",
      fee: {
        asset: "0x0000000000000000000000000000000000000000",
        registrationFee: "10000000000000000",
        dataAccessFee: "1000000000000000",
        totalDue: "11000000000000000",
      },
    };
    const gateway = {
      ...createMockPsLiteGateway(),
      async getGrant() {
        return grant;
      },
      async getBuilder() {
        return {
          id: BUILDER_ID,
          ownerAddress: owner.address,
          granteeAddress: builder.address,
          publicKey: "0x04",
          appUrl: "https://app.test",
          addedAt: COLLECTED_AT,
        };
      },
      async isRegisteredBuilder() {
        return true;
      },
    } as unknown as Parameters<typeof createTestRuntime>[0]["gateway"];

    // Seed a synced entry (dataPointId set) so buildChallenge binds an
    // accessRecord to it.
    const storage = createMemoryPsLiteStorage();
    const envelope = createDataFileEnvelope("instagram.profile", COLLECTED_AT, {
      username: "x",
    });
    const write = await storage.writeEnvelope(envelope);
    await storage.insertEntry({
      fileId: null,
      schemaId: null,
      path: write.relativePath,
      scope: "instagram.profile",
      collectedAt: COLLECTED_AT,
      sizeBytes: write.sizeBytes,
      version: 1,
      dataPointId: DATA_POINT_ID,
    });

    const runtime = createTestRuntime({
      storage,
      gateway,
      active: true,
      serverOwner: owner.address,
      identity: { address: serverAccount.address, publicKey: "0x04" },
      config: {
        server: { origin: ORIGIN },
        gateway: { url: "https://gateway.test", chainId, contracts },
        payment: { enabled: true },
      },
      serverSigner: {
        async signGrantRegistration() {
          return ("0x" + "aa".repeat(65)) as `0x${string}`;
        },
        async signRecordDataAccess(msg) {
          return serverAccount.signTypedData({
            domain: {
              name: "Vana Data Portability",
              version: "1",
              chainId,
              verifyingContract: contracts.dataRegistry as `0x${string}`,
            },
            types: RECORD_DATA_ACCESS_TYPES,
            primaryType: "RecordDataAccess",
            message: msg,
          });
        },
      },
      auth: createWeb3SignedPsLiteAuth({
        origin: () => ORIGIN,
        ownerAddress: owner.address,
        dataReadPolicyPorts: {
          authSessionVerifier: gateway,
          grantVerifier: gateway,
        },
      }),
    });

    const authHeader = await buildWeb3SignedHeader({
      wallet: builder,
      aud: ORIGIN,
      method: "GET",
      uri: "/v1/data/instagram.profile",
      grantId: GRANT_ID,
    });
    const res = await runtime.fetch(
      new Request("https://ignored.example/v1/data/instagram.profile", {
        headers: { Authorization: authHeader },
      }),
    );

    expect(res.status).toBe(402);
    const body = await res.json();
    expect(body.error).toBe("PAYMENT_REQUIRED");
    expect(body.accepts).toHaveLength(1);
    const accessRecord = body.accepts[0].accessRecord;
    expect(accessRecord).toBeDefined();
    expect(accessRecord.dataPointId).toBe(DATA_POINT_ID);
    expect(accessRecord.accessor.toLowerCase()).toBe(
      builder.address.toLowerCase(),
    );
  });
});
