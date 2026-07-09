import { describe, expect, it, vi } from "vitest";
import type { Builder, GatewayClient } from "@opendatalabs/vana-sdk/browser";
import {
  buildWeb3SignedHeader,
  createTestWallet,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import type { SyncManager } from "@opendatalabs/personal-server-ts-core/sync";
import {
  createMemoryPsLiteAccessLogStore,
  createMemoryPsLiteStateStore,
  createMemoryPsLiteStorage,
  createMemoryPsLiteTokenStore,
} from "./test-support/memory.js";
import { createPsLiteRuntime, createWeb3SignedPsLiteAuth } from "./runtime.js";
import { startPersonalServer } from "./client.js";

const ORIGIN = "https://ps-lite.local";
const ownerWallet = createTestWallet(4);

function createGateway(overrides: Partial<GatewayClient> = {}): GatewayClient {
  return {
    isRegisteredBuilder: vi.fn().mockResolvedValue(false),
    getBuilder: vi.fn().mockResolvedValue(null),
    getGrant: vi.fn().mockResolvedValue(null),
    listGrantsByUser: vi.fn().mockResolvedValue([]),
    getSchemaForScope: vi.fn().mockResolvedValue({
      id: "0xschema1",
      ownerAddress: ownerWallet.address,
      name: "instagram.profile",
      definitionUrl: "https://ipfs.io/ipfs/QmTestSchema",
      scope: "instagram.profile",
      addedAt: "2026-05-08T00:00:00.000Z",
    }),
    getServer: vi.fn().mockResolvedValue(null),
    getFile: vi.fn().mockResolvedValue(null),
    listFilesSince: vi.fn().mockResolvedValue({ files: [], cursor: null }),
    getSchema: vi.fn().mockResolvedValue(null),
    registerServer: vi.fn().mockResolvedValue({
      alreadyRegistered: false,
      serverId: "server-1",
    }),
    registerFile: vi.fn().mockResolvedValue({ fileId: "file-1" }),
    createGrant: vi.fn().mockResolvedValue({ grantId: "grant-1" }),
    revokeGrant: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  };
}

function createRuntime(gateway: GatewayClient) {
  const accessLogs = createMemoryPsLiteAccessLogStore();
  return createPsLiteRuntime({
    active: true,
    storage: createMemoryPsLiteStorage(),
    accessLogReader: accessLogs,
    accessLogWriter: accessLogs,
    tokenStore: createMemoryPsLiteTokenStore(),
    saveConfig: async () => {},
    stateCapabilities: { config: "memory" },
    gateway,
    config: {
      server: { origin: ORIGIN },
      gateway: {
        url: "https://gateway.example",
        chainId: 14800,
        contracts: {
          dataRegistry: "0x8C8788f98385F6ba1adD4234e551ABba0f82Cb7C",
          dataPortabilityPermissions:
            "0xD54523048AdD05b4d734aFaE7C68324Ebb7373eF",
          dataPortabilityServer: "0x1483B1F634DBA75AeaE60da7f01A679aabd5ee2c",
          dataPortabilityGrantees: "0x8325C0A0948483EdA023A1A2Fd895e62C5131234",
        },
      },
    },
    identity: {
      address: "0x2222222222222222222222222222222222222222",
      publicKey: "0x04public",
    },
    serverOwner: ownerWallet.address,
    serverSigner: {
      signFileRegistration: vi.fn().mockResolvedValue("0xfilesig"),
      signGrantRegistration: vi.fn().mockResolvedValue("0xgrantsig"),
      signGrantRevocation: vi.fn().mockResolvedValue("0xrevokesig"),
    },
    auth: createWeb3SignedPsLiteAuth({
      origin: () => ORIGIN,
      ownerAddress: ownerWallet.address,
    }),
  });
}

describe("startPersonalServer lite handle", () => {
  it("exposes info and registration through the unified handle", async () => {
    const gateway = createGateway();
    const ps = await startPersonalServer({
      runtime: createRuntime(gateway),
      relay: false,
      localOrigin: ORIGIN,
      gateway,
    });

    const info = await ps.ready();
    expect(info).toMatchObject({
      kind: "lite",
      status: "ready",
      ownerAddress: ownerWallet.address,
      urls: {
        local: ORIGIN,
        apiOrigin: ORIGIN,
        registration: ORIGIN,
      },
      server: {
        address: "0x2222222222222222222222222222222222222222",
        publicKey: "0x04public",
      },
    });

    const registration = await ps.prepareRegistration();
    expect(registration.candidate).toEqual({
      ownerAddress: ownerWallet.address,
      serverAddress: "0x2222222222222222222222222222222222222222",
      publicKey: "0x04public",
      serverUrl: ORIGIN,
    });

    await expect(
      ps.submitRegistration({ signature: "0xregistration" }),
    ).resolves.toEqual({ alreadyRegistered: false, serverId: "server-1" });
    expect(gateway.registerServer).toHaveBeenCalledWith({
      ...registration.candidate,
      signature: "0xregistration",
    });
  });

  it("submits the exact prepared registration request when a public server URL is provided", async () => {
    const gateway = createGateway();
    const ps = await startPersonalServer({
      runtime: createRuntime(gateway),
      relay: false,
      localOrigin: ORIGIN,
      gateway,
    });
    const registration = await ps.prepareRegistration({
      serverUrl: "https://lite-public.example",
    });

    await expect(
      ps.submitRegistration({
        request: registration,
        signature: "0xregistration",
      }),
    ).resolves.toEqual({ alreadyRegistered: false, serverId: "server-1" });
    expect(registration.candidate.serverUrl).toBe(
      "https://lite-public.example",
    );
    expect(registration.candidate.serverUrl).not.toBe(ORIGIN);
    expect(gateway.registerServer).toHaveBeenCalledWith({
      ...registration.candidate,
      signature: "0xregistration",
    });
  });

  it("submits the most recently prepared registration request when no request is passed", async () => {
    const gateway = createGateway();
    const ps = await startPersonalServer({
      runtime: createRuntime(gateway),
      relay: false,
      localOrigin: ORIGIN,
      gateway,
    });
    const registration = await ps.prepareRegistration({
      serverUrl: "https://lite-public.example",
    });

    await expect(
      ps.submitRegistration({ signature: "0xregistration" }),
    ).resolves.toEqual({ alreadyRegistered: false, serverId: "server-1" });
    expect(gateway.registerServer).toHaveBeenCalledWith({
      ...registration.candidate,
      signature: "0xregistration",
    });
  });

  it("posts data with owner Web3Signed auth", async () => {
    const gateway = createGateway();
    const ps = await startPersonalServer({
      runtime: createRuntime(gateway),
      relay: false,
      localOrigin: ORIGIN,
      gateway,
    });

    await expect(
      ps.postData(
        "instagram.profile",
        { username: "vana_debug" },
        { signMessage: ownerWallet.signMessage },
      ),
    ).resolves.toMatchObject({
      scope: "instagram.profile",
      status: "stored",
    });
  });

  it("exposes typed data and sync helpers through the public handle", async () => {
    const gateway = createGateway();
    const ps = await startPersonalServer({
      runtime: createRuntime(gateway),
      relay: false,
      localOrigin: ORIGIN,
      gateway,
    });
    const auth = { signMessage: ownerWallet.signMessage };

    await ps.postData("instagram.profile", { username: "vana_debug" }, auth);

    await expect(ps.listData({ auth, limit: 10 })).resolves.toMatchObject({
      scopes: [{ scope: "instagram.profile" }],
    });
    await expect(
      ps.listVersions("instagram.profile", { auth, limit: 1 }),
    ).resolves.toMatchObject({
      scope: "instagram.profile",
      versions: [{ fileId: null }],
    });
    await expect(
      ps.readData("instagram.profile", { auth }),
    ).resolves.toMatchObject({
      scope: "instagram.profile",
      data: { username: "vana_debug" },
    });
    await expect(ps.syncStatus({ auth })).resolves.toMatchObject({
      enabled: false,
      running: false,
    });
    await expect(ps.syncNow({ auth })).resolves.toMatchObject({
      status: "disabled",
    });
  });

  it("exposes listAccessLogs through the public handle with owner auth", async () => {
    const gateway = createGateway();
    const ps = await startPersonalServer({
      runtime: createRuntime(gateway),
      relay: false,
      localOrigin: ORIGIN,
      gateway,
    });
    const auth = { signMessage: ownerWallet.signMessage };

    // Empty by default: no builder has read anything in this fixture.
    await expect(ps.listAccessLogs({ auth })).resolves.toMatchObject({
      logs: [],
      total: 0,
      limit: 50,
      offset: 0,
    });

    // Honors pagination params on the wire.
    await expect(
      ps.listAccessLogs({ auth, limit: 5, offset: 0 }),
    ).resolves.toMatchObject({
      limit: 5,
      offset: 0,
    });
  });

  it("rejects listAccessLogs requests that lack owner auth", async () => {
    const gateway = createGateway();
    const ps = await startPersonalServer({
      runtime: createRuntime(gateway),
      relay: false,
      localOrigin: ORIGIN,
      gateway,
    });

    // No `auth` → no Web3Signed owner header → the contract rejects with
    // the standard owner-auth missing error rather than leaking logs.
    await expect(ps.listAccessLogs()).rejects.toThrow();
  });

  it("exposes grant helpers through the public handle", async () => {
    const builderAddress = createTestWallet(5).address;
    const grantId =
      "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    const gateway = createGateway({
      getBuilder: vi.fn().mockResolvedValue({
        id: `0x${"bb".repeat(32)}`,
        ownerAddress: "0xOwner",
        granteeAddress: builderAddress,
        publicKey: "0x04key",
        appUrl: "https://app.example.com",
        addedAt: "2026-01-21T10:00:00.000Z",
      } satisfies Builder),
      createGrant: vi.fn().mockResolvedValue({ grantId }),
      listGrantsByUser: vi.fn().mockResolvedValue([
        {
          id: grantId,
          grantorAddress: ownerWallet.address,
          granteeId: `0x${"bb".repeat(32)}`,
          scopes: ["instagram.*"],
          status: "confirmed",
          addedAt: "2026-01-21T10:00:00.000Z",
          expiresAt: null,
          expired: false,
          revokedAt: null,
          revocationSignature: null,
          paymentStatus: "paid",
          paidAt: "2026-01-21T10:00:05.000Z",
          paidBy: ownerWallet.address,
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
        },
      ]),
      // revokeGrantContract reads the live grantVersion before signing.
      getGrant: vi.fn().mockResolvedValue({
        id: grantId,
        grantorAddress: ownerWallet.address,
        granteeId: `0x${"bb".repeat(32)}`,
        scopes: ["instagram.*"],
        status: "confirmed",
        addedAt: "2026-01-21T10:00:00.000Z",
        expiresAt: null,
        expired: false,
        revokedAt: null,
        revocationSignature: null,
        paymentStatus: "paid",
        paidAt: "2026-01-21T10:00:05.000Z",
        paidBy: ownerWallet.address,
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
      }),
    });
    const ps = await startPersonalServer({
      runtime: createRuntime(gateway),
      relay: false,
      localOrigin: ORIGIN,
      gateway,
    });
    const auth = { signMessage: ownerWallet.signMessage };

    await expect(
      ps.createGrant({
        auth,
        granteeAddress: builderAddress,
        scopes: ["instagram.*"],
      }),
    ).resolves.toEqual({ grantId });
    await expect(ps.listGrants({ auth })).resolves.toMatchObject({
      grants: [{ id: grantId }],
    });
    await expect(ps.revokeGrant(grantId, { auth })).resolves.toEqual({
      status: "revoked",
      grantId,
    });
    expect(gateway.revokeGrant).toHaveBeenCalledWith(
      expect.objectContaining({
        grantorAddress: ownerWallet.address,
        grantId,
      }),
    );
  });

  it("preserves Request method and body when fetch applies init overrides", async () => {
    const gateway = createGateway();
    const ps = await startPersonalServer({
      runtime: createRuntime(gateway),
      relay: false,
      localOrigin: ORIGIN,
      gateway,
    });
    const body = new TextEncoder().encode(
      JSON.stringify({ username: "vana_debug" }),
    );
    const auth = await buildWeb3SignedHeader({
      wallet: ownerWallet,
      aud: ORIGIN,
      method: "POST",
      uri: "/v1/data/instagram.profile",
      body,
    });

    const res = await ps.fetch(
      new Request("https://ignored.example/v1/data/instagram.profile", {
        method: "POST",
        body,
      }),
      {
        headers: {
          Authorization: auth,
          "Content-Type": "application/json",
        },
      },
    );

    expect(res.status).toBe(201);
    await expect(res.json()).resolves.toMatchObject({
      scope: "instagram.profile",
    });
  });

  it("preserves the Request body when the engine lacks the Request.prototype.body getter (Firefox)", async () => {
    // Firefox does not implement the `Request.prototype.body` getter (no
    // fetch upload streaming), so `new Request(url, request)` - which reads
    // the body off the init bag via that getter - silently drops the body
    // and every data write reaches the runtime empty (BUI-683). Simulate the
    // Firefox engine by hiding the getter for the duration of the test.
    const bodyDescriptor = Object.getOwnPropertyDescriptor(
      Request.prototype,
      "body",
    );
    Object.defineProperty(Request.prototype, "body", {
      configurable: true,
      get: () => undefined,
    });
    try {
      const gateway = createGateway();
      const ps = await startPersonalServer({
        runtime: createRuntime(gateway),
        relay: false,
        localOrigin: ORIGIN,
        gateway,
      });
      const body = new TextEncoder().encode(
        JSON.stringify({ username: "vana_debug" }),
      );
      const auth = await buildWeb3SignedHeader({
        wallet: ownerWallet,
        aud: ORIGIN,
        method: "POST",
        uri: "/v1/data/instagram.profile",
        body,
      });

      const res = await ps.fetch(
        new Request("https://ignored.example/v1/data/instagram.profile", {
          method: "POST",
          body,
          headers: {
            Authorization: auth,
            "Content-Type": "application/json",
          },
        }),
      );

      expect(res.status).toBe(201);
      await expect(res.json()).resolves.toMatchObject({
        scope: "instagram.profile",
      });
    } finally {
      if (bodyDescriptor) {
        Object.defineProperty(Request.prototype, "body", bodyDescriptor);
      }
    }
  });

  it("uses the relay public URL for info and registration", async () => {
    const gateway = createGateway();
    const ps = await startPersonalServer({
      runtime: createRuntime(gateway),
      relay: {
        sessionId: "session-1",
        publicSuffix: "relay.example",
        webSocketFactory(_url) {
          return {
            binaryType: "arraybuffer",
            readyState: 1,
            OPEN: 1,
            CONNECTING: 0,
            onopen: null,
            onmessage: null,
            onclose: null,
            onerror: null,
            send: vi.fn(),
            close: vi.fn(),
          };
        },
      },
      localOrigin: ORIGIN,
      gateway,
    });

    const info = await ps.info();
    expect(info.urls).toMatchObject({
      local: ORIGIN,
      public: "https://session-1.relay.example",
      apiOrigin: "https://session-1.relay.example",
      registration: "https://session-1.relay.example",
    });
    await expect(ps.prepareRegistration()).resolves.toMatchObject({
      candidate: { serverUrl: "https://session-1.relay.example" },
    });

    await ps.stop();
  });

  it("reuses the saved relay session after registration", async () => {
    const relayStateStore = createMemoryPsLiteStateStore();
    const webSocketFactory = vi.fn((_url: string) => ({
      binaryType: "arraybuffer",
      readyState: 1,
      OPEN: 1,
      CONNECTING: 0,
      onopen: null,
      onmessage: null,
      onclose: null,
      onerror: null,
      send: vi.fn(),
      close: vi.fn(),
    }));
    const first = await startPersonalServer({
      runtime: createRuntime(createGateway()),
      relayStateStore,
      relay: {
        publicSuffix: "relay.example",
        webSocketFactory,
      },
      localOrigin: ORIGIN,
      gateway: createGateway(),
    });
    const firstInfo = await first.info();
    await first.submitRegistration({ signature: "0xregistration" });
    await first.stop();

    const second = await startPersonalServer({
      runtime: createRuntime(createGateway()),
      relayStateStore,
      relay: {
        publicSuffix: "relay.example",
        webSocketFactory,
      },
      localOrigin: ORIGIN,
      gateway: createGateway(),
    });

    await expect(second.info()).resolves.toMatchObject({
      urls: { public: firstInfo.urls.public },
    });
    await second.stop();
  });

  it("stops the owned sync manager when stopping an IndexedDB-backed handle", async () => {
    const runtime = createRuntime(createGateway());
    const syncManager = {
      trigger: vi.fn().mockResolvedValue(undefined),
      getStatus: vi.fn(),
      stop: vi.fn().mockResolvedValue(undefined),
    } as Pick<SyncManager, "trigger" | "getStatus" | "stop">;
    const ps = await startPersonalServer({
      runtime,
      relay: false,
      localOrigin: ORIGIN,
      syncManager,
    });

    await ps.stop();

    expect(syncManager.stop).not.toHaveBeenCalled();
  });

  it("routes generic fetch calls through the runtime", async () => {
    const gateway = createGateway();
    const ps = await startPersonalServer({
      runtime: createRuntime(gateway),
      relay: false,
      localOrigin: ORIGIN,
      gateway,
    });
    const auth = await buildWeb3SignedHeader({
      wallet: ownerWallet,
      aud: ORIGIN,
      method: "GET",
      uri: "/v1/data",
    });

    const res = await ps.fetch("/v1/data", {
      headers: { Authorization: auth },
    });

    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toMatchObject({ scopes: [] });
  });

  it("stops idempotently", async () => {
    const ps = await startPersonalServer({
      runtime: createRuntime(createGateway()),
      relay: false,
      localOrigin: ORIGIN,
    });

    await ps.stop();
    await ps.stop();

    await expect(ps.info()).resolves.toMatchObject({ status: "stopped" });
  });
});
