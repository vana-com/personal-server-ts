import { describe, expect, it, vi } from "vitest";
import type { GatewayClient } from "@opendatalabs/vana-sdk/browser";
import {
  buildWeb3SignedHeader,
  createTestWallet,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import {
  createMemoryPsLiteAccessLogStore,
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
