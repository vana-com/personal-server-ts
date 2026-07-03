import { describe, it, expect, vi, beforeEach } from "vitest";
import { createTestWallet } from "@opendatalabs/personal-server-ts-core/test-utils";
import { uiRegistrationRoutes } from "./ui-registration.js";
import type * as VanaSdkNode from "@opendatalabs/vana-sdk/node";

const gatewayMocks = vi.hoisted(() => ({
  createGatewayClient: vi.fn(),
  getDataPoint: vi.fn(),
  getServer: vi.fn(),
  registerServer: vi.fn(),
}));

vi.mock("@opendatalabs/vana-sdk/node", async (importOriginal) => {
  const actual = await importOriginal<typeof VanaSdkNode>();
  return {
    ...actual,
    createGatewayClient: gatewayMocks.createGatewayClient,
  };
});

describe("uiRegistrationRoutes", () => {
  const devToken = "dev-token";
  const owner = createTestWallet(0);
  const server = createTestWallet(1);
  const gatewayConfig = {
    url: "https://gateway.test",
    chainId: 14800,
    contracts: {
      dataRegistry: "0x8C8788f98385F6ba1adD4234e551ABba0f82Cb7C",
      dataPortabilityPermissions: "0xD54523048AdD05b4d734aFaE7C68324Ebb7373eF",
      dataPortabilityServer: "0x1483B1F634DBA75AeaE60da7f01A679aabd5ee2c",
      dataPortabilityGrantees: "0x8325C0A0948483EdA023A1A2Fd895e62C5131234",
    },
  };

  beforeEach(() => {
    vi.clearAllMocks();
    gatewayMocks.createGatewayClient.mockReturnValue({
      getDataPoint: gatewayMocks.getDataPoint,
      getServer: gatewayMocks.getServer,
      registerServer: gatewayMocks.registerServer,
    });
  });

  function authHeaders() {
    return { authorization: `Bearer ${devToken}` };
  }

  it("reports whether VANA_OWNER_PRIVATE_KEY is configured", async () => {
    const app = uiRegistrationRoutes({ devToken });
    const res = await app.request("/registration", {
      headers: authHeaders(),
    });

    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toEqual({
      ownerPrivateKeyConfigured: false,
    });
  });

  it("rejects registration without an owner private key", async () => {
    const app = uiRegistrationRoutes({ devToken });
    const res = await app.request("/registration/server", {
      method: "POST",
      headers: {
        ...authHeaders(),
        "content-type": "application/json",
      },
      body: JSON.stringify({}),
    });

    expect(res.status).toBe(503);
    expect(gatewayMocks.registerServer).not.toHaveBeenCalled();
  });

  it("signs and registers a public server URL with the configured owner key", async () => {
    gatewayMocks.getServer.mockResolvedValue(null);
    gatewayMocks.registerServer.mockResolvedValue({
      alreadyRegistered: false,
      serverId: "server-1",
    });
    const app = uiRegistrationRoutes({
      devToken,
      ownerPrivateKey: owner.privateKey,
    });

    const candidate = {
      ownerAddress: owner.address,
      serverAddress: server.address,
      publicKey: server.address,
      serverUrl: "https://server.example.com",
    };
    const res = await app.request("/registration/server", {
      method: "POST",
      headers: {
        ...authHeaders(),
        "content-type": "application/json",
      },
      body: JSON.stringify({ gatewayConfig, registration: candidate }),
    });

    expect(res.status).toBe(200);
    expect(gatewayMocks.registerServer).toHaveBeenCalledWith(
      expect.objectContaining({
        ...candidate,
        signature: expect.stringMatching(/^0x[0-9a-f]+$/i),
      }),
    );
  });

  it("rejects loopback and private network server URLs", async () => {
    const app = uiRegistrationRoutes({
      devToken,
      ownerPrivateKey: owner.privateKey,
    });

    for (const serverUrl of [
      "http://localhost:18081",
      "http://127.0.0.1:18081",
      "http://10.0.0.2:18081",
      "http://192.168.1.10:18081",
      "http://172.16.1.10:18081",
      "https://ps-lite.local",
    ]) {
      const res = await app.request("/registration/server", {
        method: "POST",
        headers: {
          ...authHeaders(),
          "content-type": "application/json",
        },
        body: JSON.stringify({
          gatewayConfig,
          registration: {
            ownerAddress: owner.address,
            serverAddress: server.address,
            publicKey: server.address,
            serverUrl,
          },
        }),
      });

      expect(res.status).toBe(400);
      await expect(res.json()).resolves.toMatchObject({
        error: { errorCode: "PUBLIC_API_URL_REQUIRED" },
      });
    }
    expect(gatewayMocks.registerServer).not.toHaveBeenCalled();
  });

  it("accepts an owner private key without 0x prefix", async () => {
    gatewayMocks.getServer.mockResolvedValue(null);
    gatewayMocks.registerServer.mockResolvedValue({
      alreadyRegistered: false,
      serverId: "server-1",
    });
    const app = uiRegistrationRoutes({
      devToken,
      ownerPrivateKey: owner.privateKey.slice(2) as `0x${string}`,
    });

    const candidate = {
      ownerAddress: owner.address,
      serverAddress: server.address,
      publicKey: server.address,
      serverUrl: "https://server.example.com",
    };
    const res = await app.request("/registration/server", {
      method: "POST",
      headers: {
        ...authHeaders(),
        "content-type": "application/json",
      },
      body: JSON.stringify({ gatewayConfig, registration: candidate }),
    });

    expect(res.status).toBe(200);
    expect(gatewayMocks.registerServer).toHaveBeenCalledWith(
      expect.objectContaining({
        ...candidate,
        signature: expect.stringMatching(/^0x[0-9a-f]+$/i),
      }),
    );
  });

  it("notifies onRegistered after a fresh registration (BUI-611 tunnel gate)", async () => {
    gatewayMocks.getServer.mockResolvedValue(null);
    gatewayMocks.registerServer.mockResolvedValue({
      alreadyRegistered: false,
      serverId: "server-1",
    });
    const onRegistered = vi.fn();
    const app = uiRegistrationRoutes({
      devToken,
      ownerPrivateKey: owner.privateKey,
      onRegistered,
    });

    const res = await app.request("/registration/server", {
      method: "POST",
      headers: {
        ...authHeaders(),
        "content-type": "application/json",
      },
      body: JSON.stringify({
        gatewayConfig,
        registration: {
          ownerAddress: owner.address,
          serverAddress: server.address,
          publicKey: server.address,
          serverUrl: "https://server.example.com",
        },
      }),
    });

    expect(res.status).toBe(200);
    expect(onRegistered).toHaveBeenCalledWith("server-1");
  });

  it("notifies onRegistered when the server is already registered", async () => {
    gatewayMocks.getServer.mockResolvedValue({ id: "server-9" });
    const onRegistered = vi.fn();
    const app = uiRegistrationRoutes({
      devToken,
      ownerPrivateKey: owner.privateKey,
      onRegistered,
    });

    const res = await app.request("/registration/server", {
      method: "POST",
      headers: {
        ...authHeaders(),
        "content-type": "application/json",
      },
      body: JSON.stringify({
        gatewayConfig,
        registration: {
          ownerAddress: owner.address,
          serverAddress: server.address,
          publicKey: server.address,
          serverUrl: "https://server.example.com",
        },
      }),
    });

    expect(res.status).toBe(200);
    expect(onRegistered).toHaveBeenCalledWith("server-9");
    expect(gatewayMocks.registerServer).not.toHaveBeenCalled();
  });

  it("checks file ids against the gateway", async () => {
    gatewayMocks.getDataPoint
      .mockResolvedValueOnce({ id: "file-1" })
      .mockResolvedValueOnce(null);
    const app = uiRegistrationRoutes({ devToken });

    const res = await app.request("/rpc/files", {
      method: "POST",
      headers: {
        ...authHeaders(),
        "content-type": "application/json",
      },
      body: JSON.stringify({
        gatewayUrl: "https://gateway.test",
        fileIds: ["file-1", "file-2"],
      }),
    });

    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toEqual({
      files: {
        "file-1": { registered: true },
        "file-2": { registered: false },
      },
    });
  });
});
