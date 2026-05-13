import { describe, expect, it, vi } from "vitest";
import type { GatewayClient } from "@opendatalabs/vana-sdk/browser";
import { createTestWallet } from "./test-utils/index.js";
import {
  createOwnerSignedPersonalServerRequest,
  createPersonalServerInfoFromHealth,
  createPersonalServerRegistrationRequest,
  dataListPath,
  dataReadPath,
  dataVersionsPath,
  parsePersonalServerJsonResponse,
  PersonalServerClientError,
  submitPersonalServerRegistration,
} from "./client.js";

const gatewayConfig = {
  chainId: 14800,
  contracts: {
    dataRegistry: "0x8C8788f98385F6ba1adD4234e551ABba0f82Cb7C",
    dataPortabilityPermissions: "0xD54523048AdD05b4d734aFaE7C68324Ebb7373eF",
    dataPortabilityServer: "0x1483B1F634DBA75AeaE60da7f01A679aabd5ee2c",
    dataPortabilityGrantees: "0x8325C0A0948483EdA023A1A2Fd895e62C5131234",
  },
};

describe("Personal Server client helpers", () => {
  it("normalizes health into the unified consumer info shape", () => {
    const info = createPersonalServerInfoFromHealth({
      kind: "lite",
      status: "ready",
      localUrl: "https://ps-lite.local",
      publicUrl: "https://session.relay.example",
      health: {
        status: "healthy",
        owner: "0x1111111111111111111111111111111111111111",
        apiOrigin: "https://session.relay.example",
        gatewayUrl: "https://gateway.example",
        gatewayConfig: { ...gatewayConfig, url: "https://gateway.example" },
        identity: {
          address: "0x2222222222222222222222222222222222222222",
          publicKey: "0x04public",
          serverId: null,
        },
        registration: {
          ownerAddress: "0x1111111111111111111111111111111111111111",
          serverAddress: "0x2222222222222222222222222222222222222222",
          publicKey: "0x04public",
          serverUrl: "https://session.relay.example",
          serverId: null,
          registered: false,
        },
      },
    });

    expect(info).toMatchObject({
      kind: "lite",
      status: "ready",
      ownerAddress: "0x1111111111111111111111111111111111111111",
      server: {
        address: "0x2222222222222222222222222222222222222222",
        publicKey: "0x04public",
        serverId: null,
      },
      urls: {
        local: "https://ps-lite.local",
        public: "https://session.relay.example",
        apiOrigin: "https://session.relay.example",
        registration: "https://session.relay.example",
      },
      registration: {
        registered: false,
        candidate: {
          ownerAddress: "0x1111111111111111111111111111111111111111",
          serverAddress: "0x2222222222222222222222222222222222222222",
          publicKey: "0x04public",
          serverUrl: "https://session.relay.example",
        },
      },
      gatewayUrl: "https://gateway.example",
      gatewayConfig,
    });
  });

  it("does not treat local health api origins as public URLs when publicUrl is explicitly null", () => {
    const info = createPersonalServerInfoFromHealth({
      kind: "node",
      status: "ready",
      localUrl: "http://127.0.0.1:34123",
      publicUrl: null,
      health: {
        status: "healthy",
        apiOrigin: "http://localhost:34123",
        gatewayConfig: { ...gatewayConfig, url: "https://gateway.example" },
        registration: {
          ownerAddress: "0x1111111111111111111111111111111111111111",
          serverAddress: "0x2222222222222222222222222222222222222222",
          publicKey: "0x04public",
          serverUrl: "http://localhost:34123",
          serverId: null,
          registered: false,
        },
      },
    });

    expect(info.urls.public).toBeNull();
    expect(info.urls.apiOrigin).toBe("http://localhost:34123");
    expect(info.urls.registration).toBe("http://localhost:34123");
  });

  it("builds server registration typed data from a candidate", () => {
    const request = createPersonalServerRegistrationRequest({
      gatewayConfig,
      ownerAddress: "0x1111111111111111111111111111111111111111",
      serverAddress: "0x2222222222222222222222222222222222222222",
      publicKey: "0x04public",
      serverUrl: "https://session.relay.example",
    });

    expect(request.typedData).toMatchObject({
      primaryType: "ServerRegistration",
      message: request.candidate,
    });
    expect(request.typedData.domain.chainId).toBe(gatewayConfig.chainId);
  });

  it("submits registration only when the server is not already registered", async () => {
    const request = createPersonalServerRegistrationRequest({
      gatewayConfig,
      ownerAddress: "0x1111111111111111111111111111111111111111",
      serverAddress: "0x2222222222222222222222222222222222222222",
      publicKey: "0x04public",
      serverUrl: "https://session.relay.example",
    });
    const gateway = {
      getServer: vi.fn().mockResolvedValue(null),
      registerServer: vi.fn().mockResolvedValue({
        alreadyRegistered: false,
        serverId: "server-1",
      }),
    };

    await expect(
      submitPersonalServerRegistration({
        gateway: gateway as Pick<GatewayClient, "getServer" | "registerServer">,
        request,
        signature: "0xsig",
      }),
    ).resolves.toEqual({ alreadyRegistered: false, serverId: "server-1" });
    expect(gateway.registerServer).toHaveBeenCalledWith({
      ...request.candidate,
      signature: "0xsig",
    });
  });

  it("returns alreadyRegistered for an active existing server with the same URL", async () => {
    const request = createPersonalServerRegistrationRequest({
      gatewayConfig,
      ownerAddress: "0x1111111111111111111111111111111111111111",
      serverAddress: "0x2222222222222222222222222222222222222222",
      publicKey: "0x04public",
      serverUrl: "https://session.relay.example",
    });
    const gateway = {
      getServer: vi.fn().mockResolvedValue({
        id: "server-1",
        ownerAddress: request.candidate.ownerAddress,
        serverAddress: request.candidate.serverAddress,
        publicKey: request.candidate.publicKey,
        serverUrl: request.candidate.serverUrl,
        addedAt: "2026-05-08T00:00:00.000Z",
        revokedAt: null,
      }),
      registerServer: vi.fn(),
    };

    await expect(
      submitPersonalServerRegistration({
        gateway: gateway as Pick<GatewayClient, "getServer" | "registerServer">,
        request,
        signature: "0xsig",
      }),
    ).resolves.toEqual({ alreadyRegistered: true, serverId: "server-1" });
    expect(gateway.registerServer).not.toHaveBeenCalled();
  });

  it("rejects an existing server registration with a different URL", async () => {
    const request = createPersonalServerRegistrationRequest({
      gatewayConfig,
      ownerAddress: "0x1111111111111111111111111111111111111111",
      serverAddress: "0x2222222222222222222222222222222222222222",
      publicKey: "0x04public",
      serverUrl: "https://new-session.relay.example",
    });
    const gateway = {
      getServer: vi.fn().mockResolvedValue({
        id: "server-1",
        ownerAddress: request.candidate.ownerAddress,
        serverAddress: request.candidate.serverAddress,
        publicKey: request.candidate.publicKey,
        serverUrl: "https://old-session.relay.example",
        addedAt: "2026-05-08T00:00:00.000Z",
        revokedAt: null,
      }),
      registerServer: vi.fn(),
    };

    await expect(
      submitPersonalServerRegistration({
        gateway: gateway as Pick<GatewayClient, "getServer" | "registerServer">,
        request,
        signature: "0xsig",
      }),
    ).rejects.toMatchObject({
      status: 409,
      errorCode: "SERVER_URL_MISMATCH",
    });
    expect(gateway.registerServer).not.toHaveBeenCalled();
  });

  it("re-registers a revoked existing server with a different URL", async () => {
    const request = createPersonalServerRegistrationRequest({
      gatewayConfig,
      ownerAddress: "0x1111111111111111111111111111111111111111",
      serverAddress: "0x2222222222222222222222222222222222222222",
      publicKey: "0x04public",
      serverUrl: "https://new-session.relay.example",
    });
    const gateway = {
      getServer: vi.fn().mockResolvedValue({
        id: "server-1",
        ownerAddress: request.candidate.ownerAddress,
        serverAddress: request.candidate.serverAddress,
        publicKey: request.candidate.publicKey,
        serverUrl: "https://old-session.relay.example",
        addedAt: "2026-05-08T00:00:00.000Z",
        revokedAt: "2026-05-13T00:00:00.000Z",
      }),
      registerServer: vi.fn().mockResolvedValue({
        alreadyRegistered: false,
        serverId: "server-2",
      }),
    };

    await expect(
      submitPersonalServerRegistration({
        gateway: gateway as Pick<GatewayClient, "getServer" | "registerServer">,
        request,
        signature: "0xsig",
      }),
    ).resolves.toEqual({ alreadyRegistered: false, serverId: "server-2" });
    expect(gateway.registerServer).toHaveBeenCalledWith({
      ...request.candidate,
      signature: "0xsig",
    });
  });

  it("creates owner-authenticated Web3Signed requests", async () => {
    const wallet = createTestWallet(0);
    const request = await createOwnerSignedPersonalServerRequest({
      origin: "https://ps.example",
      path: "/v1/data/instagram.profile",
      method: "POST",
      body: new TextEncoder().encode(JSON.stringify({ username: "test" })),
      auth: { signMessage: wallet.signMessage },
      headers: { "Content-Type": "application/json" },
    });

    expect(request.url).toBe("https://ps.example/v1/data/instagram.profile");
    expect(request.headers.get("Authorization")).toMatch(/^Web3Signed /);
    expect(request.headers.get("Content-Type")).toBe("application/json");
  });

  it("signs request paths without query strings", async () => {
    const wallet = createTestWallet(0);
    const request = await createOwnerSignedPersonalServerRequest({
      origin: "https://ps.example",
      path: "/v1/data?limit=10",
      method: "GET",
      auth: { signMessage: wallet.signMessage },
    });

    expect(request.url).toBe("https://ps.example/v1/data?limit=10");
    const payload = request.headers
      .get("Authorization")!
      .split(" ")[1]
      .split(".")[0];
    const decoded = JSON.parse(atob(payload)) as { uri: string };
    expect(decoded.uri).toBe("/v1/data");
  });

  it("builds typed data and sync helper paths", () => {
    expect(dataListPath({ scopePrefix: "instagram", limit: 10 })).toBe(
      "/v1/data?scopePrefix=instagram&limit=10",
    );
    expect(dataVersionsPath("instagram.profile", { offset: 5 })).toBe(
      "/v1/data/instagram.profile/versions?offset=5",
    );
    expect(
      dataReadPath("instagram.profile", {
        grantId: "grant-1",
        fileId: "file-1",
      }),
    ).toBe("/v1/data/instagram.profile?grantId=grant-1&fileId=file-1");
  });

  it("preserves structured API errors for consumers", async () => {
    const body = JSON.stringify({
      error: {
        code: 401,
        errorCode: "INVALID_SIGNATURE",
        message: "Invalid signature",
        details: { reason: "Missing Web3Signed prefix" },
      },
    });

    await expect(
      parsePersonalServerJsonResponse(
        new Response(body, { status: 401 }),
        "data write",
      ),
    ).rejects.toBeInstanceOf(PersonalServerClientError);
    await expect(
      parsePersonalServerJsonResponse(
        new Response(body, { status: 401 }),
        "data write",
      ),
    ).rejects.toMatchObject({
      status: 401,
      errorCode: "INVALID_SIGNATURE",
      details: { reason: "Missing Web3Signed prefix" },
    });
  });
});
