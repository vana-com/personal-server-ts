import { describe, it, expect, vi } from "vitest";
import { Hono } from "hono";
import { createWeb3AuthMiddleware } from "./web3-auth.js";
import { createBuilderCheckMiddleware } from "./builder-check.js";
import {
  createTestWallet,
  buildWeb3SignedHeader,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import type { GatewayClient } from "@opendatalabs/personal-server-ts-core/gateway";

const SERVER_ORIGIN = "http://localhost:8080";
const wallet = createTestWallet(0);

function createMockGateway(
  overrides: Partial<GatewayClient> = {},
): GatewayClient {
  return {
    isRegisteredBuilder: vi.fn().mockResolvedValue(true),
    getBuilder: vi.fn().mockResolvedValue(null),
    getGrant: vi.fn().mockResolvedValue(null),
    listGrantsByUser: vi.fn().mockResolvedValue([]),
    getSchemaForScope: vi.fn().mockResolvedValue(null),
    getServer: vi.fn().mockResolvedValue(null),
    ...overrides,
  };
}

function createApp(gateway: GatewayClient) {
  const app = new Hono();
  const web3Auth = createWeb3AuthMiddleware(SERVER_ORIGIN);
  const builderCheck = createBuilderCheckMiddleware(gateway);

  app.get("/test", web3Auth, builderCheck, (c) => {
    return c.json({ ok: true });
  });

  return app;
}

function createOwnerSessionApp(gateway: GatewayClient, sessionToken: string) {
  const app = new Hono();
  const serverOwner =
    "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd" as `0x${string}`;
  const web3Auth = createWeb3AuthMiddleware({
    serverOrigin: SERVER_ORIGIN,
    tokenStore: {
      getTokens: async () => [sessionToken],
      isValid: async (token: string) => token === sessionToken,
      addToken: async () => {},
      removeToken: async () => {},
    },
    serverOwner,
  });
  const builderCheck = createBuilderCheckMiddleware(gateway, serverOwner);

  app.get("/test", web3Auth, builderCheck, (c) => {
    return c.json({ ok: true, devBypass: c.get("devBypass") ?? false });
  });

  return app;
}

async function makeAuthRequest(app: Hono) {
  const header = await buildWeb3SignedHeader({
    wallet,
    aud: SERVER_ORIGIN,
    method: "GET",
    uri: "/test",
  });
  return app.request("/test", {
    headers: { Authorization: header },
  });
}

describe("createBuilderCheckMiddleware", () => {
  it("registered builder calls next", async () => {
    const gateway = createMockGateway({
      isRegisteredBuilder: vi.fn().mockResolvedValue(true),
    });
    const app = createApp(gateway);

    const res = await makeAuthRequest(app);

    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.ok).toBe(true);
    expect(gateway.isRegisteredBuilder).toHaveBeenCalledWith(wallet.address);
  });

  it("unregistered builder returns 401 UNREGISTERED_BUILDER", async () => {
    const gateway = createMockGateway({
      isRegisteredBuilder: vi.fn().mockResolvedValue(false),
    });
    const app = createApp(gateway);

    const res = await makeAuthRequest(app);

    expect(res.status).toBe(401);
    const json = await res.json();
    expect(json.error.errorCode).toBe("UNREGISTERED_BUILDER");
  });

  it("gateway error returns 500", async () => {
    const gateway = createMockGateway({
      isRegisteredBuilder: vi
        .fn()
        .mockRejectedValue(new Error("Gateway timeout")),
    });
    const app = createApp(gateway);

    const res = await makeAuthRequest(app);

    expect(res.status).toBe(500);
  });

  it("allows owner-authenticated bearer tokens without requiring builder registration", async () => {
    const sessionToken = "vana_ps_owner_token";
    const gateway = createMockGateway({
      isRegisteredBuilder: vi.fn().mockResolvedValue(false),
    });
    const app = createOwnerSessionApp(gateway, sessionToken);

    const res = await app.request("/test", {
      headers: { Authorization: `Bearer ${sessionToken}` },
    });

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true, devBypass: false });
    expect(gateway.isRegisteredBuilder).not.toHaveBeenCalled();
  });
});
