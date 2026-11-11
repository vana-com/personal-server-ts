import { beforeEach, describe, expect, it, vi } from "vitest";
import { pino } from "pino";
import { Hono } from "hono";
import {
  approveMcpConnection,
  createInMemoryMcpConnectionStore,
  createMcpConnection,
  type McpConnectionStore,
} from "@opendatalabs/personal-server-ts-core/mcp";
import {
  buildWeb3SignedHeader,
  createTestWallet,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import { mcpConnectionsRoutes } from "./mcp.js";

const SERVER_ORIGIN = "http://localhost:8080";
const ownerWallet = createTestWallet(9);
const otherWallet = createTestWallet(10);
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

function makeGateway(revokeGrant = vi.fn().mockResolvedValue(undefined)) {
  return {
    isRegisteredBuilder: vi.fn().mockResolvedValue(true),
    getBuilder: vi.fn().mockResolvedValue({ id: "0xbuilder" }),
    getGrant: vi.fn().mockResolvedValue({
      id: "0xold",
      scopes: ["instagram.profile"],
      grantVersion: "1",
      expiresAt: null,
      revokedAt: null,
    }),
    listGrantsByUser: vi.fn().mockResolvedValue([]),
    createGrant: vi.fn().mockResolvedValue({ grantId: "0xnew" }),
    revokeGrant,
  } as unknown as GatewayClient;
}

describe("PUT /v1/mcp/connections/:id/access", () => {
  let store: McpConnectionStore;
  let gateway: GatewayClient;
  let connectionId: string;
  let tokenHash: string;

  async function build(ownerAccessEdit: boolean, g = gateway) {
    const deps = {
      logger: pino({ level: "silent" }),
      serverOrigin: SERVER_ORIGIN,
      serverOwner: ownerWallet.address,
      gateway: g,
      gatewayConfig,
      serverSigner: {
        signGrantRegistration: vi.fn().mockResolvedValue("0xsig"),
        signGrantRevocation: vi.fn().mockResolvedValue("0xrev"),
        signRecordDataAccess: vi.fn(),
      },
      accessLogWriter: { write: vi.fn() },
      connectionStore: store,
      mcpOwnerAccessEdit: ownerAccessEdit,
    } as never;
    const app = new Hono();
    app.route("/v1/mcp/connections", mcpConnectionsRoutes(deps));
    return app;
  }

  async function put(
    app: Hono,
    body: unknown,
    wallet: typeof ownerWallet | null = ownerWallet,
  ) {
    const path = `/v1/mcp/connections/${connectionId}/access`;
    const raw = JSON.stringify(body);
    const auth = wallet
      ? await buildWeb3SignedHeader({
          wallet,
          aud: SERVER_ORIGIN,
          method: "PUT",
          uri: path,
          body: new TextEncoder().encode(raw),
        })
      : undefined;
    return app.request(path, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        ...(auth ? { Authorization: auth } : {}),
      },
      body: raw,
    });
  }

  beforeEach(async () => {
    store = createInMemoryMcpConnectionStore();
    gateway = makeGateway();
    const created = await createMcpConnection(
      { displayName: "Maple" },
      { store, publicOrigin: SERVER_ORIGIN },
    );
    connectionId = created.connectionId;
    await approveMcpConnection(
      {
        connectionId,
        grants: [{ grantId: "0xold", scopes: ["instagram.profile"] }],
      },
      { store },
    );
    tokenHash = (await store.getById(connectionId))!.tokenHash;
  });

  it("answers 404 as if absent when the option is off", async () => {
    const res = await put(await build(false), {
      scopes: ["instagram.profile"],
    });
    expect(res.status).toBe(404);
    expect(gateway.createGrant).not.toHaveBeenCalled();
  });

  it("rejects a non-owner and an unsigned caller", async () => {
    const app = await build(true);
    const scopes = ["instagram.profile"];
    expect(
      (await put(app, { scopes }, otherWallet)).status,
    ).toBeGreaterThanOrEqual(401);
    expect((await put(app, { scopes }, null)).status).toBeGreaterThanOrEqual(
      401,
    );
    expect(gateway.createGrant).not.toHaveBeenCalled();
    expect((await store.getById(connectionId))?.grants[0].grantId).toBe(
      "0xold",
    );
  });

  it("widens: same id and token, one new grant, old one revoked", async () => {
    const res = await put(await build(true), {
      scopes: ["instagram.profile", "youtube.history"],
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body).toMatchObject({
      id: connectionId,
      grantedScopes: ["instagram.profile", "youtube.history"],
      revokeFailures: [],
    });
    expect(gateway.createGrant).toHaveBeenCalledTimes(1);
    expect(gateway.revokeGrant).toHaveBeenCalledTimes(1);
    const after = await store.getById(connectionId);
    expect(after?.tokenHash).toBe(tokenHash);
    expect(after?.grants).toEqual([
      {
        grantId: "0xnew",
        scopes: ["instagram.profile", "youtube.history"],
      },
    ]);
  });

  it("narrows to a subset", async () => {
    await put(await build(true), {
      scopes: ["instagram.profile", "youtube.history"],
    });
    const res = await put(await build(true), { scopes: ["youtube.history"] });
    expect(res.status).toBe(200);
    expect((await res.json()).grantedScopes).toEqual(["youtube.history"]);
  });

  it("returns a revoke failure and keeps the new grant", async () => {
    const failing = makeGateway(vi.fn().mockRejectedValue(new Error("down")));
    const res = await put(await build(true, failing), {
      scopes: ["instagram.profile", "youtube.history"],
    });
    expect(res.status).toBe(200);
    expect((await res.json()).revokeFailures).toEqual([
      { grantId: "0xold", error: "down" },
    ]);
    expect((await store.getById(connectionId))?.grants[0].grantId).toBe(
      "0xnew",
    );
  });

  it("rejects invalid bodies with 400", async () => {
    const app = await build(true);
    for (const scopes of [[], ["vana.system.state"], ["write:memory.new"]]) {
      const res = await put(app, { scopes });
      expect(res.status).toBe(400);
    }
    expect(gateway.createGrant).not.toHaveBeenCalled();
  });
});
