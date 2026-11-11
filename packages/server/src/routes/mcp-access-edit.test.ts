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
import {
  createFakeGrantGateway,
  type FakeGrantGatewayOptions,
} from "@opendatalabs/personal-server-ts-core/test-utils";
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

function makeGateway(options: FakeGrantGatewayOptions = {}) {
  const fake = createFakeGrantGateway(options);
  fake.seed("0xold", ["instagram.profile"]);
  return fake;
}

describe("PUT /v1/mcp/connections/:id/access", () => {
  let store: McpConnectionStore;
  let fake: ReturnType<typeof makeGateway>;
  let connectionId: string;
  let tokenHash: string;

  async function build(ownerAccessEdit: boolean, g = fake) {
    const deps = {
      logger: pino({ level: "silent" }),
      serverOrigin: SERVER_ORIGIN,
      serverOwner: ownerWallet.address,
      gateway: g.gateway,
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
    fake = makeGateway();
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
    expect(fake.counter()).toBe(1n);
  });

  it("answers 404 when the option is off, for unsigned and non-owner callers too", async () => {
    const app = await build(false);
    const scopes = ["instagram.profile"];
    expect((await put(app, { scopes }, null)).status).toBe(404);
    expect((await put(app, { scopes }, otherWallet)).status).toBe(404);
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
    expect(fake.counter()).toBe(1n);
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
    expect(fake.grants.get("0xold")?.revokedAt).toBeTruthy();
    const after = await store.getById(connectionId);
    expect(after?.tokenHash).toBe(tokenHash);
    expect(after?.grants).toEqual([
      {
        grantId: "0xnew1",
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

  it("answers 202 with the failure and keeps the old id retryable when a revoke is not proven", async () => {
    const failing = makeGateway({ throwOnRevoke: () => true });
    const res = await put(await build(true, failing), {
      scopes: ["instagram.profile", "youtube.history"],
    });
    expect(res.status).toBe(202);
    const body = await res.json();
    expect(body.revokeFailures).toEqual([
      { grantId: "0xold", error: "gateway down" },
    ]);
    expect(body.pendingRevocations).toEqual(["0xold"]);
    const after = await store.getById(connectionId);
    expect(after?.grants[0].grantId).toBe("0xnew1");
    expect(after?.pendingRevocations).toEqual(["0xold"]);
  });

  it("rejects invalid bodies with 400", async () => {
    const app = await build(true);
    for (const scopes of [[], ["vana.system.state"], ["write:memory.new"]]) {
      const res = await put(app, { scopes });
      expect(res.status).toBe(400);
    }
    expect(fake.counter()).toBe(1n);
  });
});
