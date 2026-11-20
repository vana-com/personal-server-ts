import { createApp } from "../app.js";
import { initializeDatabase } from "../storage/index-schema.js";
import { createIndexManager } from "../storage/index-manager.js";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Hono } from "hono";
import { pino } from "pino";
import {
  approveMcpConnection,
  createMcpConnection,
  createInMemoryMcpConnectionStore,
  withStrictMcpGrantRegistration,
} from "@opendatalabs/personal-server-ts-core/mcp";
import {
  buildWeb3SignedHeader,
  createTestWallet,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import { mcpConnectionsRoutes } from "./mcp.js";

const A = "instagram.profile";
const B = "youtube.history";
const origin = "http://localhost:8080";
const owner = createTestWallet(9);
const foreign = createTestWallet(10);

const databases: Array<{ close(): void }> = [];
afterEach(() => {
  for (const database of databases.splice(0)) database.close();
});

async function setup(enabled = true, mounted = false) {
  const store = createInMemoryMcpConnectionStore();
  const connection = await createMcpConnection(
    { displayName: "Maple" },
    { store, publicOrigin: origin },
  );
  await approveMcpConnection(
    {
      connectionId: connection.connectionId,
      grants: [{ grantId: "0xgrant", scopes: [A, B] }],
    },
    { store },
  );
  const gateway = {
    getGrant: vi.fn(async () => ({
      id: "0xgrant",
      scopes: [A, B],
      grantVersion: "2",
      expiresAt: null,
      revokedAt: null,
      expired: false,
    })),
    getBuilder: vi.fn(async () => ({ id: "0xbuilder" })),
    createGrant: vi.fn(async () => ({ grantId: "0xgrant" })),
  };
  let app = new Hono();
  app.route(
    "/v1/mcp/connections",
    mcpConnectionsRoutes({
      logger: pino({ level: "silent" }),
      serverOrigin: origin,
      serverOwner: owner.address,
      gateway: withStrictMcpGrantRegistration(
        gateway,
        "https://gateway.test",
      ) as never,
      serverSigner: {
        signGrantRegistration: vi.fn(async () => "0xsig" as `0x${string}`),
      } as never,
      connectionStore: store,
      mcpOwnerAccessEdit: enabled,
      accessLogWriter: { write: vi.fn() } as never,
    }),
  );
  if (mounted) {
    const database = initializeDatabase(":memory:");
    databases.push(database);
    app = createApp({
      logger: pino({ level: "silent" }),
      version: "test",
      startedAt: new Date(),
      indexManager: createIndexManager(database),
      hierarchyOptions: { dataDir: "/unused-mcp-access-test" },
      serverOrigin: origin,
      serverOwner: owner.address,
      gateway: gateway as never,
      gatewayConfig: {
        url: "https://gateway.test",
        chainId: 14800,
        contracts: {
          dataRegistry: "0x0000000000000000000000000000000000000001",
          dataPortabilityPermissions:
            "0x0000000000000000000000000000000000000002",
          dataPortabilityServer: "0x0000000000000000000000000000000000000003",
          dataPortabilityGrantees: "0x0000000000000000000000000000000000000004",
        },
      },
      serverSigner: {
        signGrantRegistration: vi.fn(async () => "0xsig" as `0x${string}`),
      } as never,
      mcpConnectionStore: store,
      mcpOwnerAccessEdit: enabled,
      accessLogWriter: { write: vi.fn() } as never,
      accessLogReader: { read: vi.fn() } as never,
    });
  }
  const path = `/v1/mcp/connections/${connection.connectionId}/access`;
  async function request(
    scopes: unknown,
    auth: "owner" | "foreign" | "bearer" | "missing" = "owner",
  ) {
    const body = JSON.stringify({ scopes });
    const authorization =
      auth === "missing"
        ? undefined
        : auth === "bearer"
          ? `Bearer ${connection.connectionToken}`
          : await buildWeb3SignedHeader({
              wallet: auth === "owner" ? owner : foreign,
              aud: origin,
              method: "PUT",
              uri: path,
              body: new TextEncoder().encode(body),
            });
    return app.request(path, {
      method: "PUT",
      body,
      headers: {
        "Content-Type": "application/json",
        ...(authorization ? { Authorization: authorization } : {}),
      },
    });
  }
  return { request, store, id: connection.connectionId, gateway };
}

describe("owner access edit route", () => {
  it("mounts the route in the real app and preserves gateway conflicts instead of SDK success", async () => {
    const { request, store, id, gateway } = await setup(true, true);
    const before = await store.getById(id);
    const http = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(
        Response.json(
          { error: "Stale grantVersion", grantId: "0xgrant" },
          { status: 409 },
        ),
      );
    try {
      expect((await request([A])).status).toBe(409);
      expect(http).toHaveBeenCalledOnce();
      expect(gateway.createGrant).not.toHaveBeenCalled();
      expect(await store.getById(id)).toEqual(before);
    } finally {
      http.mockRestore();
    }
  });

  it("accepts an owner signature and registers exactly the remaining scopes", async () => {
    const { request, store, id } = await setup();
    const http = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(
        Response.json({ grantId: "0xgrant" }, { status: 201 }),
      );
    try {
      const response = await request([A]);
      expect(response.status).toBe(200);
      expect((await response.json()).connection.grantedScopes).toEqual([A]);
      expect((await store.getById(id))!.grants[0].scopes).toEqual([A]);
      expect(http).toHaveBeenCalledOnce();
      const [url, init] = http.mock.calls[0];
      expect(url).toBe("https://gateway.test/v1/grants");
      expect(JSON.parse(String(init!.body))).toMatchObject({
        scopes: [A],
        grantVersion: "3",
        signature: "0xsig",
      });
    } finally {
      http.mockRestore();
    }
  });

  it.each(["foreign", "bearer", "missing"] as const)(
    "rejects %s authentication without calling the gateway",
    async (auth) => {
      const { request, gateway, store, id } = await setup();
      const before = await store.getById(id);
      const http = vi.spyOn(globalThis, "fetch");
      try {
        const response = await request([A], auth);
        expect([401, 403]).toContain(response.status);
        expect(http).not.toHaveBeenCalled();
        expect(gateway.getGrant).not.toHaveBeenCalled();
        expect(await store.getById(id)).toEqual(before);
      } finally {
        http.mockRestore();
      }
    },
  );

  it.each([{ scopes: [] }, { scopes: [A, "spotify.profile"] }])(
    "rejects invalid scopes $scopes with 400 and no registration",
    async ({ scopes }) => {
      const { request, gateway } = await setup();
      const http = vi.spyOn(globalThis, "fetch");
      try {
        expect((await request(scopes)).status).toBe(400);
        expect(http).not.toHaveBeenCalled();
        expect(gateway.getGrant).not.toHaveBeenCalled();
      } finally {
        http.mockRestore();
      }
    },
  );

  it("answers 200 for an unchanged set without calling the gateway", async () => {
    const { request, gateway } = await setup();
    const http = vi.spyOn(globalThis, "fetch");
    try {
      expect((await request([B, A, A])).status).toBe(200);
      expect(http).not.toHaveBeenCalled();
      expect(gateway.getGrant).not.toHaveBeenCalled();
    } finally {
      http.mockRestore();
    }
  });

  it.each(["owner", "foreign", "bearer", "missing"] as const)(
    "is absent by default, including for %s",
    async (auth) => {
      const { request, gateway } = await setup(false);
      const http = vi.spyOn(globalThis, "fetch");
      try {
        expect((await request([A], auth)).status).toBe(404);
        expect(http).not.toHaveBeenCalled();
        expect(gateway.getGrant).not.toHaveBeenCalled();
      } finally {
        http.mockRestore();
      }
    },
  );
});
