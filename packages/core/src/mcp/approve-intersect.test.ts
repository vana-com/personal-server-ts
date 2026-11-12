import { describe, expect, it, vi } from "vitest";
import { createInMemoryMcpConnectionStore } from "./store.js";
import {
  approveMcpConnection,
  approveMcpScopeAccessRequest,
  createMcpConnection,
  editMcpConnectionAccess,
  requestMcpScopeAccess,
} from "./connection-api.js";

const A = "instagram.profile";
const B = "youtube.history";
/** On the gateway but not in the record: a write the local commit lost. */
const ORPHAN = "spotify.playlists";
const REQUESTED = "spotify.profile";

async function setup(gatewayScopes: string[]) {
  const store = createInMemoryMcpConnectionStore();
  const created = await createMcpConnection(
    { displayName: "Maple" },
    { store, publicOrigin: "https://ps.test" },
  );
  await approveMcpConnection(
    {
      connectionId: created.connectionId,
      grants: [{ grantId: "0xgrant", scopes: [A, B] }],
    },
    { store },
  );
  await requestMcpScopeAccess(
    { connectionId: created.connectionId, scopes: [REQUESTED] },
    { store },
  );
  const gateway = {
    getGrant: vi.fn(async () => ({
      id: "0xgrant",
      scopes: gatewayScopes,
      grantVersion: "4",
      expiresAt: null,
      revokedAt: null,
      expired: false,
    })),
    getBuilder: vi.fn(async () => ({ id: "0xbuilder" })),
    createGrant: vi.fn(async () => ({ grantId: "0xgrant" })),
  };
  const options = {
    store,
    gateway: gateway as never,
    serverOwner: "0xowner" as `0x${string}`,
    serverSigner: {
      signGrantRegistration: vi.fn(async () => "0xsig" as `0x${string}`),
    },
  };
  return { store, id: created.connectionId, gateway, options };
}

describe("scope-request approve signs only scopes the record still holds", () => {
  it("does not re-sign a scope that is on the gateway but not in the record", async () => {
    const { id, gateway, options, store } = await setup([A, B, ORPHAN]);
    const result = await approveMcpScopeAccessRequest(
      { connectionId: id, scopes: [REQUESTED] },
      options,
    );
    expect(gateway.createGrant).toHaveBeenCalledExactlyOnceWith(
      expect.objectContaining({ scopes: [A, REQUESTED, B].sort() }),
    );
    expect(result.grantedScopes).not.toContain(ORPHAN);
    expect(
      (await store.getById(id))!.grants.flatMap((grant) => grant.scopes),
    ).not.toContain(ORPHAN);
  });

  it("does not re-sign a stored scope the gateway no longer holds", async () => {
    const { id, gateway, options } = await setup([A]);
    await approveMcpScopeAccessRequest(
      { connectionId: id, scopes: [REQUESTED] },
      options,
    );
    expect(gateway.createGrant).toHaveBeenCalledExactlyOnceWith(
      expect.objectContaining({ scopes: [A, REQUESTED].sort() }),
    );
  });
});

describe("approve keeps exactly what reads serve, wildcards included", () => {
  it.each([
    {
      stored: ["chatgpt.*"],
      gateway: ["chatgpt.conversations"],
      kept: ["chatgpt.conversations"],
    },
    {
      stored: ["chatgpt.conversations"],
      gateway: ["chatgpt.*"],
      kept: ["chatgpt.conversations"],
    },
    { stored: ["chatgpt.*"], gateway: ["chatgpt.*"], kept: ["chatgpt.*"] },
  ])(
    "stored $stored, gateway $gateway keeps $kept",
    async ({ stored, gateway: gatewayScopes, kept }) => {
      const { id, gateway, options, store } = await setup(gatewayScopes);
      await store.mutate(id, (record) => ({
        ...record,
        grants: [{ grantId: "0xgrant", scopes: stored }],
      }));
      await approveMcpScopeAccessRequest(
        { connectionId: id, scopes: [REQUESTED] },
        options,
      );
      expect(gateway.createGrant).toHaveBeenCalledExactlyOnceWith(
        expect.objectContaining({ scopes: [...kept, REQUESTED].sort() }),
      );
    },
  );
});

describe("client traffic during an owner write", () => {
  it("approve commits locally when only lastUsedAt changed during the gateway write", async () => {
    const { id, gateway, options, store } = await setup([A, B]);
    gateway.createGrant.mockImplementation(async () => {
      // Every MCP request stamps lastUsedAt (routes/mcp.ts).
      await store.update(id, { lastUsedAt: "2030-01-01T00:00:00.000Z" });
      return { grantId: "0xgrant" };
    });
    const result = await approveMcpScopeAccessRequest(
      { connectionId: id, scopes: [REQUESTED] },
      options,
    );
    const stored = (await store.getById(id))!;
    expect(stored.grants).toEqual([
      { grantId: "0xgrant", scopes: [A, REQUESTED, B].sort() },
    ]);
    expect(stored.scopeAccessRequest).toBeUndefined();
    expect(stored.lastUsedAt).toBe("2030-01-01T00:00:00.000Z");
    expect(result.approvedScopes).toEqual([REQUESTED]);
  });

  it("edit commits locally when only lastUsedAt changed during the gateway write", async () => {
    const { id, gateway, options, store } = await setup([A, B]);
    gateway.createGrant.mockImplementation(async () => {
      await store.update(id, { lastUsedAt: "2030-01-01T00:00:00.000Z" });
      return { grantId: "0xgrant" };
    });
    const result = await editMcpConnectionAccess(
      { connectionId: id, scopes: [A] },
      options,
    );
    expect(result.grants).toEqual([{ grantId: "0xgrant", scopes: [A] }]);
    expect((await store.getById(id))!.grants).toEqual(result.grants);
  });

  it("still refuses the local commit when the record really changed", async () => {
    const { id, gateway, options, store } = await setup([A, B]);
    gateway.createGrant.mockImplementation(async () => {
      await requestMcpScopeAccess(
        { connectionId: id, scopes: ["linkedin.profile"] },
        { store },
      );
      return { grantId: "0xgrant" };
    });
    await expect(
      approveMcpScopeAccessRequest(
        { connectionId: id, scopes: [REQUESTED] },
        options,
      ),
    ).rejects.toMatchObject({ code: "CONCURRENT_UPDATE", status: 409 });
  });
});
