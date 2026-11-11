import { describe, expect, it, vi } from "vitest";
import { createInMemoryMcpConnectionStore } from "./store.js";
import {
  approveMcpConnection,
  createMcpConnection,
  McpConnectionStateError,
  McpScopeRequestError,
  requestMcpScopeAccess,
  revokeMcpConnection,
  setMcpConnectionAccess,
} from "./connection-api.js";

const OWNER = "0x00000000000000000000000000000000000000aa" as const;
const ORIGIN = "https://example-session.relay.test";

function gatewayMock(
  opts: { revokeImpl?: () => Promise<unknown>; newGrantId?: string } = {},
) {
  return {
    getBuilder: vi.fn(async () => ({ id: "0xbuilder" })),
    getGrant: vi.fn(async (id: string) => ({
      id,
      scopes: ["instagram.profile"],
      grantVersion: "3",
      expiresAt: null,
      revokedAt: null,
    })),
    createGrant: vi.fn(async () => ({ grantId: opts.newGrantId ?? "0xnew" })),
    revokeGrant: vi.fn(opts.revokeImpl ?? (async () => ({}))),
  };
}

const serverSigner = {
  signGrantRegistration: vi.fn(async () => "0xsig" as `0x${string}`),
  signGrantRevocation: vi.fn(async () => "0xrev" as `0x${string}`),
};

async function setup(
  grants = [
    { grantId: "0xold1", scopes: ["instagram.*"] },
    { grantId: "0xold2", scopes: ["chatgpt.history", "write:memory.claude"] },
  ],
) {
  const store = createInMemoryMcpConnectionStore();
  const created = await createMcpConnection(
    { displayName: "Maple" },
    { store, publicOrigin: ORIGIN },
  );
  await approveMcpConnection(
    { connectionId: created.connectionId, grants },
    { store },
  );
  return { store, id: created.connectionId };
}

const opts = (
  store: ReturnType<typeof createInMemoryMcpConnectionStore>,
  gateway: ReturnType<typeof gatewayMock>,
) => ({
  store,
  gateway: gateway as never,
  serverOwner: OWNER,
  serverSigner,
  now: () => new Date("2026-11-10T10:00:00.000Z"),
});

describe("setMcpConnectionAccess", () => {
  it("widens: one new grant, same connection id and token, old grants revoked", async () => {
    const { store, id } = await setup();
    const before = await store.getById(id);
    const gateway = gatewayMock();

    const result = await setMcpConnectionAccess(
      {
        connectionId: id,
        scopes: [
          "instagram.*",
          "chatgpt.history",
          "youtube.history",
          "write:memory.claude",
        ],
      },
      opts(store, gateway),
    );

    expect(gateway.createGrant).toHaveBeenCalledTimes(1);
    expect(gateway.createGrant).toHaveBeenCalledWith(
      expect.objectContaining({
        scopes: [
          "chatgpt.history",
          "instagram.*",
          "write:memory.claude",
          "youtube.history",
        ],
        grantVersion: "4",
      }),
    );
    const after = await store.getById(id);
    expect(after?.id).toBe(before?.id);
    expect(after?.tokenHash).toBe(before?.tokenHash);
    expect(after?.grants).toEqual([
      { grantId: "0xnew", scopes: result.grantedScopes },
    ]);
    expect(gateway.revokeGrant).toHaveBeenCalledTimes(2);
    expect(result.revokedGrantIds).toEqual(["0xold1", "0xold2"]);
    expect(result.revokeFailures).toEqual([]);
    expect(after?.scopeAccessDecision?.approvedScopes).toEqual([
      "youtube.history",
    ]);
  });

  it("narrows to a subset the same way", async () => {
    const { store, id } = await setup();
    const gateway = gatewayMock();
    const result = await setMcpConnectionAccess(
      { connectionId: id, scopes: ["instagram.*"] },
      opts(store, gateway),
    );
    expect(result.grantedScopes).toEqual(["instagram.*"]);
    expect((await store.getById(id))?.grants).toEqual([
      { grantId: "0xnew", scopes: ["instagram.*"] },
    ]);
    expect(gateway.createGrant).toHaveBeenCalledTimes(1);
    expect(gateway.revokeGrant).toHaveBeenCalledTimes(2);
  });

  it("keeps the new grant and reports a failed revoke", async () => {
    const { store, id } = await setup();
    let calls = 0;
    const gateway = gatewayMock({
      revokeImpl: async () => {
        calls += 1;
        if (calls === 1) throw new Error("gateway down");
        return {};
      },
    });
    const result = await setMcpConnectionAccess(
      { connectionId: id, scopes: ["instagram.*"] },
      opts(store, gateway),
    );
    expect(result.revokeFailures).toEqual([
      { grantId: "0xold1", error: "gateway down" },
    ]);
    expect(result.revokedGrantIds).toEqual(["0xold2"]);
    expect((await store.getById(id))?.grants[0].grantId).toBe("0xnew");
  });

  it("clears a pending request the new set covers, keeps the rest", async () => {
    const { store, id } = await setup();
    await requestMcpScopeAccess(
      { connectionId: id, scopes: ["youtube.history", "spotify.library"] },
      { store },
    );
    await setMcpConnectionAccess(
      { connectionId: id, scopes: ["instagram.*", "youtube.history"] },
      opts(store, gatewayMock()),
    );
    const after = await store.getById(id);
    expect(after?.scopeAccessRequest?.scopes).toEqual(["spotify.library"]);
    expect(after?.scopeAccessDecision).toMatchObject({
      decision: "approved",
      approvedScopes: ["youtube.history"],
      deniedScopes: ["spotify.library"],
    });

    await setMcpConnectionAccess(
      {
        connectionId: id,
        scopes: ["instagram.*", "youtube.history", "spotify.library"],
      },
      opts(store, gatewayMock()),
    );
    expect((await store.getById(id))?.scopeAccessRequest).toBeUndefined();
  });

  it.each([
    ["empty", []],
    ["not an array", "instagram.*"],
    ["system scope", ["vana.system.state"]],
    ["malformed scope", ["not a scope"]],
    ["new wildcard", ["instagram.*", "youtube.*"]],
    ["new write access", ["instagram.*", "write:memory.other"]],
  ])("rejects %s without touching the gateway", async (_name, scopes) => {
    const { store, id } = await setup();
    const gateway = gatewayMock();
    await expect(
      setMcpConnectionAccess(
        { connectionId: id, scopes },
        opts(store, gateway),
      ),
    ).rejects.toBeInstanceOf(McpScopeRequestError);
    expect(gateway.createGrant).not.toHaveBeenCalled();
    expect(gateway.revokeGrant).not.toHaveBeenCalled();
  });

  it("rejects a revoked connection", async () => {
    const { store, id } = await setup();
    await revokeMcpConnection(id, { store });
    await expect(
      setMcpConnectionAccess(
        { connectionId: id, scopes: ["instagram.*"] },
        opts(store, gatewayMock()),
      ),
    ).rejects.toBeInstanceOf(McpConnectionStateError);
  });
});
