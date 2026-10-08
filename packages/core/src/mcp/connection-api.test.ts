/**
 * Tests for the owner-only MCP connection management functions
 * (`createMcpConnection`, `approveMcpConnection`, `revokeMcpConnection`)
 * + the in-memory `McpConnectionStore`.
 */

import { describe, it, expect, vi } from "vitest";
import {
  createInMemoryMcpConnectionStore,
  createInMemoryMcpOAuthAuthorizationStore,
} from "./store.js";
import {
  approveMcpConnection,
  approveMcpOAuthAuthorization,
  approveMcpScopeAccessRequest,
  buildStableMcpUrl,
  buildMcpUrl,
  createMcpConnection,
  createMcpOAuthAuthorization,
  denyMcpScopeAccessRequest,
  hashConnectionToken,
  listMcpConnectionViews,
  MCP_SCOPE_REQUEST_READ_TOKEN_TTL_MS,
  McpConnectionNotFoundError,
  McpConnectionStateError,
  McpScopeRequestError,
  redeemMcpOAuthAuthorizationCode,
  refreshMcpOAuthToken,
  readMcpScopeRequestWithToken,
  requestMcpScopeAccess,
  revokeMcpConnection,
  toMcpConnectionView,
} from "./connection-api.js";
import { MCP_REFRESH_TTL_MS, MCP_TOKEN_TTL_MS } from "./token-expiry.js";
import { ensureMcpGranteeRegistered } from "./builder-registration.js";

const PUBLIC_ORIGIN = "https://example-session.relay.test";
const REDIRECT_URI = "https://claude.ai/api/mcp/auth_callback";
const GATEWAY_CONFIG = {
  chainId: 14800,
  contracts: {
    dataRegistry: "0x0000000000000000000000000000000000000001",
    dataPortabilityPermissions: "0x0000000000000000000000000000000000000002",
    dataPortabilityServer: "0x0000000000000000000000000000000000000003",
    dataPortabilityGrantees: "0x0000000000000000000000000000000000000004",
  },
} as const;

async function pkceChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(verifier),
  );
  let binary = "";
  for (const byte of new Uint8Array(digest)) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/u, "");
}

describe("mcp/connection-api", () => {
  it("creates a pending connection with grantee + raw token + mcpUrl", async () => {
    const store = createInMemoryMcpConnectionStore();
    const result = await createMcpConnection(
      { displayName: "Claude" },
      { store, publicOrigin: PUBLIC_ORIGIN },
    );

    expect(result.connectionId).toMatch(/.+/);
    expect(result.granteeAddress).toMatch(/^0x[0-9a-fA-F]{40}$/);
    expect(result.connectionToken).toMatch(/^[A-Za-z0-9_-]{20,}$/);
    expect(result.mcpUrl).toBe(
      `${PUBLIC_ORIGIN}/mcp/${encodeURIComponent(result.connectionToken)}`,
    );

    const stored = await store.getById(result.connectionId);
    expect(stored).not.toBeNull();
    expect(stored?.status).toBe("pending");
    expect(stored?.grants).toEqual([]);
    // The store keeps the hash, not the raw token.
    expect(stored?.tokenHash).toBe(
      await hashConnectionToken(result.connectionToken),
    );
    // Raw token must never be persisted on the record.
    expect(JSON.stringify(stored)).not.toContain(result.connectionToken);
  });

  it("rejects token lookup until approve runs", async () => {
    const store = createInMemoryMcpConnectionStore();
    const created = await createMcpConnection(
      { displayName: "Claude" },
      { store, publicOrigin: PUBLIC_ORIGIN },
    );
    const hash = await hashConnectionToken(created.connectionToken);
    expect(await store.getByTokenHash(hash)).toBeNull();

    await approveMcpConnection(
      {
        connectionId: created.connectionId,
        grants: [{ grantId: "g1", scopes: ["instagram.*"] }],
      },
      { store },
    );

    const looked = await store.getByTokenHash(hash);
    expect(looked).not.toBeNull();
    expect(looked?.status).toBe("approved");
    expect(looked?.grants).toEqual([
      { grantId: "g1", scopes: ["instagram.*"] },
    ]);
  });

  it("requires at least one grant on approve", async () => {
    const store = createInMemoryMcpConnectionStore();
    const created = await createMcpConnection(
      {},
      { store, publicOrigin: PUBLIC_ORIGIN },
    );
    await expect(
      approveMcpConnection(
        { connectionId: created.connectionId, grants: [] },
        { store },
      ),
    ).rejects.toThrow(/at least one grant/i);
  });

  it("approve on a revoked connection throws state error", async () => {
    const store = createInMemoryMcpConnectionStore();
    const created = await createMcpConnection(
      {},
      { store, publicOrigin: PUBLIC_ORIGIN },
    );
    await revokeMcpConnection(created.connectionId, { store });
    await expect(
      approveMcpConnection(
        {
          connectionId: created.connectionId,
          grants: [{ grantId: "g1", scopes: ["instagram.*"] }],
        },
        { store },
      ),
    ).rejects.toBeInstanceOf(McpConnectionStateError);
  });

  it("approve on unknown id throws not-found", async () => {
    const store = createInMemoryMcpConnectionStore();
    await expect(
      approveMcpConnection(
        {
          connectionId: "does-not-exist",
          grants: [{ grantId: "g1", scopes: ["instagram.*"] }],
        },
        { store },
      ),
    ).rejects.toBeInstanceOf(McpConnectionNotFoundError);
  });

  it("revoke makes the token lookup return null even with a valid hash", async () => {
    const store = createInMemoryMcpConnectionStore();
    const created = await createMcpConnection(
      {},
      { store, publicOrigin: PUBLIC_ORIGIN },
    );
    await approveMcpConnection(
      {
        connectionId: created.connectionId,
        grants: [{ grantId: "g1", scopes: ["instagram.*"] }],
      },
      { store },
    );
    const hash = await hashConnectionToken(created.connectionToken);
    expect(await store.getByTokenHash(hash)).not.toBeNull();

    const revoked = await revokeMcpConnection(created.connectionId, { store });
    expect(revoked.status).toBe("revoked");
    expect(revoked.revokedAt).toBeDefined();

    expect(await store.getByTokenHash(hash)).toBeNull();
  });

  it("listMcpConnectionViews omits private fields", async () => {
    const store = createInMemoryMcpConnectionStore();
    const created = await createMcpConnection(
      { displayName: "Claude" },
      { store, publicOrigin: PUBLIC_ORIGIN },
    );
    const views = await listMcpConnectionViews(store);
    expect(views).toHaveLength(1);
    const [view] = views;
    expect(view.id).toBe(created.connectionId);
    expect(view.displayName).toBe("Claude");
    expect(view.granteeAddress).toBe(created.granteeAddress);
    expect("encryptedGranteePrivateKey" in view).toBe(false);
    expect("tokenHash" in view).toBe(false);
  });

  it("persists an owner-reviewable scope request and clears fulfilled scopes on widening", async () => {
    const store = createInMemoryMcpConnectionStore();
    const created = await createMcpConnection(
      { displayName: "Claude" },
      { store, publicOrigin: PUBLIC_ORIGIN },
    );
    await approveMcpConnection(
      {
        connectionId: created.connectionId,
        grants: [{ grantId: "g1", scopes: ["instagram.profile"] }],
      },
      { store },
    );

    await requestMcpScopeAccess(
      {
        connectionId: created.connectionId,
        scopes: ["chatgpt.history", "spotify.profile"],
        reason: "Answer from prior chats and music.",
      },
      { store, now: () => new Date("2026-09-17T20:30:00.000Z") },
    );
    expect(
      (await listMcpConnectionViews(store))[0]?.scopeAccessRequest,
    ).toEqual({
      scopes: ["chatgpt.history", "spotify.profile"],
      reason: "Answer from prior chats and music.",
      requestedAt: "2026-09-17T20:30:00.000Z",
    });

    await approveMcpConnection(
      {
        connectionId: created.connectionId,
        grants: [
          { grantId: "g1", scopes: ["instagram.profile"] },
          { grantId: "g2", scopes: ["chatgpt.*"] },
        ],
      },
      { store },
    );
    expect(
      (await listMcpConnectionViews(store))[0]?.scopeAccessRequest,
    ).toEqual({
      scopes: ["spotify.profile"],
      reason: "Answer from prior chats and music.",
      requestedAt: "2026-09-17T20:30:00.000Z",
    });

    await requestMcpScopeAccess(
      {
        connectionId: created.connectionId,
        scopes: ["chatgpt.history", "github.profile"],
      },
      { store, now: () => new Date("2026-09-17T20:31:00.000Z") },
    );
    expect(
      (await listMcpConnectionViews(store))[0]?.scopeAccessRequest,
    ).toEqual({
      scopes: ["github.profile", "spotify.profile"],
      reason: "Answer from prior chats and music.",
      requestedAt: "2026-09-17T20:31:00.000Z",
    });

    await revokeMcpConnection(created.connectionId, { store });
    await expect(
      requestMcpScopeAccess(
        { connectionId: created.connectionId, scopes: ["github.repositories"] },
        { store },
      ),
    ).rejects.toBeInstanceOf(McpConnectionStateError);
  });

  it("keeps the existing request unchanged when the aggregate scope limit would be exceeded", async () => {
    const store = createInMemoryMcpConnectionStore();
    const created = await createMcpConnection(
      { displayName: "Claude" },
      { store, publicOrigin: PUBLIC_ORIGIN },
    );
    await approveMcpConnection(
      {
        connectionId: created.connectionId,
        grants: [{ grantId: "g1", scopes: ["instagram.profile"] }],
      },
      { store },
    );
    const firstScopes = Array.from(
      { length: 20 },
      (_, index) => `source.scope-${String(index).padStart(2, "0")}`,
    );
    await expect(
      requestMcpScopeAccess(
        { connectionId: created.connectionId, scopes: firstScopes },
        { store },
      ),
    ).resolves.toMatchObject({
      requestRecorded: true,
      connection: { scopeAccessRequest: { scopes: firstScopes } },
    });

    await expect(
      requestMcpScopeAccess(
        {
          connectionId: created.connectionId,
          scopes: ["source.scope-overflow"],
        },
        { store },
      ),
    ).resolves.toMatchObject({ requestRecorded: false });
    expect(
      (await store.getById(created.connectionId))?.scopeAccessRequest,
    ).toMatchObject({ scopes: firstScopes });
  });

  it("buildMcpUrl trims trailing slash on origin", () => {
    expect(buildMcpUrl("https://x.relay.test/", "abc")).toBe(
      "https://x.relay.test/mcp/abc",
    );
  });

  it("buildStableMcpUrl trims trailing slash on origin", () => {
    expect(buildStableMcpUrl("https://x.relay.test/")).toBe(
      "https://x.relay.test/mcp",
    );
  });

  it("creates, approves, and redeems an OAuth authorization for stable /mcp", async () => {
    const connectionStore = createInMemoryMcpConnectionStore();
    const authorizationStore = createInMemoryMcpOAuthAuthorizationStore();
    const codeVerifier = "correct-horse-battery-staple";
    const created = await createMcpOAuthAuthorization(
      {
        clientId: "claude-client",
        redirectUri: REDIRECT_URI,
        codeChallenge: await pkceChallenge(codeVerifier),
        codeChallengeMethod: "S256",
        scope: "vana:read",
        state: "state-123",
      },
      {
        connectionStore,
        authorizationStore,
        publicOrigin: PUBLIC_ORIGIN,
      },
    );

    const pending = await authorizationStore.getById(created.authorizationId);
    expect(pending?.status).toBe("pending");
    expect(JSON.stringify(pending)).not.toContain("connectionToken");
    expect(await connectionStore.getById(created.connectionId)).toMatchObject({
      status: "pending",
      granteeAddress: created.granteeAddress,
    });

    const approved = await approveMcpOAuthAuthorization(
      {
        authorizationId: created.authorizationId,
        grants: [{ grantId: "grant-1", scopes: ["chatgpt.history"] }],
      },
      { connectionStore, authorizationStore },
    );
    const redirect = new URL(approved.redirectTo);
    expect(`${redirect.origin}${redirect.pathname}`).toBe(REDIRECT_URI);
    expect(redirect.searchParams.get("state")).toBe("state-123");
    expect(redirect.searchParams.get("code")).toBe(approved.authorizationCode);

    const token = await redeemMcpOAuthAuthorizationCode(
      {
        authorizationCode: approved.authorizationCode,
        codeVerifier,
        clientId: "claude-client",
        redirectUri: REDIRECT_URI,
      },
      { authorizationStore, connectionStore },
    );
    expect(token.scope).toBe("vana:read");
    expect(token.accessToken).toMatch(/^[A-Za-z0-9_-]{20,}$/);
    expect(
      JSON.stringify(await authorizationStore.getById(created.authorizationId)),
    ).not.toContain(token.accessToken);

    const tokenHash = await hashConnectionToken(token.accessToken);
    const connection = await connectionStore.getByTokenHash(tokenHash);
    expect(connection?.status).toBe("approved");
    expect(connection?.grants).toEqual([
      { grantId: "grant-1", scopes: ["chatgpt.history"] },
    ]);

    await expect(
      redeemMcpOAuthAuthorizationCode(
        {
          authorizationCode: approved.authorizationCode,
          codeVerifier,
          clientId: "claude-client",
          redirectUri: REDIRECT_URI,
        },
        { authorizationStore, connectionStore },
      ),
    ).rejects.toThrow(/already been used/i);
  });

  it("expires the redeemed bearer after the TTL and fails closed without one", async () => {
    const connectionStore = createInMemoryMcpConnectionStore();
    const authorizationStore = createInMemoryMcpOAuthAuthorizationStore();
    const codeVerifier = "correct-horse-battery-staple";

    // Redeem far enough in the past that the minted expiry has already passed.
    const stale = await redeemAt(
      new Date(Date.now() - MCP_TOKEN_TTL_MS - 60_000),
    );
    expect(stale.token.expiresIn).toBe(MCP_TOKEN_TTL_MS / 1000);
    expect(
      await connectionStore.getByTokenHash(
        await hashConnectionToken(stale.token.accessToken),
      ),
    ).toBeNull();

    // A fresh redeem stamps issue + TTL and resolves.
    const issuedAt = new Date();
    const fresh = await redeemAt(issuedAt);
    const hash = await hashConnectionToken(fresh.token.accessToken);
    expect(await connectionStore.getByTokenHash(hash)).toMatchObject({
      tokenExpiresAt: new Date(
        issuedAt.getTime() + MCP_TOKEN_TTL_MS,
      ).toISOString(),
    });

    // A record from before the field existed is expired on read, not forever.
    await connectionStore.update(fresh.connectionId, {
      tokenExpiresAt: undefined,
    });
    expect(await connectionStore.getByTokenHash(hash)).toBeNull();

    async function redeemAt(now: Date) {
      const created = await createMcpOAuthAuthorization(
        {
          clientId: "claude-client",
          redirectUri: REDIRECT_URI,
          codeChallenge: await pkceChallenge(codeVerifier),
          codeChallengeMethod: "S256",
        },
        { connectionStore, authorizationStore, publicOrigin: PUBLIC_ORIGIN },
      );
      const approved = await approveMcpOAuthAuthorization(
        {
          authorizationId: created.authorizationId,
          grants: [{ grantId: "grant-1", scopes: ["chatgpt.history"] }],
        },
        { connectionStore, authorizationStore },
      );
      const token = await redeemMcpOAuthAuthorizationCode(
        {
          authorizationCode: approved.authorizationCode,
          codeVerifier,
          clientId: "claude-client",
          redirectUri: REDIRECT_URI,
        },
        { authorizationStore, connectionStore, now: () => now },
      );
      return { token, connectionId: created.connectionId };
    }
  });

  it("self-registers the generated MCP grantee when it is missing", async () => {
    const store = createInMemoryMcpConnectionStore();
    const created = await createMcpConnection(
      { displayName: "MCP client" },
      { store, publicOrigin: PUBLIC_ORIGIN },
    );
    const connection = await store.getById(created.connectionId);
    expect(connection).not.toBeNull();

    const getBuilder = vi.fn().mockResolvedValue(null);
    const fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ success: true, builderId: "0xbuilder" }), {
        status: 201,
      }),
    );

    await ensureMcpGranteeRegistered({
      connection: connection!,
      gateway: { getBuilder },
      gatewayConfig: GATEWAY_CONFIG,
      gatewayUrl: "https://gateway.test/",
      appUrl: "https://mcp-client.test",
      fetch,
    });

    expect(getBuilder).toHaveBeenCalledWith(connection!.granteeAddress);
    expect(fetch).toHaveBeenCalledOnce();
    const [url, init] = fetch.mock.calls[0]!;
    expect(url).toBe("https://gateway.test/v1/builders");
    expect((init as RequestInit).method).toBe("POST");
    expect(
      ((init as RequestInit).headers as Record<string, string>).authorization,
    ).toMatch(/^Web3Signed 0x[0-9a-fA-F]{130}$/);
    expect(JSON.parse((init as RequestInit).body as string)).toEqual({
      ownerAddress: connection!.granteeAddress,
      granteeAddress: connection!.granteeAddress,
      publicKey: connection!.granteePublicKey,
      appUrl: "https://mcp-client.test",
    });
  });
});

describe("mcp/connection-api refresh grant", () => {
  const CLIENT_ID = "claude-client";
  const CODE_VERIFIER = "correct-horse-battery-staple";

  it("redeem issues an access/refresh pair with a 1 h access TTL", async () => {
    const { token } = await connect();

    expect(token.expiresIn).toBe(3600);
    expect(MCP_TOKEN_TTL_MS).toBe(3600 * 1000);
    expect(token.refreshToken).toMatch(/^[A-Za-z0-9_-]{20,}$/);
    expect(token.refreshToken).not.toBe(token.accessToken);
  });

  it("rotates the pair and retires the presented refresh token", async () => {
    const { connectionStore, token } = await connect();

    const rotated = await refreshMcpOAuthToken(
      { refreshToken: token.refreshToken, clientId: CLIENT_ID },
      { connectionStore },
    );
    expect(rotated.accessToken).not.toBe(token.accessToken);
    expect(rotated.refreshToken).not.toBe(token.refreshToken);

    // The new bearer resolves, and the new refresh token rotates again.
    expect(
      await connectionStore.getByTokenHash(
        await hashConnectionToken(rotated.accessToken),
      ),
    ).toMatchObject({ status: "approved" });
    await expect(
      refreshMcpOAuthToken(
        { refreshToken: rotated.refreshToken, clientId: CLIENT_ID },
        { connectionStore },
      ),
    ).resolves.toMatchObject({ expiresIn: 3600 });
  });

  it("revokes the whole family when a rotated-out refresh token is replayed", async () => {
    const { connectionStore, token } = await connect();

    const rotated = await refreshMcpOAuthToken(
      { refreshToken: token.refreshToken, clientId: CLIENT_ID },
      { connectionStore },
    );
    await expect(
      refreshMcpOAuthToken(
        { refreshToken: token.refreshToken, clientId: CLIENT_ID },
        { connectionStore },
      ),
    ).rejects.toThrow(/already rotated/i);

    // Reuse detection kills the live refresh token too...
    await expect(
      refreshMcpOAuthToken(
        { refreshToken: rotated.refreshToken, clientId: CLIENT_ID },
        { connectionStore },
      ),
    ).rejects.toThrow(/unknown/i);

    // ...but leaves the access token to its own expiry.
    expect(
      await connectionStore.getByTokenHash(
        await hashConnectionToken(rotated.accessToken),
      ),
    ).toMatchObject({ status: "approved" });
  });

  it("rejects a refresh token that is mismatched, expired, or revoked", async () => {
    const { connectionStore, connectionId, token } = await connect();

    await expect(
      refreshMcpOAuthToken(
        { refreshToken: token.refreshToken, clientId: "someone-else" },
        { connectionStore },
      ),
    ).rejects.toThrow(/client_id does not match/i);

    const afterTtl = new Date(Date.now() + MCP_REFRESH_TTL_MS + 60_000);
    await expect(
      refreshMcpOAuthToken(
        { refreshToken: token.refreshToken, clientId: CLIENT_ID },
        { connectionStore, now: () => afterTtl },
      ),
    ).rejects.toThrow(/expired/i);

    await revokeMcpConnection(connectionId, { store: connectionStore });
    await expect(
      refreshMcpOAuthToken(
        { refreshToken: token.refreshToken, clientId: CLIENT_ID },
        { connectionStore },
      ),
    ).rejects.toThrow(/unknown/i);
  });

  /** Full authorize → approve → redeem, returning the first token pair. */
  async function connect() {
    const connectionStore = createInMemoryMcpConnectionStore();
    const authorizationStore = createInMemoryMcpOAuthAuthorizationStore();
    const created = await createMcpOAuthAuthorization(
      {
        clientId: CLIENT_ID,
        redirectUri: REDIRECT_URI,
        codeChallenge: await pkceChallenge(CODE_VERIFIER),
        codeChallengeMethod: "S256",
      },
      { connectionStore, authorizationStore, publicOrigin: PUBLIC_ORIGIN },
    );
    const approved = await approveMcpOAuthAuthorization(
      {
        authorizationId: created.authorizationId,
        grants: [{ grantId: "grant-1", scopes: ["chatgpt.history"] }],
      },
      { connectionStore, authorizationStore },
    );
    const token = await redeemMcpOAuthAuthorizationCode(
      {
        authorizationCode: approved.authorizationCode,
        codeVerifier: CODE_VERIFIER,
        clientId: CLIENT_ID,
        redirectUri: REDIRECT_URI,
      },
      { authorizationStore, connectionStore },
    );
    return { connectionStore, connectionId: created.connectionId, token };
  }
});

describe("mcp/connection-api scope request answers", () => {
  const OWNER = "0x00000000000000000000000000000000000000aa" as const;
  const REQUESTED_AT = "2026-10-07T10:00:00.000Z";
  const DECIDED_AT = "2026-10-07T10:05:00.000Z";

  function liveGrant(overrides: Record<string, unknown> = {}) {
    return {
      id: "0xgrant1",
      scopes: ["instagram.profile"],
      grantVersion: "3",
      expiresAt: null,
      revokedAt: null,
      ...overrides,
    };
  }

  function gatewayMock(live: Record<string, unknown> | null = liveGrant()) {
    return {
      getBuilder: vi.fn(async () => ({ id: "0xbuilder" })),
      getGrant: vi.fn(async () => live),
      createGrant: vi.fn(async () => ({ grantId: "0xgrant2" })),
    };
  }

  const serverSigner = {
    signGrantRegistration: vi.fn(async () => "0xsig" as `0x${string}`),
  };

  async function connectionWithRequest(
    grants = [{ grantId: "0xgrant1", scopes: ["instagram.profile"] }],
    requested = ["chatgpt.conversations", "spotify.profile"],
  ) {
    const store = createInMemoryMcpConnectionStore();
    const created = await createMcpConnection(
      { displayName: "Claude" },
      { store, publicOrigin: PUBLIC_ORIGIN },
    );
    await approveMcpConnection(
      { connectionId: created.connectionId, grants },
      { store },
    );
    await requestMcpScopeAccess(
      {
        connectionId: created.connectionId,
        scopes: requested,
        reason: "Answer from chats and music.",
      },
      { store, now: () => new Date(REQUESTED_AT) },
    );
    return { store, id: created.connectionId, grantee: created.granteeAddress };
  }

  function approveOptions(
    store: ReturnType<typeof createInMemoryMcpConnectionStore>,
    gateway: ReturnType<typeof gatewayMock>,
  ) {
    return {
      store,
      gateway: gateway as never,
      serverOwner: OWNER,
      serverSigner,
      now: () => new Date(DECIDED_AT),
    };
  }

  it("re-signs the union of existing and approved scopes, never dropping one", async () => {
    const { store, id, grantee } = await connectionWithRequest();
    // The gateway grant holds a scope this record never saw; it must survive.
    const gateway = gatewayMock(
      liveGrant({ scopes: ["instagram.profile", "github.profile"] }),
    );

    const result = await approveMcpScopeAccessRequest(
      { connectionId: id, scopes: ["spotify.profile"] },
      approveOptions(store, gateway),
    );

    expect(gateway.getGrant).toHaveBeenCalledWith("0xgrant1");
    expect(gateway.createGrant).toHaveBeenCalledWith(
      expect.objectContaining({
        grantorAddress: OWNER,
        granteeId: "0xbuilder",
        scopes: ["github.profile", "instagram.profile", "spotify.profile"],
        grantVersion: "4",
        expiresAt: "0",
      }),
    );
    expect(gateway.getBuilder).toHaveBeenCalledWith(grantee);
    expect(result.grantedScopes).toEqual([
      "github.profile",
      "instagram.profile",
      "spotify.profile",
    ]);
    expect(result.approvedScopes).toEqual(["spotify.profile"]);
    expect(result.deniedScopes).toEqual(["chatgpt.conversations"]);

    const [view] = await listMcpConnectionViews(store);
    expect(view?.grants).toEqual([
      {
        grantId: "0xgrant2",
        scopes: ["github.profile", "instagram.profile", "spotify.profile"],
      },
    ]);
    expect(view?.grantedScopes).toEqual(result.grantedScopes);
    expect(view?.scopeAccessRequest).toBeUndefined();
    expect(view?.scopeAccessDecision).toEqual({
      decision: "approved",
      approvedScopes: ["spotify.profile"],
      deniedScopes: ["chatgpt.conversations"],
      requestedAt: REQUESTED_AT,
      decidedAt: DECIDED_AT,
    });
  });

  it("keeps every grant's scopes when the connection holds several", async () => {
    const { store, id } = await connectionWithRequest([
      { grantId: "0xgrant1", scopes: ["instagram.profile"] },
      { grantId: "0xgrant1b", scopes: ["chatgpt.*"] },
    ]);
    const gateway = gatewayMock();
    gateway.getGrant.mockImplementation(async (grantId: string) =>
      grantId === "0xgrant1b"
        ? liveGrant({ id: grantId, scopes: ["chatgpt.*"], grantVersion: "7" })
        : liveGrant(),
    );

    const result = await approveMcpScopeAccessRequest(
      { connectionId: id, scopes: ["spotify.profile"] },
      approveOptions(store, gateway),
    );

    expect(result.grantedScopes).toEqual([
      "chatgpt.*",
      "instagram.profile",
      "spotify.profile",
    ]);
    expect(gateway.createGrant).toHaveBeenCalledWith(
      expect.objectContaining({ grantVersion: "8" }),
    );
  });

  it("does not resurrect scopes of a grant the owner already revoked", async () => {
    const { store, id } = await connectionWithRequest();
    const gateway = gatewayMock(
      liveGrant({ revokedAt: "2026-10-01T00:00:00.000Z", grantVersion: "5" }),
    );

    const result = await approveMcpScopeAccessRequest(
      { connectionId: id, scopes: ["spotify.profile"] },
      approveOptions(store, gateway),
    );

    expect(result.grantedScopes).toEqual(["spotify.profile"]);
    expect(gateway.createGrant).toHaveBeenCalledWith(
      expect.objectContaining({
        scopes: ["spotify.profile"],
        grantVersion: "6",
      }),
    );
  });

  it("keeps the live grant's expiry instead of making it perpetual", async () => {
    const { store, id } = await connectionWithRequest();
    const gateway = gatewayMock(liveGrant({ expiresAt: "1900000000" }));

    await approveMcpScopeAccessRequest(
      { connectionId: id, scopes: ["spotify.profile"] },
      approveOptions(store, gateway),
    );

    expect(gateway.createGrant).toHaveBeenCalledWith(
      expect.objectContaining({ expiresAt: "1900000000" }),
    );
  });

  it("rejects scopes outside the pending request or malformed, without signing", async () => {
    const { store, id } = await connectionWithRequest();
    const gateway = gatewayMock();

    for (const [scopes, code] of [
      [["github.profile"], "SCOPE_NOT_REQUESTED"],
      [["not a scope"], "INVALID_SCOPE"],
      [[], "SCOPES_REQUIRED"],
      [undefined, "SCOPES_REQUIRED"],
    ] as const) {
      await expect(
        approveMcpScopeAccessRequest(
          { connectionId: id, scopes },
          approveOptions(store, gateway),
        ),
      ).rejects.toMatchObject({ code, status: 400 });
    }
    expect(gateway.createGrant).not.toHaveBeenCalled();
    expect((await store.getById(id))?.scopeAccessRequest?.scopes).toEqual([
      "chatgpt.conversations",
      "spotify.profile",
    ]);
  });

  it("leaves the request pending when the gateway refuses the grant", async () => {
    const { store, id } = await connectionWithRequest();
    const gateway = gatewayMock();
    gateway.createGrant.mockRejectedValue(new Error("gateway down"));

    await expect(
      approveMcpScopeAccessRequest(
        { connectionId: id, scopes: ["spotify.profile"] },
        approveOptions(store, gateway),
      ),
    ).rejects.toMatchObject({ code: "GRANT_CREATION_FAILED", status: 502 });
    const stored = await store.getById(id);
    expect(stored?.scopeAccessRequest).toBeDefined();
    expect(stored?.grants).toEqual([
      { grantId: "0xgrant1", scopes: ["instagram.profile"] },
    ]);
  });

  it("refuses to store a grant signed over grants that changed meanwhile", async () => {
    const { store, id } = await connectionWithRequest();
    const gateway = gatewayMock();
    gateway.createGrant.mockImplementation(async () => {
      // Another approval widened the connection during the gateway call.
      await store.update(id, {
        grants: [{ grantId: "0xgrant1", scopes: ["github.profile"] }],
      });
      return { grantId: "0xgrant2" };
    });

    await expect(
      approveMcpScopeAccessRequest(
        { connectionId: id, scopes: ["spotify.profile"] },
        approveOptions(store, gateway),
      ),
    ).rejects.toMatchObject({ code: "CONCURRENT_UPDATE", status: 409 });
    expect((await store.getById(id))?.grants).toEqual([
      { grantId: "0xgrant1", scopes: ["github.profile"] },
    ]);
  });

  it("deny clears the request and records the denial", async () => {
    const { store, id } = await connectionWithRequest();

    const denied = await denyMcpScopeAccessRequest(
      { connectionId: id },
      { store, now: () => new Date(DECIDED_AT) },
    );

    expect(denied.scopeAccessRequest).toBeUndefined();
    expect(denied.grants).toEqual([
      { grantId: "0xgrant1", scopes: ["instagram.profile"] },
    ]);
    expect(denied.scopeAccessDecision).toEqual({
      decision: "denied",
      approvedScopes: [],
      deniedScopes: ["chatgpt.conversations", "spotify.profile"],
      requestedAt: REQUESTED_AT,
      decidedAt: DECIDED_AT,
    });
  });

  it("refuses to answer when nothing is pending", async () => {
    const { store, id } = await connectionWithRequest();
    await denyMcpScopeAccessRequest({ connectionId: id }, { store });
    const gateway = gatewayMock();

    await expect(
      denyMcpScopeAccessRequest({ connectionId: id }, { store }),
    ).rejects.toMatchObject({ code: "NO_PENDING_REQUEST", status: 409 });
    const approve = approveMcpScopeAccessRequest(
      { connectionId: id, scopes: ["spotify.profile"] },
      approveOptions(store, gateway),
    );
    await expect(approve).rejects.toBeInstanceOf(McpScopeRequestError);
    await expect(approve).rejects.toMatchObject({ code: "NO_PENDING_REQUEST" });
    expect(gateway.createGrant).not.toHaveBeenCalled();
  });

  it("throws not-found for an unknown connection", async () => {
    const store = createInMemoryMcpConnectionStore();
    await expect(
      approveMcpScopeAccessRequest(
        { connectionId: "nope", scopes: ["spotify.profile"] },
        approveOptions(store, gatewayMock()),
      ),
    ).rejects.toBeInstanceOf(McpConnectionNotFoundError);
    await expect(
      denyMcpScopeAccessRequest({ connectionId: "nope" }, { store }),
    ).rejects.toBeInstanceOf(McpConnectionNotFoundError);
  });
});

describe("mcp/connection-api scope request read token", () => {
  const T0 = new Date("2026-10-07T10:00:00.000Z");

  async function connectionWithRequest() {
    const store = createInMemoryMcpConnectionStore();
    const created = await createMcpConnection(
      { displayName: "Claude" },
      { store, publicOrigin: PUBLIC_ORIGIN },
    );
    await approveMcpConnection(
      {
        connectionId: created.connectionId,
        grants: [{ grantId: "g1", scopes: ["instagram.profile"] }],
      },
      { store },
    );
    const requested = await requestMcpScopeAccess(
      {
        connectionId: created.connectionId,
        scopes: ["chatgpt.history", "spotify.profile"],
        reason: "Answer from prior chats and music.",
      },
      { store, now: () => T0 },
    );
    return { store, connectionId: created.connectionId, requested };
  }

  it("mints a 256-bit token, returns it once and stores only its hash", async () => {
    const { store, connectionId, requested } = await connectionWithRequest();
    expect(requested.readToken).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    const record = await store.getById(connectionId);
    expect(record?.scopeAccessRequest?.readTokenHash).toBe(
      await hashConnectionToken(requested.readToken ?? ""),
    );
    expect(record?.scopeAccessRequest?.readTokenExpiresAt).toBe(
      new Date(
        T0.getTime() + MCP_SCOPE_REQUEST_READ_TOKEN_TTL_MS,
      ).toISOString(),
    );
    expect(JSON.stringify(record)).not.toContain(requested.readToken);
    // Owner views never carry the hash or expiry.
    expect(toMcpConnectionView(record!).scopeAccessRequest).not.toHaveProperty(
      "readTokenHash",
    );
  });

  it("reads a minimal view with the token until it expires", async () => {
    const { store, connectionId, requested } = await connectionWithRequest();
    const read = (at: number, token = requested.readToken) =>
      readMcpScopeRequestWithToken(
        { connectionId, token },
        { store, now: () => new Date(at) },
      );
    const view = await read(T0.getTime());
    expect(view).toEqual({
      id: connectionId,
      displayName: "Claude",
      scopeAccessRequest: {
        scopes: ["chatgpt.history", "spotify.profile"],
        reason: "Answer from prior chats and music.",
        requestedAt: T0.toISOString(),
      },
      grantedScopes: ["instagram.profile"],
    });
    const expiry = T0.getTime() + MCP_SCOPE_REQUEST_READ_TOKEN_TTL_MS;
    expect(await read(expiry - 1)).not.toBeNull();
    expect(await read(expiry)).toBeNull();
    expect(await read(T0.getTime(), "")).toBeNull();
    expect(await read(T0.getTime(), null as unknown as string)).toBeNull();
    expect(await read(T0.getTime(), "wrong")).toBeNull();
  });

  it("dies when the request is denied, narrowed, replaced, or the connection is revoked", async () => {
    const denied = await connectionWithRequest();
    await denyMcpScopeAccessRequest(
      { connectionId: denied.connectionId },
      { store: denied.store },
    );
    expect(
      await readMcpScopeRequestWithToken(
        {
          connectionId: denied.connectionId,
          token: denied.requested.readToken,
        },
        { store: denied.store, now: () => T0 },
      ),
    ).toBeNull();

    const narrowed = await connectionWithRequest();
    await approveMcpConnection(
      {
        connectionId: narrowed.connectionId,
        grants: [
          { grantId: "g1", scopes: ["instagram.profile"] },
          { grantId: "g2", scopes: ["chatgpt.*"] },
        ],
      },
      { store: narrowed.store },
    );
    const narrowedRecord = await narrowed.store.getById(narrowed.connectionId);
    expect(narrowedRecord?.scopeAccessRequest?.scopes).toEqual([
      "spotify.profile",
    ]);
    expect(narrowedRecord?.scopeAccessRequest?.readTokenHash).toBeUndefined();

    const replaced = await connectionWithRequest();
    const again = await requestMcpScopeAccess(
      { connectionId: replaced.connectionId, scopes: ["github.profile"] },
      { store: replaced.store, now: () => T0 },
    );
    expect(again.readToken).toBeDefined();
    expect(again.readToken).not.toBe(replaced.requested.readToken);
    const readReplaced = (token?: string) =>
      readMcpScopeRequestWithToken(
        { connectionId: replaced.connectionId, token },
        { store: replaced.store, now: () => T0 },
      );
    expect(await readReplaced(replaced.requested.readToken)).toBeNull();
    expect(await readReplaced(again.readToken)).not.toBeNull();

    await revokeMcpConnection(replaced.connectionId, { store: replaced.store });
    expect(await readReplaced(again.readToken)).toBeNull();
  });

  it("returns no token when the request is not rewritten, and the old one keeps working", async () => {
    const { store, connectionId, requested } = await connectionWithRequest();
    const tooMany = Array.from({ length: 30 }, (_, i) => `github.repo${i}`);
    const outcome = await requestMcpScopeAccess(
      { connectionId, scopes: tooMany },
      { store, now: () => T0 },
    );
    expect(outcome.requestRecorded).toBe(false);
    expect(outcome.readToken).toBeUndefined();
    expect(
      await readMcpScopeRequestWithToken(
        { connectionId, token: requested.readToken },
        { store, now: () => T0 },
      ),
    ).not.toBeNull();
  });
});
