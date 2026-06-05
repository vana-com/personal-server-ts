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
  buildStableMcpUrl,
  buildMcpUrl,
  createMcpConnection,
  createMcpOAuthAuthorization,
  hashConnectionToken,
  listMcpConnectionViews,
  McpConnectionNotFoundError,
  McpConnectionStateError,
  redeemMcpOAuthAuthorizationCode,
  revokeMcpConnection,
} from "./connection-api.js";
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
