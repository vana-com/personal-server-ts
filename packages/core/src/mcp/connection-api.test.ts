/**
 * Tests for the owner-only MCP connection management functions
 * (`createMcpConnection`, `approveMcpConnection`, `revokeMcpConnection`)
 * + the in-memory `McpConnectionStore`.
 */

import { describe, it, expect } from "vitest";
import { createInMemoryMcpConnectionStore } from "./store.js";
import {
  approveMcpConnection,
  buildMcpUrl,
  createMcpConnection,
  hashConnectionToken,
  listMcpConnectionViews,
  McpConnectionNotFoundError,
  McpConnectionStateError,
  revokeMcpConnection,
} from "./connection-api.js";

const PUBLIC_ORIGIN = "https://example-session.relay.test";

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
});
