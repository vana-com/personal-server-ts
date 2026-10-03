import { afterEach, describe, expect, it, vi } from "vitest";
import { IDBFactory } from "fake-indexeddb";
import {
  approveMcpConnection,
  createMcpConnection,
  requestMcpScopeAccess,
} from "@opendatalabs/personal-server-ts-core/mcp";
import { createIndexedDbMcpConnectionStore } from "./mcp-store.js";

describe("IndexedDB MCP connection mutations", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("atomically preserves concurrent requests on a legacy record", async () => {
    vi.stubGlobal("indexedDB", new IDBFactory());
    const store = createIndexedDbMcpConnectionStore({
      dbName: "mcp-scope-request-concurrency",
    });
    const created = await createMcpConnection(
      { displayName: "Claude" },
      { store, publicOrigin: "https://ps.local" },
    );
    await approveMcpConnection(
      {
        connectionId: created.connectionId,
        grants: [{ grantId: "grant-1", scopes: ["instagram.profile"] }],
      },
      { store },
    );
    expect(
      (await store.getById(created.connectionId))?.scopeAccessRequest,
    ).toBeUndefined();

    await Promise.all([
      requestMcpScopeAccess(
        { connectionId: created.connectionId, scopes: ["chatgpt.history"] },
        { store },
      ),
      requestMcpScopeAccess(
        { connectionId: created.connectionId, scopes: ["spotify.profile"] },
        { store },
      ),
    ]);

    expect(
      (await store.getById(created.connectionId))?.scopeAccessRequest,
    ).toMatchObject({ scopes: ["chatgpt.history", "spotify.profile"] });
  });

  it("cannot restore a scope concurrently approved by the owner", async () => {
    vi.stubGlobal("indexedDB", new IDBFactory());
    const store = createIndexedDbMcpConnectionStore({
      dbName: "mcp-scope-request-approval-race",
    });
    const created = await createMcpConnection(
      { displayName: "Claude" },
      { store, publicOrigin: "https://ps.local" },
    );
    await approveMcpConnection(
      {
        connectionId: created.connectionId,
        grants: [{ grantId: "grant-1", scopes: ["instagram.profile"] }],
      },
      { store },
    );

    await Promise.all([
      requestMcpScopeAccess(
        { connectionId: created.connectionId, scopes: ["chatgpt.history"] },
        { store },
      ),
      approveMcpConnection(
        {
          connectionId: created.connectionId,
          grants: [
            { grantId: "grant-1", scopes: ["instagram.profile"] },
            { grantId: "grant-2", scopes: ["chatgpt.history"] },
          ],
        },
        { store },
      ),
    ]);

    expect(
      (await store.getById(created.connectionId))?.scopeAccessRequest?.scopes ??
        [],
    ).not.toContain("chatgpt.history");
  });

  it("preserves atomic request and widening changes alongside last-used updates", async () => {
    vi.stubGlobal("indexedDB", new IDBFactory());
    const store = createIndexedDbMcpConnectionStore({
      dbName: "mcp-scope-request-last-used-races",
    });
    const created = await createMcpConnection(
      { displayName: "Claude" },
      { store, publicOrigin: "https://ps.local" },
    );
    await approveMcpConnection(
      {
        connectionId: created.connectionId,
        grants: [{ grantId: "grant-1", scopes: ["instagram.profile"] }],
      },
      { store },
    );

    await Promise.all([
      requestMcpScopeAccess(
        { connectionId: created.connectionId, scopes: ["chatgpt.history"] },
        { store },
      ),
      store.update(created.connectionId, {
        lastUsedAt: "2026-09-17T20:30:00.000Z",
      }),
    ]);
    let stored = await store.getById(created.connectionId);
    expect(stored).toMatchObject({
      lastUsedAt: "2026-09-17T20:30:00.000Z",
      scopeAccessRequest: { scopes: ["chatgpt.history"] },
    });

    await Promise.all([
      approveMcpConnection(
        {
          connectionId: created.connectionId,
          grants: [
            { grantId: "grant-1", scopes: ["instagram.profile"] },
            { grantId: "grant-2", scopes: ["chatgpt.history"] },
          ],
        },
        { store },
      ),
      store.update(created.connectionId, {
        lastUsedAt: "2026-09-17T20:31:00.000Z",
      }),
    ]);
    stored = await store.getById(created.connectionId);
    expect(stored?.lastUsedAt).toBe("2026-09-17T20:31:00.000Z");
    expect(stored?.grants).toContainEqual({
      grantId: "grant-2",
      scopes: ["chatgpt.history"],
    });
    expect(stored?.scopeAccessRequest).toBeUndefined();
  });
});

describe("IndexedDB MCP token lookup", () => {
  afterEach(() => vi.unstubAllGlobals());

  const base = {
    clientId: "client-1",
    displayName: "Claude",
    status: "approved",
    grants: [{ grantId: "grant-1", scopes: ["chatgpt.conversations"] }],
    createdAt: "2026-06-01T00:00:00.000Z",
  };

  it("keeps a connection issued before token lifetimes were stored", async () => {
    vi.stubGlobal("indexedDB", new IDBFactory());
    const store = createIndexedDbMcpConnectionStore({
      dbName: "mcp-pre-expiry",
    });
    // The shape PS-Lite < 1.17 wrote: no tokenExpiresAt, no refresh token.
    await store.create({
      ...base,
      id: "legacy",
      tokenHash: "legacy-hash",
    } as never);

    expect((await store.getByTokenHash("legacy-hash"))?.id).toBe("legacy");
  });

  it("still rejects an expired token that has a stored lifetime", async () => {
    vi.stubGlobal("indexedDB", new IDBFactory());
    const store = createIndexedDbMcpConnectionStore({ dbName: "mcp-expired" });
    await store.create({
      ...base,
      id: "expired",
      tokenHash: "expired-hash",
      tokenExpiresAt: "2026-01-01T00:00:00.000Z",
    } as never);
    await store.create({
      ...base,
      id: "no-expiry-but-refresh",
      tokenHash: "refresh-shape-hash",
      refreshTokenHash: "r",
    } as never);

    expect(await store.getByTokenHash("expired-hash")).toBeNull();
    // A record with a refresh token was written by >= 1.17, so a missing
    // access expiry there still fails closed.
    expect(await store.getByTokenHash("refresh-shape-hash")).toBeNull();
  });

  it("does not resolve a revoked pre-expiry connection", async () => {
    vi.stubGlobal("indexedDB", new IDBFactory());
    const store = createIndexedDbMcpConnectionStore({
      dbName: "mcp-pre-expiry-revoked",
    });
    await store.create({
      ...base,
      id: "revoked",
      status: "revoked",
      tokenHash: "revoked-hash",
    } as never);

    expect(await store.getByTokenHash("revoked-hash")).toBeNull();
  });
});
