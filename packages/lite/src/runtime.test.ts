import { describe, expect, it } from "vitest";
import {
  createBearerTokenPsLiteAuth,
  createMemoryPsLiteStorage,
  createPsLiteRuntime,
  createWeb3SignedPsLiteAuth,
} from "./runtime.js";
import {
  buildWeb3SignedHeader,
  createTestWallet,
} from "@opendatalabs/personal-server-ts-core/test-utils";

describe("createPsLiteRuntime", () => {
  it("reports ps-lite availability through health", async () => {
    const runtime = createPsLiteRuntime({
      storage: { kind: "indexeddb" },
      active: true,
      now: () => new Date("2026-05-08T00:00:00.000Z"),
    });

    const res = await runtime.fetch(new Request("https://ps.local/health"));

    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toEqual({
      status: "healthy",
      runtime: "ps-lite",
      storage: "indexeddb",
      active: true,
      checkedAt: "2026-05-08T00:00:00.000Z",
    });
  });

  it("returns PS_UNAVAILABLE while the browser runtime is inactive", async () => {
    const runtime = createPsLiteRuntime({
      storage: { kind: "opfs" },
      active: false,
    });

    const res = await runtime.fetch(
      new Request("https://ps.local/v1/data/instagram.profile"),
    );

    expect(res.status).toBe(503);
    const body = await res.json();
    expect(body.error.errorCode).toBe("PS_UNAVAILABLE");
  });

  it("does not allow unauthenticated writes while active", async () => {
    const runtime = createPsLiteRuntime({
      storage: createMemoryPsLiteStorage(),
      auth: createBearerTokenPsLiteAuth({
        ownerToken: "owner-token",
        builderToken: "builder-token",
      }),
      active: true,
    });

    const res = await runtime.fetch(
      new Request("https://ps.local/v1/data/instagram.profile", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "test_user" }),
      }),
    );

    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body.error.errorCode).toBe("MISSING_AUTH");
  });

  it("stores and reads data through the ps-lite data contract", async () => {
    const runtime = createPsLiteRuntime({
      storage: createMemoryPsLiteStorage(),
      auth: createBearerTokenPsLiteAuth({
        ownerToken: "owner-token",
        builderToken: "builder-token",
      }),
      active: true,
      now: () => new Date("2026-05-08T00:00:00.000Z"),
    });

    const write = await runtime.fetch(
      new Request("https://ps.local/v1/data/instagram.profile", {
        method: "POST",
        headers: {
          Authorization: "Bearer owner-token",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ username: "test_user" }),
      }),
    );
    expect(write.status).toBe(201);
    await expect(write.json()).resolves.toEqual({
      scope: "instagram.profile",
      collectedAt: "2026-05-08T00:00:00.000Z",
      status: "stored",
    });

    const read = await runtime.fetch(
      new Request(
        "https://ps.local/v1/data/instagram.profile?grantId=grant-1",
        {
          headers: { Authorization: "Bearer builder-token" },
        },
      ),
    );

    expect(read.status).toBe(200);
    await expect(read.json()).resolves.toMatchObject({
      version: "1.0",
      scope: "instagram.profile",
      collectedAt: "2026-05-08T00:00:00.000Z",
      data: { username: "test_user" },
    });
  });

  it("requires grantId for builder reads", async () => {
    const runtime = createPsLiteRuntime({
      storage: createMemoryPsLiteStorage(),
      auth: createBearerTokenPsLiteAuth({
        ownerToken: "owner-token",
        builderToken: "builder-token",
      }),
      active: true,
    });

    const res = await runtime.fetch(
      new Request("https://ps.local/v1/data/instagram.profile", {
        headers: { Authorization: "Bearer builder-token" },
      }),
    );

    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.error.errorCode).toBe("GRANT_REQUIRED");
  });

  it("lists scopes and versions from browser-local storage", async () => {
    const runtime = createPsLiteRuntime({
      storage: createMemoryPsLiteStorage(),
      auth: createBearerTokenPsLiteAuth({
        ownerToken: "owner-token",
        builderToken: "builder-token",
      }),
      active: true,
      now: () => new Date("2026-05-08T00:00:00.000Z"),
    });

    await runtime.fetch(
      new Request("https://ps.local/v1/data/instagram.profile", {
        method: "POST",
        headers: {
          Authorization: "Bearer owner-token",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ username: "test_user" }),
      }),
    );

    const scopes = await runtime.fetch(
      new Request("https://ps.local/v1/data", {
        headers: { Authorization: "Bearer builder-token" },
      }),
    );
    const versions = await runtime.fetch(
      new Request("https://ps.local/v1/data/instagram.profile/versions", {
        headers: { Authorization: "Bearer builder-token" },
      }),
    );

    expect(scopes.status).toBe(200);
    await expect(scopes.json()).resolves.toMatchObject({
      scopes: [
        {
          scope: "instagram.profile",
          latestCollectedAt: "2026-05-08T00:00:00.000Z",
          versionCount: 1,
        },
      ],
      total: 1,
    });

    expect(versions.status).toBe(200);
    await expect(versions.json()).resolves.toMatchObject({
      scope: "instagram.profile",
      versions: [{ collectedAt: "2026-05-08T00:00:00.000Z" }],
      total: 1,
    });
  });

  it("deletes a scope with owner auth", async () => {
    const runtime = createPsLiteRuntime({
      storage: createMemoryPsLiteStorage(),
      auth: createBearerTokenPsLiteAuth({
        ownerToken: "owner-token",
        builderToken: "builder-token",
      }),
      active: true,
      now: () => new Date("2026-05-08T00:00:00.000Z"),
    });

    await runtime.fetch(
      new Request("https://ps.local/v1/data/instagram.profile", {
        method: "POST",
        headers: {
          Authorization: "Bearer owner-token",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ username: "test_user" }),
      }),
    );

    const deleted = await runtime.fetch(
      new Request("https://ps.local/v1/data/instagram.profile", {
        method: "DELETE",
        headers: { Authorization: "Bearer owner-token" },
      }),
    );
    expect(deleted.status).toBe(204);

    const read = await runtime.fetch(
      new Request(
        "https://ps.local/v1/data/instagram.profile?grantId=grant-1",
        {
          headers: { Authorization: "Bearer builder-token" },
        },
      ),
    );
    expect(read.status).toBe(404);
  });

  it("supports Web3Signed owner writes and builder grant reads", async () => {
    const owner = createTestWallet(0);
    const builder = createTestWallet(1);
    const grantId = "grant-1";
    const runtime = createPsLiteRuntime({
      storage: createMemoryPsLiteStorage(),
      auth: createWeb3SignedPsLiteAuth({
        origin: "https://ps.local",
        ownerAddress: owner.address,
        dataReadPolicyPorts: {
          authSessionVerifier: {
            async getBuilder(address) {
              return address.toLowerCase() === builder.address.toLowerCase()
                ? {
                    id: "builder-1",
                    ownerAddress: builder.address,
                    granteeAddress: builder.address,
                    publicKey: "0x04",
                    appUrl: "https://builder.local",
                    addedAt: "2026-05-08T00:00:00.000Z",
                  }
                : null;
            },
          },
          grantVerifier: {
            async getGrant(id) {
              return id === grantId
                ? {
                    id: grantId,
                    grantorAddress: owner.address,
                    granteeId: "builder-1",
                    grant: JSON.stringify({
                      scopes: ["instagram.*"],
                      expiresAt: Math.floor(Date.now() / 1000) + 3600,
                    }),
                    fileIds: [],
                    status: "confirmed",
                    addedAt: "2026-05-08T00:00:00.000Z",
                    revokedAt: null,
                    revocationSignature: null,
                  }
                : null;
            },
          },
        },
      }),
      active: true,
      now: () => new Date("2026-05-08T00:00:00.000Z"),
    });

    const writeAuth = await buildWeb3SignedHeader({
      wallet: owner,
      aud: "https://ps.local",
      method: "POST",
      uri: "/v1/data/instagram.profile",
    });
    const write = await runtime.fetch(
      new Request("https://ps.local/v1/data/instagram.profile", {
        method: "POST",
        headers: {
          Authorization: writeAuth,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ username: "web3_user" }),
      }),
    );
    expect(write.status).toBe(201);

    const readAuth = await buildWeb3SignedHeader({
      wallet: builder,
      aud: "https://ps.local",
      method: "GET",
      uri: "/v1/data/instagram.profile",
      grantId,
    });
    const read = await runtime.fetch(
      new Request("https://ps.local/v1/data/instagram.profile", {
        headers: { Authorization: readAuth },
      }),
    );

    expect(read.status).toBe(200);
    await expect(read.json()).resolves.toMatchObject({
      data: { username: "web3_user" },
    });
  });

  it("returns SERVER_NOT_CONFIGURED when Web3Signed reads lack policy ports", async () => {
    const owner = createTestWallet(0);
    const builder = createTestWallet(1);
    const runtime = createPsLiteRuntime({
      storage: createMemoryPsLiteStorage(),
      auth: createWeb3SignedPsLiteAuth({
        origin: "https://ps.local",
        ownerAddress: owner.address,
      }),
      active: true,
    });

    const readAuth = await buildWeb3SignedHeader({
      wallet: builder,
      aud: "https://ps.local",
      method: "GET",
      uri: "/v1/data/instagram.profile",
      grantId: "grant-1",
    });
    const res = await runtime.fetch(
      new Request("https://ps.local/v1/data/instagram.profile", {
        headers: { Authorization: readAuth },
      }),
    );

    expect(res.status).toBe(500);
    const body = await res.json();
    expect(body.error.errorCode).toBe("SERVER_NOT_CONFIGURED");
  });

  it("can be activated for foreground handling", async () => {
    const runtime = createPsLiteRuntime({
      storage: { kind: "indexeddb" },
      active: false,
    });

    expect(await runtime.isAvailable()).toBe(false);
    runtime.activate();
    expect(await runtime.isAvailable()).toBe(true);
  });
});
