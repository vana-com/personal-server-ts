import { describe, it, expect } from "vitest";
import {
  buildMcpSessionConnection,
  createInMemoryMcpProofReplayStore,
  createInMemoryMcpSessionStore,
  createMcpSession,
  createMcpSessionAuthPort,
} from "./session.js";
import { hashConnectionToken } from "./connection-api.js";
import type {
  AuthSessionVerifierPort,
  GrantVerifierPort,
} from "../ports/index.js";

const BUILDER = "0xabc0000000000000000000000000000000000001" as const;
const OTHER = "0xdef0000000000000000000000000000000000002" as const;

function grant(overrides: Record<string, unknown> = {}) {
  return {
    id: "grant_1",
    granteeId: BUILDER,
    scopes: ["instagram.profile"],
    revokedAt: null,
    expiresAt: null,
    ...overrides,
  };
}

// Minimal fakes for the two ports verifyDataReadPolicy/createMcpSession use.
function fakeGateway(
  grantValue: unknown,
  builderId: string | null = BUILDER,
): AuthSessionVerifierPort & GrantVerifierPort {
  return {
    getBuilder: async () => (builderId ? { id: builderId } : null),
    getGrant: async () => grantValue,
  } as unknown as AuthSessionVerifierPort & GrantVerifierPort;
}

describe("createMcpSession", () => {
  it("mints a token for a valid builder + grant and stores it by hash", async () => {
    const store = createInMemoryMcpSessionStore();
    const gw = fakeGateway(grant());
    const result = await createMcpSession(
      { builderAddress: BUILDER, grantId: "grant_1" },
      {
        store,
        authSessionVerifier: gw,
        grantVerifier: gw,
        randomToken: () => "tok_test",
      },
    );
    expect(result.accessToken).toBe("tok_test");
    expect(result.grantId).toBe("grant_1");
    expect(result.scopes).toEqual(["instagram.profile"]);
    const rec = await store.getByTokenHash(
      await hashConnectionToken("tok_test"),
    );
    expect(rec?.builderAddress).toBe(BUILDER);
    expect(rec?.grantId).toBe("grant_1");
  });

  it("rejects an unregistered builder", async () => {
    const gw = fakeGateway(grant(), null);
    await expect(
      createMcpSession(
        { builderAddress: BUILDER, grantId: "grant_1" },
        {
          store: createInMemoryMcpSessionStore(),
          authSessionVerifier: gw,
          grantVerifier: gw,
          randomToken: () => "t",
        },
      ),
    ).rejects.toThrow();
  });

  it("rejects a grant not owned by the builder", async () => {
    const gw = fakeGateway(grant({ granteeId: OTHER }));
    await expect(
      createMcpSession(
        { builderAddress: BUILDER, grantId: "grant_1" },
        {
          store: createInMemoryMcpSessionStore(),
          authSessionVerifier: gw,
          grantVerifier: gw,
          randomToken: () => "t",
        },
      ),
    ).rejects.toThrow();
  });

  it("rejects a revoked grant", async () => {
    const gw = fakeGateway(grant({ revokedAt: "2020-01-01T00:00:00Z" }));
    await expect(
      createMcpSession(
        { builderAddress: BUILDER, grantId: "grant_1" },
        {
          store: createInMemoryMcpSessionStore(),
          authSessionVerifier: gw,
          grantVerifier: gw,
          randomToken: () => "t",
        },
      ),
    ).rejects.toThrow();
  });

  it("rejects a replayed handshake proof (same proof id, still live)", async () => {
    const gw = fakeGateway(grant());
    const opts = {
      store: createInMemoryMcpSessionStore(),
      authSessionVerifier: gw,
      grantVerifier: gw,
      randomToken: () => "tok",
      replayStore: createInMemoryMcpProofReplayStore(),
    };
    const input = {
      builderAddress: BUILDER,
      grantId: "grant_1",
      proof: { id: "proof-abc", expiresAtMs: Date.now() + 60_000 },
    };
    // First use mints a token.
    await expect(createMcpSession(input, opts)).resolves.toMatchObject({
      grantId: "grant_1",
    });
    // Replaying the same proof id is rejected instead of minting a second token.
    await expect(createMcpSession(input, opts)).rejects.toThrow(
      /already used/i,
    );
  });

  it("allows a fresh proof id after a prior one was consumed", async () => {
    const gw = fakeGateway(grant());
    const replayStore = createInMemoryMcpProofReplayStore();
    const base = {
      store: createInMemoryMcpSessionStore(),
      authSessionVerifier: gw,
      grantVerifier: gw,
      randomToken: () => "tok",
      replayStore,
    };
    await createMcpSession(
      {
        builderAddress: BUILDER,
        grantId: "grant_1",
        proof: { id: "proof-1", expiresAtMs: Date.now() + 60_000 },
      },
      base,
    );
    await expect(
      createMcpSession(
        {
          builderAddress: BUILDER,
          grantId: "grant_1",
          proof: { id: "proof-2", expiresAtMs: Date.now() + 60_000 },
        },
        base,
      ),
    ).resolves.toMatchObject({ grantId: "grant_1" });
  });
});

describe("createMcpSessionAuthPort", () => {
  it("authorizes a read for a covered scope as the builder", async () => {
    const gw = fakeGateway(grant());
    const port = createMcpSessionAuthPort({
      builderAddress: BUILDER,
      grantId: "grant_1",
      authSessionVerifier: gw,
      grantVerifier: gw,
    });
    const result = await port.authorizeBuilderRead({
      request: new Request("http://ps.local/"),
      scope: "instagram.profile",
    });
    expect(result).toMatchObject({ builder: BUILDER, grantId: "grant_1" });
  });

  it("rejects an uncovered scope (isolation guarantee)", async () => {
    const gw = fakeGateway(grant());
    const port = createMcpSessionAuthPort({
      builderAddress: BUILDER,
      grantId: "grant_1",
      authSessionVerifier: gw,
      grantVerifier: gw,
    });
    await expect(
      port.authorizeBuilderRead({
        request: new Request("http://ps.local/"),
        scope: "instagram.posts",
      }),
    ).rejects.toThrow();
  });

  it("refuses owner operations", async () => {
    const gw = fakeGateway(grant());
    const port = createMcpSessionAuthPort({
      builderAddress: BUILDER,
      grantId: "grant_1",
      authSessionVerifier: gw,
      grantVerifier: gw,
    });
    await expect(
      port.authorizeOwner(new Request("http://ps.local/")),
    ).rejects.toThrow();
  });
});

describe("buildMcpSessionConnection", () => {
  it("builds a synthetic approved connection carrying the grant", () => {
    const { connection, account } = buildMcpSessionConnection({
      builderAddress: BUILDER,
      grantId: "grant_1",
      scopes: ["instagram.profile"],
    });
    expect(connection.status).toBe("approved");
    expect(connection.granteeAddress).toBe(BUILDER);
    expect(connection.grants).toEqual([
      { grantId: "grant_1", scopes: ["instagram.profile"] },
    ]);
    // A throwaway signing key exists but is not the builder's key.
    expect(account.address).toMatch(/^0x[0-9a-fA-F]{40}$/);
    expect(account.address.toLowerCase()).not.toBe(BUILDER);
  });
});
