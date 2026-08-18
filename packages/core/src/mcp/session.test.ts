import { describe, it, expect, vi } from "vitest";
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
const OWNER = "0x0000000000000000000000000000000000000aaa" as const;

function grant(overrides: Record<string, unknown> = {}) {
  return {
    id: "grant_1",
    grantorAddress: OWNER,
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
        serverOwner: OWNER,
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
          serverOwner: OWNER,
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
          serverOwner: OWNER,
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
          serverOwner: OWNER,
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
      serverOwner: OWNER,
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

  it("does not consume the proof when validation fails, so a valid retry succeeds", async () => {
    const replayStore = createInMemoryMcpProofReplayStore();
    let builderCalls = 0;
    const gw = {
      getBuilder: async () => {
        builderCalls += 1;
        if (builderCalls === 1) throw new Error("transient gateway failure");
        return { id: BUILDER };
      },
      getGrant: async () => grant(),
    } as unknown as AuthSessionVerifierPort & GrantVerifierPort;
    const opts = {
      store: createInMemoryMcpSessionStore(),
      authSessionVerifier: gw,
      grantVerifier: gw,
      serverOwner: OWNER,
      randomToken: () => "tok",
      replayStore,
    };
    const input = {
      builderAddress: BUILDER,
      grantId: "grant_1",
      proof: { id: "proof-retry", expiresAtMs: Date.now() + 60_000 },
    };
    // First attempt fails during validation (before the proof is consumed).
    await expect(createMcpSession(input, opts)).rejects.toThrow(/transient/);
    // Retrying the SAME proof now succeeds — it was never marked as consumed.
    await expect(createMcpSession(input, opts)).resolves.toMatchObject({
      grantId: "grant_1",
    });
  });

  it("releases the proof when session persistence fails, so a retry succeeds", async () => {
    const replayStore = createInMemoryMcpProofReplayStore();
    const gw = fakeGateway(grant());
    let createCalls = 0;
    const store = {
      ...createInMemoryMcpSessionStore(),
      async create(record: unknown) {
        createCalls += 1;
        if (createCalls === 1) throw new Error("transient store failure");
        // Delegate to a real store on retry.
        return realStore.create(record as never);
      },
    };
    const realStore = createInMemoryMcpSessionStore();
    const opts = {
      store: store as never,
      authSessionVerifier: gw,
      grantVerifier: gw,
      serverOwner: OWNER,
      randomToken: () => "tok",
      replayStore,
    };
    const input = {
      builderAddress: BUILDER,
      grantId: "grant_1",
      proof: { id: "proof-persist", expiresAtMs: Date.now() + 60_000 },
    };
    // First attempt: validation passes, proof consumed, but store.create fails.
    await expect(createMcpSession(input, opts)).rejects.toThrow(
      /store failure/,
    );
    // The proof was released on failure, so retrying the same proof succeeds.
    await expect(createMcpSession(input, opts)).resolves.toMatchObject({
      grantId: "grant_1",
    });
  });

  it("allows a fresh proof id after a prior one was consumed", async () => {
    const gw = fakeGateway(grant());
    const replayStore = createInMemoryMcpProofReplayStore();
    const base = {
      store: createInMemoryMcpSessionStore(),
      authSessionVerifier: gw,
      grantVerifier: gw,
      serverOwner: OWNER,
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

  it("rejects a grant issued by a grantor that is not the server owner", async () => {
    const gw = fakeGateway(grant({ grantorAddress: OTHER }));
    await expect(
      createMcpSession(
        { builderAddress: BUILDER, grantId: "grant_1" },
        {
          store: createInMemoryMcpSessionStore(),
          authSessionVerifier: gw,
          grantVerifier: gw,
          serverOwner: OWNER,
          randomToken: () => "t",
        },
      ),
    ).rejects.toMatchObject({ errorCode: "GRANT_OWNER_MISMATCH" });
  });

  it("fails closed on a grant with no grantor", async () => {
    const gw = fakeGateway(grant({ grantorAddress: undefined }));
    await expect(
      createMcpSession(
        { builderAddress: BUILDER, grantId: "grant_1" },
        {
          store: createInMemoryMcpSessionStore(),
          authSessionVerifier: gw,
          grantVerifier: gw,
          serverOwner: OWNER,
          randomToken: () => "t",
        },
      ),
    ).rejects.toMatchObject({ errorCode: "GRANT_OWNER_MISMATCH" });
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
      serverOwner: OWNER,
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
      serverOwner: OWNER,
    });
    await expect(
      port.authorizeBuilderRead({
        request: new Request("http://ps.local/"),
        scope: "instagram.posts",
      }),
    ).rejects.toThrow();
  });

  it("rejects a read under a grant issued by a grantor that is not the server owner", async () => {
    const gw = fakeGateway(grant({ grantorAddress: OTHER }));
    const port = createMcpSessionAuthPort({
      builderAddress: BUILDER,
      grantId: "grant_1",
      authSessionVerifier: gw,
      grantVerifier: gw,
      serverOwner: OWNER,
    });
    await expect(
      port.authorizeBuilderRead({
        request: new Request("http://ps.local/"),
        scope: "instagram.profile",
      }),
    ).rejects.toMatchObject({ errorCode: "GRANT_OWNER_MISMATCH" });
  });

  it("refuses owner operations", async () => {
    const gw = fakeGateway(grant());
    const port = createMcpSessionAuthPort({
      builderAddress: BUILDER,
      grantId: "grant_1",
      authSessionVerifier: gw,
      grantVerifier: gw,
      serverOwner: OWNER,
    });
    await expect(
      port.authorizeOwner(new Request("http://ps.local/")),
    ).rejects.toThrow();
  });

  it("binds the x402 payment cycle to the pinned data version, not the latest", async () => {
    const PINNED_AT = "2026-06-05T00:00:00Z";
    const gw = fakeGateway(
      grant({
        paymentStatus: "pending",
        fee: {
          totalDue: "100",
          asset: "0x0000000000000000000000000000000000000fee",
        },
      }),
    );
    // Two versions exist; `at` selects which one the payment binds to.
    const findEntry = vi.fn(({ at }: { at?: string }) => ({
      scope: "instagram.profile",
      collectedAt: at ?? "2026-06-06T00:00:00Z",
      fileId: at === PINNED_AT ? "file-old" : "file-latest",
      sizeBytes: 10,
      dataPointId: "0x00000000000000000000000000000000000000dp",
      version: at === PINNED_AT ? 3 : 7,
    }));
    const signRecordDataAccess = vi.fn().mockResolvedValue("0xsig");
    const port = createMcpSessionAuthPort({
      builderAddress: BUILDER,
      grantId: "grant_1",
      authSessionVerifier: gw,
      grantVerifier: gw,
      serverOwner: OWNER,
      payment: {
        dataApiDeps: {
          storage: { findEntry } as never,
          auth: {} as never,
          accessLogWriter: { write: vi.fn() },
          serverSigner: { signRecordDataAccess },
          serverOwner: OWNER,
          serverAddress: "0x0000000000000000000000000000000000000ccc",
        },
        gateway: gw as never,
        gatewayConfig: {
          chainId: 14800,
          contracts: {
            dataRegistry: "0x0000000000000000000000000000000000000001",
            dataPortabilityPermissions:
              "0x0000000000000000000000000000000000000002",
            dataPortabilityServer: "0x0000000000000000000000000000000000000003",
            dataPortabilityGrantees:
              "0x0000000000000000000000000000000000000004",
          },
        } as never,
        gatewayUrl: "https://gateway.test",
      },
    });

    // No X-PAYMENT header → the cycle must issue a challenge (402) whose
    // accessRecord is signed over the PINNED version, not the latest.
    await expect(
      port.authorizeBuilderRead({
        request: new Request("http://ps.local/"),
        scope: "instagram.profile",
        at: PINNED_AT,
      }),
    ).rejects.toMatchObject({ code: 402, errorCode: "PAYMENT_REQUIRED" });

    expect(findEntry).toHaveBeenCalledWith(
      expect.objectContaining({ scope: "instagram.profile", at: PINNED_AT }),
    );
    expect(signRecordDataAccess).toHaveBeenCalledWith(
      expect.objectContaining({ version: 3n }),
    );
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
