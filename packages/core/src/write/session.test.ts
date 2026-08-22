import { describe, it, expect, vi } from "vitest";
import {
  createInMemoryWriteProofReplayStore,
  createInMemoryWriteSessionStore,
  createWriteSession,
  hashWriteSessionToken,
} from "./session.js";
import type {
  AuthSessionVerifierPort,
  GrantVerifierPort,
} from "../ports/index.js";

const BUILDER = "0xabc0000000000000000000000000000000000001" as const;
const OWNER = "0x0000000000000000000000000000000000000aaa" as const;

function grant(overrides: Record<string, unknown> = {}) {
  return {
    id: "grant_w1",
    grantorAddress: OWNER,
    granteeId: BUILDER,
    scopes: ["write:notes.entries"],
    revokedAt: null,
    expiresAt: null,
    ...overrides,
  };
}

// Minimal fakes for the two ports createWriteSession uses.
function fakeGateway(
  grantValue: unknown,
  builderId: string | null = BUILDER,
): AuthSessionVerifierPort & GrantVerifierPort {
  return {
    getBuilder: async () => (builderId ? { id: builderId } : null),
    getGrant: async () => grantValue,
  } as unknown as AuthSessionVerifierPort & GrantVerifierPort;
}

describe("createWriteSession", () => {
  it("mints a token for a valid builder + write-grant and stores it by hash", async () => {
    const store = createInMemoryWriteSessionStore();
    const gw = fakeGateway(grant());
    const result = await createWriteSession(
      { builderAddress: BUILDER, grantId: "grant_w1" },
      {
        store,
        authSessionVerifier: gw,
        grantVerifier: gw,
        serverOwner: OWNER,
        randomToken: () => "tok_write",
      },
    );
    expect(result.accessToken).toBe("tok_write");
    expect(result.grantId).toBe("grant_w1");
    expect(result.writeScopes).toEqual(["notes.entries"]);
    const rec = await store.getByTokenHash(
      await hashWriteSessionToken("tok_write"),
    );
    expect(rec?.builderAddress).toBe(BUILDER);
    expect(rec?.grantId).toBe("grant_w1");
    expect(rec?.writeScopes).toEqual(["notes.entries"]);
  });

  it("rejects a grant with no write scopes (a read-grant cannot open a write session)", async () => {
    const gw = fakeGateway(grant({ scopes: ["notes.entries"] }));
    await expect(
      createWriteSession(
        { builderAddress: BUILDER, grantId: "grant_w1" },
        {
          store: createInMemoryWriteSessionStore(),
          authSessionVerifier: gw,
          grantVerifier: gw,
          serverOwner: OWNER,
          randomToken: () => "t",
        },
      ),
    ).rejects.toMatchObject({ errorCode: "SCOPE_MISMATCH" });
  });

  it("rejects an unregistered builder", async () => {
    const gw = fakeGateway(grant(), null);
    await expect(
      createWriteSession(
        { builderAddress: BUILDER, grantId: "grant_w1" },
        {
          store: createInMemoryWriteSessionStore(),
          authSessionVerifier: gw,
          grantVerifier: gw,
          serverOwner: OWNER,
          randomToken: () => "t",
        },
      ),
    ).rejects.toMatchObject({ errorCode: "UNREGISTERED_BUILDER" });
  });

  it("rejects a missing grant", async () => {
    const gw = fakeGateway(null);
    await expect(
      createWriteSession(
        { builderAddress: BUILDER, grantId: "grant_missing" },
        {
          store: createInMemoryWriteSessionStore(),
          authSessionVerifier: gw,
          grantVerifier: gw,
          serverOwner: OWNER,
          randomToken: () => "t",
        },
      ),
    ).rejects.toMatchObject({ errorCode: "GRANT_REQUIRED" });
  });

  it("rejects a revoked grant", async () => {
    const gw = fakeGateway(grant({ revokedAt: "2026-01-22T00:00:00.000Z" }));
    await expect(
      createWriteSession(
        { builderAddress: BUILDER, grantId: "grant_w1" },
        {
          store: createInMemoryWriteSessionStore(),
          authSessionVerifier: gw,
          grantVerifier: gw,
          serverOwner: OWNER,
          randomToken: () => "t",
        },
      ),
    ).rejects.toMatchObject({ errorCode: "GRANT_REVOKED" });
  });

  it("rejects a handshake signer that is not the grant builder", async () => {
    const gw = fakeGateway(grant({ granteeId: "0xother" }));
    await expect(
      createWriteSession(
        { builderAddress: BUILDER, grantId: "grant_w1" },
        {
          store: createInMemoryWriteSessionStore(),
          authSessionVerifier: gw,
          grantVerifier: gw,
          serverOwner: OWNER,
          randomToken: () => "t",
        },
      ),
    ).rejects.toMatchObject({ errorCode: "INVALID_SIGNATURE" });
  });

  it("rejects a grant issued by a grantor that is not the server owner", async () => {
    const gw = fakeGateway(grant({ grantorAddress: "0xNotTheOwner" }));
    await expect(
      createWriteSession(
        { builderAddress: BUILDER, grantId: "grant_w1" },
        {
          store: createInMemoryWriteSessionStore(),
          authSessionVerifier: gw,
          grantVerifier: gw,
          serverOwner: OWNER,
          randomToken: () => "t",
        },
      ),
    ).rejects.toMatchObject({ errorCode: "GRANT_OWNER_MISMATCH" });
  });

  it("fails closed on a grant with no grantor", async () => {
    const gw = fakeGateway(grant({ grantorAddress: null }));
    await expect(
      createWriteSession(
        { builderAddress: BUILDER, grantId: "grant_w1" },
        {
          store: createInMemoryWriteSessionStore(),
          authSessionVerifier: gw,
          grantVerifier: gw,
          serverOwner: OWNER,
          randomToken: () => "t",
        },
      ),
    ).rejects.toMatchObject({ errorCode: "GRANT_OWNER_MISMATCH" });
  });

  it("rejects a replayed handshake proof (same proof id, still live)", async () => {
    const gw = fakeGateway(grant());
    const replayStore = createInMemoryWriteProofReplayStore();
    const options = {
      store: createInMemoryWriteSessionStore(),
      authSessionVerifier: gw,
      grantVerifier: gw,
      serverOwner: OWNER,
      randomToken: () => `t_${Math.random()}`,
      replayStore,
    };
    const proof = { id: "proof-1", expiresAtMs: Date.now() + 60_000 };
    await createWriteSession(
      { builderAddress: BUILDER, grantId: "grant_w1", proof },
      options,
    );
    await expect(
      createWriteSession(
        { builderAddress: BUILDER, grantId: "grant_w1", proof },
        options,
      ),
    ).rejects.toMatchObject({ errorCode: "WRITE_SESSION_PROOF_REPLAY" });
  });

  it("releases the proof when session persistence fails, so a retry succeeds", async () => {
    const gw = fakeGateway(grant());
    const replayStore = createInMemoryWriteProofReplayStore();
    const failingStore = {
      create: vi.fn().mockRejectedValueOnce(new Error("disk full")),
      getByTokenHash: vi.fn().mockResolvedValue(null),
    };
    const proof = { id: "proof-2", expiresAtMs: Date.now() + 60_000 };
    const options = {
      store: failingStore,
      authSessionVerifier: gw,
      grantVerifier: gw,
      serverOwner: OWNER,
      randomToken: () => "t",
      replayStore,
    };
    await expect(
      createWriteSession(
        { builderAddress: BUILDER, grantId: "grant_w1", proof },
        options,
      ),
    ).rejects.toThrow("disk full");
    // Same proof retries cleanly after the rollback.
    failingStore.create.mockResolvedValueOnce(undefined);
    await expect(
      createWriteSession(
        { builderAddress: BUILDER, grantId: "grant_w1", proof },
        options,
      ),
    ).resolves.toMatchObject({ grantId: "grant_w1" });
  });

  it("expires stored sessions", async () => {
    const store = createInMemoryWriteSessionStore();
    const gw = fakeGateway(grant());
    const now = Date.now();
    await createWriteSession(
      { builderAddress: BUILDER, grantId: "grant_w1" },
      {
        store,
        authSessionVerifier: gw,
        grantVerifier: gw,
        serverOwner: OWNER,
        randomToken: () => "tok_exp",
        ttlMs: -1,
        now: () => now,
      },
    );
    expect(
      await store.getByTokenHash(await hashWriteSessionToken("tok_exp")),
    ).toBeNull();
  });
});
