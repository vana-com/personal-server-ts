import { describe, expect, it, vi } from "vitest";
import type {
  Builder,
  GatewayGrantResponse,
} from "@opendatalabs/vana-sdk/browser";
import { verifyDataReadPolicy } from "./data-read.js";

const BUILDER_ADDRESS = "0x0000000000000000000000000000000000000001";
const BUILDER_ID = "0xbuilder1";

const builder: Builder = {
  id: BUILDER_ID,
  ownerAddress: "0xOwner",
  granteeAddress: BUILDER_ADDRESS,
  publicKey: "0x04key",
  appUrl: "https://app.example.com",
  addedAt: "2026-01-21T10:00:00.000Z",
};

// Canary GatewayGrantResponse is fully flat: top-level scopes + expiresAt
// (string | null), no signed JSON blob, no fileIds. paymentStatus is a
// separate axis from on-chain `status` and is what gate-on-payment policy
// reads through the fee verifier.
function makeGrant(
  overrides: Partial<GatewayGrantResponse> = {},
): GatewayGrantResponse {
  return {
    id: "grant-123",
    grantorAddress: "0xOwner",
    granteeId: BUILDER_ID,
    scopes: ["instagram.*"],
    status: "confirmed",
    addedAt: "2026-01-21T10:00:00.000Z",
    expiresAt: String(Math.floor(Date.now() / 1000) + 3600),
    expired: false,
    revokedAt: null,
    revocationSignature: null,
    paymentStatus: "paid",
    paidAt: "2026-01-21T10:00:05.000Z",
    paidBy: "0xOwner",
    grantVersion: "1",
    settleTxHash: null,
    settleSubmittedAt: null,
    revocationTxHash: null,
    revocationSubmittedAt: null,
    fee: {
      asset: "0x0000000000000000000000000000000000000000",
      registrationFee: "10000000000000000",
      dataAccessFee: "1000000000000000",
      totalDue: "11000000000000000",
    },
    ...overrides,
  };
}

describe("verifyDataReadPolicy", () => {
  it("returns the grant after builder, grant, scope, expiry, revocation pass", async () => {
    // Payment gating is now enforced by the X402 layer on the GET handler,
    // not by the data-read policy. The policy returns the grant once the
    // non-payment invariants (builder registered, scopes cover, not
    // revoked / expired, signer matches granteeId) all hold.
    const grant = makeGrant();
    const result = await verifyDataReadPolicy(
      {
        signer: BUILDER_ADDRESS,
        grantId: grant.id,
        requestedScope: "instagram.profile",
        serverOwner: "0xOwner",
      },
      {
        authSessionVerifier: { getBuilder: vi.fn().mockResolvedValue(builder) },
        grantVerifier: { getGrant: vi.fn().mockResolvedValue(grant) },
      },
    );

    expect(result).toBe(grant);
  });

  it("passes when serverOwner matches the grant's grantor", async () => {
    const grant = makeGrant({ grantorAddress: "0xOwner" });
    const result = await verifyDataReadPolicy(
      {
        signer: BUILDER_ADDRESS,
        grantId: grant.id,
        requestedScope: "instagram.profile",
        serverOwner: "0xOwner",
      },
      {
        authSessionVerifier: { getBuilder: vi.fn().mockResolvedValue(builder) },
        grantVerifier: { getGrant: vi.fn().mockResolvedValue(grant) },
      },
    );
    expect(result).toBe(grant);
  });

  it("rejects GRANT_OWNER_MISMATCH when the grantor is a different owner", async () => {
    // A grant issued by 0xOwner must not be honored by a server owned by
    // someone else, even if grantee + scope check out.
    const grant = makeGrant({ grantorAddress: "0xOwner" });
    await expect(
      verifyDataReadPolicy(
        {
          signer: BUILDER_ADDRESS,
          grantId: grant.id,
          requestedScope: "instagram.profile",
          serverOwner: "0xSomeoneElse",
        },
        {
          authSessionVerifier: {
            getBuilder: vi.fn().mockResolvedValue(builder),
          },
          grantVerifier: { getGrant: vi.fn().mockResolvedValue(grant) },
        },
      ),
    ).rejects.toMatchObject({ errorCode: "GRANT_OWNER_MISMATCH" });
  });

  it("fails closed with SERVER_NOT_CONFIGURED when serverOwner is absent", async () => {
    // A read must never be authorized when the server can't identify its own
    // owner — otherwise the ownership binding silently no-ops.
    const grant = makeGrant();
    await expect(
      verifyDataReadPolicy(
        {
          signer: BUILDER_ADDRESS,
          grantId: grant.id,
          requestedScope: "instagram.profile",
          // Simulate an untyped / JS caller passing no owner — the runtime
          // guard must still fail closed (the type now requires serverOwner).
          serverOwner: undefined as unknown as `0x${string}`,
        },
        {
          authSessionVerifier: {
            getBuilder: vi.fn().mockResolvedValue(builder),
          },
          grantVerifier: { getGrant: vi.fn().mockResolvedValue(grant) },
        },
      ),
    ).rejects.toMatchObject({ errorCode: "SERVER_NOT_CONFIGURED" });
  });

  it("fails closed with GRANT_OWNER_MISMATCH when the grant has no grantor", async () => {
    // Gateway responses are untrusted runtime data despite their type — a grant
    // with a missing grantor must be rejected, not treated as a match.
    const grant = makeGrant({ grantorAddress: "" });
    await expect(
      verifyDataReadPolicy(
        {
          signer: BUILDER_ADDRESS,
          grantId: grant.id,
          requestedScope: "instagram.profile",
          serverOwner: "0xOwner",
        },
        {
          authSessionVerifier: {
            getBuilder: vi.fn().mockResolvedValue(builder),
          },
          grantVerifier: { getGrant: vi.fn().mockResolvedValue(grant) },
        },
      ),
    ).rejects.toMatchObject({ errorCode: "GRANT_OWNER_MISMATCH" });
  });

  it("returns GRANT_REVOKED when grant.revokedAt is set", async () => {
    await expect(
      verifyDataReadPolicy(
        {
          signer: BUILDER_ADDRESS,
          grantId: "grant-123",
          requestedScope: "instagram.profile",
          serverOwner: "0xOwner",
        },
        {
          authSessionVerifier: {
            getBuilder: vi.fn().mockResolvedValue(builder),
          },
          grantVerifier: {
            getGrant: vi
              .fn()
              .mockResolvedValue(
                makeGrant({ revokedAt: "2026-05-01T00:00:00Z" }),
              ),
          },
        },
      ),
    ).rejects.toMatchObject({ errorCode: "GRANT_REVOKED" });
  });

  it("returns GRANT_EXPIRED when grant.expiresAt is in the past", async () => {
    await expect(
      verifyDataReadPolicy(
        {
          signer: BUILDER_ADDRESS,
          grantId: "grant-123",
          requestedScope: "instagram.profile",
          serverOwner: "0xOwner",
        },
        {
          authSessionVerifier: {
            getBuilder: vi.fn().mockResolvedValue(builder),
          },
          grantVerifier: {
            getGrant: vi.fn().mockResolvedValue(
              makeGrant({
                expiresAt: String(Math.floor(Date.now() / 1000) - 3600),
              }),
            ),
          },
        },
      ),
    ).rejects.toMatchObject({ errorCode: "GRANT_EXPIRED" });
  });

  it("accepts ISO expiresAt timestamps from the current DPv2 gateway", async () => {
    const grant = makeGrant({
      expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
    });
    const result = await verifyDataReadPolicy(
      {
        signer: BUILDER_ADDRESS,
        grantId: grant.id,
        requestedScope: "instagram.profile",
        serverOwner: "0xOwner",
      },
      {
        authSessionVerifier: { getBuilder: vi.fn().mockResolvedValue(builder) },
        grantVerifier: { getGrant: vi.fn().mockResolvedValue(grant) },
      },
    );

    expect(result).toBe(grant);
  });

  it("treats expiresAt='0' as perpetual (no expiry check)", async () => {
    const grant = makeGrant({ expiresAt: "0" });
    const result = await verifyDataReadPolicy(
      {
        signer: BUILDER_ADDRESS,
        grantId: grant.id,
        requestedScope: "instagram.profile",
        serverOwner: "0xOwner",
      },
      {
        authSessionVerifier: { getBuilder: vi.fn().mockResolvedValue(builder) },
        grantVerifier: { getGrant: vi.fn().mockResolvedValue(grant) },
      },
    );
    expect(result).toBe(grant);
  });

  it("treats expiresAt=null as perpetual (no expiry check)", async () => {
    const grant = makeGrant({ expiresAt: null });
    const result = await verifyDataReadPolicy(
      {
        signer: BUILDER_ADDRESS,
        grantId: grant.id,
        requestedScope: "instagram.profile",
        serverOwner: "0xOwner",
      },
      {
        authSessionVerifier: { getBuilder: vi.fn().mockResolvedValue(builder) },
        grantVerifier: { getGrant: vi.fn().mockResolvedValue(grant) },
      },
    );
    expect(result).toBe(grant);
  });

  it("returns SCOPE_MISMATCH when grant scopes do not cover the read", async () => {
    await expect(
      verifyDataReadPolicy(
        {
          signer: BUILDER_ADDRESS,
          grantId: "grant-123",
          requestedScope: "instagram.profile",
          serverOwner: "0xOwner",
        },
        {
          authSessionVerifier: {
            getBuilder: vi.fn().mockResolvedValue(builder),
          },
          grantVerifier: {
            getGrant: vi
              .fn()
              .mockResolvedValue(makeGrant({ scopes: ["twitter.*"] })),
          },
        },
      ),
    ).rejects.toMatchObject({ errorCode: "SCOPE_MISMATCH" });
  });

  it("returns SCOPE_MISMATCH when grant has empty scopes", async () => {
    await expect(
      verifyDataReadPolicy(
        {
          signer: BUILDER_ADDRESS,
          grantId: "grant-empty",
          requestedScope: "instagram.profile",
          serverOwner: "0xOwner",
        },
        {
          authSessionVerifier: {
            getBuilder: vi.fn().mockResolvedValue(builder),
          },
          grantVerifier: {
            getGrant: vi.fn().mockResolvedValue(makeGrant({ scopes: [] })),
          },
        },
      ),
    ).rejects.toMatchObject({ errorCode: "SCOPE_MISMATCH" });
  });

  it("returns INVALID_SIGNATURE when signer doesn't match grant.granteeId", async () => {
    await expect(
      verifyDataReadPolicy(
        {
          signer: BUILDER_ADDRESS,
          grantId: "grant-123",
          requestedScope: "instagram.profile",
          serverOwner: "0xOwner",
        },
        {
          authSessionVerifier: {
            getBuilder: vi.fn().mockResolvedValue(builder),
          },
          grantVerifier: {
            getGrant: vi
              .fn()
              .mockResolvedValue(makeGrant({ granteeId: "0xsomeoneelse" })),
          },
        },
      ),
    ).rejects.toMatchObject({ errorCode: "INVALID_SIGNATURE" });
  });

  it("returns UNREGISTERED_BUILDER when signer is unknown", async () => {
    await expect(
      verifyDataReadPolicy(
        {
          signer: BUILDER_ADDRESS,
          grantId: "grant-123",
          requestedScope: "instagram.profile",
          serverOwner: "0xOwner",
        },
        {
          authSessionVerifier: { getBuilder: vi.fn().mockResolvedValue(null) },
          grantVerifier: { getGrant: vi.fn() },
        },
      ),
    ).rejects.toMatchObject({ errorCode: "UNREGISTERED_BUILDER" });
  });

  it("returns GRANT_REQUIRED when no grantId is provided", async () => {
    await expect(
      verifyDataReadPolicy(
        {
          signer: BUILDER_ADDRESS,
          requestedScope: "instagram.profile",
          serverOwner: "0xOwner",
        },
        {
          authSessionVerifier: {
            getBuilder: vi.fn().mockResolvedValue(builder),
          },
          grantVerifier: { getGrant: vi.fn() },
        },
      ),
    ).rejects.toMatchObject({ errorCode: "GRANT_REQUIRED" });
  });

  it("returns GRANT_REQUIRED when the grant is not found", async () => {
    await expect(
      verifyDataReadPolicy(
        {
          signer: BUILDER_ADDRESS,
          grantId: "grant-missing",
          requestedScope: "instagram.profile",
          serverOwner: "0xOwner",
        },
        {
          authSessionVerifier: {
            getBuilder: vi.fn().mockResolvedValue(builder),
          },
          grantVerifier: { getGrant: vi.fn().mockResolvedValue(null) },
        },
      ),
    ).rejects.toMatchObject({ errorCode: "GRANT_REQUIRED" });
  });

  it("returns PS_UNAVAILABLE when the runtime availability port is down", async () => {
    await expect(
      verifyDataReadPolicy(
        {
          signer: BUILDER_ADDRESS,
          grantId: "grant-123",
          requestedScope: "instagram.profile",
          serverOwner: "0xOwner",
        },
        {
          authSessionVerifier: {
            getBuilder: vi.fn().mockResolvedValue(builder),
          },
          grantVerifier: { getGrant: vi.fn().mockResolvedValue(makeGrant()) },
          runtimeAvailability: { isAvailable: vi.fn().mockReturnValue(false) },
        },
      ),
    ).rejects.toMatchObject({ errorCode: "PS_UNAVAILABLE" });
  });
});

describe("derivative grants never leak across a lineage edge", () => {
  // A derivative of chatgpt.conversations lives in its own namespace (the
  // naming rule enforced at write time). The read policy matches the
  // requested scope against the grant entries verbatim, so a grant on either
  // side of the lineage edge confers nothing on the other.
  const SOURCE_SCOPE = "chatgpt.conversations";
  const DERIVED_SCOPE = "spine.health.summary";

  function ports(grant: GatewayGrantResponse) {
    return {
      authSessionVerifier: { getBuilder: vi.fn().mockResolvedValue(builder) },
      grantVerifier: { getGrant: vi.fn().mockResolvedValue(grant) },
    };
  }

  it("a grant on the derived scope reads the derivative only", async () => {
    const grant = makeGrant({ scopes: [DERIVED_SCOPE] });
    await expect(
      verifyDataReadPolicy(
        {
          signer: BUILDER_ADDRESS,
          grantId: grant.id,
          requestedScope: DERIVED_SCOPE,
          serverOwner: "0xOwner",
        },
        ports(grant),
      ),
    ).resolves.toBe(grant);
    await expect(
      verifyDataReadPolicy(
        {
          signer: BUILDER_ADDRESS,
          grantId: grant.id,
          requestedScope: SOURCE_SCOPE,
          serverOwner: "0xOwner",
        },
        ports(grant),
      ),
    ).rejects.toMatchObject({ errorCode: "SCOPE_MISMATCH" });
  });

  it("a grant on the source (exact or wildcard) does not read the derivative", async () => {
    for (const scopes of [[SOURCE_SCOPE], ["chatgpt.*"]]) {
      const grant = makeGrant({ scopes });
      await expect(
        verifyDataReadPolicy(
          {
            signer: BUILDER_ADDRESS,
            grantId: grant.id,
            requestedScope: DERIVED_SCOPE,
            serverOwner: "0xOwner",
          },
          ports(grant),
        ),
      ).rejects.toMatchObject({ errorCode: "SCOPE_MISMATCH" });
    }
  });

  it("documents why the naming rule exists: a derivative named under the source namespace would leak", async () => {
    // Not reachable through the write path (400 LINEAGE_SCOPE_UNDER_SOURCE_PREFIX),
    // pinned here so a grammar change that widens this is caught.
    const grant = makeGrant({ scopes: ["chatgpt.*"] });
    await expect(
      verifyDataReadPolicy(
        {
          signer: BUILDER_ADDRESS,
          grantId: grant.id,
          requestedScope: "chatgpt.health-summary",
          serverOwner: "0xOwner",
        },
        ports(grant),
      ),
    ).resolves.toBe(grant);
  });
});
