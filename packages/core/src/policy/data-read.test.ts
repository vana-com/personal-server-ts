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
  it("returns the grant after builder, grant, scope, expiry, revocation, and fee pass", async () => {
    const grant = makeGrant();
    const result = await verifyDataReadPolicy(
      {
        signer: BUILDER_ADDRESS,
        grantId: grant.id,
        requestedScope: "instagram.profile",
      },
      {
        authSessionVerifier: { getBuilder: vi.fn().mockResolvedValue(builder) },
        grantVerifier: { getGrant: vi.fn().mockResolvedValue(grant) },
        feeVerifier: {
          verifyDataReadFee: vi.fn().mockResolvedValue({ ok: true }),
        },
      },
    );

    expect(result).toBe(grant);
  });

  it("returns FEE_REQUIRED when the fee verifier denies the read", async () => {
    await expect(
      verifyDataReadPolicy(
        {
          signer: BUILDER_ADDRESS,
          grantId: "grant-123",
          requestedScope: "instagram.profile",
        },
        {
          authSessionVerifier: {
            getBuilder: vi.fn().mockResolvedValue(builder),
          },
          grantVerifier: { getGrant: vi.fn().mockResolvedValue(makeGrant()) },
          feeVerifier: {
            verifyDataReadFee: vi
              .fn()
              .mockResolvedValue({ ok: false, reason: "unpaid" }),
          },
        },
      ),
    ).rejects.toMatchObject({ errorCode: "FEE_REQUIRED" });
  });

  it("returns GRANT_REVOKED when grant.revokedAt is set", async () => {
    await expect(
      verifyDataReadPolicy(
        {
          signer: BUILDER_ADDRESS,
          grantId: "grant-123",
          requestedScope: "instagram.profile",
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

  it("treats expiresAt='0' as perpetual (no expiry check)", async () => {
    const grant = makeGrant({ expiresAt: "0" });
    const result = await verifyDataReadPolicy(
      {
        signer: BUILDER_ADDRESS,
        grantId: grant.id,
        requestedScope: "instagram.profile",
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
