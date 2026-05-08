import { describe, expect, it, vi } from "vitest";
import type { Builder } from "@opendatalabs/vana-sdk/node";
import type { GatewayGrantResponse } from "@opendatalabs/vana-sdk/node";
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

function makeGrant(
  overrides: Partial<GatewayGrantResponse> = {},
): GatewayGrantResponse {
  return {
    id: "grant-123",
    grantorAddress: "0xOwner",
    granteeId: BUILDER_ID,
    grant: JSON.stringify({
      scopes: ["instagram.*"],
      expiresAt: Math.floor(Date.now() / 1000) + 3600,
    }),
    fileIds: [],
    status: "confirmed",
    addedAt: "2026-01-21T10:00:00.000Z",
    revokedAt: null,
    revocationSignature: null,
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

  it("allows a requested fileId included in a file-restricted grant", async () => {
    const grant = makeGrant({ fileIds: ["file-1"] });
    const result = await verifyDataReadPolicy(
      {
        signer: BUILDER_ADDRESS,
        grantId: grant.id,
        requestedScope: "instagram.profile",
        fileId: "file-1",
      },
      {
        authSessionVerifier: { getBuilder: vi.fn().mockResolvedValue(builder) },
        grantVerifier: { getGrant: vi.fn().mockResolvedValue(grant) },
      },
    );

    expect(result).toBe(grant);
  });

  it("returns SCOPE_MISMATCH when a file-restricted grant lacks the requested fileId", async () => {
    await expect(
      verifyDataReadPolicy(
        {
          signer: BUILDER_ADDRESS,
          grantId: "grant-123",
          requestedScope: "instagram.profile",
          fileId: "file-2",
        },
        {
          authSessionVerifier: {
            getBuilder: vi.fn().mockResolvedValue(builder),
          },
          grantVerifier: {
            getGrant: vi
              .fn()
              .mockResolvedValue(makeGrant({ fileIds: ["file-1"] })),
          },
        },
      ),
    ).rejects.toMatchObject({ errorCode: "SCOPE_MISMATCH" });
  });

  it("requires fileId when a grant is restricted to fileIds", async () => {
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
              .mockResolvedValue(makeGrant({ fileIds: ["file-1"] })),
          },
        },
      ),
    ).rejects.toMatchObject({ errorCode: "SCOPE_MISMATCH" });
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
