import { describe, expect, it } from "vitest";
import {
  BUILDER_REGISTRATION_TYPES,
  GRANT_REGISTRATION_TYPES,
  builderRegistrationDomain,
  grantRegistrationDomain,
  type Builder,
  type DataPortabilityGatewayConfig,
  type GatewayGrantResponse,
} from "@opendatalabs/vana-sdk/browser";
import { privateKeyToAccount } from "viem/accounts";
import {
  GrantRevokedError,
  SignedArtifactInvalidError,
  SignedArtifactMissingError,
} from "../errors/catalog.js";
import { createTestWallet } from "../test-utils/wallet.js";
import { verifySignedArtifacts } from "./signed-artifacts.js";

const owner = createTestWallet(30);
const builderOwner = createTestWallet(31);
const grantee = privateKeyToAccount(createTestWallet(32).privateKey);
const GRANTEE_ID = `0x${"66".repeat(32)}` as const;
const gatewayConfig = {
  chainId: 14_800,
  contracts: {
    dataRegistry: owner.address,
    dataPortabilityPermissions: owner.address,
    dataPortabilityServer: owner.address,
    dataPortabilityGrantees: owner.address,
    dataPortabilityEscrow: owner.address,
    feeRegistry: owner.address,
  },
} satisfies DataPortabilityGatewayConfig;

type SignedGrant = GatewayGrantResponse & { signature?: string };
type SignedBuilder = Builder & { signature?: string };

async function signedArtifacts(): Promise<{
  grant: SignedGrant;
  builder: SignedBuilder;
}> {
  const builder: SignedBuilder = {
    id: GRANTEE_ID,
    ownerAddress: builderOwner.address,
    granteeAddress: grantee.address,
    publicKey: grantee.publicKey,
    appUrl: "https://builder.example",
    addedAt: "2026-09-03T00:00:00.000Z",
  };
  builder.signature = await builderOwner.signTypedData({
    domain: builderRegistrationDomain(gatewayConfig),
    types: BUILDER_REGISTRATION_TYPES,
    primaryType: "BuilderRegistration",
    message: {
      ownerAddress: builder.ownerAddress,
      granteeAddress: builder.granteeAddress,
      publicKey: builder.publicKey,
      appUrl: builder.appUrl,
    },
  });

  const grant: SignedGrant = {
    id: `0x${"77".repeat(32)}`,
    grantorAddress: owner.address,
    granteeId: GRANTEE_ID,
    scopes: ["instagram.profile"],
    status: "confirmed",
    addedAt: "2026-09-03T00:00:00.000Z",
    expiresAt: "0",
    expired: false,
    revokedAt: null,
    revocationSignature: null,
    paymentStatus: "paid",
    paidAt: null,
    paidBy: null,
    grantVersion: "1",
    settleTxHash: null,
    settleSubmittedAt: null,
    revocationTxHash: null,
    revocationSubmittedAt: null,
    fee: {
      asset: owner.address,
      registrationFee: "0",
      dataAccessFee: "0",
      totalDue: "0",
    },
  };
  grant.signature = await owner.signTypedData({
    domain: grantRegistrationDomain(gatewayConfig),
    types: GRANT_REGISTRATION_TYPES,
    primaryType: "GrantRegistration",
    message: {
      grantorAddress: grant.grantorAddress,
      granteeId: grant.granteeId,
      scopes: grant.scopes,
      grantVersion: grant.grantVersion,
      expiresAt: grant.expiresAt,
    },
  });

  return { grant, builder };
}

describe("verifySignedArtifacts", () => {
  it("accepts grantor and builder registrations bound to the grantee key", async () => {
    const artifacts = await signedArtifacts();

    await expect(
      verifySignedArtifacts({
        ...artifacts,
        gatewayConfig,
        ownerAddress: owner.address,
      }),
    ).resolves.toBeUndefined();
  });

  it("fails closed when signed gateway artifacts are missing", async () => {
    const artifacts = await signedArtifacts();
    delete artifacts.grant.signature;

    await expect(
      verifySignedArtifacts({
        ...artifacts,
        gatewayConfig,
        ownerAddress: owner.address,
      }),
    ).rejects.toBeInstanceOf(SignedArtifactMissingError);
  });

  it("returns typed failures for revoked and malformed artifacts", async () => {
    const revoked = await signedArtifacts();
    revoked.grant.revokedAt = "2026-09-03T01:00:00.000Z";
    await expect(
      verifySignedArtifacts({
        ...revoked,
        gatewayConfig,
        ownerAddress: owner.address,
      }),
    ).rejects.toBeInstanceOf(GrantRevokedError);

    const malformed = await signedArtifacts();
    malformed.builder.signature = "not-a-signature";
    await expect(
      verifySignedArtifacts({
        ...malformed,
        gatewayConfig,
        ownerAddress: owner.address,
      }),
    ).rejects.toBeInstanceOf(SignedArtifactInvalidError);
  });
});
