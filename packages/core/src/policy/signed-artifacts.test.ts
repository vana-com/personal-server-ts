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
import { deriveBuilderId, verifySignedArtifacts } from "./signed-artifacts.js";

const owner = createTestWallet(30);
const builderOwner = createTestWallet(31);
const grantee = privateKeyToAccount(createTestWallet(32).privateKey);
const attackerOwner = createTestWallet(33);
const attacker = privateKeyToAccount(createTestWallet(34).privateKey);
const BUILDER_APP_URL = "https://builder.example";
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
const GRANTEE_ID = deriveBuilderId(
  {
    ownerAddress: builderOwner.address,
    granteeAddress: grantee.address,
    publicKey: grantee.publicKey,
    appUrl: BUILDER_APP_URL,
  },
  gatewayConfig,
);

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
    appUrl: BUILDER_APP_URL,
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
  it("matches the Gateway builder id fixture", () => {
    expect(
      deriveBuilderId(
        {
          ownerAddress: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
          granteeAddress: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
          publicKey:
            "0x049d9031e97dd78ff8c15aa86939de9b1e791066a0224e331bc962a2099a7b1f0464b8bbafe1535f2301c72c2cb3535b172da30b02686ab0393d348614f157fbdb",
          appUrl: "https://mybuilder.example.com",
        },
        {
          ...gatewayConfig,
          contracts: {
            ...gatewayConfig.contracts,
            dataPortabilityGrantees:
              "0x8C8788f98385F6ba1adD4234e551ABba0f82Cb7C",
          },
        },
      ),
    ).toBe(
      "0xd94af6af1fd59edf3404921e43924a30f943ccfa2b2511b6bce18753193743dc",
    );
  });

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

  it("rejects a signed builder relabeled with the granted id", async () => {
    const artifacts = await signedArtifacts();
    artifacts.builder.ownerAddress = attackerOwner.address;
    artifacts.builder.granteeAddress = attacker.address;
    artifacts.builder.publicKey = attacker.publicKey;
    artifacts.builder.signature = await attackerOwner.signTypedData({
      domain: builderRegistrationDomain(gatewayConfig),
      types: BUILDER_REGISTRATION_TYPES,
      primaryType: "BuilderRegistration",
      message: {
        ownerAddress: artifacts.builder.ownerAddress,
        granteeAddress: artifacts.builder.granteeAddress,
        publicKey: artifacts.builder.publicKey,
        appUrl: artifacts.builder.appUrl,
      },
    });

    await expect(
      verifySignedArtifacts({
        ...artifacts,
        gatewayConfig,
        ownerAddress: owner.address,
      }),
    ).rejects.toBeInstanceOf(SignedArtifactInvalidError);
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
