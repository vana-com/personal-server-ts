import {
  BUILDER_REGISTRATION_TYPES,
  builderRegistrationDomain,
  verifyGrantRegistration,
  type Builder,
  type DataPortabilityGatewayConfig,
  type GatewayGrantResponse,
} from "@opendatalabs/vana-sdk/browser";
import { isAddressEqual, recoverTypedDataAddress, type Address } from "viem";
import { publicKeyToAddress } from "viem/accounts";
import {
  GrantRevokedError,
  SignedArtifactInvalidError,
  SignedArtifactMissingError,
} from "../errors/catalog.js";

export type SignedGrant = GatewayGrantResponse & { signature?: string };
export type SignedBuilder = Builder & { signature?: string };

export interface SignedArtifactInput {
  grant: SignedGrant;
  builder: SignedBuilder;
  gatewayConfig: DataPortabilityGatewayConfig;
  ownerAddress: Address;
}

export async function verifySignedArtifacts(
  input: SignedArtifactInput,
): Promise<void> {
  if (input.grant.revokedAt !== null) {
    throw new GrantRevokedError({ grantId: input.grant.id });
  }
  if (!input.grant.signature || !input.builder.signature) {
    throw new SignedArtifactMissingError();
  }

  let grant;
  try {
    grant = await verifyGrantRegistration({
      gatewayConfig: input.gatewayConfig,
      grantorAddress: input.grant.grantorAddress as Address,
      granteeId: input.grant.granteeId as `0x${string}`,
      scopes: input.grant.scopes,
      grantVersion: input.grant.grantVersion,
      expiresAt: input.grant.expiresAt ?? "0",
      signature: input.grant.signature as `0x${string}`,
    });
  } catch {
    throw new SignedArtifactInvalidError({ artifact: "grant" });
  }
  if (
    !grant.valid ||
    !sameAddress(grant.grantorAddress, input.ownerAddress) ||
    !sameAddress(grant.grantorAddress, input.grant.grantorAddress)
  ) {
    throw new SignedArtifactInvalidError({ artifact: "grant" });
  }

  let recoveredBuilder: Address;
  let publicKeyAddress: Address;
  try {
    recoveredBuilder = await recoverTypedDataAddress({
      domain: builderRegistrationDomain(input.gatewayConfig),
      types: BUILDER_REGISTRATION_TYPES,
      primaryType: "BuilderRegistration",
      message: {
        ownerAddress: input.builder.ownerAddress as Address,
        granteeAddress: input.builder.granteeAddress as Address,
        publicKey: input.builder.publicKey,
        appUrl: input.builder.appUrl,
      },
      signature: input.builder.signature as `0x${string}`,
    });
    publicKeyAddress = publicKeyToAddress(
      input.builder.publicKey as `0x${string}`,
    );
  } catch {
    throw new SignedArtifactInvalidError({ artifact: "builder" });
  }

  if (
    !sameAddress(recoveredBuilder, input.builder.ownerAddress) ||
    !sameAddress(publicKeyAddress, input.builder.granteeAddress) ||
    input.builder.id.toLowerCase() !== input.grant.granteeId.toLowerCase()
  ) {
    throw new SignedArtifactInvalidError({ artifact: "builder" });
  }
}

function sameAddress(left: string, right: string): boolean {
  try {
    return isAddressEqual(left as Address, right as Address);
  } catch {
    return false;
  }
}
