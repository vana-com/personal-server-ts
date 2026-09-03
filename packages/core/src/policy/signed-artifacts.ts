import {
  BUILDER_REGISTRATION_TYPES,
  builderRegistrationDomain,
  verifyGrantRegistration,
  type Builder,
  type DataPortabilityGatewayConfig,
  type GatewayGrantResponse,
} from "@opendatalabs/vana-sdk/browser";
import {
  encodeAbiParameters,
  isAddressEqual,
  keccak256,
  recoverTypedDataAddress,
  toHex,
  type Address,
  type Hex,
} from "viem";
import { publicKeyToAddress } from "viem/accounts";
import {
  GrantRevokedError,
  SignedArtifactInvalidError,
  SignedArtifactMissingError,
} from "../errors/catalog.js";

export type SignedGrant = GatewayGrantResponse & { signature?: string };
export type SignedBuilder = Builder & { signature?: string };

const DOMAIN_TYPE =
  "DataPortabilityDomain(uint256 chainId,address verifyingContract)";
const DOMAIN_TYPE_HASH = keccak256(toHex(DOMAIN_TYPE));

export interface SignedArtifactInput {
  grant: SignedGrant;
  builder: SignedBuilder;
  gatewayConfig: DataPortabilityGatewayConfig;
  ownerAddress: Address;
}

export async function verifySignedArtifacts(
  input: SignedArtifactInput,
): Promise<void> {
  // TODO(step-4): revokedAt is Gateway-attested; verify revocation on-chain (contract s1 step 6).
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
  let builderId: Hex;
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
    builderId = deriveBuilderId(input.builder, input.gatewayConfig);
  } catch {
    throw new SignedArtifactInvalidError({ artifact: "builder" });
  }

  if (
    !sameAddress(recoveredBuilder, input.builder.ownerAddress) ||
    !sameAddress(publicKeyAddress, input.builder.granteeAddress) ||
    // id is not signed; rebinding it to the signed fields stops a Gateway from
    // pairing an attacker's signed builder with the owner's grant.
    builderId.toLowerCase() !== input.builder.id.toLowerCase() ||
    builderId.toLowerCase() !== input.grant.granteeId.toLowerCase()
  ) {
    throw new SignedArtifactInvalidError({ artifact: "builder" });
  }
}

export function deriveBuilderId(
  builder: Pick<
    Builder,
    "ownerAddress" | "granteeAddress" | "publicKey" | "appUrl"
  >,
  gatewayConfig: DataPortabilityGatewayConfig,
): Hex {
  const domain = builderRegistrationDomain(gatewayConfig);
  if (domain.chainId === undefined || domain.verifyingContract === undefined) {
    throw new Error("Builder registration domain is incomplete");
  }
  // Gateway/on-chain IDs use this custom domain separator, distinct from the
  // standard EIP-712 domain hash used to verify the builder signature above.
  const domainSeparator = keccak256(
    encodeAbiParameters(
      [
        { name: "typeHash", type: "bytes32" },
        { name: "chainId", type: "uint256" },
        { name: "verifyingContract", type: "address" },
      ],
      [DOMAIN_TYPE_HASH, BigInt(domain.chainId), domain.verifyingContract],
    ),
  );

  return keccak256(
    encodeAbiParameters(
      [
        { name: "domainSeparator", type: "bytes32" },
        { name: "owner", type: "address" },
        { name: "granteeAddress", type: "address" },
        { name: "publicKey", type: "string" },
        { name: "appUrl", type: "string" },
      ],
      [
        domainSeparator,
        builder.ownerAddress as Address,
        builder.granteeAddress as Address,
        builder.publicKey,
        builder.appUrl,
      ],
    ),
  );
}

function sameAddress(left: string, right: string): boolean {
  try {
    return isAddressEqual(left as Address, right as Address);
  } catch {
    return false;
  }
}
