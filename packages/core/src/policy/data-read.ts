import type { GatewayGrantResponse } from "@opendatalabs/vana-sdk/browser";
import { scopeCoveredByGrant } from "@opendatalabs/vana-sdk/browser";
import {
  FeeRequiredError,
  GrantExpiredError,
  GrantRequiredError,
  GrantRevokedError,
  InvalidSignatureError,
  PsUnavailableError,
  ScopeMismatchError,
  UnregisteredBuilderError,
} from "../errors/catalog.js";
import {
  allowAllFeeVerifier,
  type AuthSessionVerifierPort,
  type FeeVerifierPort,
  type GrantVerifierPort,
  type RuntimeAvailabilityPort,
} from "../ports/index.js";

export interface DataReadPolicyInput {
  signer: `0x${string}`;
  grantId?: string;
  requestedScope: string;
  fileId?: string;
}

export interface DataReadPolicyPorts {
  authSessionVerifier: AuthSessionVerifierPort;
  grantVerifier: GrantVerifierPort;
  feeVerifier?: FeeVerifierPort;
  runtimeAvailability?: RuntimeAvailabilityPort;
}

function parseGrantPayload(grantString: string): {
  scopes: string[];
  expiresAt: number;
} {
  try {
    const parsed = JSON.parse(grantString) as {
      scopes?: string[];
      expiresAt?: number;
    };
    return {
      scopes: Array.isArray(parsed.scopes) ? parsed.scopes : [],
      expiresAt: typeof parsed.expiresAt === "number" ? parsed.expiresAt : 0,
    };
  } catch {
    return { scopes: [], expiresAt: 0 };
  }
}

export async function verifyDataReadPolicy(
  input: DataReadPolicyInput,
  ports: DataReadPolicyPorts,
): Promise<GatewayGrantResponse> {
  const available = await ports.runtimeAvailability?.isAvailable();
  if (available === false) {
    throw new PsUnavailableError();
  }

  const builder = await ports.authSessionVerifier.getBuilder(input.signer);
  if (!builder) {
    throw new UnregisteredBuilderError();
  }

  if (!input.grantId) {
    throw new GrantRequiredError({
      reason: "No grantId in authorization payload",
    });
  }

  const grant = await ports.grantVerifier.getGrant(input.grantId);
  if (!grant) {
    throw new GrantRequiredError({
      reason: "Grant not found",
      grantId: input.grantId,
    });
  }

  if (grant.revokedAt !== null) {
    throw new GrantRevokedError({ grantId: grant.id });
  }

  const grantPayload = parseGrantPayload(grant.grant);
  if (grantPayload.expiresAt > 0) {
    const now = Math.floor(Date.now() / 1000);
    if (grantPayload.expiresAt < now) {
      throw new GrantExpiredError({ expiresAt: grantPayload.expiresAt });
    }
  }

  if (!scopeCoveredByGrant(input.requestedScope, grantPayload.scopes)) {
    throw new ScopeMismatchError({
      requestedScope: input.requestedScope,
      grantedScopes: grantPayload.scopes,
    });
  }

  if (grant.fileIds.length > 0) {
    if (!input.fileId) {
      throw new ScopeMismatchError({
        requestedScope: input.requestedScope,
        reason: "Grant is restricted to fileIds; request must include fileId",
        grantedFileIds: grant.fileIds,
      });
    }
    if (!grant.fileIds.includes(input.fileId)) {
      throw new ScopeMismatchError({
        requestedScope: input.requestedScope,
        requestedFileId: input.fileId,
        grantedFileIds: grant.fileIds,
      });
    }
  }

  if (builder.id !== grant.granteeId) {
    throw new InvalidSignatureError({
      reason: "Request signer is not the grant builder",
      expected: grant.granteeId,
      actual: input.signer,
    });
  }

  const feeVerifier = ports.feeVerifier ?? allowAllFeeVerifier;
  const fee = await feeVerifier.verifyDataReadFee({
    grantId: grant.id,
    builderAddress: input.signer,
    requestedScope: input.requestedScope,
  });
  if (!fee.ok) {
    throw new FeeRequiredError({
      grantId: grant.id,
      reason: fee.reason ?? "Fee verification failed",
    });
  }

  return grant;
}
