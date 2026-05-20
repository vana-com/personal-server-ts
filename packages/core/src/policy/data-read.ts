import type { GatewayGrantResponse } from "@opendatalabs/vana-sdk/browser";
import {
  parseGrantRegistrationPayload,
  scopeCoveredByGrant,
} from "@opendatalabs/vana-sdk/browser";
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

  // DP RPC is migrating to a flat grant shape: fields once carried inside the
  // signed `grant` payload (scopes, expiresAt) are returned as top-level
  // columns, and `fileIds` is going away. Read either shape — prefer flat,
  // fall back to parsing the legacy signed payload — until the migration
  // lands across consumers. See vana-com/data-gateway#17.
  const flat = grant as Omit<GatewayGrantResponse, "grant" | "fileIds"> & {
    grant?: string;
    fileIds?: string[];
    scopes?: string[];
    expiresAt?: number;
  };
  const legacyPayload = flat.grant
    ? parseGrantRegistrationPayload(flat.grant)
    : null;

  const scopes = flat.scopes ?? legacyPayload?.scopes;
  if (!scopes) {
    throw new ScopeMismatchError({
      requestedScope: input.requestedScope,
      reason: "Grant has no scopes",
    });
  }

  const expiresAt = flat.expiresAt ?? legacyPayload?.expiresAt;
  if (expiresAt !== undefined && expiresAt > 0) {
    const now = Math.floor(Date.now() / 1000);
    if (expiresAt < now) {
      throw new GrantExpiredError({ expiresAt });
    }
  }

  if (!scopeCoveredByGrant(input.requestedScope, scopes)) {
    throw new ScopeMismatchError({
      requestedScope: input.requestedScope,
      grantedScopes: scopes,
    });
  }

  // fileIds restriction is legacy-only; the flat shape has no per-grant file
  // pinning. Enforce only when the field is present.
  const fileIds = flat.fileIds;
  if (fileIds && fileIds.length > 0) {
    if (!input.fileId) {
      throw new ScopeMismatchError({
        requestedScope: input.requestedScope,
        reason: "Grant is restricted to fileIds; request must include fileId",
        grantedFileIds: fileIds,
      });
    }
    if (!fileIds.includes(input.fileId)) {
      throw new ScopeMismatchError({
        requestedScope: input.requestedScope,
        requestedFileId: input.fileId,
        grantedFileIds: fileIds,
      });
    }
  }

  if (builder.id.toLowerCase() !== grant.granteeId.toLowerCase()) {
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
