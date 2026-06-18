import type { GatewayGrantResponse } from "@opendatalabs/vana-sdk/browser";
import { scopeCoveredByGrant } from "@opendatalabs/vana-sdk/browser";
import {
  GrantExpiredError,
  GrantRequiredError,
  GrantRevokedError,
  InvalidSignatureError,
  PsUnavailableError,
  ScopeMismatchError,
  UnregisteredBuilderError,
} from "../errors/catalog.js";
import {
  type AuthSessionVerifierPort,
  type GrantVerifierPort,
  type RuntimeAvailabilityPort,
} from "../ports/index.js";

export interface DataReadPolicyInput {
  signer: `0x${string}`;
  grantId?: string;
  requestedScope: string;
  // fileId is retained on the input shape for backwards-compat with callers
  // that pass it; the canary policy no longer enforces fileId pinning.
  fileId?: string;
}

export interface DataReadPolicyPorts {
  authSessionVerifier: AuthSessionVerifierPort;
  grantVerifier: GrantVerifierPort;
  // feeVerifier is gone — payment is enforced by the X402 layer on
  // GET /v1/data/:scope, which forwards the builder's signed payment to
  // gateway.payForOperation. The policy no longer gates reads on
  // grant.paymentStatus.
  runtimeAvailability?: RuntimeAvailabilityPort;
}

function parseExpiresAtSeconds(value: unknown): number | null {
  if (value === null || value === undefined || value === "0") return 0;
  if (typeof value === "number") return Number.isFinite(value) ? value : null;
  if (typeof value !== "string") return null;

  const numeric = Number(value);
  if (Number.isFinite(numeric)) return numeric;

  const millis = Date.parse(value);
  return Number.isNaN(millis) ? null : Math.floor(millis / 1000);
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

  // Canary GatewayGrantResponse is flat — scopes is a top-level string[]
  // and expiresAt is a decimal-string uint256 (`null` = perpetual). The
  // legacy signed `grant` JSON blob and `fileIds` pinning are gone.
  if (!grant.scopes || grant.scopes.length === 0) {
    throw new ScopeMismatchError({
      requestedScope: input.requestedScope,
      reason: "Grant has no scopes",
    });
  }

  if (grant.expiresAt !== null && grant.expiresAt !== undefined) {
    // DPv2 may surface either the legacy uint256-seconds string or the
    // current gateway ISO timestamp. Parse both so the policy stays aligned
    // with the gateway response shape.
    const expiresAtSec = parseExpiresAtSeconds(grant.expiresAt);
    if (expiresAtSec === null) {
      throw new ScopeMismatchError({
        requestedScope: input.requestedScope,
        reason: "Grant expiry is invalid",
      });
    }
    if (expiresAtSec > 0) {
      const nowSec = Math.floor(Date.now() / 1000);
      if (expiresAtSec < nowSec) {
        throw new GrantExpiredError({
          expiresAt: expiresAtSec,
        });
      }
    }
  }

  if (!scopeCoveredByGrant(input.requestedScope, grant.scopes)) {
    throw new ScopeMismatchError({
      requestedScope: input.requestedScope,
      grantedScopes: grant.scopes,
    });
  }

  if (builder.id.toLowerCase() !== grant.granteeId.toLowerCase()) {
    throw new InvalidSignatureError({
      reason: "Request signer is not the grant builder",
      expected: grant.granteeId,
      actual: input.signer,
    });
  }

  return grant;
}
