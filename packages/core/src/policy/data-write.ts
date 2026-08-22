import type { GatewayGrantResponse } from "@opendatalabs/vana-sdk/browser";
import { scopeMatchesPattern } from "@opendatalabs/vana-sdk/browser";
import {
  GrantExpiredError,
  GrantOwnerMismatchError,
  GrantRequiredError,
  GrantRevokedError,
  InvalidSignatureError,
  PsUnavailableError,
  ScopeMismatchError,
  ServerNotConfiguredError,
  UnregisteredBuilderError,
} from "../errors/catalog.js";
import {
  type AuthSessionVerifierPort,
  type GrantVerifierPort,
  type RuntimeAvailabilityPort,
} from "../ports/index.js";
import { parseGrantExpiresAtSeconds } from "./data-read.js";

/**
 * Write-grant encoding: a grant scope entry prefixed with `write:` authorizes
 * the grantee to WRITE into the scope it names (e.g. `write:notes.entries`,
 * `write:notes.*`). The suffix uses the same pattern grammar as read scopes
 * (`*` / `{prefix}.*` / exact), evaluated with the SDK's scopeMatchesPattern.
 *
 * Why a scope-entry prefix and not a new grant field: the gateway's grant
 * shape (GatewayGrantResponse) has no permission axis — `scopes` is its only
 * capability carrier — and the gateway validates scope entries as opaque
 * non-empty strings, so `write:`-prefixed entries flow through createGrant /
 * getGrant / the EIP-712 GrantRegistration signature unchanged. The Personal
 * Server is the sole interpreter.
 *
 * Separation of powers falls out of the encoding:
 *   - read policy matches the REQUESTED scope against grant entries verbatim
 *     (scopeCoveredByGrant), and a requested scope never carries the prefix,
 *     so `write:x` entries can never satisfy a read;
 *   - write policy (below) only honors `write:`-prefixed entries, so plain
 *     read entries can never satisfy a write.
 */
export const WRITE_SCOPE_PREFIX = "write:";

export function isWriteScopeEntry(entry: string): boolean {
  return entry.startsWith(WRITE_SCOPE_PREFIX);
}

/** The scope patterns a grant authorizes for writing (prefix stripped). */
export function writeScopePatterns(grantScopes: readonly string[]): string[] {
  return grantScopes
    .filter(isWriteScopeEntry)
    .map((entry) => entry.slice(WRITE_SCOPE_PREFIX.length))
    .filter((pattern) => pattern.length > 0);
}

export function scopeCoveredByWriteGrant(
  requestedScope: string,
  grantScopes: readonly string[],
): boolean {
  return writeScopePatterns(grantScopes).some((pattern) =>
    scopeMatchesPattern(requestedScope, pattern),
  );
}

/**
 * Fee seam for builder writes. Write fee mechanics are undecided — the
 * default (no port wired) is FREE. When a fee model lands (x402-style like
 * reads, or something else), implement this port and wire it into
 * DataWritePolicyPorts; the policy calls it after all authorization
 * invariants pass, so a fee rejection never masks an auth failure.
 */
export interface WriteFeeVerifierPort {
  assertWriteAllowed(input: {
    builder: `0x${string}`;
    grant: GatewayGrantResponse;
    scope: string;
  }): Promise<void>;
}

export interface DataWritePolicyInput {
  signer: `0x${string}`;
  grantId?: string;
  requestedScope: string;
  /**
   * This server's owner address. The grant's grantor MUST equal it — a grant
   * issued by a different owner is rejected. Required (not optional) so that
   * TypeScript flags any caller that fails to bind the write to the server
   * owner; the check also fails closed at runtime for untyped/JS callers.
   */
  serverOwner: `0x${string}`;
}

export interface DataWritePolicyPorts {
  authSessionVerifier: AuthSessionVerifierPort;
  grantVerifier: GrantVerifierPort;
  runtimeAvailability?: RuntimeAvailabilityPort;
  /** Absent = writes are free (see WriteFeeVerifierPort). */
  writeFeeVerifier?: WriteFeeVerifierPort;
}

/**
 * Authorize one builder write against a write-grant. Mirrors
 * verifyDataReadPolicy invariant-for-invariant (builder registered, grant
 * present / not revoked / not expired, scope coverage, grantee binding,
 * owner binding) — but scope coverage only honors `write:`-prefixed grant
 * entries, so a read-grant never confers write access.
 */
export async function verifyDataWritePolicy(
  input: DataWritePolicyInput,
  ports: DataWritePolicyPorts,
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
      reason: "No grantId bound to the write session",
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

  if (!grant.scopes || writeScopePatterns(grant.scopes).length === 0) {
    throw new ScopeMismatchError({
      requestedScope: input.requestedScope,
      reason: "Grant has no write scopes",
    });
  }

  if (grant.expiresAt !== null && grant.expiresAt !== undefined) {
    const expiresAtSec = parseGrantExpiresAtSeconds(grant.expiresAt);
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

  if (!scopeCoveredByWriteGrant(input.requestedScope, grant.scopes)) {
    throw new ScopeMismatchError({
      requestedScope: input.requestedScope,
      grantedScopes: grant.scopes,
      reason: "Grant does not authorize writing to this scope",
    });
  }

  if (builder.id.toLowerCase() !== grant.granteeId.toLowerCase()) {
    throw new InvalidSignatureError({
      reason: "Write signer is not the grant builder",
      expected: grant.granteeId,
      actual: input.signer,
    });
  }

  // Ownership binding — the grant MUST have been issued by THIS server's
  // owner (same fail-closed rules as verifyDataReadPolicy: a missing
  // serverOwner or a grantor-less gateway response rejects, never skips).
  if (!input.serverOwner) {
    throw new ServerNotConfiguredError({
      reason: "serverOwner is required to verify grant ownership",
    });
  }
  if (
    !grant.grantorAddress ||
    grant.grantorAddress.toLowerCase() !== input.serverOwner.toLowerCase()
  ) {
    throw new GrantOwnerMismatchError({
      grantId: grant.id,
      expected: input.serverOwner,
      actual: grant.grantorAddress ?? null,
    });
  }

  // All authorization invariants passed — apply the fee seam last (default
  // free; see WriteFeeVerifierPort).
  await ports.writeFeeVerifier?.assertWriteAllowed({
    builder: input.signer,
    grant,
    scope: input.requestedScope,
  });

  return grant;
}
