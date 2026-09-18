import type { GatewayGrantResponse } from "@opendatalabs/vana-sdk/browser";
import { scopeCoveredByGrant } from "@opendatalabs/vana-sdk/browser";
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
import { verifyPdppGrantBinding } from "../grants/pdpp-binding.js";
import type { PdppGrantBindingStore } from "../grants/pdpp-binding-store.js";

export interface DataReadPolicyInput {
  signer: `0x${string}`;
  grantId?: string;
  requestedScope: string;
  // fileId is retained on the input shape for backwards-compat with callers
  // that pass it; the canary policy no longer enforces fileId pinning.
  fileId?: string;
  /**
   * This server's owner address. The grant's grantor MUST equal it — a grant
   * issued by a different owner is rejected. Required (not optional) so that
   * TypeScript flags any caller that fails to bind the read to the server
   * owner; the check also fails closed at runtime for untyped/JS callers.
   */
  serverOwner: `0x${string}`;
  /**
   * The PDPP grant id the caller is reading under, when the read is authorized
   * through a PDPP grant rather than a bare chain grant (§6).
   *
   * Optional because the chain-grant read path predates PDPP and still works
   * on its own. When present — and only then — the PDPP↔chain binding is
   * enforced in addition to every existing check, never instead of one.
   */
  pdppGrantId?: string;
}

export interface DataReadPolicyPorts {
  authSessionVerifier: AuthSessionVerifierPort;
  grantVerifier: GrantVerifierPort;
  /**
   * Retained PDPP↔chain grant bindings. Required only to serve reads that
   * present a `pdppGrantId`; a PS with no PDPP surface omits it.
   */
  pdppGrantBindings?: PdppGrantBindingStore;
  /**
   * The chain deployment this PS is configured against. Required alongside
   * `pdppGrantBindings` so a binding recorded on one network cannot authorize
   * a read on another.
   */
  chainDeployment?: { chainId: number; contractAddress: `0x${string}` };
  // feeVerifier is gone — payment is enforced by the X402 layer on
  // GET /v1/data/:scope, which forwards the builder's signed payment to
  // gateway.payForOperation. The policy no longer gates reads on
  // grant.paymentStatus.
  runtimeAvailability?: RuntimeAvailabilityPort;
}

/**
 * Parse a grant's `expiresAt` into unix seconds. Accepts the legacy
 * uint256-seconds string, a numeric value, or the current gateway ISO
 * timestamp. Returns 0 for "perpetual" encodings (null/undefined/"0") and
 * null for unparseable input. Shared by the read and write policies so both
 * stay aligned with the gateway response shape.
 */
export function parseGrantExpiresAtSeconds(value: unknown): number | null {
  if (value === null || value === undefined || value === "0") return 0;
  if (typeof value === "number") return Number.isFinite(value) ? value : null;
  if (typeof value !== "string") return null;

  const numeric = Number(value);
  if (Number.isFinite(numeric)) return numeric;

  const millis = Date.parse(value);
  return Number.isNaN(millis) ? null : Math.floor(millis / 1000);
}

/** Auth-result sentinels; see the reserved-grantId check below. */
export const SENTINEL_GRANT_IDS = new Set(["owner", "policy-bypass"]);

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

  // "owner" / "policy-bypass" are server-internal auth-result sentinels that
  // confer the unredacted owner view and the x402 payment exemption. Neither
  // caller input nor a gateway-supplied grant id may ever occupy them.
  if (SENTINEL_GRANT_IDS.has(input.grantId)) {
    throw new GrantRequiredError({
      reason: "Reserved grantId",
      grantId: input.grantId,
    });
  }

  const grant = await ports.grantVerifier.getGrant(input.grantId);
  if (!grant) {
    throw new GrantRequiredError({
      reason: "Grant not found",
      grantId: input.grantId,
    });
  }

  if (SENTINEL_GRANT_IDS.has(grant.id)) {
    throw new GrantRequiredError({
      reason: "Grant resolved to a reserved id",
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

  // Ownership binding — the grant MUST have been issued by THIS server's owner.
  // Otherwise any PS holding the requested scope's data would serve it under a
  // grant issued by a *different* owner (the happy-path binding is the app
  // resolving the grantor's own PS via serverAddress — a convention, not an
  // enforcement). Fail CLOSED: a missing serverOwner (server misconfig) or a
  // grant with no grantor (gateway responses are untrusted runtime data,
  // despite their type) must reject, never skip the check.
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

  // §6 — PDPP↔chain binding. Runs last, so it strengthens the chain-grant
  // checks above rather than substituting for them: a read presenting a PDPP
  // grant must satisfy BOTH authorities.
  if (input.pdppGrantId !== undefined) {
    // Fail closed. A PS that cannot check the binding must not serve the read
    // as if there were nothing to check — that would make the binding
    // bypassable by simply omitting the store.
    //
    // The client is told only that no binding authorizes the read. Reporting
    // "this server is misconfigured" would disclose the operator's deployment
    // state to an unauthorized caller, and the distinction is useless to a
    // client either way: both mean "not authorized here". `misconfigured` is
    // carried in the details for the operator's logs.
    if (!ports.pdppGrantBindings || !ports.chainDeployment) {
      throw new GrantRequiredError({
        reason: "No binding authorizes this PDPP grant",
        pdppGrantId: input.pdppGrantId,
        misconfigured: true,
      });
    }

    const binding = ports.pdppGrantBindings.getByPdppGrantId(input.pdppGrantId);
    if (!binding) {
      throw new GrantRequiredError({
        reason: "No retained binding for this PDPP grant",
        pdppGrantId: input.pdppGrantId,
      });
    }

    // The binding must point at the very chain grant we just validated;
    // otherwise a caller could pair a valid PDPP grant with an unrelated
    // chain grant that happens to pass on its own.
    if (binding.permission.permissionId !== grant.id) {
      throw new ScopeMismatchError({
        requestedScope: input.requestedScope,
        reason: "PDPP binding does not reference the presented chain grant",
        expected: binding.permission.permissionId,
        actual: grant.id,
      });
    }

    verifyPdppGrantBinding({
      binding,
      pdppGrantId: input.pdppGrantId,
      serverOwner: input.serverOwner,
      requestSigner: input.signer,
      chainGrant: grant,
      deployment: ports.chainDeployment,
    });
  }

  return grant;
}
