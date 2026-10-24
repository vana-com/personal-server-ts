import type { PdppAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import {
  mapInactiveToError,
  pdppBearerReadLease,
  type BearerAdmission,
  type PdppChainEvidence,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import {
  deliver,
  evidenceTime,
  type DeliveryLease,
} from "@opendatalabs/personal-server-ts-core/policy";
import { PdppError } from "@opendatalabs/personal-server-ts-core/errors/pdpp";
import {
  chainDenialError,
  type PdppChainDenialCause,
  type PdppProtocolProfile,
} from "./bearer-response.js";

/** Deployment authority shared by every PDPP read surface. */
export interface PdppReadAuthority {
  auth: PdppAuthorizationService;
  protocolProfile?: PdppProtocolProfile;
  /**
   * Configured means every client read must pass this authority. Omission is
   * the existing explicit chain-neutral deployment contract; owner reads do
   * not depend on a grantee's chain permission.
   */
  chainEnforcement?: PdppChainEnforcementPort;
}

/** The existing chain policy port; all read surfaces consume the same decision. */
export interface PdppChainEnforcementPort {
  authorize(input: {
    pdppGrantId: string;
    clientId: string;
  }): Promise<PdppChainDecision>;
}
export type PdppChainDecision =
  | { ok: true; expiresAt?: string | null }
  | { ok: false; retryable: true; reason: string }
  | {
      ok: false;
      retryable: false;
      reason: string;
      cause: PdppChainDenialCause;
    };

/** Complete authorization admission; selection adds its own data dependencies. */
export interface PdppReadAdmission extends BearerAdmission {
  readonly lease: DeliveryLease;
}

/**
 * Complete a dated bearer admission under the deployment's read authorities.
 * The same lease rechecks known deadlines and local revocation after slow
 * chain work, then accompanies the result through every release boundary.
 */
export async function admitPdppRead(
  authority: PdppReadAuthority,
  admission: BearerAdmission,
): Promise<PdppReadAdmission> {
  const context = admission.context;
  if (!context.active) throw mapInactiveToError(context);
  let chain: Parameters<typeof pdppBearerReadLease>[2];
  if (authority.chainEnforcement && context.tokenKind === "client") {
    const grantId = context.grant?.grant_id;
    if (!grantId)
      throw chainDenialError(
        "invalid",
        "No chain binding for this grant",
        authority.protocolProfile,
      );
    const verify = async (): Promise<PdppChainEvidence> => {
      const decision = await authority.chainEnforcement!.authorize({
        pdppGrantId: grantId,
        clientId: context.clientId ?? "",
      });
      if (!decision.ok) {
        if (decision.retryable)
          throw new PdppError(
            "api_error",
            "Chain authorization could not be verified",
          );
        throw chainDenialError(
          decision.cause,
          decision.reason,
          authority.protocolProfile,
        );
      }
      return { expiresAt: decision.expiresAt };
    };
    const verifiedAt = evidenceTime();
    chain = {
      chain: { admitted: await verify(), reverify: verify, verifiedAt },
    };
  }
  const lease = pdppBearerReadLease(authority.auth, admission, chain);
  await deliver(lease, () => undefined);
  return { ...admission, lease };
}
