/**
 * Enforcing the Vana chain permission on PDPP client reads.
 *
 * ## The gap this closes
 *
 * A PDPP access token proves the owner consented. It does not prove the Vana
 * permission that authorizes the read is still live. Those are two authorities
 * over two different objects, and the bearer read path checked only the first:
 * it resolved a locally-issued token in-process and served records. So a
 * permission revoked on chain kept reading fine through PDPP, and the ledger's
 * authority was silently not enforced for any PDPP client.
 *
 * This adapter is the join. It looks up the retained binding for the presented
 * PDPP grant, reads the chain grant live, and hands both to
 * `verifyPdppGrantBinding`, which checks every axis at once: the record, the
 * deployment, the owner, the grantee app, and revocation.
 *
 * ## Why the verification is not re-implemented here
 *
 * `packages/core/src/grants/pdpp-binding.ts` already does it, and correctly:
 * bindings are keyed by the chain's own identity tuple rather than a derived
 * hash, the record is append-only, and revocation is read live instead of
 * mirrored into storage. Re-deriving any of that here would create a second
 * opinion about what a valid binding is, and the two would drift. This file
 * only supplies inputs and translates the outcome.
 *
 * `verifyPdppGrantBinding` checks revocation but NOT expiry — that axis is
 * added here, immediately after it passes, using the same
 * `parseGrantExpiresAtSeconds` the legacy chain-grant read path
 * (`verifyDataReadPolicy`) uses. Without it, this bearer path would silently
 * keep serving an expired-but-not-revoked grant that the legacy path already
 * denies — a gap, not a design choice.
 *
 * ## Fail closed, and the retryable distinction
 *
 * Every denial path answers "no". The only judgment this file makes is whether
 * a "no" is *definite* or merely *unknown*:
 *
 *   - No binding, wrong owner, wrong grantee, revoked, expired → definite.
 *     Asking again changes nothing.
 *   - Gateway unreachable, RPC timeout, malformed response → unknown.
 *
 * Unknown must still deny. Not knowing is not permission, and an outage that
 * opened reads would be an authorization bypass that nobody notices, because
 * the reads all look successful. What unknown gets is a *retryable* answer, so
 * the route can say "try again" rather than "your grant is dead" to a client
 * whose grant is probably fine.
 *
 * A missing binding is deliberately in the definite-denial bucket, not the
 * unknown one. "Not bound yet" and "never bound" are indistinguishable from
 * here, so treating absence as a temporary condition would let an unbound
 * grant read for as long as a caller kept retrying.
 */

import {
  verifyPdppGrantBinding,
  type PdppGrantBindingStore,
} from "@opendatalabs/personal-server-ts-core/grants";
import { parseGrantExpiresAtSeconds } from "@opendatalabs/personal-server-ts-core/policy";
import type { GatewayGrantResponse } from "@opendatalabs/vana-sdk/browser";
import type { Logger } from "pino";
import type {
  PdppChainDecision,
  PdppChainEnforcementPort,
} from "../routes/pdpp-records.js";

export interface ChainEnforcementOptions {
  /** Retained bindings, written at grant creation. */
  bindings: PdppGrantBindingStore;
  /**
   * Reads the chain grant as it stands NOW. Returning null means "this
   * permission does not exist", which `verifyPdppGrantBinding` treats as
   * revoked; THROWING means "I could not find out", which is retryable.
   *
   * The two are different answers and must not be collapsed: a gateway that
   * returns null on a network error would turn every outage into a permanent
   * revocation for every client.
   */
  readChainGrant(permissionId: string): Promise<GatewayGrantResponse | null>;
  /** The owner this server is configured for, at read time. */
  serverOwner: `0x${string}`;
  /** The deployment the PS is configured against. */
  deployment: { chainId: number; contractAddress: `0x${string}` };
  /**
   * The app's grantee wallet address for a given PDPP `client_id`.
   *
   * Resolved per request rather than taken from the binding, because this is
   * the half that proves the CALLER is the bound app rather than merely
   * knowing its grant id. Returning null denies.
   */
  granteeAddressFor(clientId: string): `0x${string}` | null;
  logger: Logger;
  /**
   * Deterministic clock for expiry comparisons. Defaults to the real clock;
   * tests inject a fixed value so expiry assertions aren't a race against
   * wall time.
   */
  now?: () => Date;
}

export function chainPermissionEnforcement(
  options: ChainEnforcementOptions,
): PdppChainEnforcementPort {
  const { bindings, deployment, logger, serverOwner } = options;

  return {
    async authorize({ clientId, pdppGrantId }): Promise<PdppChainDecision> {
      const binding = bindings.getByPdppGrantId(pdppGrantId);
      if (!binding) {
        // Definite: absence of a binding is not a pending state.
        return {
          ok: false,
          reason: "No chain binding for this grant",
          retryable: false,
        };
      }

      const granteeAddress = options.granteeAddressFor(clientId);
      if (!granteeAddress) {
        return {
          ok: false,
          reason: "No grantee address for this client",
          retryable: false,
        };
      }

      let chainGrant: GatewayGrantResponse | null;
      try {
        chainGrant = await options.readChainGrant(
          binding.permission.permissionId,
        );
      } catch (err) {
        // Unknown, not denied. Logged at warn because a persistent unknown is
        // an outage worth paging on, and it is invisible in the response.
        logger.warn(
          {
            err: (err as Error).message,
            permissionId: binding.permission.permissionId,
            pdppGrantId,
          },
          "PDPP chain enforcement: could not read chain grant",
        );
        return {
          ok: false,
          reason: "Chain grant could not be read",
          retryable: true,
        };
      }

      try {
        verifyPdppGrantBinding({
          binding,
          chainGrant,
          deployment,
          pdppGrantId,
          // The caller proves it is the app by being the bound grantee. On the
          // bearer path the token IS the proof of which client is calling, so
          // the resolved address for that client_id stands in for a signature.
          requestSigner: granteeAddress,
          serverOwner,
        });
      } catch (err) {
        // Every failure here is definite: owner mismatch, grantee mismatch,
        // wrong deployment, or revocation. None improve on retry.
        return {
          ok: false,
          reason: (err as Error).message,
          retryable: false,
        };
      }

      // `verifyPdppGrantBinding` does not check expiry — it only checks
      // revocation. The legacy `/v1/data/:scope` chain-grant read path
      // (`verifyDataReadPolicy`) enforces `grant.expiresAt`; this bearer path
      // must not silently skip a check that path already makes. `chainGrant`
      // is non-null here (a null grant already returned above via
      // `verifyPdppGrantBinding`'s "not found = revoked" check).
      const expiresAtSec = parseGrantExpiresAtSeconds(chainGrant!.expiresAt);
      if (expiresAtSec === null) {
        return {
          ok: false,
          reason: "Grant expiry is invalid",
          retryable: false,
        };
      }
      if (expiresAtSec > 0) {
        const nowSec = Math.floor(
          (options.now?.() ?? new Date()).getTime() / 1000,
        );
        if (expiresAtSec < nowSec) {
          return {
            ok: false,
            reason: "Grant has expired",
            retryable: false,
          };
        }
      }

      return { ok: true };
    },
  };
}
