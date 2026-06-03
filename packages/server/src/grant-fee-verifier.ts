import type {
  FeeVerifierPort,
  FeeVerificationInput,
  FeeVerificationResult,
} from "@opendatalabs/personal-server-ts-core/ports";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import type { Logger } from "pino";

/**
 * Fee verifier that gates data reads on the grant's payment status at DP RPC.
 *
 * Implements {@link FeeVerifierPort}: a read is allowed only when DP RPC
 * reports the grant's registration fee as `paid`.
 *
 * @remarks
 * Payment is settled out of band — the payer (sponsor / builder app) calls DP
 * RPC `POST /v1/escrow/pay` directly with their own EIP-712 signature. The
 * Personal Server neither relays nor holds payments; it only enforces the
 * resulting `paymentStatus` on the grant. Contract per the DP RPC
 * `GET /v1/grants` spec (BUI-398).
 *
 * Backed by `gateway.getGrant(grantId)` from the canary SDK — the typed
 * client both handles the gateway envelope unwrap and surfaces a flat
 * `paymentStatus` field on {@link GatewayGrantResponse} so we don't need
 * to fork the wire shape here.
 */

export interface GrantFeeVerifierOptions {
  gateway: Pick<GatewayClient, "getGrant">;
  logger?: Logger;
}

export function createGrantFeeVerifier(
  options: GrantFeeVerifierOptions,
): FeeVerifierPort {
  return {
    async verifyDataReadFee(
      input: FeeVerificationInput,
    ): Promise<FeeVerificationResult> {
      // Fail closed: any uncertainty about payment must not release data.
      // gateway.getGrant throws on transport/HTTP errors and returns null
      // for 404 — both treated as "unavailable".
      let grant: Awaited<ReturnType<GatewayClient["getGrant"]>>;
      try {
        grant = await options.gateway.getGrant(input.grantId);
      } catch (err) {
        options.logger?.warn(
          { err, grantId: input.grantId },
          "Fee check: DP RPC getGrant failed",
        );
        return { ok: false, reason: "Payment status unavailable" };
      }

      if (!grant) {
        options.logger?.warn(
          { grantId: input.grantId },
          "Fee check: DP RPC returned no grant for id",
        );
        return { ok: false, reason: "Payment status unavailable" };
      }

      if (grant.paymentStatus === "paid") {
        return { ok: true };
      }
      return {
        ok: false,
        reason: `Grant registration fee not paid (status: ${
          grant.paymentStatus ?? "unknown"
        })`,
      };
    },
  };
}
