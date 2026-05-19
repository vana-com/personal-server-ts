import type {
  FeeVerifierPort,
  FeeVerificationInput,
  FeeVerificationResult,
} from "@opendatalabs/personal-server-ts-core/ports";
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
 */

export interface GrantFeeVerifierOptions {
  /** DP RPC base URL (same origin as the gateway client). */
  gatewayUrl: string;
  logger?: Logger;
  /**
   * Abort the DP RPC fee lookup after this many ms so a hung request fails
   * closed instead of stalling every protected read. Default 5000.
   */
  timeoutMs?: number;
}

/** The grant payment field the verifier reads from a DP RPC grant record. */
interface GrantPaymentView {
  paymentStatus?: "pending" | "paid";
}

export function createGrantFeeVerifier(
  options: GrantFeeVerifierOptions,
): FeeVerifierPort {
  const base = options.gatewayUrl.replace(/\/+$/, "");
  const timeoutMs = options.timeoutMs ?? 5000;

  return {
    async verifyDataReadFee(
      input: FeeVerificationInput,
    ): Promise<FeeVerificationResult> {
      // Fail closed: any uncertainty about payment must not release data.
      // A hung DP RPC is aborted after `timeoutMs`; the abort throws and is
      // handled here as "unavailable".
      let res: Response;
      try {
        res = await fetch(
          `${base}/v1/grants/${encodeURIComponent(input.grantId)}`,
          { signal: AbortSignal.timeout(timeoutMs) },
        );
      } catch (err) {
        options.logger?.warn(
          { err, grantId: input.grantId },
          "Fee check: DP RPC request failed",
        );
        return { ok: false, reason: "Payment status unavailable" };
      }

      if (!res.ok) {
        options.logger?.warn(
          { status: res.status, grantId: input.grantId },
          "Fee check: DP RPC returned an error",
        );
        return { ok: false, reason: "Payment status unavailable" };
      }

      let paymentStatus: GrantPaymentView["paymentStatus"];
      try {
        // DP RPC wraps GET responses as `{ data, proof }`.
        const body = (await res.json()) as { data?: GrantPaymentView };
        paymentStatus = body.data?.paymentStatus;
      } catch {
        return { ok: false, reason: "Payment status unavailable" };
      }

      if (paymentStatus === "paid") {
        return { ok: true };
      }
      return {
        ok: false,
        reason: `Grant registration fee not paid (status: ${
          paymentStatus ?? "unknown"
        })`,
      };
    },
  };
}
