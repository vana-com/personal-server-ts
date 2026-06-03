import { describe, it, expect, vi } from "vitest";
import type {
  GatewayClient,
  GatewayGrantResponse,
} from "@opendatalabs/vana-sdk/node";
import { createGrantFeeVerifier } from "./grant-fee-verifier.js";
import type { FeeVerificationInput } from "@opendatalabs/personal-server-ts-core/ports";

const input: FeeVerificationInput = {
  grantId: "0xgrant",
  builderAddress: "0x1111111111111111111111111111111111111111",
  requestedScope: "instagram.profile",
};

function grantResponse(
  paymentStatus: GatewayGrantResponse["paymentStatus"] | undefined,
): GatewayGrantResponse {
  return {
    id: input.grantId,
    grantorAddress: "0xowner",
    granteeId: "0xbuilder",
    scopes: ["instagram.*"],
    status: "confirmed",
    addedAt: "2026-01-01T00:00:00Z",
    expiresAt: null,
    expired: false,
    revokedAt: null,
    revocationSignature: null,
    paymentStatus: paymentStatus as GatewayGrantResponse["paymentStatus"],
    paidAt: paymentStatus === "paid" ? "2026-01-01T00:00:05Z" : null,
    paidBy: paymentStatus === "paid" ? "0xpayer" : null,
    grantVersion: "1",
    settleTxHash: null,
    settleSubmittedAt: null,
    revocationTxHash: null,
    revocationSubmittedAt: null,
    fee: {
      asset: "0x0000000000000000000000000000000000000000",
      registrationFee: "0",
      dataAccessFee: "0",
      totalDue: "0",
    },
  };
}

function makeGateway(
  getGrant: (id: string) => Promise<GatewayGrantResponse | null>,
): Pick<GatewayClient, "getGrant"> {
  return { getGrant: vi.fn(getGrant) };
}

describe("createGrantFeeVerifier", () => {
  it("allows the read when the grant fee is paid", async () => {
    const gateway = makeGateway(async () => grantResponse("paid"));
    const verifier = createGrantFeeVerifier({ gateway });

    expect(await verifier.verifyDataReadFee(input)).toEqual({ ok: true });
    expect(gateway.getGrant).toHaveBeenCalledWith(input.grantId);
  });

  it("blocks the read when the grant fee is pending", async () => {
    const gateway = makeGateway(async () => grantResponse("pending"));
    const verifier = createGrantFeeVerifier({ gateway });

    const result = await verifier.verifyDataReadFee(input);
    expect(result.ok).toBe(false);
    expect(result.ok ? "" : result.reason).toContain("pending");
  });

  it("blocks the read when paymentStatus is absent", async () => {
    const gateway = makeGateway(async () => grantResponse(undefined));
    const verifier = createGrantFeeVerifier({ gateway });

    const result = await verifier.verifyDataReadFee(input);
    expect(result.ok).toBe(false);
    expect(result.ok ? "" : result.reason).toContain("unknown");
  });

  it("fails closed when the gateway client throws", async () => {
    const gateway = makeGateway(async () => {
      throw new Error("ECONNREFUSED");
    });
    const verifier = createGrantFeeVerifier({ gateway });

    expect(await verifier.verifyDataReadFee(input)).toEqual({
      ok: false,
      reason: "Payment status unavailable",
    });
  });

  it("fails closed when the gateway returns null (grant not found)", async () => {
    const gateway = makeGateway(async () => null);
    const verifier = createGrantFeeVerifier({ gateway });

    expect(await verifier.verifyDataReadFee(input)).toEqual({
      ok: false,
      reason: "Payment status unavailable",
    });
  });
});
