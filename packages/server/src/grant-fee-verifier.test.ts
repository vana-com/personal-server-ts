import { describe, it, expect, vi, afterEach } from "vitest";
import { createGrantFeeVerifier } from "./grant-fee-verifier.js";
import type { FeeVerificationInput } from "@opendatalabs/personal-server-ts-core/ports";

const GATEWAY_URL = "https://dp-rpc.example";

const input: FeeVerificationInput = {
  grantId: "0xgrant",
  builderAddress: "0x1111111111111111111111111111111111111111",
  requestedScope: "instagram.profile",
};

function mockFetch(impl: () => Response | Promise<Response>) {
  const fn = vi.fn(impl);
  vi.stubGlobal("fetch", fn);
  return fn;
}

function grantResponse(paymentStatus?: string) {
  return new Response(
    JSON.stringify({ data: { id: input.grantId, paymentStatus }, proof: {} }),
    { status: 200, headers: { "Content-Type": "application/json" } },
  );
}

afterEach(() => vi.unstubAllGlobals());

describe("createGrantFeeVerifier", () => {
  it("allows the read when the grant fee is paid", async () => {
    mockFetch(() => grantResponse("paid"));
    const verifier = createGrantFeeVerifier({ gatewayUrl: GATEWAY_URL });

    expect(await verifier.verifyDataReadFee(input)).toEqual({ ok: true });
  });

  it("blocks the read when the grant fee is pending", async () => {
    mockFetch(() => grantResponse("pending"));
    const verifier = createGrantFeeVerifier({ gatewayUrl: GATEWAY_URL });

    expect((await verifier.verifyDataReadFee(input)).ok).toBe(false);
  });

  it("blocks the read when paymentStatus is absent", async () => {
    mockFetch(() => grantResponse(undefined));
    const verifier = createGrantFeeVerifier({ gatewayUrl: GATEWAY_URL });

    expect((await verifier.verifyDataReadFee(input)).ok).toBe(false);
  });

  it("fails closed when DP RPC returns an error", async () => {
    mockFetch(() => new Response("nope", { status: 500 }));
    const verifier = createGrantFeeVerifier({ gatewayUrl: GATEWAY_URL });

    expect(await verifier.verifyDataReadFee(input)).toEqual({
      ok: false,
      reason: "Payment status unavailable",
    });
  });

  it("fails closed when DP RPC is unreachable", async () => {
    mockFetch(() => Promise.reject(new Error("ECONNREFUSED")));
    const verifier = createGrantFeeVerifier({ gatewayUrl: GATEWAY_URL });

    expect(await verifier.verifyDataReadFee(input)).toEqual({
      ok: false,
      reason: "Payment status unavailable",
    });
  });

  it("queries the grant-by-id endpoint with an abort signal, trimming a trailing slash", async () => {
    const fn = mockFetch(() => grantResponse("paid"));
    const verifier = createGrantFeeVerifier({ gatewayUrl: `${GATEWAY_URL}/` });

    await verifier.verifyDataReadFee(input);

    expect(fn).toHaveBeenCalledWith(
      `${GATEWAY_URL}/v1/grants/${encodeURIComponent(input.grantId)}`,
      { signal: expect.any(AbortSignal) },
    );
  });

  it("fails closed when the DP RPC request times out", async () => {
    mockFetch(
      () =>
        new Promise((_resolve, reject) => {
          reject(new DOMException("The operation timed out.", "TimeoutError"));
        }),
    );
    const verifier = createGrantFeeVerifier({
      gatewayUrl: GATEWAY_URL,
      timeoutMs: 10,
    });

    expect(await verifier.verifyDataReadFee(input)).toEqual({
      ok: false,
      reason: "Payment status unavailable",
    });
  });
});
