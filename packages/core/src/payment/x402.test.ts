import { describe, it, expect } from "vitest";
import {
  GENERIC_PAYMENT_TYPES,
  escrowPaymentDomain,
  type DataPortabilityGatewayConfig,
  type GatewayGrantResponse,
} from "@opendatalabs/vana-sdk/browser";
import { privateKeyToAccount } from "viem/accounts";
import {
  buildChallenge,
  encodePaymentHeader,
  nextPaymentNonce,
  paymentNonceIssueTimeMs,
  parsePaymentHeader,
  verifyPayment,
  type X402Payment,
} from "./x402.js";

const gatewayConfig: DataPortabilityGatewayConfig = {
  chainId: 14800,
  contracts: {
    dataRegistry: "0x0000000000000000000000000000000000000001",
    dataPortabilityPermissions: "0x0000000000000000000000000000000000000002",
    dataPortabilityServer: "0x0000000000000000000000000000000000000003",
    dataPortabilityGrantees: "0x0000000000000000000000000000000000000004",
    dataPortabilityEscrow: "0x0000000000000000000000000000000000000005",
    feeRegistry: "0x0000000000000000000000000000000000000006",
  },
};

// Deterministic keys so signatures are reproducible across runs.
const builderAccount = privateKeyToAccount(
  ("0x" + "11".repeat(32)) as `0x${string}`,
);
const serverAccount = privateKeyToAccount(
  ("0x" + "22".repeat(32)) as `0x${string}`,
);
const GRANT_ID =
  "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" as const;
const OWNER_ADDRESS =
  "0x0000000000000000000000000000000000000aaa" as `0x${string}`;

function makeGrant(
  overrides: Partial<GatewayGrantResponse> = {},
): GatewayGrantResponse {
  return {
    id: GRANT_ID,
    grantorAddress: OWNER_ADDRESS,
    granteeId: ("0x" + "bb".repeat(32)) as `0x${string}`,
    scopes: ["instagram.*"],
    status: "confirmed",
    addedAt: "2026-01-21T10:00:00.000Z",
    expiresAt: null,
    expired: false,
    revokedAt: null,
    revocationSignature: null,
    paymentStatus: "pending",
    paidAt: null,
    paidBy: null,
    grantVersion: "1",
    settleTxHash: null,
    settleSubmittedAt: null,
    revocationTxHash: null,
    revocationSubmittedAt: null,
    fee: {
      asset: "0x0000000000000000000000000000000000000000",
      registrationFee: "10000000000000000",
      dataAccessFee: "1000000000000000",
      totalDue: "11000000000000000",
    },
    ...overrides,
  };
}

describe("nextPaymentNonce", () => {
  it("produces strictly-monotonic-across-ms values", async () => {
    const a = nextPaymentNonce();
    await new Promise((r) => setTimeout(r, 2));
    const b = nextPaymentNonce();
    // The high 32 bits encode Date.now(); b should be later than a.
    expect(paymentNonceIssueTimeMs(b) >= paymentNonceIssueTimeMs(a)).toBe(true);
    // Full value strictly increases when ms ticks forward.
    expect(b > a).toBe(true);
  });

  it("issue-time extraction recovers Date.now()", () => {
    const t0 = BigInt(Date.now());
    const nonce = nextPaymentNonce();
    const issued = paymentNonceIssueTimeMs(nonce);
    expect(issued >= t0).toBe(true);
    expect(issued - t0 <= 1000n).toBe(true);
  });
});

describe("buildChallenge", () => {
  it("includes amount=totalDue and registrationOwed=true on pending grants", async () => {
    const challenge = await buildChallenge({
      builder: builderAccount.address,
      grantId: GRANT_ID,
      grant: makeGrant({ paymentStatus: "pending" }),
      network: "vana:14800",
      gatewayConfig,
    });
    expect(challenge.x402Version).toBe(1);
    expect(challenge.error).toBe("PAYMENT_REQUIRED");
    expect(challenge.accepts).toHaveLength(1);
    const accept = challenge.accepts[0];
    expect(accept.scheme).toBe("vana-escrow-grant");
    expect(accept.amount).toBe("11000000000000000");
    expect(accept.breakdown.registrationOwed).toBe(true);
    expect(accept.message.payerAddress).toBe(builderAccount.address);
    expect(accept.message.opId).toBe(GRANT_ID);
    expect(accept.message.opType).toBe("grant");
  });

  it("emits accessRecord only when entry.dataPointId is non-null and signer is supplied", async () => {
    const grant = makeGrant();
    const dataPointId =
      "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" as const;

    const withSigner = await buildChallenge({
      builder: builderAccount.address,
      grantId: GRANT_ID,
      grant,
      network: "vana:14800",
      gatewayConfig,
      serverSigner: {
        async signRecordDataAccess() {
          return ("0x" + "ee".repeat(65)) as `0x${string}`;
        },
      },
      serverOwner: OWNER_ADDRESS,
      entry: { dataPointId, scope: "instagram.profile", version: 1 },
    });
    expect(withSigner.accepts[0].accessRecord).toBeDefined();
    expect(withSigner.accepts[0].accessRecord?.dataPointId).toBe(dataPointId);
    expect(withSigner.accepts[0].accessRecord?.accessor).toBe(
      builderAccount.address,
    );
    expect(withSigner.accepts[0].accessRecord?.version).toBe("1");

    const noEntry = await buildChallenge({
      builder: builderAccount.address,
      grantId: GRANT_ID,
      grant,
      network: "vana:14800",
      gatewayConfig,
      serverSigner: {
        async signRecordDataAccess() {
          return ("0x" + "ee".repeat(65)) as `0x${string}`;
        },
      },
      serverOwner: OWNER_ADDRESS,
      entry: { dataPointId: null, scope: "instagram.profile", version: 1 },
    });
    expect(noEntry.accepts[0].accessRecord).toBeUndefined();
  });

  it("amount reflects paymentStatus: paid grants get dataAccessFee only", async () => {
    const paid = await buildChallenge({
      builder: builderAccount.address,
      grantId: GRANT_ID,
      grant: makeGrant({
        paymentStatus: "paid",
        paidAt: "2026-01-21T10:00:05.000Z",
        paidBy: OWNER_ADDRESS,
        // gateway's totalDue already accounts for paymentStatus
        fee: {
          asset: "0x0000000000000000000000000000000000000000",
          registrationFee: "10000000000000000",
          dataAccessFee: "1000000000000000",
          totalDue: "1000000000000000",
        },
      }),
      network: "vana:14800",
      gatewayConfig,
    });
    expect(paid.accepts[0].amount).toBe("1000000000000000");
    expect(paid.accepts[0].breakdown.registrationOwed).toBe(false);
  });
});

describe("parsePaymentHeader", () => {
  it("returns null for missing / blank / malformed header", () => {
    expect(parsePaymentHeader(null)).toBeNull();
    expect(parsePaymentHeader(undefined)).toBeNull();
    expect(parsePaymentHeader("")).toBeNull();
    expect(parsePaymentHeader("not-base64-???")).toBeNull();
    // Valid base64 but invalid JSON
    expect(parsePaymentHeader(btoa("not json"))).toBeNull();
    // Valid base64+JSON but wrong shape
    expect(parsePaymentHeader(btoa('{"hello":"world"}'))).toBeNull();
  });

  it("round-trips a well-formed X402Payment via encodePaymentHeader", () => {
    const payment: X402Payment = {
      x402Version: 1,
      scheme: "vana-escrow-grant",
      network: "vana:14800",
      payload: {
        message: {
          payerAddress: builderAccount.address,
          opType: "grant",
          opId: GRANT_ID,
          asset: "0x0000000000000000000000000000000000000000",
          amount: "11000000000000000",
          paymentNonce: "1",
        },
        signature: ("0x" + "ab".repeat(65)) as `0x${string}`,
      },
    };
    const encoded = encodePaymentHeader(payment);
    const decoded = parsePaymentHeader(encoded);
    expect(decoded).toEqual(payment);
  });

  it("rejects an X-PAYMENT with a non-positive paymentNonce", () => {
    const encoded = btoa(
      JSON.stringify({
        x402Version: 1,
        scheme: "vana-escrow-grant",
        network: "vana:14800",
        payload: {
          message: {
            payerAddress: builderAccount.address,
            opType: "grant",
            opId: GRANT_ID,
            asset: "0x0000000000000000000000000000000000000000",
            amount: "11000000000000000",
            paymentNonce: "0",
          },
          signature: "0x" + "ab".repeat(65),
        },
      }),
    );
    expect(parsePaymentHeader(encoded)).toBeNull();
  });
});

describe("verifyPayment", () => {
  async function makeSignedPayment(overrides?: {
    paymentNonce?: bigint;
    amount?: string;
    opId?: `0x${string}`;
  }): Promise<X402Payment> {
    const nonce = overrides?.paymentNonce ?? nextPaymentNonce();
    const amount = overrides?.amount ?? "11000000000000000";
    const opId = overrides?.opId ?? GRANT_ID;
    const message = {
      payerAddress: builderAccount.address,
      opType: "grant" as const,
      opId,
      asset: "0x0000000000000000000000000000000000000000" as `0x${string}`,
      amount: BigInt(amount),
      paymentNonce: nonce,
    };
    const signature = await builderAccount.signTypedData({
      domain: escrowPaymentDomain(gatewayConfig),
      types: GENERIC_PAYMENT_TYPES,
      primaryType: "GenericPayment",
      message,
    });
    return {
      x402Version: 1,
      scheme: "vana-escrow-grant",
      network: "vana:14800",
      payload: {
        message: { ...message, amount, paymentNonce: nonce.toString() },
        signature,
      },
    };
  }

  it("accepts a payment whose fields match the live grant", async () => {
    const payment = await makeSignedPayment();
    const result = await verifyPayment({
      builder: builderAccount.address,
      grantId: GRANT_ID,
      grant: makeGrant(),
      serverAddress: serverAccount.address,
      gatewayConfig,
      serverOwner: OWNER_ADDRESS,
      payment,
    });
    expect(result.ok).toBe(true);
  });

  it("rejects when payerAddress doesn't match the authenticated builder", async () => {
    const payment = await makeSignedPayment();
    const result = await verifyPayment({
      builder: "0x9999999999999999999999999999999999999999",
      grantId: GRANT_ID,
      grant: makeGrant(),
      serverAddress: serverAccount.address,
      gatewayConfig,
      serverOwner: OWNER_ADDRESS,
      payment,
    });
    expect(result.ok).toBe(false);
    expect(result.ok ? "" : result.reason).toMatch(/payerAddress/);
  });

  it("rejects when amount diverges from grant.fee.totalDue", async () => {
    const payment = await makeSignedPayment({ amount: "12345" });
    const result = await verifyPayment({
      builder: builderAccount.address,
      grantId: GRANT_ID,
      grant: makeGrant(),
      serverAddress: serverAccount.address,
      gatewayConfig,
      serverOwner: OWNER_ADDRESS,
      payment,
    });
    expect(result.ok).toBe(false);
    expect(result.ok ? "" : result.reason).toMatch(/amount/);
  });

  it("rejects an old paymentNonce (outside the freshness window)", async () => {
    // Build a nonce dated 11 minutes ago. The high 32 bits carry ms-since-epoch.
    const oldMs = BigInt(Date.now() - 11 * 60 * 1000);
    const oldNonce = (oldMs << 32n) + 1n;
    const payment = await makeSignedPayment({ paymentNonce: oldNonce });
    const result = await verifyPayment({
      builder: builderAccount.address,
      grantId: GRANT_ID,
      grant: makeGrant(),
      serverAddress: serverAccount.address,
      gatewayConfig,
      serverOwner: OWNER_ADDRESS,
      payment,
    });
    expect(result.ok).toBe(false);
    expect(result.ok ? "" : result.reason).toMatch(/freshness/);
  });

  it("rejects a payment with a tampered signature", async () => {
    const payment = await makeSignedPayment();
    payment.payload.signature = ("0x" + "00".repeat(65)) as `0x${string}`;
    const result = await verifyPayment({
      builder: builderAccount.address,
      grantId: GRANT_ID,
      grant: makeGrant(),
      serverAddress: serverAccount.address,
      gatewayConfig,
      serverOwner: OWNER_ADDRESS,
      payment,
    });
    expect(result.ok).toBe(false);
  });
});
