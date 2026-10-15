/**
 * The paid-read contract, from the client's side.
 *
 * A third-party app pays for a read by picking one offer from the 402
 * challenge, signing it, and retrying. Apps are written from different
 * sources: the protocol spec documents `data_access` (opId = the receipt's
 * recordId), older apps and the PS itself used `grant` (opId = grant id),
 * and the SDK prefers `data_access` when offered. OpenPet shipped a
 * data_access-only client and broke when this server only quoted `grant`.
 *
 * These tests run each kind of client against buildChallenge →
 * verifyPayment and pin the rule that prevents a repeat: for every grant
 * state a read can be in, every client either gets an offer it can sign and
 * the server accepts, or gets exactly the offer it must pay first.
 */
import { describe, it, expect } from "vitest";
import {
  GENERIC_PAYMENT_TYPES,
  RECORD_DATA_ACCESS_TYPES,
  dataRegistryDomain,
  escrowPaymentDomain,
  type DataPortabilityGatewayConfig,
  type GatewayGrantResponse,
} from "@opendatalabs/vana-sdk/browser";
import {
  buildEscrowPaymentHeader,
  parsePersonalServerPaymentRequired,
} from "@opendatalabs/vana-sdk";
import { privateKeyToAccount } from "viem/accounts";
import {
  DATA_ACCESS_OP_TYPE,
  GRANT_OP_TYPE,
  buildChallenge,
  encodePaymentHeader,
  parsePaymentHeader,
  verifyPayment,
  type X402Accept,
  type X402Challenge,
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

const builder = privateKeyToAccount(("0x" + "11".repeat(32)) as `0x${string}`);
const server = privateKeyToAccount(("0x" + "22".repeat(32)) as `0x${string}`);
const OWNER = "0x0000000000000000000000000000000000000aaa" as `0x${string}`;
const GRANT_ID =
  "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" as const;
const DATA_POINT_ID = ("0x" + "dd".repeat(32)) as `0x${string}`;
const ENTRY = {
  dataPointId: DATA_POINT_ID,
  scope: "instagram.profile",
  version: 3,
};
const ASSET = "0x0000000000000000000000000000000000000000" as `0x${string}`;

const serverSigner = {
  signRecordDataAccess: (msg: {
    ownerAddress: `0x${string}`;
    scope: string;
    version: bigint;
    accessor: `0x${string}`;
    recordId: `0x${string}`;
  }) =>
    server.signTypedData({
      domain: dataRegistryDomain(gatewayConfig),
      types: RECORD_DATA_ACCESS_TYPES,
      primaryType: "RecordDataAccess",
      message: msg,
    }),
};

function grant(
  paymentStatus: "pending" | "paid",
  overrides: Partial<GatewayGrantResponse> = {},
): GatewayGrantResponse {
  const paid = paymentStatus === "paid";
  return {
    id: GRANT_ID,
    grantorAddress: OWNER,
    granteeId: ("0x" + "bb".repeat(32)) as `0x${string}`,
    scopes: ["instagram.profile"],
    status: "confirmed",
    addedAt: "2026-01-21T10:00:00.000Z",
    expiresAt: null,
    expired: false,
    revokedAt: null,
    revocationSignature: null,
    paymentStatus,
    paidAt: paid ? "2026-01-21T10:00:05.000Z" : null,
    paidBy: paid ? builder.address : null,
    grantVersion: "1",
    settleTxHash: null,
    settleSubmittedAt: null,
    revocationTxHash: null,
    revocationSubmittedAt: null,
    // The gateway's totalDue already drops the registration fee once paid.
    fee: {
      asset: ASSET,
      registrationFee: "10000000000000000",
      dataAccessFee: "1000000000000000",
      totalDue: paid ? "1000000000000000" : "11000000000000000",
    },
    ...overrides,
  };
}

async function challengeFor(
  paymentStatus: "pending" | "paid",
  withRecord: boolean,
  overrides: Partial<GatewayGrantResponse> = {},
): Promise<X402Challenge> {
  return buildChallenge({
    builder: builder.address,
    grantId: GRANT_ID,
    grant: grant(paymentStatus, overrides),
    network: "vana:14800",
    gatewayConfig,
    ...(withRecord
      ? { serverSigner, serverOwner: OWNER, entry: ENTRY }
      : { entry: { ...ENTRY, dataPointId: null } }),
  });
}

/** A client signs one offer the way the spec and the SDK both do. */
async function pay(offer: X402Accept): Promise<string> {
  const m = offer.message;
  const signature = await builder.signTypedData({
    domain: escrowPaymentDomain(gatewayConfig),
    types: GENERIC_PAYMENT_TYPES,
    primaryType: "GenericPayment",
    message: {
      payerAddress: m.payerAddress,
      opType: m.opType,
      opId: m.opId,
      asset: m.asset,
      amount: BigInt(m.amount),
      paymentNonce: BigInt(m.paymentNonce),
    },
  });
  const payment: X402Payment = {
    x402Version: 1,
    scheme: offer.scheme,
    network: offer.network,
    payload: {
      message: m,
      signature,
      ...(offer.accessRecord ? { accessRecord: offer.accessRecord } : {}),
    },
  };
  return encodePaymentHeader(payment);
}

async function serverAccepts(
  header: string,
  paymentStatus: "pending" | "paid",
  withRecord: boolean,
  overrides: Partial<GatewayGrantResponse> = {},
) {
  const payment = parsePaymentHeader(header);
  if (!payment) return { ok: false as const, reason: "unparseable" };
  return verifyPayment({
    builder: builder.address,
    grantId: GRANT_ID,
    grant: grant(paymentStatus, overrides),
    entry: withRecord ? ENTRY : { ...ENTRY, dataPointId: null },
    serverAddress: server.address,
    gatewayConfig,
    serverOwner: OWNER,
    payment,
  });
}

const offerOf = (c: X402Challenge, opType: string) =>
  c.accepts.find((a) => a.message.opType === opType);

// Every state a paid read can meet: registration owed or paid, and the
// served entry registered with the gateway (receipt signable) or not yet.
const STATES = [
  { paymentStatus: "pending", withRecord: false },
  { paymentStatus: "pending", withRecord: true },
  { paymentStatus: "paid", withRecord: false },
  { paymentStatus: "paid", withRecord: true },
] as const;

describe("paid-read contract: every client shape the protocol has published", () => {
  it.each(STATES)(
    "a grant-only client is always offered and accepted ($paymentStatus, record=$withRecord)",
    async ({ paymentStatus, withRecord }) => {
      const challenge = await challengeFor(paymentStatus, withRecord);
      // First position too: clients that read accepts[0] keep working.
      expect(challenge.accepts[0].message.opType).toBe(GRANT_OP_TYPE);
      const result = await serverAccepts(
        await pay(challenge.accepts[0]),
        paymentStatus,
        withRecord,
      );
      expect(result).toMatchObject({ ok: true });
    },
  );

  it("a spec (data_access) client is offered data_access once registration is paid and a receipt exists", async () => {
    const challenge = await challengeFor("paid", true);
    const offer = offerOf(challenge, DATA_ACCESS_OP_TYPE);
    expect(offer).toBeDefined();
    // The payment commits to the exact server-signed receipt.
    expect(offer!.message.opId).toBe(offer!.accessRecord!.recordId);
    expect(offer!.message.amount).toBe(grant("paid").fee.totalDue);
    const result = await serverAccepts(await pay(offer!), "paid", true);
    expect(result).toMatchObject({ ok: true });
  });

  it.each([
    { paymentStatus: "pending", withRecord: true },
    { paymentStatus: "pending", withRecord: false },
    { paymentStatus: "paid", withRecord: false },
  ] as const)(
    "no data_access offer where the gateway would refuse one ($paymentStatus, record=$withRecord)",
    async ({ paymentStatus, withRecord }) => {
      // pending: data_access never carries the registration fee.
      // no record: data_access has no receipt to bind to.
      const challenge = await challengeFor(paymentStatus, withRecord);
      expect(offerOf(challenge, DATA_ACCESS_OP_TYPE)).toBeUndefined();
      expect(challenge.accepts).toHaveLength(1);
    },
  );

  // A paid grant the gateway still refuses data_access under. SDK clients
  // prefer data_access whenever offered, so offering it here would turn a
  // payable read (via the grant offer) into a gateway 403 or an endless
  // re-challenge. The grant offer stays.
  it.each([
    { why: "chain sync failed", overrides: { status: "failed" } },
    {
      why: "revoked",
      overrides: { revokedAt: "2026-01-22T00:00:00.000Z" },
    },
    { why: "expired", overrides: { expired: true } },
    // The read is covered here, but the gateway matches the scope exactly.
    {
      why: "the grant covers the scope by wildcard",
      overrides: { scopes: ["instagram.*"] },
    },
    {
      why: "data-access fee disabled",
      overrides: {
        fee: {
          asset: "0x00000000000000000000000000000000000000aa",
          registrationFee: "10000000000000000",
          dataAccessFee: "0",
          totalDue: "0",
        },
      },
    },
  ] as const)(
    "no data_access offer, and none accepted, when $why",
    async ({ overrides }) => {
      const o = overrides as Partial<GatewayGrantResponse>;
      const challenge = await challengeFor("paid", true, o);
      expect(offerOf(challenge, DATA_ACCESS_OP_TYPE)).toBeUndefined();
      expect(challenge.accepts[0].message.opType).toBe(GRANT_OP_TYPE);
      // A client that builds data_access anyway is refused locally, not
      // forwarded to a gateway that would reject it.
      const live = await challengeFor("paid", true);
      const header = await pay(offerOf(live, DATA_ACCESS_OP_TYPE)!);
      const result = await serverAccepts(header, "paid", true, o);
      expect(result).toMatchObject({ ok: false });
    },
  );

  it("refuses a data_access payment while registration is unpaid", async () => {
    // A client that builds data_access itself (no offer for it) must not
    // skip the registration fee.
    const paid = await challengeFor("paid", true);
    const header = await pay(offerOf(paid, DATA_ACCESS_OP_TYPE)!);
    const result = await serverAccepts(header, "pending", true);
    expect(result).toMatchObject({ ok: false });
    expect(result.ok ? "" : result.reason).toMatch(/registration is unpaid/);
  });

  it("refuses a data_access payment whose opId is not the receipt's recordId", async () => {
    const challenge = await challengeFor("paid", true);
    const offer = offerOf(challenge, DATA_ACCESS_OP_TYPE)!;
    const forged: X402Accept = {
      ...offer,
      message: { ...offer.message, opId: GRANT_ID },
    };
    const result = await serverAccepts(await pay(forged), "paid", true);
    expect(result).toMatchObject({ ok: false });
    expect(result.ok ? "" : result.reason).toMatch(/recordId/);
  });

  it("refuses a data_access payment without its receipt", async () => {
    const challenge = await challengeFor("paid", true);
    const { accessRecord: _dropped, ...bare } = offerOf(
      challenge,
      DATA_ACCESS_OP_TYPE,
    )!;
    const result = await serverAccepts(await pay(bare), "paid", true);
    expect(result).toMatchObject({ ok: false });
    expect(result.ok ? "" : result.reason).toMatch(/accessRecord is required/);
  });

  it("refuses a data_access payment on a receipt this server did not sign", async () => {
    const challenge = await challengeFor("paid", true);
    const offer = offerOf(challenge, DATA_ACCESS_OP_TYPE)!;
    const other = privateKeyToAccount(
      ("0x" + "33".repeat(32)) as `0x${string}`,
    );
    const recordId = offer.accessRecord!.recordId;
    const signature = await other.signTypedData({
      domain: dataRegistryDomain(gatewayConfig),
      types: RECORD_DATA_ACCESS_TYPES,
      primaryType: "RecordDataAccess",
      message: {
        ownerAddress: OWNER,
        scope: ENTRY.scope,
        version: BigInt(ENTRY.version),
        accessor: builder.address,
        recordId,
      },
    });
    const forged: X402Accept = {
      ...offer,
      accessRecord: { ...offer.accessRecord!, signature },
    };
    const result = await serverAccepts(await pay(forged), "paid", true);
    expect(result).toMatchObject({ ok: false });
    expect(result.ok ? "" : result.reason).toMatch(/not this personal server/);
  });
});

describe("paid-read contract: the SDK as the client", () => {
  // The SDK is what most builders run. It prefers data_access when offered
  // and falls back to grant; both must round-trip through this server.
  async function sdkPays(
    paymentStatus: "pending" | "paid",
    withRecord: boolean,
  ): Promise<{ opType: string; header: string }> {
    const challenge = await challengeFor(paymentStatus, withRecord);
    const required = await parsePersonalServerPaymentRequired(
      new Response(JSON.stringify(challenge), { status: 402 }),
      GRANT_ID,
    );
    const header = await buildEscrowPaymentHeader({
      payerAddress: builder.address,
      required,
      config: {
        chainId: gatewayConfig.chainId,
        escrowContract: gatewayConfig.contracts.dataPortabilityEscrow,
        signTypedData: (args) =>
          builder.signTypedData(
            args as Parameters<typeof builder.signTypedData>[0],
          ),
      },
    });
    return { opType: required.opType, header };
  }

  it.each(STATES)(
    "SDK pays and the server accepts ($paymentStatus, record=$withRecord)",
    async ({ paymentStatus, withRecord }) => {
      const { opType, header } = await sdkPays(paymentStatus, withRecord);
      const expected =
        paymentStatus === "paid" && withRecord
          ? DATA_ACCESS_OP_TYPE
          : GRANT_OP_TYPE;
      expect(opType).toBe(expected);
      const result = await serverAccepts(header, paymentStatus, withRecord);
      expect(result).toMatchObject({ ok: true });
    },
  );
});
