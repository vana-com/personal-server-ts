import { afterEach, describe, expect, it, vi } from "vitest";
import {
  GENERIC_PAYMENT_TYPES,
  RECORD_DATA_ACCESS_TYPES,
  dataRegistryDomain,
  escrowPaymentDomain,
  type DataPortabilityGatewayConfig,
  type GatewayGrantResponse,
} from "@opendatalabs/vana-sdk/browser";
import { privateKeyToAccount } from "viem/accounts";
import {
  handlePersonalServerDataRequest,
  handleX402Cycle,
  type PersonalServerDataApiDeps,
  type X402CycleResult,
} from "../api/index.js";
import { encodePaymentHeader, type X402Payment } from "./x402.js";

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
const grantId = ("0x" + "ab".repeat(32)) as `0x${string}`;
const dataPointId = ("0x" + "cd".repeat(32)) as `0x${string}`;
const owner = "0x0000000000000000000000000000000000000aaa" as const;
const scope = "instagram.profile";
const paidAt = "2026-11-09T09:00:00.000Z";
type Fault = "throw-after-commit" | "409-after-commit" | "500-after-commit" | "503-after-commit" | "400" | "402" | "409-race";

function fixture() {
  let time = Date.now();
  vi.spyOn(Date, "now").mockImplementation(() => time);
  const grant = {
    id: grantId, grantorAddress: owner,
    granteeId: ("0x" + "bb".repeat(32)) as `0x${string}`,
    scopes: [scope], status: "confirmed", addedAt: paidAt, expiresAt: null,
    expired: false, revokedAt: null, revocationSignature: null,
    paymentStatus: "paid", paidAt, paidBy: builder.address, grantVersion: "1",
    settleTxHash: null, settleSubmittedAt: null, revocationTxHash: null,
    revocationSubmittedAt: null,
    fee: { asset: "0x0000000000000000000000000000000000000000",
      registrationFee: "0", dataAccessFee: "10", totalDue: "10" },
  } as GatewayGrantResponse;
  let entry: { dataPointId: typeof dataPointId; scope: string; version: number } | undefined =
    { dataPointId, scope, version: 1 };
  let nonces = 0;
  let records = 0;
  let debits = 0;
  let fault: Fault | undefined;
  const ledger = new Map<string, { fingerprint: string; response: { paidAt: string } }>();
  const paymentFetch = vi.fn(async (_url: unknown, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body));
    const fingerprint = JSON.stringify({ body, signature: new Headers(init?.headers).get("authorization") });
    const key = body.accessRecord.recordId as string;
    const previous = ledger.get(key);
    if (previous) {
      if (previous.fingerprint !== fingerprint) {
        return Response.json({ error: "accessRecord.recordId is already paid with different signed payment fields; amount, paymentNonce, and GenericPayment signature must match" }, { status: 409 });
      }
      return Response.json(previous.response);
    }
    const next = fault;
    fault = undefined;
    if (next === "409-race") {
      return Response.json({ error: "Registration was paid by another payer between request and commit; refetch payment status and retry with the data-access-only amount" }, { status: 409 });
    }
    if (next === "400" || next === "402") {
      return Response.json({ error: next === "400" ? "Payment amount does not match the canonical fee total for this op" : "insufficient balance" }, { status: Number(next) });
    }
    // The committed ledger, rather than the transport, owns debit count.
    const response = { paidAt };
    ledger.set(key, { fingerprint, response });
    debits += 1;
    if (next === "throw-after-commit") throw new Error("response lost after commit");
    if (next === "409-after-commit") return Response.json({ error: "settlement in progress" }, { status: 409 });
    if (next === "500-after-commit") return Response.json({ error: "response failed" }, { status: 500 });
    if (next === "503-after-commit") return new Response("unavailable", { status: 503 });
    return Response.json(response);
  });
  const gateway = { getGrant: vi.fn(async () => grant) };
  const readBody = vi.fn(() => { throw new Error("Data must not be read before confirmed payment"); });
  const storage = new Proxy({ findEntry: () => entry }, {
    get(target, key) { return key in target ? Reflect.get(target, key) : readBody; },
  });
  const deps = {
    storage, gateway, gatewayConfig, gatewayUrl: "https://gateway.invalid",
    serverAddress: server.address, serverOwner: owner, paymentEnabled: true,
    serverSigner: {
      signRecordDataAccess: (message: {
        ownerAddress: `0x${string}`; scope: string; version: bigint;
        accessor: `0x${string}`; recordId: `0x${string}`;
      }) => server.signTypedData({
        domain: dataRegistryDomain(gatewayConfig), types: RECORD_DATA_ACCESS_TYPES,
        primaryType: "RecordDataAccess", message,
      }),
    },
    paymentFetch: paymentFetch as unknown as typeof fetch,
    generatePaymentNonce: () => (BigInt(time) << 32n) + BigInt(++nonces),
    generateRecordId: () => ("0x" + (++records).toString(16).padStart(64, "0")) as `0x${string}`,
    now: () => new Date(time),
    logger: { debug: vi.fn(), info: vi.fn(), error: vi.fn() },
    auth: { authorizeBuilderRead: vi.fn(async () => ({ builder: builder.address, grantId })) },
    accessLogWriter: { write: vi.fn() },
  } as unknown as PersonalServerDataApiDeps;
  function request(header?: string) {
    return new Request("https://server.invalid/" + scope, {
      headers: header ? { "X-PAYMENT": header } : {},
    });
  }
  function cycle(header?: string, cycleDeps = deps) {
    return handleX402Cycle({
      deps: cycleDeps, request: request(header), scope, grantId, builder: builder.address,
      gateway, gatewayConfig, gatewayUrl: "https://gateway.invalid",
    });
  }
  async function sign() {
    const initial = await cycle();
    expect(initial.kind).toBe("challenge");
    if (initial.kind !== "challenge") throw new Error("missing initial challenge");
    const accept = initial.body.accepts[0];
    const signature = await builder.signTypedData({
      domain: escrowPaymentDomain(gatewayConfig), types: GENERIC_PAYMENT_TYPES,
      primaryType: "GenericPayment",
      message: { ...accept.message, amount: BigInt(accept.message.amount),
        paymentNonce: BigInt(accept.message.paymentNonce) },
    });
    const payment: X402Payment = {
      x402Version: 1, scheme: "vana-escrow-grant", network: accept.network,
      payload: { message: accept.message, signature, accessRecord: accept.accessRecord },
    };
    return { payment, header: encodePaymentHeader(payment) };
  }
  return {
    deps, grant, gateway, paymentFetch, readBody, cycle, sign, request,
    setFault: (value: Fault) => { fault = value; },
    age: () => { time += 11 * 60 * 1000; },
    advanceVersion: () => { if (entry) entry.version += 1; },
    removeEntry: () => { entry = undefined; },
    counts: () => ({ nonces, records, debits }),
  };
}

function expectUnknown(result: X402CycleResult) {
  expect(result.kind).toBe("gateway-error");
  if (result.kind !== "gateway-error") throw new Error("uncertain payment was not rejected");
  expect(result.status).toBe(503);
  expect(result.body).toMatchObject({ error: "PAYMENT_OUTCOME_UNKNOWN" });
  expect(result.body).not.toHaveProperty("accepts");
  expect(result.body).not.toHaveProperty("accessRecord");
  expect(result.body).not.toHaveProperty("paymentNonce");
  expect(JSON.stringify(result.body)).toMatch(/same X-PAYMENT/i);
}

afterEach(() => vi.restoreAllMocks());

describe("uncertain payment settlement", () => {
  it("UNCERTAIN_PAYMENT_RECHALLENGES: commit then throw; retry the identical payment once", async () => {
    const f = fixture();
    const { header } = await f.sign();
    f.setFault("throw-after-commit");
    expectUnknown(await f.cycle(header));
    expect(f.counts()).toEqual({ nonces: 1, records: 1, debits: 1 });
    expect(await f.cycle(header)).toEqual({ kind: "ok", payResponse: { paidAt } });
    expect(f.counts()).toEqual({ nonces: 1, records: 1, debits: 1 });
    expect(f.paymentFetch.mock.calls[1]?.[1]).toEqual(f.paymentFetch.mock.calls[0]?.[1]);
  });

  it("CONFLICT_RECHALLENGES: a same-payment 409 is unknown, never a fresh challenge or success", async () => {
    const f = fixture();
    const { header } = await f.sign();
    f.setFault("409-after-commit");
    expectUnknown(await f.cycle(header));
    expect(f.counts()).toEqual({ nonces: 1, records: 1, debits: 1 });
    expect((await f.cycle(header)).kind).toBe("ok");
    expect(f.counts().debits).toBe(1);
  });

  it.each(["500-after-commit", "503-after-commit"] as const)(
    "GATEWAY_5XX: %s is unknown with no replacement payment", async (fault) => {
      const f = fixture();
      const { header } = await f.sign();
      f.setFault(fault);
      expectUnknown(await f.cycle(header));
      expect(f.counts()).toEqual({ nonces: 1, records: 1, debits: 1 });
      expect((await f.cycle(header)).kind).toBe("ok");
      expect(f.counts().debits).toBe(1);
    },
  );

  it("REVALIDATE_SETTLED_AS_NEW: exact retry after fee change is not charged again", async () => {
    const f = fixture();
    const { header } = await f.sign();
    f.setFault("throw-after-commit");
    await f.cycle(header);
    f.grant.fee.totalDue = "20";
    // A reconstructed dependency object must not lose the retry proof.
    expect(await f.cycle(header, { ...f.deps })).toEqual({ kind: "ok", payResponse: { paidAt } });
    expect(f.counts()).toEqual({ nonces: 1, records: 1, debits: 1 });
  });

  it("a registration race 409 rolls back the debit, so it gets a fresh challenge", async () => {
    const f = fixture();
    const { header } = await f.sign();
    f.setFault("409-race");
    expect((await f.cycle(header)).kind).toBe("challenge");
    expect(f.counts().debits).toBe(0);
  });

  it("a first payment for an older data version is refused before any debit", async () => {
    const f = fixture();
    const { header } = await f.sign();
    f.advanceVersion();
    expect((await f.cycle(header)).kind).toBe("challenge");
    expect(f.counts().debits).toBe(0);
  });

  it("a retry after the data version changed is re-challenged (known residue)", async () => {
    const f = fixture();
    const { header } = await f.sign();
    f.setFault("throw-after-commit");
    await f.cycle(header);
    f.advanceVersion();
    expect((await f.cycle(header, { ...f.deps })).kind).toBe("challenge");
    expect(f.counts().debits).toBe(1);
  });

  it("a retry later than the freshness window after a lost response is re-challenged (known residue)", async () => {
    const f = fixture();
    const { header } = await f.sign();
    f.setFault("throw-after-commit");
    await f.cycle(header);
    f.age();
    expect((await f.cycle(header, { ...f.deps })).kind).toBe("challenge");
    expect(f.counts()).toEqual({ nonces: 2, records: 2, debits: 1 });
  });

  it("SERVE_ON_UNKNOWN: the real HTTP dispatcher stops before reading data", async () => {
    const f = fixture();
    const { header } = await f.sign();
    f.setFault("throw-after-commit");
    const response = await handlePersonalServerDataRequest(f.request(header), f.deps);
    expect(response.status).toBe(503);
    expect(await response.json()).toMatchObject({ error: "PAYMENT_OUTCOME_UNKNOWN" });
    expect(response.headers.has("X-PAYMENT-RESPONSE")).toBe(false);
    expect(f.readBody).not.toHaveBeenCalled();
    expect(f.deps.accessLogWriter.write).not.toHaveBeenCalled();
    expect(f.counts()).toEqual({ nonces: 1, records: 1, debits: 1 });
  });

  it("successful first payment retains its response and incurs one debit", async () => {
    const f = fixture();
    const { header } = await f.sign();
    expect(await f.cycle(header)).toEqual({ kind: "ok", payResponse: { paidAt } });
    expect(f.counts()).toEqual({ nonces: 1, records: 1, debits: 1 });
  });

  it("400 shape rejection retains the current fresh-challenge behavior", async () => {
    const f = fixture();
    const { header } = await f.sign();
    f.setFault("400");
    expect((await f.cycle(header)).kind).toBe("challenge");
    expect(f.counts()).toEqual({ nonces: 2, records: 2, debits: 0 });
  });

  it("402 insufficient balance remains verbatim, without a new nonce", async () => {
    const f = fixture();
    const { header } = await f.sign();
    f.setFault("402");
    expect(await f.cycle(header)).toEqual({
      kind: "gateway-error", status: 402, body: { error: "insufficient balance" },
    });
    expect(f.counts()).toEqual({ nonces: 1, records: 1, debits: 0 });
  });

  it("an exact retry cannot bypass a newly failing authorization gate", async () => {
    const f = fixture();
    const { header } = await f.sign();
    f.setFault("throw-after-commit");
    await f.cycle(header);
    const auth = { ...f.deps.auth, authorizeBuilderRead: vi.fn(async () => { throw new Error("grant revoked"); }) };
    const response = await handlePersonalServerDataRequest(f.request(header), { ...f.deps, auth });
    expect(response.status).not.toBe(200);
    expect(f.paymentFetch).toHaveBeenCalledTimes(1);
    expect(f.readBody).not.toHaveBeenCalled();
  });

  it("an exact retry cannot bypass a newly visible deletion", async () => {
    const f = fixture();
    const { header } = await f.sign();
    f.setFault("throw-after-commit");
    await f.cycle(header);
    f.removeEntry();
    const scopeDeletions = {
      resolve: async () => ({ deleted: true, deletedAt: paidAt }),
    } as unknown as PersonalServerDataApiDeps["scopeDeletions"];
    const response = await handlePersonalServerDataRequest(f.request(header), { ...f.deps, scopeDeletions });
    expect(response.status).toBe(410);
    expect(f.paymentFetch).toHaveBeenCalledTimes(1);
    expect(f.readBody).not.toHaveBeenCalled();
  });
});
