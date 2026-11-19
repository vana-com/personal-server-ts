import { describe, it, expect, vi } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import {
  dataRegistryDomain,
  escrowPaymentDomain,
  GENERIC_PAYMENT_TYPES,
  RECORD_DATA_ACCESS_TYPES,
  type DataPortabilityGatewayConfig,
  type GatewayGrantResponse,
} from "@opendatalabs/vana-sdk/browser";
import { handleX402Cycle, type X402CycleInput } from "../api/index.js";
import { encodePaymentHeader } from "./x402.js";
import { computeDataPointId } from "../sync/data-point-id.js";
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
    scopes: ["pdpp.fixture.items"],
    status: "pending",
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
      registrationFee: "1000000000000000",
      dataAccessFee: "10000000000000000",
      totalDue: "11000000000000000",
    },
    ...overrides,
  };
}

async function cycle(status: number, errorBody: unknown) {
  const servedEntry = { scope: "pdpp.fixture~.items", version: 7 };
  const grant = makeGrant();
  const paymentFetch = vi.fn(async () => Response.json(errorBody, { status }));
  const logger = { info: vi.fn() };
  const input = {
    scope: "pdpp.fixture.items",
    servedEntry,
    grantId: GRANT_ID,
    builder: builderAccount.address,
    gateway: { getGrant: async () => grant },
    gatewayConfig,
    gatewayUrl: "https://gateway.test",
    deps: {
      serverOwner: OWNER_ADDRESS,
      serverAddress: serverAccount.address,
      serverSigner: {
        signRecordDataAccess: (
          message: Parameters<typeof serverAccount.signTypedData>[0]["message"],
        ) =>
          serverAccount.signTypedData({
            domain: dataRegistryDomain(gatewayConfig),
            types: RECORD_DATA_ACCESS_TYPES,
            primaryType: "RecordDataAccess",
            message,
          } as never),
      },
      paymentFetch,
      logger,
    },
    request: new Request("https://server.test/v1/data/pdpp.fixture.items"),
  } as unknown as X402CycleInput;
  const challenge = await handleX402Cycle(input);
  if (challenge.kind !== "challenge") throw new Error("Expected challenge");
  const accept = challenge.body.accepts[0]!;
  const signature = await builderAccount.signTypedData({
    domain: escrowPaymentDomain(gatewayConfig),
    types: GENERIC_PAYMENT_TYPES,
    primaryType: "GenericPayment",
    message: {
      ...accept.message,
      amount: BigInt(accept.message.amount),
      paymentNonce: BigInt(accept.message.paymentNonce),
    },
  } as never);
  input.request = new Request(input.request.url, {
    headers: {
      "x-payment": encodePaymentHeader({
        x402Version: 1,
        scheme: "vana-escrow-grant",
        network: "vana:14800",
        payload: {
          message: accept.message,
          signature,
          accessRecord: accept.accessRecord,
        },
      }),
    },
  });
  const result = await handleX402Cycle(input);
  expect(paymentFetch).toHaveBeenCalledOnce();
  const forwarded = JSON.parse(
    (paymentFetch.mock.calls[0] as unknown as [string, RequestInit])[1]
      .body as string,
  );
  expect(forwarded.accessRecord).toMatchObject({
    dataPointId: computeDataPointId(OWNER_ADDRESS, servedEntry.scope),
    version: "7",
    accessor: builderAccount.address,
  });
  return { result, logger };
}

describe("stream-head payment forwarding diagnostics", () => {
  it("preserves safe diagnostics on a relayed payment error", async () => {
    const { result, logger } = await cycle(402, {
      error: "Insufficient finalized balance",
      available: "0",
    });
    expect(result).toMatchObject({
      kind: "gateway-error",
      status: 402,
      body: {
        available: "0",
        gatewayStatus: 402,
        gatewayReasonCode: "GATEWAY_REJECTED",
      },
    });
    expect(logger.info).toHaveBeenCalledWith(
      expect.objectContaining({ status: 402, reasonCode: "GATEWAY_REJECTED" }),
      expect.any(String),
    );
  });

  it("preserves a closed-set gateway rejection on the fresh challenge", async () => {
    const { result, logger } = await cycle(400, {
      reasonCode: "RECEIPT_VERSION_UNAVAILABLE",
      error: "untrusted diagnostic",
    });
    expect(result).toMatchObject({
      kind: "challenge",
      body: {
        gatewayStatus: 400,
        gatewayReasonCode: "RECEIPT_VERSION_UNAVAILABLE",
      },
    });
    expect(logger.info).toHaveBeenCalledWith(
      expect.objectContaining({
        status: 400,
        reasonCode: "RECEIPT_VERSION_UNAVAILABLE",
      }),
      expect.any(String),
    );
    expect(JSON.stringify(logger.info.mock.calls)).not.toContain(
      "untrusted diagnostic",
    );
  });
  it("does not propagate arbitrary gateway codes or bodies", async () => {
    const { result, logger } = await cycle(400, {
      reasonCode: "private arbitrary text",
      error: "untrusted diagnostic",
    });
    expect(JSON.stringify(result)).not.toContain("private arbitrary text");
    expect(JSON.stringify(logger.info.mock.calls)).not.toContain(
      "untrusted diagnostic",
    );
  });
});
