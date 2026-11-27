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
import { isOwnAppRead } from "./own-app.js";
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
  const servedEntry = { scope: "pdpp.fixture~.~log", version: 3 };
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
    version: "3",
    accessor: builderAccount.address,
  });
  return {
    result,
    logger,
    forwarded,
    headers: (paymentFetch.mock.calls[0] as unknown as [string, RequestInit])[1]
      .headers,
  };
}

describe("log-bound payment forwarding diagnostics", () => {
  it("forwards a log-only registered receipt with logical authorization unchanged", async () => {
    const { result, forwarded, headers } = await cycle(200, { success: true });
    expect(result).toMatchObject({ kind: "ok" });
    expect(forwarded).toMatchObject({
      opType: "grant",
      accessRecord: {
        dataPointId: computeDataPointId(OWNER_ADDRESS, "pdpp.fixture~.~log"),
        version: "3",
      },
    });
    expect(forwarded.accessRecord).not.toHaveProperty("scope");
    expect(forwarded.accessRecord).not.toHaveProperty("ownerAddress");
    if (process.env.PAYMENT_FIXTURE_PATH) {
      const { writeFileSync } = await import("node:fs");
      writeFileSync(
        process.env.PAYMENT_FIXTURE_PATH,
        JSON.stringify(
          {
            body: forwarded,
            headers,
            owner: OWNER_ADDRESS,
            server: serverAccount.address,
            scope: "pdpp.fixture~.~log",
          },
          null,
          2,
        ) + "\n",
      );
    }
  });
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

describe("own-app read fee evidence", () => {
  const input = {
    accountUrl: "https://account.test:8443",
    appAddress: "0xAa",
    dataOwner: "0xBb",
    chainId: 14800,
  };
  const evidence = {
    object: "own_app_read_eligibility",
    appAddress: "0xaa",
    dataOwner: "0xbb",
    network: "moksha",
  };

  it.each([
    [14800, "moksha", "eligible", true],
    [1480, "mainnet", "not_eligible", false],
  ] as const)(
    "binds an Account answer to chain %s and normalized addresses",
    async (chainId, network, eligibility, expected) => {
      const fetch = vi.fn(async (_url: URL, _init: RequestInit) =>
        Response.json({ ...evidence, network, eligibility }),
      );
      vi.stubGlobal("fetch", fetch);
      try {
        await expect(isOwnAppRead({ ...input, chainId })).resolves.toBe(
          expected,
        );
        expect(fetch).toHaveBeenCalledOnce();
        const [url, init] = fetch.mock.calls[0]!;
        expect(url.origin).toBe("https://account.test:8443");
        expect(url.pathname).toBe("/api/v1/apps/own-data-read-eligibility");
        expect(Object.fromEntries(url.searchParams)).toEqual({
          appAddress: "0xaa",
          dataOwner: "0xbb",
          network,
        });
        expect(init).toMatchObject({ redirect: "error", cache: "no-store" });
      } finally {
        vi.unstubAllGlobals();
      }
    },
  );

  it.each([
    ["appAddress", "0xcc"],
    ["dataOwner", "0xcc"],
    ["network", "mainnet"],
  ])(
    "rejects an eligible response bound to a different %s",
    async (field, value) => {
      vi.stubGlobal("fetch", async () =>
        Response.json({ ...evidence, eligibility: "eligible", [field]: value }),
      );
      try {
        await expect(isOwnAppRead(input)).rejects.toThrow(
          "Mismatched own-app evidence",
        );
      } finally {
        vi.unstubAllGlobals();
      }
    },
  );

  it("does not request evidence from a non-origin Account URL or an unsupported chain", async () => {
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);
    try {
      await expect(
        isOwnAppRead({ ...input, accountUrl: "https://account.test/a" }),
      ).rejects.toThrow("Own-app Account must be an HTTPS origin");
      await expect(isOwnAppRead({ ...input, chainId: 1 })).rejects.toThrow(
        "Unsupported own-app network",
      );
      expect(fetch).not.toHaveBeenCalled();
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
