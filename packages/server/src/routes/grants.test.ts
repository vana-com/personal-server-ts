import { describe, it, expect, vi } from "vitest";
import { pino } from "pino";
import type {
  Builder,
  DataPortabilityGatewayConfig,
  GatewayClient,
  GatewayGrantResponse,
  GrantListItem,
} from "@opendatalabs/vana-sdk/node";
import {
  GRANT_REGISTRATION_TYPES,
  grantRegistrationDomain,
} from "@opendatalabs/vana-sdk/node";
import {
  createTestWallet,
  buildWeb3SignedHeader,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import { grantsRoutes } from "./grants.js";

const logger = pino({ level: "silent" });
const SERVER_ORIGIN = "http://localhost:8080";

// Canary DataPortabilityContracts adds dataPortabilityEscrow + feeRegistry.
// Both are required by `DataPortabilityGatewayConfig`; the values don't
// matter for these tests since we only exercise EIP-712 domain hashing.
const gatewayConfig = {
  chainId: 14800,
  contracts: {
    dataRegistry: "0x0000000000000000000000000000000000000001",
    dataPortabilityPermissions: "0x0000000000000000000000000000000000000002",
    dataPortabilityServer: "0x0000000000000000000000000000000000000003",
    dataPortabilityGrantees: "0x0000000000000000000000000000000000000004",
    dataPortabilityEscrow: "0x0000000000000000000000000000000000000005",
    feeRegistry: "0x0000000000000000000000000000000000000006",
  },
} satisfies DataPortabilityGatewayConfig;

const owner = createTestWallet(0);
const builder = createTestWallet(1);

const BUILDER_ID =
  "0x1111111111111111111111111111111111111111111111111111111111111111";

function makeGrantResponse(
  overrides: Partial<GatewayGrantResponse> = {},
): GatewayGrantResponse {
  return {
    id: "0xgrant1",
    grantorAddress: owner.address,
    granteeId: BUILDER_ID,
    scopes: ["instagram.*"],
    status: "confirmed",
    addedAt: "2025-01-01T00:00:00Z",
    expiresAt: null,
    expired: false,
    revokedAt: null,
    revocationSignature: null,
    paymentStatus: "paid",
    paidAt: "2025-01-01T00:00:05Z",
    paidBy: owner.address,
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

function createMockGateway(): GatewayClient {
  return {
    isRegisteredBuilder: vi.fn().mockResolvedValue(true),
    getBuilder: vi.fn().mockResolvedValue({
      id: BUILDER_ID,
      ownerAddress: "0xOwner",
      granteeAddress: builder.address,
      publicKey: "0x04key",
      appUrl: "https://app.example.com",
      addedAt: "2026-01-21T10:00:00.000Z",
    } satisfies Builder),
    getGrant: vi.fn().mockResolvedValue(null),
    listGrantsByUser: vi.fn().mockResolvedValue([]),
    getSchemaForScope: vi.fn().mockResolvedValue(null),
    getServer: vi.fn().mockResolvedValue(null),
    getFile: vi.fn().mockResolvedValue(null),
    listFilesSince: vi.fn().mockResolvedValue({ files: [], cursor: null }),
    getSchema: vi.fn().mockResolvedValue(null),
    registerServer: vi.fn().mockResolvedValue({ alreadyRegistered: false }),
    registerBuilder: vi.fn().mockResolvedValue({ alreadyRegistered: false }),
    registerDataPoint: vi
      .fn()
      .mockResolvedValue({ dataPointId: "0xdp", expectedVersion: "1" }),
    registerFile: vi.fn().mockResolvedValue({ fileId: "file-1" }),
    createGrant: vi.fn().mockResolvedValue({ grantId: "grant-123" }),
    revokeGrant: vi.fn().mockResolvedValue(undefined),
    getEscrowBalance: vi.fn().mockResolvedValue({ balances: [] }),
    submitEscrowDeposit: vi
      .fn()
      .mockResolvedValue({ status: "pending", account: owner.address }),
    payForOperation: vi.fn().mockResolvedValue({}),
    settle: vi.fn().mockResolvedValue({
      scanned: 0,
      confirmed: 0,
      submitted: 0,
      skipped: 0,
      failed: 0,
      items: [],
      reconciled: { items: [] },
    }),
  } as unknown as GatewayClient;
}

function createMockServerSigner() {
  return {
    signFileRegistration: vi
      .fn()
      .mockResolvedValue("0xfilesig" as `0x${string}`),
    signGrantRegistration: vi
      .fn()
      .mockResolvedValue("0xgrantsig" as `0x${string}`),
    signGrantRevocation: vi
      .fn()
      .mockResolvedValue("0xrevokesig" as `0x${string}`),
    signAddData: vi.fn().mockResolvedValue("0xadddatasig" as `0x${string}`),
  };
}

const futureExpiry = Math.floor(Date.now() / 1000) + 3600;

// Canary verify body is the structured EIP-712 shape: top-level scopes,
// grantVersion, expiresAt. No JSON `grant` blob, no fileIds.
interface CanaryVerifyBody {
  grantorAddress: `0x${string}`;
  granteeId: `0x${string}`;
  scopes: string[];
  grantVersion: string;
  expiresAt: string;
  signature: `0x${string}`;
}

interface SignVerifyBodyParams {
  scopes?: string[];
  grantVersion?: bigint;
  expiresAt?: bigint;
}

async function signVerifyBody(
  params: SignVerifyBodyParams = {},
): Promise<CanaryVerifyBody> {
  const scopes = params.scopes ?? ["instagram.*"];
  const grantVersion = params.grantVersion ?? 1n;
  const expiresAt = params.expiresAt ?? BigInt(futureExpiry);
  const signature = await owner.signTypedData({
    domain: grantRegistrationDomain(gatewayConfig) as unknown as Record<
      string,
      unknown
    >,
    types: GRANT_REGISTRATION_TYPES as unknown as Record<
      string,
      Array<{ name: string; type: string }>
    >,
    primaryType: "GrantRegistration",
    message: {
      grantorAddress: owner.address,
      granteeId: BUILDER_ID,
      scopes,
      grantVersion,
      expiresAt,
    },
  });
  return {
    grantorAddress: owner.address,
    granteeId: BUILDER_ID,
    scopes,
    grantVersion: grantVersion.toString(),
    expiresAt: expiresAt.toString(),
    signature,
  };
}

function createApp(
  overrides?: Partial<{
    gateway: GatewayClient;
    serverSigner: ReturnType<typeof createMockServerSigner>;
  }>,
) {
  return grantsRoutes({
    logger,
    gateway: overrides?.gateway ?? createMockGateway(),
    gatewayConfig,
    serverOwner: owner.address,
    serverOrigin: SERVER_ORIGIN,
    serverSigner: overrides?.serverSigner ?? createMockServerSigner(),
  });
}

describe("GET /", () => {
  async function getWithOwnerAuth(app: ReturnType<typeof grantsRoutes>) {
    const auth = await buildWeb3SignedHeader({
      wallet: owner,
      aud: SERVER_ORIGIN,
      method: "GET",
      uri: "/",
    });
    return app.request("/", {
      method: "GET",
      headers: { authorization: auth },
    });
  }

  it("returns grants from gateway", async () => {
    const mockGateway = createMockGateway();
    const grants: GrantListItem[] = [
      makeGrantResponse({ id: "0xgrant1", scopes: ["instagram.*"] }),
      makeGrantResponse({
        id: "0xgrant2",
        scopes: ["twitter.*"],
        addedAt: "2025-01-02T00:00:00Z",
      }),
    ];
    vi.mocked(mockGateway.listGrantsByUser).mockResolvedValue(grants);

    const app = createApp({ gateway: mockGateway });
    const res = await getWithOwnerAuth(app);

    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.grants).toEqual(grants);
    expect(mockGateway.listGrantsByUser).toHaveBeenCalledWith(owner.address);
  });

  it("returns empty grants array when gateway has none", async () => {
    const mockGateway = createMockGateway();
    vi.mocked(mockGateway.listGrantsByUser).mockResolvedValue([]);

    const app = createApp({ gateway: mockGateway });
    const res = await getWithOwnerAuth(app);

    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.grants).toEqual([]);
  });

  it("returns 500 on gateway error", async () => {
    const mockGateway = createMockGateway();
    vi.mocked(mockGateway.listGrantsByUser).mockRejectedValue(
      new Error("Gateway down"),
    );

    const app = createApp({ gateway: mockGateway });
    const res = await getWithOwnerAuth(app);

    expect(res.status).toBe(500);
  });
});

describe("POST /verify", () => {
  it("valid grant + signature returns { valid: true, scopes, grantVersion, expiresAt }", async () => {
    const app = createApp();
    const body = await signVerifyBody();

    const res = await app.request("/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });

    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.valid).toBe(true);
    expect(json.grantorAddress).toBe(owner.address);
    expect(json.granteeId).toBe(BUILDER_ID);
    expect(json.scopes).toEqual(["instagram.*"]);
    expect(json.grantVersion).toBe("1");
    expect(json.expiresAt).toBe(String(futureExpiry));
  });

  it("tampered scopes returns { valid: false }", async () => {
    const app = createApp();
    const body = await signVerifyBody();
    // Mutate scopes after signing — the EIP-712 hash changes so recovery
    // produces a different signer.
    body.scopes = ["*"];

    const res = await app.request("/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });

    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.valid).toBe(false);
    expect(json.error).toBeDefined();
  });

  it("expired grant returns { valid: false }", async () => {
    const app = createApp();
    const pastExpiry = BigInt(Math.floor(Date.now() / 1000) - 3600);
    const body = await signVerifyBody({ expiresAt: pastExpiry });

    const res = await app.request("/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });

    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.valid).toBe(false);
    expect(json.error).toContain("expired");
  });

  it("expiresAt: 0 (no expiry) returns { valid: true }", async () => {
    const app = createApp();
    const body = await signVerifyBody({ expiresAt: 0n });

    const res = await app.request("/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });

    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.valid).toBe(true);
    expect(json.expiresAt).toBe("0");
  });

  it("missing required fields returns 400", async () => {
    const app = createApp();

    const res = await app.request("/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ grantId: "test" }),
    });

    expect(res.status).toBe(400);
    const json = await res.json();
    expect(json.error).toBe("INVALID_BODY");
  });

  it("invalid JSON body returns 400", async () => {
    const app = createApp();

    const res = await app.request("/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "not json",
    });

    expect(res.status).toBe(400);
    const json = await res.json();
    expect(json.error).toBe("INVALID_BODY");
  });
});

describe("POST /", () => {
  async function postWithOwnerAuth(
    app: ReturnType<typeof grantsRoutes>,
    body: Record<string, unknown>,
  ) {
    const bodyStr = JSON.stringify(body);
    const auth = await buildWeb3SignedHeader({
      wallet: owner,
      aud: SERVER_ORIGIN,
      method: "POST",
      uri: "/",
      bodyHash: `sha256:${await import("node:crypto").then((c) => c.createHash("sha256").update(bodyStr).digest("hex"))}`,
    });
    return app.request("/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        authorization: auth,
      },
      body: bodyStr,
    });
  }

  it("creates grant via gateway and returns grantId", async () => {
    const mockGateway = createMockGateway();
    const mockSigner = createMockServerSigner();

    const app = createApp({ gateway: mockGateway, serverSigner: mockSigner });
    const res = await postWithOwnerAuth(app, {
      granteeAddress: builder.address,
      scopes: ["instagram.*"],
    });

    expect(res.status).toBe(201);
    const json = await res.json();
    expect(json.grantId).toBe("grant-123");

    expect(mockGateway.getBuilder).toHaveBeenCalledWith(builder.address);

    // Default grantVersion is 1n; expiresAt defaults to 0n.
    expect(mockSigner.signGrantRegistration).toHaveBeenCalledWith({
      grantorAddress: owner.address,
      granteeId: BUILDER_ID,
      scopes: ["instagram.*"],
      grantVersion: 1n,
      expiresAt: 0n,
    });

    expect(mockGateway.createGrant).toHaveBeenCalledWith({
      grantorAddress: owner.address,
      granteeId: BUILDER_ID,
      scopes: ["instagram.*"],
      grantVersion: "1",
      expiresAt: "0",
      signature: "0xgrantsig",
    });
  });

  it("returns 404 when builder is not registered", async () => {
    const mockGateway = createMockGateway();
    vi.mocked(mockGateway.getBuilder).mockResolvedValue(null);

    const app = createApp({ gateway: mockGateway });
    const res = await postWithOwnerAuth(app, {
      granteeAddress: builder.address,
      scopes: ["instagram.*"],
    });

    expect(res.status).toBe(404);
    const json = await res.json();
    expect(json.error.errorCode).toBe("BUILDER_NOT_REGISTERED");
  });

  it("returns 500 when serverSigner is not configured", async () => {
    const app = grantsRoutes({
      logger,
      gateway: createMockGateway(),
      gatewayConfig,
      serverOwner: owner.address,
      serverOrigin: SERVER_ORIGIN,
    });

    const res = await postWithOwnerAuth(app, {
      granteeAddress: builder.address,
      scopes: ["instagram.*"],
    });

    expect(res.status).toBe(500);
    const json = await res.json();
    expect(json.error.errorCode).toBe("SERVER_SIGNER_NOT_CONFIGURED");
  });

  it("returns 400 for invalid body (missing scopes)", async () => {
    const app = createApp();
    const res = await postWithOwnerAuth(app, {
      granteeAddress: builder.address,
    });

    expect(res.status).toBe(400);
    const json = await res.json();
    expect(json.error).toBe("INVALID_BODY");
  });

  it("returns 400 for invalid body (missing granteeAddress)", async () => {
    const app = createApp();
    const res = await postWithOwnerAuth(app, {
      scopes: ["instagram.*"],
    });

    expect(res.status).toBe(400);
    const json = await res.json();
    expect(json.error).toBe("INVALID_BODY");
  });

  it("forwards optional expiresAt and grantVersion to signer + gateway", async () => {
    const mockGateway = createMockGateway();
    const mockSigner = createMockServerSigner();

    const app = createApp({ gateway: mockGateway, serverSigner: mockSigner });
    const res = await postWithOwnerAuth(app, {
      granteeAddress: builder.address,
      scopes: ["instagram.*"],
      expiresAt: 1700000000,
      grantVersion: "7",
    });

    expect(res.status).toBe(201);
    expect(mockSigner.signGrantRegistration).toHaveBeenCalledWith({
      grantorAddress: owner.address,
      granteeId: BUILDER_ID,
      scopes: ["instagram.*"],
      grantVersion: 7n,
      expiresAt: 1700000000n,
    });
    expect(mockGateway.createGrant).toHaveBeenCalledWith(
      expect.objectContaining({
        grantVersion: "7",
        expiresAt: "1700000000",
      }),
    );
  });
});

describe("DELETE /:grantId", () => {
  async function deleteWithOwnerAuth(
    app: ReturnType<typeof grantsRoutes>,
    grantId: `0x${string}`,
  ) {
    const auth = await buildWeb3SignedHeader({
      wallet: owner,
      aud: SERVER_ORIGIN,
      method: "DELETE",
      uri: `/${grantId}`,
    });
    return app.request(`/${grantId}`, {
      method: "DELETE",
      headers: { authorization: auth },
    });
  }

  it("revokes grant via gateway with grantVersion + 1", async () => {
    const mockGateway = createMockGateway();
    const mockSigner = createMockServerSigner();
    const grantId =
      "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    vi.mocked(mockGateway.getGrant).mockResolvedValue(
      makeGrantResponse({ id: grantId, grantVersion: "3" }),
    );

    const app = createApp({ gateway: mockGateway, serverSigner: mockSigner });
    const res = await deleteWithOwnerAuth(app, grantId);

    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toEqual({ status: "revoked", grantId });
    // Revocation increments the (grantor, grantee) monotonic nonce —
    // current grant.grantVersion is "3", revocation must use "4".
    expect(mockSigner.signGrantRevocation).toHaveBeenCalledWith({
      grantorAddress: owner.address,
      grantId,
      grantVersion: 4n,
    });
    expect(mockGateway.revokeGrant).toHaveBeenCalledWith({
      grantorAddress: owner.address,
      grantId,
      grantVersion: "4",
      signature: "0xrevokesig",
    });
  });

  it("returns 404 when the grant doesn't exist on the gateway", async () => {
    const mockGateway = createMockGateway();
    vi.mocked(mockGateway.getGrant).mockResolvedValue(null);
    const grantId =
      "0x9999999999999999999999999999999999999999999999999999999999999999";

    const app = createApp({ gateway: mockGateway });
    const res = await deleteWithOwnerAuth(app, grantId);

    expect(res.status).toBe(404);
    const json = await res.json();
    expect(json.error.errorCode).toBe("GRANT_NOT_FOUND");
  });
});
