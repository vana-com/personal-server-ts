import { describe, it, expect, vi } from "vitest";
import { pino } from "pino";
import type { GatewayClient, Builder } from "@opendatalabs/vana-sdk/node";
import type { GatewayGrantResponse } from "@opendatalabs/vana-sdk/node";
import {
  createTestWallet,
  buildWeb3SignedHeader,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import {
  createInMemoryWriteSessionStore,
  hashWriteSessionToken,
} from "@opendatalabs/personal-server-ts-core/write";
import { writeSessionRoutes } from "./write-session.js";

const SERVER_ORIGIN = "http://localhost:8080";
const builderWallet = createTestWallet(0);
const ownerWallet = createTestWallet(9);

const BUILDER_ID = "0xbuilder1";

function createMockGateway(
  overrides: Partial<GatewayClient> = {},
): GatewayClient {
  return {
    isRegisteredBuilder: vi.fn().mockResolvedValue(true),
    getBuilder: vi.fn().mockResolvedValue({
      id: BUILDER_ID,
      ownerAddress: "0xOwner",
      granteeAddress: builderWallet.address,
      publicKey: "0x04key",
      appUrl: "https://app.example.com",
      addedAt: "2026-01-21T10:00:00.000Z",
    } satisfies Builder),
    getGrant: vi.fn().mockResolvedValue(null),
    ...overrides,
  } as unknown as GatewayClient;
}

function makeWriteGrant(
  overrides: Partial<GatewayGrantResponse> = {},
): GatewayGrantResponse {
  return {
    id: "grant-w-1",
    grantorAddress: ownerWallet.address,
    granteeId: BUILDER_ID,
    scopes: ["write:notes.entries"],
    status: "confirmed",
    addedAt: "2026-01-21T10:00:00.000Z",
    expiresAt: null,
    expired: false,
    revokedAt: null,
    revocationSignature: null,
    paymentStatus: "paid",
    paidAt: null,
    paidBy: null,
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
    ...overrides,
  };
}

const logger = pino({ level: "silent" });

async function handshakeHeader(
  options: { grantId?: string; iat?: number } = {},
) {
  return buildWeb3SignedHeader({
    wallet: builderWallet,
    aud: SERVER_ORIGIN,
    method: "POST",
    uri: "/session",
    grantId: options.grantId ?? "grant-w-1",
    iat: options.iat,
  });
}

describe("POST /v1/write/session", () => {
  it("mints a bearer token for a valid builder + write-grant handshake", async () => {
    const sessionStore = createInMemoryWriteSessionStore();
    const app = writeSessionRoutes({
      logger,
      serverOrigin: SERVER_ORIGIN,
      serverOwner: ownerWallet.address,
      gateway: createMockGateway({
        getGrant: vi.fn().mockResolvedValue(makeWriteGrant()),
      }),
      sessionStore,
    });

    const res = await app.request("/session", {
      method: "POST",
      headers: { Authorization: await handshakeHeader() },
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.token_type).toBe("Bearer");
    expect(body.access_token).toMatch(/^vana_write_/);
    expect(body.expires_in).toBeGreaterThan(0);
    expect(body.scope).toBe("notes.entries");

    const record = await sessionStore.getByTokenHash(
      await hashWriteSessionToken(body.access_token),
    );
    expect(record?.builderAddress).toBe(builderWallet.address);
    expect(record?.grantId).toBe("grant-w-1");
    expect(record?.writeScopes).toEqual(["notes.entries"]);
  });

  it("rejects a read-grant (no write: scope entries)", async () => {
    const app = writeSessionRoutes({
      logger,
      serverOrigin: SERVER_ORIGIN,
      serverOwner: ownerWallet.address,
      gateway: createMockGateway({
        getGrant: vi
          .fn()
          .mockResolvedValue(makeWriteGrant({ scopes: ["notes.entries"] })),
      }),
      sessionStore: createInMemoryWriteSessionStore(),
    });

    const res = await app.request("/session", {
      method: "POST",
      headers: { Authorization: await handshakeHeader() },
    });
    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.error.errorCode).toBe("SCOPE_MISMATCH");
  });

  it("rejects a proof without a grantId claim", async () => {
    const app = writeSessionRoutes({
      logger,
      serverOrigin: SERVER_ORIGIN,
      serverOwner: ownerWallet.address,
      gateway: createMockGateway(),
      sessionStore: createInMemoryWriteSessionStore(),
    });

    const auth = await buildWeb3SignedHeader({
      wallet: builderWallet,
      aud: SERVER_ORIGIN,
      method: "POST",
      uri: "/session",
    });
    const res = await app.request("/session", {
      method: "POST",
      headers: { Authorization: auth },
    });
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error.errorCode).toBe("GRANT_ID_REQUIRED");
  });

  it("rejects non-Web3Signed mechanisms (a dev token cannot open a write session)", async () => {
    const app = writeSessionRoutes({
      logger,
      serverOrigin: SERVER_ORIGIN,
      serverOwner: ownerWallet.address,
      gateway: createMockGateway(),
      devToken: "dev-token-1",
      sessionStore: createInMemoryWriteSessionStore(),
    });

    const res = await app.request("/session", {
      method: "POST",
      headers: { Authorization: "Bearer dev-token-1" },
    });
    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body.error.errorCode).toBe("WRITE_SESSION_PROOF_REQUIRED");
  });

  it("rejects a replayed handshake proof", async () => {
    const app = writeSessionRoutes({
      logger,
      serverOrigin: SERVER_ORIGIN,
      serverOwner: ownerWallet.address,
      gateway: createMockGateway({
        getGrant: vi.fn().mockResolvedValue(makeWriteGrant()),
      }),
      sessionStore: createInMemoryWriteSessionStore(),
    });

    const auth = await handshakeHeader();
    const first = await app.request("/session", {
      method: "POST",
      headers: { Authorization: auth },
    });
    expect(first.status).toBe(200);

    const replay = await app.request("/session", {
      method: "POST",
      headers: { Authorization: auth },
    });
    expect(replay.status).toBe(401);
    const body = await replay.json();
    expect(body.error.errorCode).toBe("WRITE_SESSION_PROOF_REPLAY");
  });

  it("returns 500 when the server owner is not configured", async () => {
    const app = writeSessionRoutes({
      logger,
      serverOrigin: SERVER_ORIGIN,
      gateway: createMockGateway(),
      sessionStore: createInMemoryWriteSessionStore(),
    });

    const res = await app.request("/session", {
      method: "POST",
      headers: { Authorization: await handshakeHeader() },
    });
    expect(res.status).toBe(500);
    const body = await res.json();
    expect(body.error.errorCode).toBe("SERVER_NOT_CONFIGURED");
  });
});
