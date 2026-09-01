/**
 * Write API demo slice (e2e): a builder opens a write-session against a
 * running PS with a WRITE-grant, POSTs a JSON record into a scope through the
 * normal ingest path (PS-side owner signing, builder attribution stamped),
 * and read-back requires a SEPARATE read-grant — the write-grant never
 * confers read.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { startTestServer, type TestServer } from "./helpers/server.js";
import { startMockGateway, type MockGateway } from "./helpers/mock-gateway.js";
import {
  createTestWallet,
  buildWeb3SignedHeader,
} from "../../packages/core/src/test-utils/index.js";

const KNOWN_SIG =
  "0xedbb7743cce459345238442dcfb291f234a321d253485eaa58251aa0f28ea8f1410ab988bae2657b689cd24417b41e315efc22ba333024f4a6269c424ded8d361b";

// The mock gateway registers every builder under this id (see helpers).
const BUILDER_ID = "0xbuilder1";
const WRITE_GRANT_ID = "0xwritegrant1";
const READ_GRANT_ID = "0xreadgrant1";
const SCOPE = "notes.entries";

const builderWallet = createTestWallet(3);

function grantBase(owner: string): Record<string, unknown> {
  return {
    grantorAddress: owner,
    granteeId: BUILDER_ID,
    status: "confirmed",
    addedAt: new Date().toISOString(),
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
  };
}

describe("Write API (e2e)", () => {
  let server: TestServer;
  let gateway: MockGateway;
  let owner: string;

  beforeAll(async () => {
    gateway = await startMockGateway();
    server = await startTestServer({
      gatewayUrl: gateway.url,
      masterKeySignature: KNOWN_SIG,
    });

    const health = await fetch(`${server.url}/health`);
    owner = (await health.json()).owner as string;
    expect(owner).toMatch(/^0x/);

    // The owner has issued the builder a WRITE-grant on the scope. (Grant
    // registration itself reuses the existing POST /v1/grants surface; here
    // the gateway is mocked so we seed the stored grant directly.)
    gateway.setGrant(WRITE_GRANT_ID, {
      id: WRITE_GRANT_ID,
      scopes: [`write:${SCOPE}`],
      ...grantBase(owner),
    });
  }, 30000);

  afterAll(async () => {
    await server?.cleanup();
    await gateway?.cleanup();
  });

  let sessionToken: string;

  it("answers CORS preflight for both Write API routes without credentials", async () => {
    // A browser builder app preflights both routes; the real HTTP server must
    // answer 204 before auth and allowlist the delegated-write headers.
    for (const path of ["/v1/write/session", `/v1/data/${SCOPE}`]) {
      const res = await fetch(`${server.url}${path}`, {
        method: "OPTIONS",
        headers: {
          Origin: "https://builder.example",
          "Access-Control-Request-Method": "POST",
          "Access-Control-Request-Headers":
            "authorization, content-type, x-vana-write-signature",
        },
      });
      expect(res.status, path).toBe(204);
      expect(res.headers.get("access-control-allow-origin"), path).toBe("*");
      const allowed = (
        res.headers.get("access-control-allow-headers") ?? ""
      ).toLowerCase();
      expect(allowed, path).toContain("authorization");
      expect(allowed, path).toContain("x-vana-write-signature");
    }
  });

  it("opens a write-session with a Web3Signed handshake + write-grant", async () => {
    const auth = await buildWeb3SignedHeader({
      wallet: builderWallet,
      aud: server.url,
      method: "POST",
      uri: "/v1/write/session",
      grantId: WRITE_GRANT_ID,
    });
    const res = await fetch(`${server.url}/v1/write/session`, {
      method: "POST",
      headers: { Authorization: auth },
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.token_type).toBe("Bearer");
    expect(body.scope).toBe(SCOPE);
    sessionToken = body.access_token;
    expect(sessionToken).toMatch(/^vana_write_/);
  });

  it("writes a JSON record through the normal ingest path with attribution", async () => {
    const rawBody = JSON.stringify({
      note: "hello from the builder",
      source: "write-api-e2e",
    });
    const signature = await buildWeb3SignedHeader({
      wallet: builderWallet,
      aud: server.url,
      method: "POST",
      uri: `/v1/data/${SCOPE}`,
      body: new TextEncoder().encode(rawBody),
      grantId: WRITE_GRANT_ID,
    });
    const res = await fetch(`${server.url}/v1/data/${SCOPE}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${sessionToken}`,
        "X-Vana-Write-Signature": signature,
      },
      body: rawBody,
    });
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.scope).toBe(SCOPE);
    expect(body.collectedAt).toBeDefined();
  });

  it("read-back WITHOUT a read-grant fails: the write-grant never confers read", async () => {
    const auth = await buildWeb3SignedHeader({
      wallet: builderWallet,
      aud: server.url,
      method: "GET",
      uri: `/v1/data/${SCOPE}`,
      grantId: WRITE_GRANT_ID,
    });
    const res = await fetch(`${server.url}/v1/data/${SCOPE}`, {
      headers: { Authorization: auth },
    });
    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.error.errorCode).toBe("SCOPE_MISMATCH");
  });

  it("read-back with a SEPARATE read-grant succeeds without the server-stamped attribution", async () => {
    gateway.setGrant(READ_GRANT_ID, {
      id: READ_GRANT_ID,
      scopes: [SCOPE],
      ...grantBase(owner),
    });

    const auth = await buildWeb3SignedHeader({
      wallet: builderWallet,
      aud: server.url,
      method: "GET",
      uri: `/v1/data/${SCOPE}`,
      grantId: READ_GRANT_ID,
    });
    const res = await fetch(`${server.url}/v1/data/${SCOPE}`, {
      headers: { Authorization: auth },
    });
    expect(res.status).toBe(200);
    const envelope = await res.json();
    expect(envelope.scope).toBe(SCOPE);
    expect(envelope.data.note).toBe("hello from the builder");
    // The builder attribution is stored with the record but never served on
    // a grantee read (the writing builder's identity must not leak to other
    // grantees); the owner's read and the verify path retain it. Covered at
    // the route level in data-lineage.test.ts.
    expect(envelope.data.$writtenBy).toBeUndefined();
    expect(envelope.data.$lineage).toBeUndefined();
  });

  it("a session write to an uncovered scope is rejected", async () => {
    const rawBody = JSON.stringify({ note: "nope" });
    const signature = await buildWeb3SignedHeader({
      wallet: builderWallet,
      aud: server.url,
      method: "POST",
      uri: "/v1/data/other.scope",
      body: new TextEncoder().encode(rawBody),
      grantId: WRITE_GRANT_ID,
    });
    const res = await fetch(`${server.url}/v1/data/other.scope`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${sessionToken}`,
        "X-Vana-Write-Signature": signature,
      },
      body: rawBody,
    });
    expect(res.status).toBe(403);
  });

  it("a read-grant cannot open a write-session", async () => {
    const auth = await buildWeb3SignedHeader({
      wallet: builderWallet,
      aud: server.url,
      method: "POST",
      uri: "/v1/write/session",
      grantId: READ_GRANT_ID,
    });
    const res = await fetch(`${server.url}/v1/write/session`, {
      method: "POST",
      headers: { Authorization: auth },
    });
    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.error.errorCode).toBe("SCOPE_MISMATCH");
  });
});
