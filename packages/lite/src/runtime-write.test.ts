/**
 * Delegated (Write API) sessions in the BROWSER personal server.
 *
 * Mirrors the Node build's write-session and attribution suites
 * (packages/server/src/routes/write-session.test.ts and data-write.test.ts)
 * against `createPsLiteRuntime`, because the security question is not "does
 * PS-Lite have the feature" but "does PS-Lite check the same things". Every
 * assertion here has a twin over there: audience, method, signed uri, body
 * hash over the stored representation, the grantId claim, the optional nonce,
 * the replay reservation, and a LIVE grant re-check on every single write.
 */

import { describe, expect, it, vi } from "vitest";
import type { GatewayGrantResponse } from "@opendatalabs/vana-sdk/browser";
import {
  buildWeb3SignedHeader,
  createTestWallet,
} from "../../core/src/test-utils/index.js";
import {
  WRITE_SIGNATURE_HEADER,
  WRITER_ATTRIBUTION_KEY,
  binaryWriteSignedBytes,
  createInMemoryWriteProofReplayStore,
  createInMemoryWriteSessionStore,
  hashWriteSessionToken,
  verifyStoredWriterAttribution,
  type WriteSessionStore,
} from "@opendatalabs/personal-server-ts-core/write";
import {
  createBearerTokenPsLiteAuth,
  createPsLiteRuntime,
  createWeb3SignedPsLiteAuth,
  type PsLiteRuntime,
} from "./runtime.js";
import {
  createMemoryPsLiteAccessLogStore,
  createMemoryPsLiteStorage,
  createMemoryPsLiteTokenStore,
} from "./test-support/memory.js";
import { createMockPsLiteGateway } from "./test-support/gateway.js";

const PS_ORIGIN = "https://ps.local";
const SCOPE = "notes.entries";
const WRITE_GRANT_ID = "grant-w-1";
const BUILDER_ID = "0xbuilder1";

const builderWallet = createTestWallet(0);
const otherWallet = createTestWallet(5);
const ownerWallet = createTestWallet(9);

function makeGrant(
  overrides: Partial<GatewayGrantResponse> = {},
): GatewayGrantResponse {
  return {
    id: WRITE_GRANT_ID,
    grantorAddress: ownerWallet.address,
    granteeId: BUILDER_ID,
    scopes: [`write:${SCOPE}`],
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

type MockGateway = ReturnType<typeof createMockPsLiteGateway>;

function createWriteGateway(grant: GatewayGrantResponse | null): MockGateway {
  return {
    ...createMockPsLiteGateway(),
    isRegisteredBuilder: vi.fn().mockResolvedValue(true),
    getBuilder: vi.fn().mockResolvedValue({
      id: BUILDER_ID,
      ownerAddress: "0xOwner",
      granteeAddress: builderWallet.address,
      publicKey: "0x04key",
      appUrl: "https://app.example.com",
      addedAt: "2026-01-21T10:00:00.000Z",
    }),
    getGrant: vi.fn().mockResolvedValue(grant),
  } as MockGateway;
}

interface Harness {
  runtime: PsLiteRuntime;
  gateway: MockGateway;
  sessionStore: WriteSessionStore;
  accessLog: ReturnType<typeof createMemoryPsLiteAccessLogStore>;
}

function setup(
  options: {
    grant?: GatewayGrantResponse | null;
    /** Omit the whole write-session wiring (owner-only ingest). */
    writeSessions?: false;
  } = {},
): Harness {
  const gateway = createWriteGateway(
    options.grant === undefined ? makeGrant() : options.grant,
  );
  const sessionStore = createInMemoryWriteSessionStore();
  const replayStore = createInMemoryWriteProofReplayStore();
  const accessLog = createMemoryPsLiteAccessLogStore();
  const enabled = options.writeSessions !== false;
  const policyPorts = { authSessionVerifier: gateway, grantVerifier: gateway };
  const runtime = createPsLiteRuntime({
    storage: createMemoryPsLiteStorage(),
    gateway,
    serverOwner: ownerWallet.address,
    serverOrigin: PS_ORIGIN,
    accessLogReader: accessLog,
    accessLogWriter: accessLog,
    tokenStore: createMemoryPsLiteTokenStore(),
    saveConfig: async () => {},
    stateCapabilities: { config: "memory" },
    auth: createWeb3SignedPsLiteAuth({
      origin: PS_ORIGIN,
      ownerAddress: ownerWallet.address,
      dataReadPolicyPorts: policyPorts,
      ...(enabled
        ? { writeSessions: { store: sessionStore, replayStore, policyPorts } }
        : {}),
    }),
    ...(enabled
      ? { writeSessionStore: sessionStore, writeProofReplayStore: replayStore }
      : {}),
    active: true,
  });
  return { runtime, gateway, sessionStore, accessLog };
}

/** The builder's Web3Signed handshake to POST /v1/write/session. */
async function handshake(
  runtime: PsLiteRuntime,
  options: { grantId?: string | null; iat?: number } = {},
): Promise<Response> {
  const grantId =
    options.grantId === null ? undefined : (options.grantId ?? WRITE_GRANT_ID);
  const authorization = await buildWeb3SignedHeader({
    wallet: builderWallet,
    aud: PS_ORIGIN,
    method: "POST",
    uri: "/v1/write/session",
    ...(grantId === undefined ? {} : { grantId }),
    ...(options.iat === undefined ? {} : { iat: options.iat }),
  });
  return runtime.fetch(
    new Request(`${PS_ORIGIN}/v1/write/session`, {
      method: "POST",
      headers: { Authorization: authorization },
    }),
  );
}

async function openSession(runtime: PsLiteRuntime): Promise<string> {
  const res = await handshake(runtime);
  expect(res.status).toBe(200);
  return (await res.json()).access_token as string;
}

interface SessionWriteOptions {
  token: string;
  scope?: string;
  /** Exact bytes to send (and, by default, to sign). */
  rawBody?: string;
  signatureWallet?: ReturnType<typeof createTestWallet>;
  omitSignature?: boolean;
  /** Sign a different uri than the one requested. */
  signedUri?: string;
  /** Sign different bytes than the ones sent. */
  signedBody?: string;
  signedGrantId?: string;
  nonce?: string;
}

async function sessionWrite(
  runtime: PsLiteRuntime,
  body: unknown,
  options: SessionWriteOptions,
): Promise<Response> {
  const scope = options.scope ?? SCOPE;
  const path = `/v1/data/${scope}`;
  const rawBody = options.rawBody ?? JSON.stringify(body);
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Authorization: `Bearer ${options.token}`,
  };
  if (!options.omitSignature) {
    headers[WRITE_SIGNATURE_HEADER] = await buildWeb3SignedHeader({
      wallet: options.signatureWallet ?? builderWallet,
      aud: PS_ORIGIN,
      method: "POST",
      uri: options.signedUri ?? path,
      body: new TextEncoder().encode(options.signedBody ?? rawBody),
      grantId: options.signedGrantId ?? WRITE_GRANT_ID,
      ...(options.nonce === undefined ? {} : { nonce: options.nonce }),
    });
  }
  return runtime.fetch(
    new Request(`${PS_ORIGIN}${path}`, {
      method: "POST",
      headers,
      body: rawBody,
    }),
  );
}

async function ownerRead(
  runtime: PsLiteRuntime,
  scope = SCOPE,
): Promise<Response> {
  const authorization = await buildWeb3SignedHeader({
    wallet: ownerWallet,
    aud: PS_ORIGIN,
    method: "GET",
    uri: `/v1/data/${scope}`,
  });
  return runtime.fetch(
    new Request(`${PS_ORIGIN}/v1/data/${scope}`, {
      headers: { Authorization: authorization },
    }),
  );
}

async function ownerWrite(
  runtime: PsLiteRuntime,
  body: unknown,
  scope = SCOPE,
): Promise<Response> {
  const rawBody = JSON.stringify(body);
  const authorization = await buildWeb3SignedHeader({
    wallet: ownerWallet,
    aud: PS_ORIGIN,
    method: "POST",
    uri: `/v1/data/${scope}`,
    body: new TextEncoder().encode(rawBody),
  });
  return runtime.fetch(
    new Request(`${PS_ORIGIN}/v1/data/${scope}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: authorization,
      },
      body: rawBody,
    }),
  );
}

describe("PS-Lite POST /v1/write/session", () => {
  it("mints a bearer token for a valid builder + write-grant handshake", async () => {
    const { runtime, sessionStore } = setup();
    const res = await handshake(runtime);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.token_type).toBe("Bearer");
    expect(body.access_token).toMatch(/^vana_write_/);
    expect(body.expires_in).toBeGreaterThan(0);
    expect(body.scope).toBe(SCOPE);

    const record = await sessionStore.getByTokenHash(
      await hashWriteSessionToken(body.access_token),
    );
    expect(record?.builderAddress).toBe(builderWallet.address);
    expect(record?.grantId).toBe(WRITE_GRANT_ID);
    expect(record?.writeScopes).toEqual([SCOPE]);
  });

  it("rejects a read-only grant: no write: entries, no session", async () => {
    const { runtime } = setup({ grant: makeGrant({ scopes: [SCOPE] }) });
    const res = await handshake(runtime);
    expect(res.status).toBe(403);
    expect((await res.json()).error.errorCode).toBe("SCOPE_MISMATCH");
  });

  it("rejects a proof without a grantId claim", async () => {
    const { runtime } = setup();
    const res = await handshake(runtime, { grantId: null });
    expect(res.status).toBe(400);
    expect((await res.json()).error.errorCode).toBe("GRANT_ID_REQUIRED");
  });

  it("rejects a replayed handshake proof", async () => {
    const { runtime } = setup();
    const authorization = await buildWeb3SignedHeader({
      wallet: builderWallet,
      aud: PS_ORIGIN,
      method: "POST",
      uri: "/v1/write/session",
      grantId: WRITE_GRANT_ID,
    });
    const send = () =>
      runtime.fetch(
        new Request(`${PS_ORIGIN}/v1/write/session`, {
          method: "POST",
          headers: { Authorization: authorization },
        }),
      );
    expect((await send()).status).toBe(200);
    const replay = await send();
    expect(replay.status).toBe(401);
    expect((await replay.json()).error.errorCode).toBe(
      "WRITE_SESSION_PROOF_REPLAY",
    );
  });

  it("rejects a proof signed for another server's audience", async () => {
    const { runtime } = setup();
    const authorization = await buildWeb3SignedHeader({
      wallet: builderWallet,
      aud: "https://someone-elses-ps.example",
      method: "POST",
      uri: "/v1/write/session",
      grantId: WRITE_GRANT_ID,
    });
    const res = await runtime.fetch(
      new Request(`${PS_ORIGIN}/v1/write/session`, {
        method: "POST",
        headers: { Authorization: authorization },
      }),
    );
    expect(res.status).toBe(401);
    expect((await res.json()).error.errorCode).toBe(
      "WRITE_SESSION_AUTH_FAILED",
    );
  });

  it("is not mounted at all when the runtime has no session store", async () => {
    const { runtime } = setup({ writeSessions: false });
    expect((await handshake(runtime)).status).toBe(404);
  });

  it("answers 405 for a non-POST handshake", async () => {
    const { runtime } = setup();
    const res = await runtime.fetch(
      new Request(`${PS_ORIGIN}/v1/write/session`),
    );
    expect(res.status).toBe(405);
  });
});

describe("PS-Lite delegated writes to POST /v1/data/:scope", () => {
  it("a builder with a write grant opens a session and writes with attribution", async () => {
    const { runtime } = setup();
    const token = await openSession(runtime);
    const res = await sessionWrite(runtime, { note: "by builder" }, { token });
    expect(res.status).toBe(201);

    const read = await ownerRead(runtime);
    expect(read.status).toBe(200);
    const envelope = await read.json();
    expect(envelope.data.note).toBe("by builder");
    const attribution = envelope.data[WRITER_ATTRIBUTION_KEY];
    expect(attribution.builder).toBe(builderWallet.address);
    expect(attribution.grantId).toBe(WRITE_GRANT_ID);
    expect(attribution.bodyHash).toMatch(/^sha256:/);

    // The record proves its own authorship, with no server state involved.
    const verified = await verifyStoredWriterAttribution(envelope, {
      expectedOrigin: PS_ORIGIN,
    });
    expect(verified.builder.toLowerCase()).toBe(
      builderWallet.address.toLowerCase(),
    );
  });

  it("stamps the write into the owner's access log under the grant", async () => {
    const { runtime, accessLog } = setup();
    const write = vi.spyOn(accessLog, "write");
    const token = await openSession(runtime);
    expect((await sessionWrite(runtime, { note: "x" }, { token })).status).toBe(
      201,
    );
    expect(write).toHaveBeenCalledWith(
      expect.objectContaining({
        action: "write",
        builder: builderWallet.address,
        grantId: WRITE_GRANT_ID,
        scope: SCOPE,
      }),
    );
  });

  it("a binary write is signed over its stored representation", async () => {
    const { runtime } = setup();
    const token = await openSession(runtime);
    const bytes = new TextEncoder().encode("%PDF-1.7 fake report");
    const representation = {
      contentType: "application/pdf",
      filename: "report.pdf",
      metadataHeader: "DEXA scan",
    };
    const signature = await buildWeb3SignedHeader({
      wallet: builderWallet,
      aud: PS_ORIGIN,
      method: "POST",
      uri: `/v1/data/${SCOPE}`,
      body: await binaryWriteSignedBytes({ bytes, ...representation }),
      grantId: WRITE_GRANT_ID,
    });
    const res = await runtime.fetch(
      new Request(`${PS_ORIGIN}/v1/data/${SCOPE}`, {
        method: "POST",
        headers: {
          "Content-Type": representation.contentType,
          "X-Filename": representation.filename,
          "X-Vana-Metadata": representation.metadataHeader,
          Authorization: `Bearer ${token}`,
          [WRITE_SIGNATURE_HEADER]: signature,
        },
        body: bytes,
      }),
    );
    expect(res.status).toBe(201);
    const envelope = await (await ownerRead(runtime)).json();
    expect(envelope.data.$binary).toBe(true);
    expect(envelope.data.filename).toBe("report.pdf");
    await expect(
      verifyStoredWriterAttribution(envelope, { expectedOrigin: PS_ORIGIN }),
    ).resolves.toMatchObject({ grantId: WRITE_GRANT_ID });
  });

  it("a read-only grant cannot write: the session can never be opened", async () => {
    // A read grant is refused at the handshake, so there is no token to
    // present. Belt and braces: a forged bearer is not a session either.
    const { runtime } = setup({ grant: makeGrant({ scopes: [SCOPE] }) });
    expect((await handshake(runtime)).status).toBe(403);
    const res = await sessionWrite(
      runtime,
      { note: "x" },
      { token: "vana_write_forged" },
    );
    // Unknown bearer -> owner fall-through -> the owner gate refuses it.
    expect(res.status).toBe(401);
  });

  it("re-checks the live grant per write: revocation stops the NEXT write", async () => {
    const { runtime, gateway } = setup();
    const token = await openSession(runtime);
    expect((await sessionWrite(runtime, { n: 1 }, { token })).status).toBe(201);

    (gateway.getGrant as ReturnType<typeof vi.fn>).mockResolvedValue(
      makeGrant({ revokedAt: "2026-08-20T00:00:00.000Z" }),
    );
    const res = await sessionWrite(runtime, { n: 2 }, { token });
    expect(res.status).toBe(403);
    expect((await res.json()).error.errorCode).toBe("GRANT_REVOKED");
  });

  it("re-checks the live grant per write: a narrowed grant stops the NEXT write", async () => {
    const { runtime, gateway } = setup();
    const token = await openSession(runtime);
    expect((await sessionWrite(runtime, { n: 1 }, { token })).status).toBe(201);

    // The owner narrows the grant to a different scope after the handshake.
    (gateway.getGrant as ReturnType<typeof vi.fn>).mockResolvedValue(
      makeGrant({ scopes: ["write:something.else"] }),
    );
    const res = await sessionWrite(runtime, { n: 2 }, { token });
    expect(res.status).toBe(403);
    expect((await res.json()).error.errorCode).toBe("SCOPE_MISMATCH");
  });

  it("refuses a write to a scope the grant never covered", async () => {
    const { runtime } = setup();
    const token = await openSession(runtime);
    const res = await sessionWrite(
      runtime,
      { note: "x" },
      { token, scope: "other.scope" },
    );
    expect(res.status).toBe(403);
    expect((await res.json()).error.errorCode).toBe("SCOPE_MISMATCH");
  });

  it("refuses a replayed proof: the same signed request is stored once", async () => {
    const { runtime } = setup();
    const token = await openSession(runtime);
    const rawBody = JSON.stringify({ note: "once" });
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
      [WRITE_SIGNATURE_HEADER]: await buildWeb3SignedHeader({
        wallet: builderWallet,
        aud: PS_ORIGIN,
        method: "POST",
        uri: `/v1/data/${SCOPE}`,
        body: new TextEncoder().encode(rawBody),
        grantId: WRITE_GRANT_ID,
      }),
    };
    const send = () =>
      runtime.fetch(
        new Request(`${PS_ORIGIN}/v1/data/${SCOPE}`, {
          method: "POST",
          headers,
          body: rawBody,
        }),
      );
    expect((await send()).status).toBe(201);
    const replay = await send();
    expect(replay.status).toBe(401);
    expect((await replay.json()).error.errorCode).toBe(
      "WRITE_ATTRIBUTION_REPLAY",
    );
    expect((await (await ownerRead(runtime)).json()).data.note).toBe("once");
  });

  it("refuses a proof signed for a different uri", async () => {
    const { runtime } = setup();
    const token = await openSession(runtime);
    const res = await sessionWrite(
      runtime,
      { note: "x" },
      { token, signedUri: "/v1/data/other.scope" },
    );
    expect(res.status).toBe(401);
    expect((await res.json()).error.errorCode).toBe(
      "WRITE_ATTRIBUTION_INVALID",
    );
  });

  it("refuses a proof signed over a different body", async () => {
    const { runtime } = setup();
    const token = await openSession(runtime);
    const res = await sessionWrite(
      runtime,
      { note: "sent" },
      { token, signedBody: JSON.stringify({ note: "signed" }) },
    );
    expect(res.status).toBe(401);
    expect((await res.json()).error.errorCode).toBe(
      "WRITE_ATTRIBUTION_INVALID",
    );
    expect((await ownerRead(runtime)).status).toBe(404);
  });

  it("refuses a proof signed by another key", async () => {
    const { runtime } = setup();
    const token = await openSession(runtime);
    const res = await sessionWrite(
      runtime,
      { note: "x" },
      { token, signatureWallet: otherWallet },
    );
    expect(res.status).toBe(401);
    expect((await res.json()).error.errorCode).toBe(
      "WRITE_ATTRIBUTION_SIGNER_MISMATCH",
    );
  });

  it("refuses a proof claiming another grant", async () => {
    const { runtime } = setup();
    const token = await openSession(runtime);
    const res = await sessionWrite(
      runtime,
      { note: "x" },
      { token, signedGrantId: "grant-somebody-elses" },
    );
    expect(res.status).toBe(401);
    expect((await res.json()).error.errorCode).toBe(
      "WRITE_ATTRIBUTION_GRANT_MISMATCH",
    );
  });

  it("refuses a session write with no proof at all", async () => {
    const { runtime } = setup();
    const token = await openSession(runtime);
    const res = await sessionWrite(
      runtime,
      { note: "x" },
      { token, omitSignature: true },
    );
    expect(res.status).toBe(401);
    expect((await res.json()).error.errorCode).toBe(
      "WRITE_ATTRIBUTION_REQUIRED",
    );
  });

  it("refuses a non-compact JSON body whose attribution could not be re-checked", async () => {
    const { runtime } = setup();
    const token = await openSession(runtime);
    const res = await sessionWrite(runtime, null, {
      token,
      rawBody: JSON.stringify({ note: "pretty" }, null, 2),
    });
    expect(res.status).toBe(400);
    expect((await res.json()).error.errorCode).toBe("WRITE_BODY_NOT_CANONICAL");
    expect((await ownerRead(runtime)).status).toBe(404);
  });

  it("refuses a payload carrying the reserved $writtenBy key", async () => {
    const { runtime } = setup();
    const token = await openSession(runtime);
    const res = await sessionWrite(
      runtime,
      { note: "x", [WRITER_ATTRIBUTION_KEY]: { builder: "0xforged" } },
      { token },
    );
    expect(res.status).toBe(400);
  });

  it("an expired session token is not a session: it falls through to the owner gate", async () => {
    const { runtime, sessionStore } = setup();
    const expired = "vana_write_expired";
    await sessionStore.create({
      tokenHash: await hashWriteSessionToken(expired),
      builderAddress: builderWallet.address,
      grantId: WRITE_GRANT_ID,
      writeScopes: [SCOPE],
      createdAt: new Date().toISOString(),
      expiresAtMs: Date.now() - 1,
    });
    const res = await sessionWrite(runtime, { note: "x" }, { token: expired });
    expect(res.status).toBe(401);
  });

  it("an unknown bearer falls through to the owner gate", async () => {
    const { runtime } = setup();
    const res = await sessionWrite(
      runtime,
      { note: "x" },
      { token: "not-a-session-token" },
    );
    expect(res.status).toBe(401);
  });

  it("owner writes still work and are never stamped with attribution", async () => {
    const { runtime } = setup();
    expect((await ownerWrite(runtime, { note: "owner write" })).status).toBe(
      201,
    );
    const envelope = await (await ownerRead(runtime)).json();
    expect(envelope.data.note).toBe("owner write");
    expect(envelope.data[WRITER_ATTRIBUTION_KEY]).toBeUndefined();
  });

  it("owner writes still work when write sessions are not wired at all", async () => {
    const { runtime } = setup({ writeSessions: false });
    expect((await ownerWrite(runtime, { note: "owner only" })).status).toBe(
      201,
    );
    const envelope = await (await ownerRead(runtime)).json();
    expect(envelope.data.note).toBe("owner only");
  });

  it("a write-grant never satisfies a builder READ of the same scope", async () => {
    const { runtime } = setup();
    const token = await openSession(runtime);
    expect(
      (await sessionWrite(runtime, { note: "secret" }, { token })).status,
    ).toBe(201);
    const authorization = await buildWeb3SignedHeader({
      wallet: builderWallet,
      aud: PS_ORIGIN,
      method: "GET",
      uri: `/v1/data/${SCOPE}`,
      grantId: WRITE_GRANT_ID,
    });
    const res = await runtime.fetch(
      new Request(`${PS_ORIGIN}/v1/data/${SCOPE}`, {
        headers: { Authorization: authorization },
      }),
    );
    expect(res.status).toBe(403);
    expect((await res.json()).error.errorCode).toBe("SCOPE_MISMATCH");
  });
});

describe("PS-Lite write sessions on the bearer-token auth adapter", () => {
  /**
   * The dev/bridge adapter authenticates the owner with a static token, but
   * its delegated-write half is the same shared authorizer: a static builder
   * token still cannot write, and a real session still needs a real proof.
   */
  function bearerSetup() {
    const gateway = createWriteGateway(makeGrant());
    const sessionStore = createInMemoryWriteSessionStore();
    const replayStore = createInMemoryWriteProofReplayStore();
    const accessLog = createMemoryPsLiteAccessLogStore();
    const runtime = createPsLiteRuntime({
      storage: createMemoryPsLiteStorage(),
      gateway,
      serverOwner: ownerWallet.address,
      serverOrigin: PS_ORIGIN,
      accessLogReader: accessLog,
      accessLogWriter: accessLog,
      tokenStore: createMemoryPsLiteTokenStore(),
      saveConfig: async () => {},
      stateCapabilities: { config: "memory" },
      auth: createBearerTokenPsLiteAuth({
        ownerToken: "owner-token",
        builderToken: "builder-token",
        writeSessions: {
          store: sessionStore,
          replayStore,
          policyPorts: {
            authSessionVerifier: gateway,
            grantVerifier: gateway,
          },
          serverOrigin: PS_ORIGIN,
          serverOwner: ownerWallet.address,
        },
      }),
      writeSessionStore: sessionStore,
      writeProofReplayStore: replayStore,
      active: true,
    });
    return { runtime };
  }

  it("mints and redeems a session, and the static builder token still cannot write", async () => {
    const { runtime } = bearerSetup();
    const token = await openSession(runtime);
    expect(
      (await sessionWrite(runtime, { note: "ok" }, { token })).status,
    ).toBe(201);

    const forged = await runtime.fetch(
      new Request(`${PS_ORIGIN}/v1/data/${SCOPE}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer builder-token",
        },
        body: JSON.stringify({ note: "nope" }),
      }),
    );
    expect(forged.status).toBe(401);
  });
});
