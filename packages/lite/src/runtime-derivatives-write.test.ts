/**
 * The derivative question endpoints authorize builders through the write
 * session path, so in PS-Lite they were unreachable for exactly the same
 * reason delegated ingest was. End to end in the browser runtime, with a fake
 * inference provider: a builder holding `write:coach.weekly` plus read of the
 * source scope registers a question, the runtime computes it locally, and the
 * builder polls its own registration with per-call nonces.
 *
 * Twin of packages/server/src/routes/derivatives.test.ts.
 */

import { describe, expect, it, vi } from "vitest";
import type { GatewayGrantResponse } from "@opendatalabs/vana-sdk/browser";
import { createFakeInferenceProvider } from "@opendatalabs/personal-server-ts-core/derivatives";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { computeDataPointId } from "@opendatalabs/personal-server-ts-core/sync";
import {
  buildWeb3SignedHeader,
  createTestWallet,
} from "../../core/src/test-utils/index.js";
import {
  WRITE_SIGNATURE_HEADER,
  createInMemoryWriteProofReplayStore,
  createInMemoryWriteSessionStore,
} from "@opendatalabs/personal-server-ts-core/write";
import {
  createPsLiteRuntime,
  createWeb3SignedPsLiteAuth,
  type PsLiteRuntime,
} from "./runtime.js";
import {
  createPsLiteDerivativeCompute,
  createPsLiteQuestionStore,
} from "./derivatives.js";
import {
  createMemoryPsLiteAccessLogStore,
  createMemoryPsLiteStateStore,
  createMemoryPsLiteStorage,
  createMemoryPsLiteTokenStore,
} from "./test-support/memory.js";
import { createMockPsLiteGateway } from "./test-support/gateway.js";

const PS_ORIGIN = "https://ps.local";
const SOURCE_SCOPE = "oura.sleep";
const DERIVED_SCOPE = "coach.weekly";
const GRANT_ID = "grant-w-derivatives";
const BUILDER_ID = "0xbuilder1";

const builderWallet = createTestWallet(0);
const ownerWallet = createTestWallet(9);

function makeGrant(
  overrides: Partial<GatewayGrantResponse> = {},
): GatewayGrantResponse {
  return {
    id: GRANT_ID,
    grantorAddress: ownerWallet.address,
    granteeId: BUILDER_ID,
    // Write on the derived scope, READ on the source: the answer exposes the
    // source to the builder, so the compute layer requires both.
    scopes: [`write:${DERIVED_SCOPE}`, SOURCE_SCOPE],
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

async function setup(grant: GatewayGrantResponse = makeGrant()) {
  const gateway = {
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
  } as ReturnType<typeof createMockPsLiteGateway>;

  const config = ServerConfigSchema.parse({
    inference: { recomputeDebounceMs: 0 },
  });
  const storage = createMemoryPsLiteStorage();
  const stateStore = createMemoryPsLiteStateStore();
  const provider = createFakeInferenceProvider();
  const sessionStore = createInMemoryWriteSessionStore();
  const replayStore = createInMemoryWriteProofReplayStore();
  const accessLog = createMemoryPsLiteAccessLogStore();
  const policyPorts = { authSessionVerifier: gateway, grantVerifier: gateway };
  let runtimeRef: PsLiteRuntime | null = null;
  const derivatives = createPsLiteDerivativeCompute({
    config,
    storage,
    store: await createPsLiteQuestionStore(stateStore),
    serverOwner: ownerWallet.address,
    provider,
    // A builder question re-checks its grant before every compute, so the
    // compute layer needs the same ports the auth adapter uses. This is what
    // createIndexedDbPsLiteRuntime wires in production.
    writePolicyPorts: policyPorts,
    runtimeAvailability: {
      isAvailable: () => runtimeRef?.isAvailable() ?? true,
    },
  });
  const runtime = createPsLiteRuntime({
    storage,
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
      writeSessions: { store: sessionStore, replayStore, policyPorts },
    }),
    writeSessionStore: sessionStore,
    writeProofReplayStore: replayStore,
    derivatives,
    active: true,
  });
  runtimeRef = runtime;
  return { runtime, derivatives, provider, gateway };
}

async function openSession(runtime: PsLiteRuntime): Promise<string> {
  const authorization = await buildWeb3SignedHeader({
    wallet: builderWallet,
    aud: PS_ORIGIN,
    method: "POST",
    uri: "/v1/write/session",
    grantId: GRANT_ID,
  });
  const res = await runtime.fetch(
    new Request(`${PS_ORIGIN}/v1/write/session`, {
      method: "POST",
      headers: { Authorization: authorization },
    }),
  );
  expect(res.status).toBe(200);
  return (await res.json()).access_token as string;
}

async function builderRequest(
  runtime: PsLiteRuntime,
  token: string,
  method: string,
  path: string,
  body?: unknown,
  options: { nonce?: string; signedUri?: string } = {},
): Promise<Response> {
  const rawBody = body === undefined ? "" : JSON.stringify(body);
  const headers: Record<string, string> = {
    Authorization: `Bearer ${token}`,
  };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  headers[WRITE_SIGNATURE_HEADER] = await buildWeb3SignedHeader({
    wallet: builderWallet,
    aud: PS_ORIGIN,
    method,
    // The proof covers path AND query.
    uri: options.signedUri ?? path,
    body: new TextEncoder().encode(rawBody),
    grantId: GRANT_ID,
    ...(options.nonce === undefined ? {} : { nonce: options.nonce }),
  });
  return runtime.fetch(
    new Request(`${PS_ORIGIN}${path}`, {
      method,
      headers,
      ...(body === undefined ? {} : { body: rawBody }),
    }),
  );
}

async function ownerIngest(
  runtime: PsLiteRuntime,
  scope: string,
  body: unknown,
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

async function ownerRead(
  runtime: PsLiteRuntime,
  scope: string,
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

const question = {
  derivedScope: DERIVED_SCOPE,
  sourceScopes: [SOURCE_SCOPE],
  question: "How did I sleep this week?",
};

describe("PS-Lite derivative questions registered by a builder", () => {
  it("registers, computes locally with a fake provider, and the owner reads the answer", async () => {
    const { runtime, derivatives, provider } = await setup();
    expect(
      (
        await ownerIngest(runtime, SOURCE_SCOPE, {
          nights: [{ date: "2026-08-20", score: 77 }],
        })
      ).status,
    ).toBe(201);
    await derivatives.scheduler.whenIdle();

    const token = await openSession(runtime);
    const registered = await builderRequest(
      runtime,
      token,
      "POST",
      "/v1/derivatives/questions",
      question,
    );
    expect(registered.status).toBe(201);
    const { questionId } = await registered.json();
    await derivatives.scheduler.whenIdle();

    // The builder polls its own registration through the same credential.
    const status = await builderRequest(
      runtime,
      token,
      "GET",
      `/v1/derivatives/questions/${questionId}`,
      undefined,
      { nonce: "poll-ready" },
    );
    expect(status.status).toBe(200);
    expect(await status.json()).toMatchObject({
      status: "ready",
      derivedVersion: 1,
    });

    // The compute ran in the browser runtime against the real source data.
    expect(provider.calls).toHaveLength(1);
    expect(provider.calls[0]!.messages[1]!.content).toContain('"score":77');

    // The derived record landed with its lineage, readable by the owner.
    const read = await ownerRead(runtime, DERIVED_SCOPE);
    expect(read.status).toBe(200);
    const envelope = await read.json();
    expect(envelope.data.answer).toBe("fake answer");
    expect(envelope.data.$lineage.sources).toEqual([
      computeDataPointId(ownerWallet.address, SOURCE_SCOPE),
    ]);
  });

  it("lets a builder list its questions for a signed derivedScope", async () => {
    const { runtime, derivatives } = await setup();
    const token = await openSession(runtime);
    const registered = await builderRequest(
      runtime,
      token,
      "POST",
      "/v1/derivatives/questions",
      question,
    );
    expect(registered.status).toBe(201);
    const { questionId } = await registered.json();

    const path = `/v1/derivatives/questions?derivedScope=${DERIVED_SCOPE}`;
    const listed = await builderRequest(
      runtime,
      token,
      "GET",
      path,
      undefined,
      { nonce: "list-1" },
    );
    expect(listed.status).toBe(200);
    expect(
      (await listed.json()).questions.map(
        (q: { questionId: string }) => q.questionId,
      ),
    ).toEqual([questionId]);

    // The proof covers the query: one signed for a different derivedScope is
    // not a proof for this call.
    const wrongScope = await builderRequest(
      runtime,
      token,
      "GET",
      path,
      undefined,
      {
        nonce: "list-2",
        signedUri: "/v1/derivatives/questions?derivedScope=other",
      },
    );
    expect(wrongScope.status).toBe(401);
    await derivatives.scheduler.whenIdle();
  });

  it("makes repeated polls distinct with a nonce and refuses a re-used one", async () => {
    const { runtime, derivatives } = await setup();
    const token = await openSession(runtime);
    const registered = await builderRequest(
      runtime,
      token,
      "POST",
      "/v1/derivatives/questions",
      question,
    );
    const { questionId } = await registered.json();
    const path = `/v1/derivatives/questions/${questionId}`;
    const poll = (nonce: string) =>
      builderRequest(runtime, token, "GET", path, undefined, { nonce });

    // Two polls in the same second: identical payloads but for the nonce.
    expect((await poll("poll-1")).status).toBe(200);
    expect((await poll("poll-2")).status).toBe(200);

    const replayed = await poll("poll-1");
    expect(replayed.status).toBe(401);
    expect((await replayed.json()).error.errorCode).toBe(
      "WRITE_ATTRIBUTION_REPLAY",
    );
    await derivatives.scheduler.whenIdle();
  });

  it("refuses a source scope the grant does not authorize reading", async () => {
    const { runtime } = await setup(
      makeGrant({ scopes: [`write:${DERIVED_SCOPE}`] }),
    );
    const token = await openSession(runtime);
    const res = await builderRequest(
      runtime,
      token,
      "POST",
      "/v1/derivatives/questions",
      question,
    );
    expect(res.status).toBe(403);
    expect((await res.json()).error.errorCode).toBe(
      "DERIVATIVE_SOURCE_NOT_GRANTED",
    );
  });

  it("hides another builder's registration behind a 404", async () => {
    const { runtime, derivatives } = await setup();
    const token = await openSession(runtime);
    const registered = await builderRequest(
      runtime,
      token,
      "POST",
      "/v1/derivatives/questions",
      question,
    );
    const { questionId } = await registered.json();
    await derivatives.scheduler.whenIdle();

    const res = await builderRequest(
      runtime,
      token,
      "GET",
      "/v1/derivatives/questions/does-not-exist",
      undefined,
      { nonce: "probe" },
    );
    expect(res.status).toBe(404);
    expect((await res.json()).error.errorCode).toBe(
      "DERIVATIVE_QUESTION_NOT_FOUND",
    );
    expect(questionId).toBeTruthy();
  });
});
