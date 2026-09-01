/**
 * End to end through the composed app: a builder registers a question with
 * its write session, the compute layer answers it with a fake provider and
 * writes the derivative with `$lineage`, the owner reads it back, and a
 * fresh source version marks the question stale and recomputes.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { pino } from "pino";
import type { Hono } from "hono";
import type {
  Builder,
  GatewayClient,
  GatewayGrantResponse,
} from "@opendatalabs/vana-sdk/node";
import {
  buildWeb3SignedHeader,
  createTestWallet,
} from "../../../core/src/test-utils/index.js";
import {
  WRITE_SIGNATURE_HEADER,
  createInMemoryWriteSessionStore,
  hashWriteSessionToken,
  type WriteSessionStore,
} from "@opendatalabs/personal-server-ts-core/write";
import {
  computeQuestion,
  createFakeInferenceProvider,
  createRecomputeScheduler,
  type FakeInferenceProvider,
  type RecomputeScheduler,
} from "@opendatalabs/personal-server-ts-core/derivatives";
import { computeDataPointId } from "@opendatalabs/personal-server-ts-core/sync";
import { initializeDatabase } from "../storage/index-schema.js";
import { createIndexManager } from "../storage/index-manager.js";
import { createNodeDataStorage } from "../storage/node-data-storage.js";
import { createSqliteQuestionStore } from "../storage/question-store.js";
import { createApp, type AppDeps } from "../app.js";

const SERVER_ORIGIN = "http://localhost:8080";
const DEV_TOKEN = "dev-token";
const SESSION_TOKEN = "vana_write_test_token";
const WRITE_GRANT_ID = "grant-w-1";
const BUILDER_ID = "0xbuilder1";
const builderWallet = createTestWallet(0);
const ownerWallet = createTestWallet(9);
const logger = pino({ level: "silent" });

function createMockGateway(
  scopes: string[] = ["write:coach.*", "oura.sleep"],
): GatewayClient {
  const grant: GatewayGrantResponse = {
    id: WRITE_GRANT_ID,
    grantorAddress: ownerWallet.address,
    granteeId: BUILDER_ID,
    scopes,
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
  };
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
    getGrant: vi.fn().mockResolvedValue(grant),
  } as unknown as GatewayClient;
}

describe("/v1/derivatives/questions (composed app)", () => {
  let dataDir: string;
  let app: Hono;
  let cleanup: () => void;
  let provider: FakeInferenceProvider;
  let scheduler: RecomputeScheduler;
  let writeSessionStore: WriteSessionStore;
  let baseDeps: AppDeps;

  beforeEach(async () => {
    dataDir = await mkdtemp(join(tmpdir(), "derivatives-route-test-"));
    const db = initializeDatabase(":memory:");
    const indexManager = createIndexManager(db);
    const hierarchyOptions = { dataDir };
    const dataStorage = createNodeDataStorage({
      indexManager,
      hierarchyOptions,
    });
    const store = createSqliteQuestionStore(db);
    provider = createFakeInferenceProvider();
    const gateway = createMockGateway();
    scheduler = createRecomputeScheduler({
      store,
      debounceMs: 0,
      compute: (questionId) =>
        computeQuestion(questionId, {
          storage: dataStorage,
          store,
          provider,
          serverOwner: ownerWallet.address,
          writePolicyPorts: {
            authSessionVerifier: gateway,
            grantVerifier: gateway,
          },
        }),
    });
    writeSessionStore = createInMemoryWriteSessionStore();
    await writeSessionStore.create({
      tokenHash: await hashWriteSessionToken(SESSION_TOKEN),
      builderAddress: builderWallet.address,
      grantId: WRITE_GRANT_ID,
      writeScopes: ["coach.*"],
      createdAt: new Date().toISOString(),
      expiresAtMs: Date.now() + 60_000,
    });
    baseDeps = {
      logger,
      version: "test",
      startedAt: new Date(),
      indexManager,
      hierarchyOptions,
      serverOrigin: SERVER_ORIGIN,
      serverOwner: ownerWallet.address,
      gateway,
      accessLogWriter: { write: vi.fn().mockResolvedValue(undefined) },
      accessLogReader: { read: vi.fn() } as never,
      dataStorage,
      devToken: DEV_TOKEN,
      writeSessionStore,
      derivativeCompute: { store, scheduler },
    };
    app = createApp(baseDeps);
    cleanup = () => {
      scheduler.stop();
      indexManager.close();
    };
  });

  afterEach(async () => {
    cleanup();
    vi.useRealTimers();
    await rm(dataDir, { recursive: true, force: true });
  });

  /** Ingest stamps versions at second precision; move the clock past it. */
  function nextSecond() {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date(Date.now() + 1_000));
  }

  const owner = { Authorization: `Bearer ${DEV_TOKEN}` };

  async function ownerIngest(scope: string, body: unknown) {
    return app.request(`/v1/data/${scope}`, {
      method: "POST",
      headers: { ...owner, "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  }

  async function builderRequest(
    method: string,
    path: string,
    body?: unknown,
    options: { signedUri?: string; nonce?: string } = {},
  ): Promise<Response> {
    const rawBody = body === undefined ? "" : JSON.stringify(body);
    const headers: Record<string, string> = {
      Authorization: `Bearer ${SESSION_TOKEN}`,
    };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    headers[WRITE_SIGNATURE_HEADER] = await buildWeb3SignedHeader({
      wallet: builderWallet,
      aud: SERVER_ORIGIN,
      method,
      // The proof covers path AND query; a caller may sign a different uri
      // to exercise the binding.
      uri: options.signedUri ?? path,
      body: new TextEncoder().encode(rawBody),
      grantId: WRITE_GRANT_ID,
      ...(options.nonce === undefined ? {} : { nonce: options.nonce }),
    });
    return app.request(path, {
      method,
      headers,
      body: body === undefined ? undefined : rawBody,
    });
  }

  const question = {
    derivedScope: "coach.weekly",
    sourceScopes: ["oura.sleep"],
    question: "How did I sleep this week?",
  };

  it("builder registers, PS computes with lineage, owner reads, refresh recomputes", async () => {
    expect(
      (
        await ownerIngest("oura.sleep", {
          nights: [{ date: "2026-08-20", score: 70 }],
        })
      ).status,
    ).toBe(201);
    await scheduler.whenIdle();

    const registered = await builderRequest(
      "POST",
      "/v1/derivatives/questions",
      question,
    );
    expect(registered.status).toBe(201);
    const created = await registered.json();
    expect(created).toMatchObject({
      derivedScope: "coach.weekly",
      status: "pending",
      registeredBy: {
        kind: "builder",
        builder: builderWallet.address,
        grantId: WRITE_GRANT_ID,
      },
    });
    const id: string = created.questionId;

    await scheduler.whenIdle();
    const status = await app.request(`/v1/derivatives/questions/${id}`, {
      headers: owner,
    });
    expect(status.status).toBe(200);
    expect(await status.json()).toMatchObject({
      status: "ready",
      derivedVersion: 1,
      lastComputedAt: expect.any(String),
      error: null,
    });

    // The derivative is an ordinary owner record with the source lineage.
    const read = await app.request("/v1/data/coach.weekly", { headers: owner });
    expect(read.status).toBe(200);
    const envelope = await read.json();
    expect(envelope.data.$lineage.sources).toEqual([
      computeDataPointId(ownerWallet.address, "oura.sleep"),
    ]);
    expect(envelope.data).toMatchObject({
      questionId: id,
      answer: "fake answer",
      evidence: "fake evidence",
      sources: [{ scope: "oura.sleep", version: 1 }],
    });
    expect(envelope.data.$writtenBy).toBeUndefined();
    expect(provider.calls).toHaveLength(1);
    expect(provider.calls[0]!.messages[1]!.content).toContain('"score":70');

    // A new source version marks the question stale and recomputes.
    nextSecond();
    expect(
      (
        await ownerIngest("oura.sleep", {
          nights: [{ date: "2026-08-21", score: 90 }],
        })
      ).status,
    ).toBe(201);
    await scheduler.whenIdle();
    const after = await app.request(`/v1/derivatives/questions/${id}`, {
      headers: owner,
    });
    expect(await after.json()).toMatchObject({
      status: "ready",
      derivedVersion: 2,
    });
    expect(provider.calls).toHaveLength(2);
    expect(provider.calls[1]!.messages[1]!.content).toContain('"score":90');

    // A write into an unrelated scope leaves it alone.
    nextSecond();
    await ownerIngest("notes.entries", { note: "x" });
    await scheduler.whenIdle();
    expect(provider.calls).toHaveLength(2);

    // The builder polls readiness with a fresh signed proof.
    const poll = await builderRequest("GET", `/v1/derivatives/questions/${id}`);
    expect(poll.status).toBe(200);
    expect((await poll.json()).status).toBe("ready");

    // The builder can delete its own registration.
    const removed = await builderRequest(
      "DELETE",
      `/v1/derivatives/questions/${id}`,
    );
    expect(removed.status).toBe(200);
    expect(
      (await app.request(`/v1/derivatives/questions/${id}`, { headers: owner }))
        .status,
    ).toBe(404);
  });

  it("marks the question failed (not the data) when the provider fails, and the owner can recompute", async () => {
    await ownerIngest("oura.sleep", { nights: [{ secret: "s" }] });
    let fail = true;
    provider = createFakeInferenceProvider({
      respond: () => {
        if (fail) throw new Error("boom with secret");
        return { content: '{"answer":"ok","evidence":"e"}' };
      },
    });
    // Rebuild the app on the failing provider.
    scheduler.stop();
    const store = baseDeps.derivativeCompute!.store;
    scheduler = createRecomputeScheduler({
      store,
      debounceMs: 0,
      compute: (questionId) =>
        computeQuestion(questionId, {
          storage: baseDeps.dataStorage!,
          store,
          provider,
          serverOwner: ownerWallet.address,
        }),
    });
    app = createApp({ ...baseDeps, derivativeCompute: { store, scheduler } });

    const registered = await app.request("/v1/derivatives/questions", {
      method: "POST",
      headers: { ...owner, "Content-Type": "application/json" },
      body: JSON.stringify(question),
    });
    expect(registered.status).toBe(201);
    const id = (await registered.json()).questionId as string;
    await scheduler.whenIdle();
    const failed = await (
      await app.request(`/v1/derivatives/questions/${id}`, { headers: owner })
    ).json();
    expect(failed.status).toBe("failed");
    expect(failed.error).toBe("compute failed (Error)");
    expect(
      (await app.request("/v1/data/coach.weekly", { headers: owner })).status,
    ).toBe(404);

    fail = false;
    const recompute = await app.request(
      `/v1/derivatives/questions/${id}/recompute`,
      { method: "POST", headers: owner },
    );
    expect(recompute.status).toBe(202);
    await scheduler.whenIdle();
    const ready = await (
      await app.request(`/v1/derivatives/questions/${id}`, { headers: owner })
    ).json();
    expect(ready).toMatchObject({
      status: "ready",
      error: null,
      derivedVersion: 1,
    });
  });

  it("refuses a builder registration outside its write grant and replayed proofs", async () => {
    const outside = await builderRequest("POST", "/v1/derivatives/questions", {
      ...question,
      derivedScope: "spine.summary",
    });
    expect(outside.status).toBe(403);
    expect((await outside.json()).error.errorCode).toBe("SCOPE_MISMATCH");

    // Sources must be read-granted: the write grant alone confers nothing
    // on bank.transactions, so the question is refused and never scheduled.
    const ungranted = await builderRequest(
      "POST",
      "/v1/derivatives/questions",
      { ...question, sourceScopes: ["oura.sleep", "bank.transactions"] },
    );
    expect(ungranted.status).toBe(403);
    const ungrantedBody = await ungranted.json();
    expect(ungrantedBody.error.errorCode).toBe("DERIVATIVE_SOURCE_NOT_GRANTED");
    expect(ungrantedBody.error.details).toEqual({
      scopes: ["bank.transactions"],
    });
    await scheduler.whenIdle();
    expect(provider.calls).toHaveLength(0);

    const list = await app.request("/v1/derivatives/questions", {
      headers: owner,
    });
    expect((await list.json()).questions).toEqual([]);

    // Same signed proof twice: the second is a replay.
    const rawBody = JSON.stringify(question);
    const proof = await buildWeb3SignedHeader({
      wallet: builderWallet,
      aud: SERVER_ORIGIN,
      method: "POST",
      uri: "/v1/derivatives/questions",
      body: new TextEncoder().encode(rawBody),
      grantId: WRITE_GRANT_ID,
    });
    const send = () =>
      app.request("/v1/derivatives/questions", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${SESSION_TOKEN}`,
          "Content-Type": "application/json",
          [WRITE_SIGNATURE_HEADER]: proof,
        },
        body: rawBody,
      });
    expect((await send()).status).toBe(201);
    const replay = await send();
    expect(replay.status).toBe(401);
    expect((await replay.json()).error.errorCode).toBe(
      "WRITE_ATTRIBUTION_REPLAY",
    );
    await scheduler.whenIdle();
  });

  it("a write-only grant cannot register a question over any source", async () => {
    app = createApp({
      ...baseDeps,
      gateway: createMockGateway(["write:coach.*"]),
    });
    const res = await builderRequest(
      "POST",
      "/v1/derivatives/questions",
      question,
    );
    expect(res.status).toBe(403);
    expect((await res.json()).error.errorCode).toBe(
      "DERIVATIVE_SOURCE_NOT_GRANTED",
    );
    const list = await app.request("/v1/derivatives/questions", {
      headers: owner,
    });
    expect((await list.json()).questions).toEqual([]);
  });

  it("binds the question list to the derived scope the proof signed", async () => {
    const registered = await builderRequest(
      "POST",
      "/v1/derivatives/questions",
      question,
    );
    expect(registered.status).toBe(201);

    const listPath = "/v1/derivatives/questions?derivedScope=coach.weekly";
    const mine = await builderRequest("GET", listPath);
    expect(mine.status).toBe(200);
    expect((await mine.json()).questions).toHaveLength(1);

    // The scope decides the authorization, so a proof that only signed the
    // path does not authorize any scope.
    const barePath = await builderRequest("GET", listPath, undefined, {
      signedUri: "/v1/derivatives/questions",
    });
    expect(barePath.status).toBe(401);
    expect((await barePath.json()).error.errorCode).toBe(
      "WRITE_ATTRIBUTION_INVALID",
    );

    // And a proof signed for one scope does not carry over to another.
    const otherScope = await builderRequest(
      "GET",
      "/v1/derivatives/questions?derivedScope=coach.daily",
      undefined,
      { signedUri: listPath },
    );
    expect(otherScope.status).toBe(401);
  });

  it("tells a builder the derived scope is required instead of 401", async () => {
    const res = await builderRequest("GET", "/v1/derivatives/questions");
    expect(res.status).toBe(400);
    expect((await res.json()).error.errorCode).toBe(
      "DERIVATIVE_DERIVED_SCOPE_REQUIRED",
    );
  });

  it("answers 404, not 401, for an unknown question id", async () => {
    const res = await builderRequest(
      "GET",
      "/v1/derivatives/questions/does-not-exist",
    );
    expect(res.status).toBe(404);
    expect((await res.json()).error.errorCode).toBe(
      "DERIVATIVE_QUESTION_NOT_FOUND",
    );
  });

  it("lets a builder poll with a nonce and refuses a re-used one", async () => {
    const registered = await builderRequest(
      "POST",
      "/v1/derivatives/questions",
      question,
    );
    const id = (await registered.json()).questionId as string;
    const path = `/v1/derivatives/questions/${id}`;
    const poll = (nonce: string) =>
      builderRequest("GET", path, undefined, { nonce });

    // Two polls in the same second: identical payloads but for the nonce.
    expect((await poll("poll-1")).status).toBe(200);
    expect((await poll("poll-2")).status).toBe(200);

    const replayed = await poll("poll-1");
    expect(replayed.status).toBe(401);
    expect((await replayed.json()).error.errorCode).toBe(
      "WRITE_ATTRIBUTION_REPLAY",
    );
    await scheduler.whenIdle();
  });

  it("answers 503 when no compute layer is wired and 401 without credentials", async () => {
    const bare = createApp({ ...baseDeps, derivativeCompute: null });
    const res = await bare.request("/v1/derivatives/questions", {
      headers: owner,
    });
    expect(res.status).toBe(503);
    const anon = await app.request("/v1/derivatives/questions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(question),
    });
    expect(anon.status).toBe(401);
  });
});
