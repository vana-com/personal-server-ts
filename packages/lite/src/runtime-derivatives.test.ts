import { describe, expect, it, vi } from "vitest";
import {
  createFakeInferenceProvider,
  type QuestionRegistration,
} from "@opendatalabs/personal-server-ts-core/derivatives";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { computeDataPointId } from "@opendatalabs/personal-server-ts-core/sync";
import { createBearerTokenPsLiteAuth, createPsLiteRuntime } from "./runtime.js";
import {
  createPsLiteDerivativeCompute,
  createPsLiteQuestionStore,
  psLiteInferenceConfigured,
} from "./derivatives.js";
import {
  createMemoryPsLiteAccessLogStore,
  createMemoryPsLiteStateStore,
  createMemoryPsLiteStorage,
  createMemoryPsLiteTokenStore,
} from "./test-support/memory.js";
import { createMockPsLiteGateway } from "./test-support/gateway.js";

const OWNER = "0x1111111111111111111111111111111111111111" as const;
const ownerHeaders = { Authorization: "Bearer owner-token" };

async function setup(
  options: { active?: boolean; seedQuestions?: QuestionRegistration[] } = {},
) {
  const config = ServerConfigSchema.parse({
    inference: { recomputeDebounceMs: 0 },
  });
  const storage = createMemoryPsLiteStorage();
  const stateStore = createMemoryPsLiteStateStore();
  if (options.seedQuestions) {
    // What a previous session persisted, present before the store loads.
    await stateStore.set("derivative-questions-v1", {
      version: 1,
      questions: options.seedQuestions,
    });
  }
  const provider = createFakeInferenceProvider();
  const store = await createPsLiteQuestionStore(stateStore);
  let runtimeRef: ReturnType<typeof createPsLiteRuntime> | null = null;
  const derivatives = createPsLiteDerivativeCompute({
    config,
    storage,
    store,
    serverOwner: OWNER,
    provider,
    runtimeAvailability: {
      isAvailable: () => runtimeRef?.isAvailable() ?? true,
    },
  });
  const accessLogStore = createMemoryPsLiteAccessLogStore();
  const runtime = createPsLiteRuntime({
    storage,
    gateway: createMockPsLiteGateway(),
    accessLogReader: accessLogStore,
    accessLogWriter: accessLogStore,
    tokenStore: createMemoryPsLiteTokenStore(),
    saveConfig: async () => {},
    stateCapabilities: { config: "memory" },
    auth: createBearerTokenPsLiteAuth({
      ownerToken: "owner-token",
      builderToken: "builder-token",
    }),
    serverOwner: OWNER,
    derivatives,
    active: options.active ?? true,
  });
  runtimeRef = runtime;
  return { runtime, derivatives, provider, stateStore, storage };
}

async function ingest(
  runtime: Awaited<ReturnType<typeof setup>>["runtime"],
  scope: string,
  body: unknown,
) {
  return runtime.fetch(
    new Request(`https://ps.local/v1/data/${scope}`, {
      method: "POST",
      headers: { ...ownerHeaders, "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  );
}

describe("PS-Lite derivative compute", () => {
  it("owner registers a question, the runtime computes it locally and persists the registration", async () => {
    const { runtime, derivatives, provider, stateStore } = await setup();
    expect(
      (await ingest(runtime, "oura.sleep", { nights: [{ score: 77 }] })).status,
    ).toBe(201);
    await derivatives.scheduler.whenIdle();

    const registered = await runtime.fetch(
      new Request("https://ps.local/v1/derivatives/questions", {
        method: "POST",
        headers: { ...ownerHeaders, "Content-Type": "application/json" },
        body: JSON.stringify({
          derivedScope: "coach.weekly",
          sourceScopes: ["oura.sleep"],
          question: "How did I sleep?",
        }),
      }),
    );
    expect(registered.status).toBe(201);
    const { questionId } = await registered.json();
    await derivatives.scheduler.whenIdle();

    const status = await runtime.fetch(
      new Request(`https://ps.local/v1/derivatives/questions/${questionId}`, {
        headers: ownerHeaders,
      }),
    );
    expect(await status.json()).toMatchObject({
      status: "ready",
      derivedVersion: 1,
    });
    expect(provider.calls).toHaveLength(1);
    expect(provider.calls[0]!.messages[1]!.content).toContain('"score":77');

    const read = await runtime.fetch(
      new Request("https://ps.local/v1/data/coach.weekly", {
        headers: ownerHeaders,
      }),
    );
    expect(read.status).toBe(200);
    const envelope = await read.json();
    expect(envelope.data.$lineage.sources).toEqual([
      computeDataPointId(OWNER, "oura.sleep"),
    ]);
    expect(envelope.data.answer).toBe("fake answer");

    // The registration lives in the state store (survives a reload).
    const persisted = await stateStore.get<{
      version: 1;
      questions: QuestionRegistration[];
    }>("derivative-questions-v1");
    expect(persisted?.questions.map((q) => q.questionId)).toEqual([questionId]);
    const reloaded = await createPsLiteQuestionStore(stateStore);
    expect((await reloaded.get(questionId))?.status).toBe("ready");
  });

  it("defaults recompute to on-change for registrations saved before the field existed", async () => {
    const stateStore = createMemoryPsLiteStateStore();
    const legacy = {
      questionId: "q-legacy",
      derivedScope: "coach.weekly",
      sourceScopes: ["oura.sleep"],
      question: "q",
      model: null,
      registeredBy: { kind: "owner" },
      status: "ready",
      error: null,
      createdAt: "2026-08-27T00:00:00.000Z",
      updatedAt: "2026-08-27T00:00:00.000Z",
      lastComputedAt: "2026-08-27T00:00:00.000Z",
      derivedVersion: 1,
      derivedCollectedAt: "2026-08-27T00:00:00Z",
    };
    await stateStore.set("derivative-questions-v1", {
      version: 1,
      questions: [legacy],
    });
    const store = await createPsLiteQuestionStore(stateStore);
    expect((await store.get("q-legacy"))!.recompute).toBe("on-change");
  });

  it("activate() on a fresh runtime reschedules questions a previous session left pending", async () => {
    const { runtime, derivatives } = await setup({
      active: false,
      seedQuestions: [
        {
          questionId: "q-boot",
          derivedScope: "coach.weekly",
          sourceScopes: ["oura.sleep"],
          question: "q",
          model: null,
          recompute: "on-change",
          registeredBy: { kind: "owner" },
          status: "pending",
          error: null,
          createdAt: "2026-08-27T00:00:00.000Z",
          updatedAt: "2026-08-27T00:00:00.000Z",
          lastComputedAt: null,
          derivedVersion: null,
          derivedCollectedAt: null,
        },
      ],
    });
    runtime.activate();
    await derivatives.scheduler.whenIdle();
    // The source scope holds no data, so the compute fails; what matters
    // is that activation rescheduled the question at all (before the fix
    // the first start() was a no-op and it stayed pending forever).
    expect((await derivatives.store.get("q-boot"))!.status).toBe("failed");
  });

  it("deactivate() stops the scheduler and activate() restarts it", async () => {
    const { runtime, derivatives } = await setup();
    const stop = vi.spyOn(derivatives.scheduler, "stop");
    const start = vi.spyOn(derivatives.scheduler, "start");
    runtime.deactivate();
    expect(stop).toHaveBeenCalledTimes(1);
    runtime.activate();
    expect(start).toHaveBeenCalledTimes(1);
  });

  it("skips computes while inactive and picks pending questions up on activate()", async () => {
    const { runtime, derivatives, provider } = await setup();
    await ingest(runtime, "oura.sleep", { nights: [{ score: 1 }] });
    const registered = await runtime.fetch(
      new Request("https://ps.local/v1/derivatives/questions", {
        method: "POST",
        headers: { ...ownerHeaders, "Content-Type": "application/json" },
        body: JSON.stringify({
          derivedScope: "coach.weekly",
          sourceScopes: ["oura.sleep"],
          question: "q",
        }),
      }),
    );
    const { questionId } = await registered.json();
    runtime.deactivate();
    await derivatives.scheduler.whenIdle();
    expect(provider.calls).toHaveLength(0);
    expect((await derivatives.store.get(questionId))!.status).toBe("pending");
    runtime.activate();
    await derivatives.scheduler.whenIdle();
    expect(provider.calls).toHaveLength(1);
    expect((await derivatives.store.get(questionId))!.status).toBe("ready");
  });

  it("does not consider the direct-provider default a configured relay", () => {
    expect(psLiteInferenceConfigured(ServerConfigSchema.parse({}))).toBe(false);
    expect(
      psLiteInferenceConfigured(
        ServerConfigSchema.parse({
          inference: { baseUrl: "https://inference.phala.com/v1/" },
        }),
      ),
    ).toBe(false);
    expect(
      psLiteInferenceConfigured(
        ServerConfigSchema.parse({
          inference: { baseUrl: "https://inference-relay.vana.org/v1" },
        }),
      ),
    ).toBe(true);
  });

  it("a static builder token cannot register (it is not a write session) and the route is 503 without compute", async () => {
    const { runtime } = await setup();
    const res = await runtime.fetch(
      new Request("https://ps.local/v1/derivatives/questions", {
        method: "POST",
        headers: {
          Authorization: "Bearer builder-token",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          derivedScope: "coach.weekly",
          sourceScopes: ["oura.sleep"],
          question: "q",
        }),
      }),
    );
    expect(res.status).toBe(401);

    const accessLogStore = createMemoryPsLiteAccessLogStore();
    const bare = createPsLiteRuntime({
      storage: createMemoryPsLiteStorage(),
      auth: createBearerTokenPsLiteAuth({
        ownerToken: "owner-token",
        builderToken: "builder-token",
      }),
      accessLogReader: accessLogStore,
      accessLogWriter: accessLogStore,
      tokenStore: createMemoryPsLiteTokenStore(),
      saveConfig: async () => {},
      stateCapabilities: { config: "memory" },
      active: true,
    });
    const unavailable = await bare.fetch(
      new Request("https://ps.local/v1/derivatives/questions", {
        headers: ownerHeaders,
      }),
    );
    expect(unavailable.status).toBe(503);
  });
});
