import { describe, expect, it, vi } from "vitest";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";
import { computeDataPointId } from "../sync/data-point-id.js";
import { readStoredLineage } from "../lineage/lineage.js";
import { ingestDataContract } from "../contracts/data.js";
import { computeQuestion, type QuestionComputeDeps } from "./compute.js";
import {
  createFakeInferenceProvider,
  createOpenAiCompatibleInferenceProvider,
  InferenceRequestError,
} from "./inference.js";
import { createPhalaE2eeEncryption } from "./e2ee/phala.js";
import { createFakeE2eeGateway } from "../test-utils/e2ee-gateway.js";
import { createRecomputeScheduler } from "./scheduler.js";
import type { DataWritePolicyPorts } from "../policy/data-write.js";
import type { ScopeDeletionTracker } from "../sync/scope-deletions.js";
import { createInMemoryQuestionStore } from "./store.js";
import type { QuestionRegistration } from "./types.js";

const OWNER = "0x1111111111111111111111111111111111111111" as const;
const BUILDER = "0x2222222222222222222222222222222222222222" as const;

function registration(
  overrides: Partial<QuestionRegistration> = {},
): QuestionRegistration {
  return {
    questionId: "q-1",
    derivedScope: "coach.weekly",
    sourceScopes: ["oura.sleep", "chatgpt.conversations"],
    question: "How did I sleep?",
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
    ...overrides,
  };
}

async function seed(
  storage: ReturnType<typeof createMemoryDataStorage>,
  scope: string,
  body: Record<string, unknown>,
  collectedAt = "2026-08-20T00:00:00Z",
) {
  const result = await ingestDataContract({
    storage,
    scopeParam: scope,
    body,
    collectedAt,
    status: "stored",
  });
  if (!result.ok) throw new Error("seed failed");
}

function deps(
  overrides: Partial<QuestionComputeDeps> = {},
): QuestionComputeDeps & {
  storage: ReturnType<typeof createMemoryDataStorage>;
} {
  const storage = createMemoryDataStorage();
  return {
    storage,
    store: createInMemoryQuestionStore({ initial: [registration()] }),
    provider: createFakeInferenceProvider(),
    serverOwner: OWNER,
    now: () => new Date("2026-08-27T12:00:00.000Z"),
    retryDelaysMs: [0, 0],
    ...overrides,
  };
}

function builderRegistration(): QuestionRegistration {
  return registration({
    registeredBy: { kind: "builder", builder: BUILDER, grantId: "g-1" },
  });
}

/** Gateway stand-in for the write policy: the grant as it is right now. */
function policyPorts(
  scopes: string[],
  options: {
    revokedAt?: string | null;
    getGrant?: () => Promise<unknown>;
  } = {},
): DataWritePolicyPorts {
  const getGrant =
    options.getGrant ??
    (async () => ({
      id: "g-1",
      grantorAddress: OWNER,
      granteeId: "b",
      scopes,
      revokedAt: options.revokedAt ?? null,
      expiresAt: null,
    }));
  return {
    authSessionVerifier: {
      getBuilder: async () => ({ id: "b", granteeAddress: BUILDER }) as never,
    },
    grantVerifier: {
      getGrant: getGrant as DataWritePolicyPorts["grantVerifier"]["getGrant"],
    },
  };
}

function fakeCalls(d: QuestionComputeDeps) {
  return (d.provider as ReturnType<typeof createFakeInferenceProvider>).calls;
}

describe("computeQuestion", () => {
  it("writes the answer into the derived scope with $lineage = the source data point ids", async () => {
    const d = deps();
    await seed(d.storage, "oura.sleep", {
      nights: [
        { date: "2026-08-18", score: 70 },
        { date: "2026-08-19", score: 80 },
      ],
    });
    await seed(d.storage, "chatgpt.conversations", { items: [{ title: "x" }] });
    const notify = vi.fn();
    d.syncManager = { notifyNewData: notify };

    const outcome = await computeQuestion("q-1", d);
    expect(outcome.status).toBe("ready");

    const entry = d.storage.findEntry({ scope: "coach.weekly" });
    expect(entry).toBeDefined();
    const envelope = await d.storage.readEnvelope(
      "coach.weekly",
      entry!.collectedAt,
    );
    const expectedIds = [
      computeDataPointId(OWNER, "oura.sleep"),
      computeDataPointId(OWNER, "chatgpt.conversations"),
    ];
    expect(readStoredLineage(envelope.data)).toEqual({
      sources: expectedIds,
      writtenAt: "2026-08-27T12:00:00.000Z",
    });
    expect(envelope.data).toMatchObject({
      questionId: "q-1",
      question: "How did I sleep?",
      answer: "fake answer",
      evidence: "fake evidence",
      model: "fake-model",
      computedAt: "2026-08-27T12:00:00.000Z",
      sources: [
        {
          scope: "oura.sleep",
          version: 1,
          collectedAt: "2026-08-20T00:00:00Z",
        },
        {
          scope: "chatgpt.conversations",
          version: 1,
          collectedAt: "2026-08-20T00:00:00Z",
        },
      ],
      lineage: expectedIds,
      inference: { receiptId: "fake-receipt" },
    });
    expect(envelope.data).not.toHaveProperty("$writtenBy");

    const stored = await d.store.get("q-1");
    expect(stored).toMatchObject({
      status: "ready",
      error: null,
      lastComputedAt: "2026-08-27T12:00:00.000Z",
      derivedVersion: 1,
      derivedCollectedAt: "2026-08-27T12:00:00Z",
    });
    expect(notify).toHaveBeenCalledTimes(1);

    // The prompt carried the trimmed source data and the question.
    const provider = d.provider as ReturnType<
      typeof createFakeInferenceProvider
    >;
    expect(provider.calls[0]!.model).toBe("fake-model");
    const user = provider.calls[0]!.messages[1]!.content;
    expect(user).toContain("How did I sleep?");
    expect(user).toContain("### Scope: oura.sleep");
    expect(user).toContain('"score":80');
  });

  it("trims each source to the newest N items", async () => {
    const d = deps({ maxSourceItems: 1 });
    await seed(d.storage, "oura.sleep", {
      nights: [
        { date: "2026-08-18", score: 70 },
        { date: "2026-08-19", score: 80 },
      ],
    });
    await seed(d.storage, "chatgpt.conversations", { items: [] });
    await computeQuestion("q-1", d);
    const user = (d.provider as ReturnType<typeof createFakeInferenceProvider>)
      .calls[0]!.messages[1]!.content;
    expect(user).toContain('"score":80');
    expect(user).not.toContain('"score":70');
  });

  it("marks the question failed with a short reason when a source has no local data", async () => {
    const d = deps();
    await seed(d.storage, "oura.sleep", { nights: [] });
    const outcome = await computeQuestion("q-1", d);
    expect(outcome).toMatchObject({
      status: "failed",
      error: "source scope chatgpt.conversations has no local data",
    });
    expect((await d.store.get("q-1"))!.status).toBe("failed");
    expect(d.storage.findEntry({ scope: "coach.weekly" })).toBeUndefined();
    expect(
      (d.provider as ReturnType<typeof createFakeInferenceProvider>).calls,
    ).toHaveLength(0);
  });

  it("stores only the provider status on an inference failure, never the prompt", async () => {
    const d = deps({
      provider: createFakeInferenceProvider({
        respond: () => {
          throw new Error('{"prompt":"secret user data"}');
        },
      }),
    });
    await seed(d.storage, "oura.sleep", { secret: "user data" });
    await seed(d.storage, "chatgpt.conversations", { items: [] });
    const outcome = await computeQuestion("q-1", d);
    expect(outcome.status).toBe("failed");
    const stored = (await d.store.get("q-1"))!;
    expect(stored.status).toBe("failed");
    expect(stored.error).toBe("compute failed (Error)");
    expect(stored.error).not.toContain("secret");
  });

  it("re-checks a builder's write grant before computing and fails closed", async () => {
    const d = deps({
      store: createInMemoryQuestionStore({ initial: [builderRegistration()] }),
      writePolicyPorts: policyPorts(
        ["write:coach.weekly", "oura.sleep", "chatgpt.conversations"],
        { revokedAt: "2026-08-26T00:00:00.000Z" },
      ),
    });
    await seed(d.storage, "oura.sleep", {});
    await seed(d.storage, "chatgpt.conversations", {});
    const outcome = await computeQuestion("q-1", d);
    expect(outcome).toMatchObject({ status: "failed" });
    expect((await d.store.get("q-1"))!.error).toMatch(/^GRANT_REVOKED/);
    expect(fakeCalls(d)).toHaveLength(0);
  });

  it("fails closed when the grant no longer reads every source (narrowed after registration)", async () => {
    const d = deps({
      store: createInMemoryQuestionStore({ initial: [builderRegistration()] }),
      // The write entry is intact; the read entry for chatgpt is gone.
      writePolicyPorts: policyPorts(["write:coach.weekly", "oura.sleep"]),
    });
    await seed(d.storage, "oura.sleep", {});
    await seed(d.storage, "chatgpt.conversations", { secret: "s" });
    const outcome = await computeQuestion("q-1", d);
    expect(outcome).toMatchObject({ status: "failed" });
    const stored = (await d.store.get("q-1"))!;
    expect(stored.error).toMatch(/^DERIVATIVE_SOURCE_NOT_GRANTED/);
    expect(stored.error).not.toContain("secret");
    expect(fakeCalls(d)).toHaveLength(0);
    expect(d.storage.findEntry({ scope: "coach.weekly" })).toBeUndefined();

    // A write: entry on the source is not a read entry either.
    const writeOnly = deps({
      store: createInMemoryQuestionStore({ initial: [builderRegistration()] }),
      writePolicyPorts: policyPorts([
        "write:coach.weekly",
        "oura.sleep",
        "write:chatgpt.*",
      ]),
    });
    await seed(writeOnly.storage, "oura.sleep", {});
    await seed(writeOnly.storage, "chatgpt.conversations", {});
    expect(await computeQuestion("q-1", writeOnly)).toMatchObject({
      status: "failed",
    });
    expect(fakeCalls(writeOnly)).toHaveLength(0);
  });

  it("fails closed for a builder question when no grant verifier is wired", async () => {
    const d = deps({
      store: createInMemoryQuestionStore({ initial: [builderRegistration()] }),
    });
    await seed(d.storage, "oura.sleep", {});
    await seed(d.storage, "chatgpt.conversations", {});
    expect(await computeQuestion("q-1", d)).toMatchObject({
      status: "failed",
      error: "builder grant verification is not configured",
    });
    expect(fakeCalls(d)).toHaveLength(0);
  });

  it("retries a transient gateway failure during the grant check, but not a policy failure", async () => {
    let calls = 0;
    const grant = {
      id: "g-1",
      grantorAddress: OWNER,
      granteeId: "b",
      scopes: ["write:coach.weekly", "oura.sleep", "chatgpt.conversations"],
      revokedAt: null,
      expiresAt: null,
    };
    const d = deps({
      store: createInMemoryQuestionStore({ initial: [builderRegistration()] }),
      writePolicyPorts: policyPorts([], {
        getGrant: async () => {
          calls += 1;
          if (calls < 3) throw new Error("ECONNRESET");
          return grant;
        },
      }),
    });
    await seed(d.storage, "oura.sleep", {});
    await seed(d.storage, "chatgpt.conversations", {});
    expect((await computeQuestion("q-1", d)).status).toBe("ready");
    expect(calls).toBe(3);

    const down = deps({
      store: createInMemoryQuestionStore({ initial: [builderRegistration()] }),
      writePolicyPorts: policyPorts([], {
        getGrant: async () => {
          throw new Error("gateway down");
        },
      }),
    });
    await seed(down.storage, "oura.sleep", {});
    await seed(down.storage, "chatgpt.conversations", {});
    expect(await computeQuestion("q-1", down)).toMatchObject({
      status: "failed",
      error: "compute failed (Error)",
    });
    expect(fakeCalls(down)).toHaveLength(0);
  });

  it("retries transient inference failures up to three attempts and gives up on permanent ones", async () => {
    let attempts = 0;
    const flaky = deps({
      provider: createFakeInferenceProvider({
        respond: () => {
          attempts += 1;
          if (attempts < 3) {
            throw new InferenceRequestError("rate limited", 429, {
              code: "httpError",
            });
          }
          return { content: '{"answer":"third time","evidence":"e"}' };
        },
      }),
    });
    await seed(flaky.storage, "oura.sleep", {});
    await seed(flaky.storage, "chatgpt.conversations", {});
    expect((await computeQuestion("q-1", flaky)).status).toBe("ready");
    expect(attempts).toBe(3);

    let permanent = 0;
    const bad = deps({
      provider: createFakeInferenceProvider({
        respond: () => {
          permanent += 1;
          throw new InferenceRequestError("bad request", 400, {
            code: "httpError",
          });
        },
      }),
    });
    await seed(bad.storage, "oura.sleep", {});
    await seed(bad.storage, "chatgpt.conversations", {});
    expect(await computeQuestion("q-1", bad)).toMatchObject({
      status: "failed",
      error: "bad request",
    });
    expect(permanent).toBe(1);

    let transport = 0;
    const dead = deps({
      provider: createFakeInferenceProvider({
        respond: () => {
          transport += 1;
          throw new InferenceRequestError("no response", null, {
            code: "transport",
          });
        },
      }),
    });
    await seed(dead.storage, "oura.sleep", {});
    await seed(dead.storage, "chatgpt.conversations", {});
    expect((await computeQuestion("q-1", dead)).status).toBe("failed");
    expect(transport).toBe(3);
  });

  it("refuses a tombstoned source exactly like a read would", async () => {
    const tracker = {
      resolve: async (scope: string) =>
        scope === "chatgpt.conversations"
          ? {
              deleted: true,
              deletedAt: "2026-08-26T00:00:00.000Z",
              version: null,
              source: "gateway",
            }
          : { deleted: false },
    } as unknown as ScopeDeletionTracker;
    const d = deps({ scopeDeletions: tracker });
    await seed(d.storage, "oura.sleep", {});
    // A stale local copy is still there; the tombstone wins.
    await seed(d.storage, "chatgpt.conversations", { secret: "s" });
    expect(await computeQuestion("q-1", d)).toMatchObject({
      status: "failed",
      error: "source scope chatgpt.conversations is deleted",
    });
    expect(fakeCalls(d)).toHaveLength(0);
  });

  it("refuses to consume its own output through stored lineage (cross-replica cycle)", async () => {
    const withLineage = async (
      storage: ReturnType<typeof createMemoryDataStorage>,
      scope: string,
      from: string,
    ) => {
      const r = await ingestDataContract({
        storage,
        scopeParam: scope,
        body: { v: 1 },
        collectedAt: "2026-08-21T00:00:00Z",
        status: "stored",
        lineage: {
          sources: [computeDataPointId(OWNER, from)],
          writtenAt: "2026-08-21T00:00:00Z",
        },
      });
      if (!r.ok) throw new Error("seed failed");
    };
    const selfSourcing = () =>
      createInMemoryQuestionStore({
        initial: [
          registration({
            derivedScope: "coach.weekly",
            sourceScopes: ["spine.summary"],
          }),
        ],
      });

    // spine.summary was derived (on another replica) from coach.weekly.
    const d = deps({ store: selfSourcing() });
    await seed(d.storage, "coach.weekly", { answer: "old" });
    await withLineage(d.storage, "spine.summary", "coach.weekly");
    expect((await computeQuestion("q-1", d)).status).toBe("failed");
    expect((await d.store.get("q-1"))!.error).toMatch(/^DERIVATIVE_CYCLE/);
    expect(fakeCalls(d)).toHaveLength(0);
    expect(d.storage.countVersions("coach.weekly")).toBe(1);

    // Transitive: spine.summary <- other.mid <- coach.weekly.
    const t = deps({ store: selfSourcing() });
    await seed(t.storage, "coach.weekly", { answer: "old" });
    await withLineage(t.storage, "other.mid", "coach.weekly");
    await withLineage(t.storage, "spine.summary", "other.mid");
    expect((await computeQuestion("q-1", t)).status).toBe("failed");
    expect((await t.store.get("q-1"))!.error).toMatch(/^DERIVATIVE_CYCLE/);
    expect(fakeCalls(t)).toHaveLength(0);

    // Unrelated lineage is fine.
    const ok = deps({ store: selfSourcing() });
    await withLineage(ok.storage, "spine.summary", "oura.sleep");
    expect((await computeQuestion("q-1", ok)).status).toBe("ready");
  });

  it("skips (status untouched) while the runtime is unavailable", async () => {
    const d = deps({ runtimeAvailability: { isAvailable: () => false } });
    await seed(d.storage, "oura.sleep", {});
    await seed(d.storage, "chatgpt.conversations", {});
    expect(await computeQuestion("q-1", d)).toEqual({
      status: "skipped",
      reason: "runtime-unavailable",
    });
    expect((await d.store.get("q-1"))!.status).toBe("pending");
    expect(fakeCalls(d)).toHaveLength(0);
  });

  it("fires onDerivedWritten so a chain A -> B -> C refreshes C when A changes", async () => {
    const storage = createMemoryDataStorage();
    const store = createInMemoryQuestionStore({
      initial: [
        registration({
          questionId: "q-b",
          derivedScope: "b.mid",
          sourceScopes: ["a.raw"],
          createdAt: "2026-08-27T00:00:00.000Z",
        }),
        registration({
          questionId: "q-c",
          derivedScope: "c.final",
          sourceScopes: ["b.mid"],
          createdAt: "2026-08-27T00:00:01.000Z",
        }),
      ],
    });
    const provider = createFakeInferenceProvider();
    let tick = 0;
    const now = () => new Date(Date.UTC(2026, 7, 27, 12, 0, tick++));
    const scheduler = createRecomputeScheduler({
      store,
      debounceMs: 0,
      serverOwner: OWNER,
      compute: (questionId) =>
        computeQuestion(questionId, {
          storage,
          store,
          provider,
          serverOwner: OWNER,
          now,
          retryDelaysMs: [0, 0],
          onDerivedWritten: (event) =>
            scheduler.markSourceChanged(event.scope, {
              lineageSources: event.lineageSources,
            }),
        }),
    });
    await seed(storage, "a.raw", { v: 1 }, "2026-08-20T00:00:00Z");
    scheduler.requestRecompute("q-b", { immediate: true });
    await scheduler.whenIdle();
    expect((await store.get("q-b"))!.status).toBe("ready");
    expect((await store.get("q-c"))!.status).toBe("ready");
    expect(provider.calls).toHaveLength(2);

    // A changes: B recomputes, then C recomputes from the new B.
    await seed(storage, "a.raw", { v: 2 }, "2026-08-21T00:00:00Z");
    scheduler.markSourceChanged("a.raw");
    await scheduler.whenIdle();
    expect(provider.calls).toHaveLength(4);
    expect(storage.countVersions("b.mid")).toBe(2);
    expect(storage.countVersions("c.final")).toBe(2);
    const c = (await store.get("q-c"))!;
    expect(c).toMatchObject({ status: "ready", derivedVersion: 2 });
    const cEnvelope = await storage.readEnvelope(
      "c.final",
      c.derivedCollectedAt!,
    );
    expect(readStoredLineage(cEnvelope.data)!.sources).toEqual([
      computeDataPointId(OWNER, "b.mid"),
    ]);
    scheduler.stop();
  });

  it("fails without an owner address (lineage ids need it)", async () => {
    const d = deps({ serverOwner: undefined });
    const outcome = await computeQuestion("q-1", d);
    expect(outcome).toMatchObject({
      status: "failed",
      error: "server owner is not configured",
    });
  });

  it("skips an unknown question", async () => {
    const d = deps();
    expect(await computeQuestion("nope", d)).toEqual({
      status: "skipped",
      reason: "unknown-question",
    });
  });
});

describe("computeQuestion with E2EE to a fake Phala gateway", () => {
  it("sends the prompt as ciphertext through the relay and stores the decrypted answer", async () => {
    const gateway = await createFakeE2eeGateway({
      respond: ({ messages }) => {
        // The enclave sees the plaintext prompt with the owner's data in it.
        expect(messages.map((m) => m.content).join("\n")).toContain(
          "REM 91 minutes",
        );
        return JSON.stringify({
          answer: "You slept well: REM was 91 minutes.",
          evidence: "oura.sleep 2026-08-19",
        });
      },
    });
    const provider = createOpenAiCompatibleInferenceProvider({
      baseUrl: "https://relay.test/v1",
      fetch: gateway.fetch,
      encryption: createPhalaE2eeEncryption({
        baseUrl: "https://relay.test/v1",
        fetch: gateway.fetch,
      }),
    });
    const d = deps({ provider });
    await seed(d.storage, "oura.sleep", {
      nights: [{ date: "2026-08-19", note: "REM 91 minutes" }],
    });
    await seed(d.storage, "chatgpt.conversations", {
      items: [{ title: "hello" }],
    });

    const outcome = await computeQuestion("q-1", d);
    expect(outcome.status).toBe("ready");

    // What the relay saw: ciphertext only, never the data or the question.
    expect(gateway.requests).toHaveLength(1);
    const wire = JSON.stringify(gateway.requests[0]!.body);
    expect(wire).not.toContain("REM 91");
    expect(wire).not.toContain("How did I sleep");
    expect(wire).not.toContain("hello");
    for (const message of gateway.requests[0]!.body.messages as Array<{
      content: string;
    }>) {
      expect(message.content).toMatch(/^[0-9a-f]+$/);
    }
    expect(gateway.requests[0]!.headers["x-e2ee-version"]).toBe("2");

    // What was stored: the decrypted answer, with the receipt id.
    const entry = d.storage.findEntry({ scope: "coach.weekly" });
    const envelope = await d.storage.readEnvelope(
      "coach.weekly",
      entry!.collectedAt,
    );
    expect(envelope.data).toMatchObject({
      answer: "You slept well: REM was 91 minutes.",
      evidence: "oura.sleep 2026-08-19",
      inference: { receiptId: "rcpt-1" },
    });
  });

  it("fails the question (no retry storm) when the gateway key cannot be verified", async () => {
    const gateway = await createFakeE2eeGateway({ supportedE2eeVersions: [] });
    const provider = createOpenAiCompatibleInferenceProvider({
      baseUrl: "https://relay.test/v1",
      fetch: gateway.fetch,
      encryption: createPhalaE2eeEncryption({
        baseUrl: "https://relay.test/v1",
        fetch: gateway.fetch,
      }),
    });
    const d = deps({ provider });
    await seed(d.storage, "oura.sleep", { nights: [] });
    await seed(d.storage, "chatgpt.conversations", { items: [] });
    const outcome = await computeQuestion("q-1", d);
    expect(outcome.status).toBe("failed");
    expect(outcome.status === "failed" && outcome.error).toContain(
      "e2ee key fetch failed (e2ee_unsupported)",
    );
    expect(gateway.requests).toHaveLength(0);
    expect(gateway.attestationRequests).toHaveLength(1);
  });
});
