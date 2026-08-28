import { describe, expect, it, vi } from "vitest";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";
import { computeDataPointId } from "../sync/data-point-id.js";
import { readStoredLineage } from "../lineage/lineage.js";
import { ingestDataContract } from "../contracts/data.js";
import { computeQuestion, type QuestionComputeDeps } from "./compute.js";
import { createFakeInferenceProvider } from "./inference.js";
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
    ...overrides,
  };
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
      store: createInMemoryQuestionStore({
        initial: [
          registration({
            registeredBy: { kind: "builder", builder: BUILDER, grantId: "g-1" },
          }),
        ],
      }),
      writePolicyPorts: {
        authSessionVerifier: {
          getBuilder: async () =>
            ({ id: "b", granteeAddress: BUILDER }) as never,
        },
        grantVerifier: {
          getGrant: async () =>
            ({
              id: "g-1",
              grantorAddress: OWNER,
              granteeId: "b",
              scopes: ["write:coach.weekly"],
              revokedAt: "2026-08-26T00:00:00.000Z",
              expiresAt: null,
            }) as never,
        },
      },
    });
    await seed(d.storage, "oura.sleep", {});
    await seed(d.storage, "chatgpt.conversations", {});
    const outcome = await computeQuestion("q-1", d);
    expect(outcome).toMatchObject({ status: "failed" });
    expect((await d.store.get("q-1"))!.error).toMatch(/^GRANT_REVOKED/);
    expect(
      (d.provider as ReturnType<typeof createFakeInferenceProvider>).calls,
    ).toHaveLength(0);
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
