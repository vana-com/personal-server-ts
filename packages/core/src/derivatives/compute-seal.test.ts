/**
 * A derivative is a legacy write. These tests pin what compute does when the
 * seal refuses it: no inference spend when the refusal is known up front, a
 * closed failure vocabulary, and only the unknown mode is retryable.
 */
import { describe, expect, it } from "vitest";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";
import { ingestDataContract } from "../contracts/data.js";
import { computeQuestion, type QuestionComputeDeps } from "./compute.js";
import { createFakeInferenceProvider } from "./inference.js";
import { createInMemoryQuestionStore } from "./store.js";
import { createLegacyWriteSeal } from "../storage/legacy-write-seal.js";
import { authorityHearing } from "../test-utils/account-mode.js";
import { fixedLegacyWriteSeal } from "../test-utils/legacy-write-seal.js";
import type { LegacyWriteSeal } from "../storage/legacy-write-seal.js";
import type { AccountStorageModeValue } from "../api/account-storage-mode.js";
import type { QuestionRegistration } from "./types.js";

const OWNER = "0x1111111111111111111111111111111111111111" as const;

const registration: QuestionRegistration = {
  questionId: "q-1",
  derivedScope: "coach.weekly",
  sourceScopes: ["oura.sleep"],
  question: "How did I sleep?",
  model: null,
  answerShape: null,
  recompute: "on-change",
  registeredBy: { kind: "owner" },
  status: "pending",
  error: null,
  errorCode: null,
  createdAt: "2026-08-27T00:00:00.000Z",
  updatedAt: "2026-08-27T00:00:00.000Z",
  lastComputedAt: null,
  derivedVersion: null,
  derivedCollectedAt: null,
};

/** A seal whose mode a test can change after it has seeded the storage. */
function switchableSeal(start: AccountStorageModeValue) {
  let mode = start;
  const seal: LegacyWriteSeal = {
    commit: (write) => fixedLegacyWriteSeal(mode).commit(write),
    remove: (work) => fixedLegacyWriteSeal(mode).remove(work),
    admit: () => fixedLegacyWriteSeal(mode).admit(),
    verdict: () => fixedLegacyWriteSeal(mode).verdict(),
  };
  return {
    seal,
    set(next: AccountStorageModeValue) {
      mode = next;
    },
  };
}

async function build(seal: LegacyWriteSeal) {
  const storage = createMemoryDataStorage({ legacyWriteSeal: seal });
  const seeded = await ingestDataContract({
    storage,
    scopeParam: "oura.sleep",
    body: { nights: [{ date: "2026-08-18", score: 70 }] },
    collectedAt: "2026-08-20T00:00:00Z",
    status: "stored",
  });
  if (!seeded.ok) throw new Error("seed failed");
  const provider = createFakeInferenceProvider();
  const deps: QuestionComputeDeps = {
    storage,
    store: createInMemoryQuestionStore({ initial: [registration] }),
    provider,
    serverOwner: OWNER,
    now: () => new Date("2026-08-27T12:00:00.000Z"),
    retryDelaysMs: [0, 0],
  };
  return { deps, storage, provider };
}

describe("computeQuestion when legacy storage is closed", () => {
  // COMPUTE_SPENDS_INFERENCE_BEFORE_SEAL
  it("on a switched account fails closed as internal without asking the model", async () => {
    const mode = switchableSeal("unswitched");
    const f = await build(mode.seal);
    mode.set("switched");
    const outcome = await computeQuestion("q-1", f.deps);
    expect(outcome.status).toBe("failed");
    expect(f.provider.calls).toHaveLength(0);
    expect(f.storage.findEntry({ scope: "coach.weekly" })).toBeUndefined();
    const stored = await f.deps.store.get("q-1");
    expect(stored).toMatchObject({ status: "failed", errorCode: "internal" });
    expect(stored?.error).toMatch(/stream sync/);
  });

  it("while the mode is unknown fails as inference_unavailable, the retryable class", async () => {
    const mode = switchableSeal("unswitched");
    const f = await build(mode.seal);
    mode.set("unknown");
    await computeQuestion("q-1", f.deps);
    expect(f.provider.calls).toHaveLength(0);
    expect(await f.deps.store.get("q-1")).toMatchObject({
      status: "failed",
      errorCode: "inference_unavailable",
    });
  });

  // The seal closes after the model has answered: the write itself is refused.
  it("stores nothing when the switch lands while the model is answering", async () => {
    const authority = await authorityHearing(OWNER, "off");
    const seal = createLegacyWriteSeal({ authority, owner: OWNER });
    const f = await build(seal);
    const original = f.provider.chat.bind(f.provider);
    f.provider.chat = async (...args: Parameters<typeof original>) => {
      await authority.submitEvidence({
        owner: OWNER,
        state: "on",
      });
      return original(...args);
    };
    const outcome = await computeQuestion("q-1", f.deps);
    expect(outcome.status).toBe("failed");
    expect(f.provider.calls).toHaveLength(1);
    expect(f.storage.findEntry({ scope: "coach.weekly" })).toBeUndefined();
    expect(await f.deps.store.get("q-1")).toMatchObject({
      status: "failed",
      errorCode: "internal",
    });
  });

  it("writes the derivative on an unswitched account", async () => {
    const f = await build(fixedLegacyWriteSeal("unswitched"));
    expect((await computeQuestion("q-1", f.deps)).status).toBe("ready");
    expect(f.storage.findEntry({ scope: "coach.weekly" })).toBeDefined();
  });
});
