import { describe, expect, it } from "vitest";
import {
  createQuestionRegistration,
  findDerivationCycle,
  parseQuestionInput,
} from "./registration.js";
import { createInMemoryQuestionStore } from "./store.js";
import { questionRegistrationView } from "./types.js";

const valid = {
  derivedScope: "coach.weekly",
  sourceScopes: ["chatgpt.conversations", "oura.sleep"],
  question: "How did my sleep relate to my mood this week?",
};

describe("parseQuestionInput", () => {
  it("accepts a valid registration and normalizes the model to null", () => {
    expect(parseQuestionInput(valid)).toEqual({
      derivedScope: "coach.weekly",
      sourceScopes: ["chatgpt.conversations", "oura.sleep"],
      question: valid.question,
      model: null,
      recompute: "on-change",
    });
    expect(parseQuestionInput({ ...valid, model: "z-ai/glm-5.2" }).model).toBe(
      "z-ai/glm-5.2",
    );
  });

  it("ignores a `mode` the way it ignores any other unknown body key", () => {
    // There is one compute path now, so `mode` is not a field. It is not
    // rejected either: this parser reads only the keys it knows, so a stale
    // client that still sends one registers exactly as if it had not.
    for (const stale of ["completion", "code", "agentic", 1, {}]) {
      const parsed = parseQuestionInput({ ...valid, mode: stale });
      expect(parsed).not.toHaveProperty("mode");
      expect(parsed.question).toBe(valid.question);
    }
  });

  it("accepts both recompute policies and defaults a null to on-change", () => {
    expect(
      parseQuestionInput({ ...valid, recompute: "snapshot" }).recompute,
    ).toBe("snapshot");
    expect(
      parseQuestionInput({ ...valid, recompute: "on-change" }).recompute,
    ).toBe("on-change");
    expect(parseQuestionInput({ ...valid, recompute: null }).recompute).toBe(
      "on-change",
    );
  });

  it.each([
    ["not an object", "nope"],
    ["missing derivedScope", { ...valid, derivedScope: undefined }],
    ["derivedScope not a scope", { ...valid, derivedScope: "one" }],
    ["derivedScope with bad chars", { ...valid, derivedScope: "a.b/c" }],
    ["empty sourceScopes", { ...valid, sourceScopes: [] }],
    ["sourceScopes not an array", { ...valid, sourceScopes: "oura.sleep" }],
    [
      "duplicate source",
      { ...valid, sourceScopes: ["oura.sleep", "oura.sleep"] },
    ],
    [
      "derived scope as its own source",
      { ...valid, sourceScopes: ["coach.weekly"] },
    ],
    [
      "too many sources",
      {
        ...valid,
        sourceScopes: Array.from({ length: 17 }, (_, i) => `s${i}.x`),
      },
    ],
    ["empty question", { ...valid, question: "   " }],
    ["question not a string", { ...valid, question: 42 }],
    ["question too long", { ...valid, question: "x".repeat(8_001) }],
    ["model with spaces", { ...valid, model: "gpt 4" }],
    ["model not a string", { ...valid, model: 1 }],
    ["unknown recompute policy", { ...valid, recompute: "weekly" }],
    ["recompute not a string", { ...valid, recompute: true }],
  ])("rejects %s with DERIVATIVE_QUESTION_INVALID", (_label, body) => {
    expect(() => parseQuestionInput(body)).toThrow(
      expect.objectContaining({ errorCode: "DERIVATIVE_QUESTION_INVALID" }),
    );
  });

  it("applies the lineage naming rule (derived scope under a source namespace)", () => {
    expect(() =>
      parseQuestionInput({
        ...valid,
        derivedScope: "chatgpt.summary",
      }),
    ).toThrow(
      expect.objectContaining({
        errorCode: "LINEAGE_SCOPE_UNDER_SOURCE_PREFIX",
        code: 400,
      }),
    );
  });
});

describe("findDerivationCycle", () => {
  it("is null for a tree", () => {
    expect(
      findDerivationCycle(
        {
          derivedScope: "coach.weekly",
          sourceScopes: ["chatgpt.conversations"],
        },
        [{ derivedScope: "spine.summary", sourceScopes: ["coach.weekly"] }],
      ),
    ).toBeNull();
  });

  it("finds a direct cycle through another registration", () => {
    expect(
      findDerivationCycle({ derivedScope: "a.x", sourceScopes: ["b.y"] }, [
        { derivedScope: "b.y", sourceScopes: ["a.x"] },
      ]),
    ).toEqual(["a.x", "b.y", "a.x"]);
  });

  it("finds a transitive cycle", () => {
    expect(
      findDerivationCycle({ derivedScope: "a.x", sourceScopes: ["b.y"] }, [
        { derivedScope: "b.y", sourceScopes: ["c.z"] },
        { derivedScope: "c.z", sourceScopes: ["a.x", "d.w"] },
      ]),
    ).toEqual(["a.x", "b.y", "c.z", "a.x"]);
  });
});

describe("createQuestionRegistration", () => {
  it("stores a pending registration", async () => {
    const store = createInMemoryQuestionStore();
    const registration = await createQuestionRegistration({
      body: valid,
      registeredBy: { kind: "owner" },
      store,
      questionId: "q-1",
      now: () => new Date("2026-08-27T10:00:00.000Z"),
    });
    expect(registration).toMatchObject({
      questionId: "q-1",
      status: "pending",
      error: null,
      createdAt: "2026-08-27T10:00:00.000Z",
      lastComputedAt: null,
      derivedVersion: null,
    });
    expect(await store.get("q-1")).toEqual(registration);
  });

  it("refuses a registration that would create a recompute cycle", async () => {
    const store = createInMemoryQuestionStore();
    await createQuestionRegistration({
      body: { derivedScope: "b.y", sourceScopes: ["a.x"], question: "q" },
      registeredBy: { kind: "owner" },
      store,
      questionId: "q-1",
      now: () => new Date(),
    });
    await expect(
      createQuestionRegistration({
        body: { derivedScope: "a.x", sourceScopes: ["b.y"], question: "q" },
        registeredBy: { kind: "owner" },
        store,
        questionId: "q-2",
        now: () => new Date(),
      }),
    ).rejects.toMatchObject({ errorCode: "DERIVATIVE_CYCLE", code: 409 });
    expect(await store.get("q-2")).toBeNull();
  });
});

describe("createInMemoryQuestionStore", () => {
  it("loads a seeded registration that still carries a legacy `mode`", async () => {
    // A build that predates this change wrote `mode` onto every record. The
    // in-memory store is the one PS-Lite rehydrates into, so a record that
    // still has the key must round-trip rather than be rejected or read wrong.
    const legacy = {
      questionId: "q-legacy",
      derivedScope: "coach.weekly",
      sourceScopes: ["oura.sleep"],
      question: "How did I sleep?",
      model: null,
      mode: "code",
      recompute: "on-change" as const,
      registeredBy: { kind: "owner" as const },
      status: "ready" as const,
      error: null,
      createdAt: "2026-08-01T00:00:00.000Z",
      updatedAt: "2026-08-01T00:00:00.000Z",
      lastComputedAt: null,
      derivedVersion: null,
      derivedCollectedAt: null,
    };
    const store = createInMemoryQuestionStore({ initial: [legacy] });

    const loaded = await store.get("q-legacy");
    expect(loaded).not.toBeNull();
    expect(loaded!.question).toBe("How did I sleep?");
    expect(loaded!.status).toBe("ready");
    expect(loaded!.recompute).toBe("on-change");
    // The dead key is carried, not interpreted: it reaches no compute path,
    // and the public view is built by explicit field picks.
    expect(questionRegistrationView(loaded!)).not.toHaveProperty("mode");

    // And it stays loadable across an update.
    await store.update("q-legacy", { status: "stale" });
    expect((await store.get("q-legacy"))!.status).toBe("stale");
  });
});
