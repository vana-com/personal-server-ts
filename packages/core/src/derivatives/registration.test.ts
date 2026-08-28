import { describe, expect, it } from "vitest";
import {
  createQuestionRegistration,
  findDerivationCycle,
  parseQuestionInput,
} from "./registration.js";
import { createInMemoryQuestionStore } from "./store.js";

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
      mode: "completion",
    });
    expect(parseQuestionInput({ ...valid, model: "z-ai/glm-5.2" }).model).toBe(
      "z-ai/glm-5.2",
    );
  });

  it("defaults mode to completion, accepts code, and refuses anything else", () => {
    // An existing client that has never heard of `mode` keeps working.
    expect(parseQuestionInput(valid).mode).toBe("completion");
    expect(parseQuestionInput({ ...valid, mode: undefined }).mode).toBe(
      "completion",
    );
    expect(parseQuestionInput({ ...valid, mode: null }).mode).toBe(
      "completion",
    );
    expect(parseQuestionInput({ ...valid, mode: "code" }).mode).toBe("code");

    // "agentic" was PR #231's second mode; it is deliberately not ours.
    for (const bad of ["agentic", "", "CODE", 1, true, {}]) {
      expect(() => parseQuestionInput({ ...valid, mode: bad })).toThrow(
        /mode must be one of/,
      );
    }
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
