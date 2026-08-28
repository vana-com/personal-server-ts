import { describe, expect, it } from "vitest";
import type { QuestionRegistration } from "@opendatalabs/personal-server-ts-core/derivatives";
import { initializeDatabase } from "./index-schema.js";
import { createSqliteQuestionStore } from "./question-store.js";

function registration(
  overrides: Partial<QuestionRegistration> = {},
): QuestionRegistration {
  return {
    questionId: "q-1",
    derivedScope: "coach.weekly",
    sourceScopes: ["oura.sleep", "chatgpt.conversations"],
    question: "How did I sleep?",
    model: null,
    mode: "completion",
    registeredBy: {
      kind: "builder",
      builder: "0x2222222222222222222222222222222222222222",
      grantId: "g-1",
    },
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

describe("createSqliteQuestionStore", () => {
  it("round-trips registrations, filters, updates and deletes", async () => {
    const db = initializeDatabase(":memory:");
    const store = createSqliteQuestionStore(db);
    await store.insert(registration());
    await store.insert(
      registration({
        questionId: "q-2",
        derivedScope: "spine.summary",
        sourceScopes: ["oura.sleep"],
        registeredBy: { kind: "owner" },
        createdAt: "2026-08-27T00:00:01.000Z",
      }),
    );

    expect(await store.get("q-1")).toEqual(registration());
    expect((await store.list()).map((r) => r.questionId)).toEqual([
      "q-1",
      "q-2",
    ]);
    expect(
      (await store.list({ sourceScope: "chatgpt.conversations" })).map(
        (r) => r.questionId,
      ),
    ).toEqual(["q-1"]);
    expect(
      (await store.list({ derivedScope: "spine.summary" })).map(
        (r) => r.questionId,
      ),
    ).toEqual(["q-2"]);
    expect(
      (
        await store.list({
          builder: "0x2222222222222222222222222222222222222222",
        })
      ).map((r) => r.questionId),
    ).toEqual(["q-1"]);

    const updated = await store.update("q-1", {
      status: "ready",
      lastComputedAt: "2026-08-27T01:00:00.000Z",
      derivedVersion: 4,
      derivedCollectedAt: "2026-08-27T01:00:00Z",
      updatedAt: "2026-08-27T01:00:00.000Z",
    });
    expect(updated).toMatchObject({ status: "ready", derivedVersion: 4 });
    expect(await store.get("q-1")).toEqual(updated);
    expect(await store.update("nope", { status: "stale" })).toBeNull();

    // The table survives a second store on the same database.
    const again = createSqliteQuestionStore(db);
    expect((await again.list()).length).toBe(2);

    expect(await store.delete("q-1")).toBe(true);
    expect(await store.delete("q-1")).toBe(false);
    expect(await store.get("q-1")).toBeNull();
    db.close();
  });

  it("refuses a duplicate question id", async () => {
    const store = createSqliteQuestionStore(initializeDatabase(":memory:"));
    await store.insert(registration());
    await expect(store.insert(registration())).rejects.toThrow();
  });
});
