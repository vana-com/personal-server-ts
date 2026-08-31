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
    recompute: "on-change",
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

  it("round-trips the recompute policy", async () => {
    const store = createSqliteQuestionStore(initializeDatabase(":memory:"));
    await store.insert(registration({ recompute: "snapshot" }));
    expect((await store.get("q-1"))!.recompute).toBe("snapshot");
  });

  it("migrates a table created before the recompute column existed", async () => {
    const db = initializeDatabase(":memory:");
    // The pre-recompute schema, verbatim, with one row already in it.
    db.exec(`
      CREATE TABLE derivative_questions (
        question_id TEXT PRIMARY KEY,
        derived_scope TEXT NOT NULL,
        source_scopes TEXT NOT NULL,
        question TEXT NOT NULL,
        model TEXT,
        registered_by TEXT NOT NULL,
        status TEXT NOT NULL,
        error TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        last_computed_at TEXT,
        derived_version INTEGER,
        derived_collected_at TEXT
      )`);
    db.prepare(
      `INSERT INTO derivative_questions (
        question_id, derived_scope, source_scopes, question, registered_by,
        status, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      "q-old",
      "coach.weekly",
      JSON.stringify(["oura.sleep"]),
      "q",
      JSON.stringify({ kind: "owner" }),
      "ready",
      "2026-08-27T00:00:00.000Z",
      "2026-08-27T00:00:00.000Z",
    );

    const store = createSqliteQuestionStore(db);
    expect((await store.get("q-old"))!.recompute).toBe("on-change");
    // New rows land in the migrated table with their own policy.
    await store.insert(
      registration({ questionId: "q-new", recompute: "snapshot" }),
    );
    expect((await store.get("q-new"))!.recompute).toBe("snapshot");
    db.close();
  });
});
