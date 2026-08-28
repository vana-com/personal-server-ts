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

describe("createSqliteQuestionStore mode column", () => {
  it("round-trips both modes", async () => {
    const db = initializeDatabase(":memory:");
    const store = createSqliteQuestionStore(db);
    await store.insert(registration({ questionId: "q-c", mode: "code" }));
    await store.insert(registration({ questionId: "q-p", mode: "completion" }));
    expect((await store.get("q-c"))?.mode).toBe("code");
    expect((await store.get("q-p"))?.mode).toBe("completion");
  });

  it("migrates a table created before the mode column existed", async () => {
    const db = initializeDatabase(":memory:");

    // Reproduce the pre-mode schema exactly, then seed a row through it, so
    // this is a real in-place upgrade rather than a fresh table with a default.
    db.exec(
      "CREATE TABLE derivative_questions (" +
        "question_id TEXT PRIMARY KEY, derived_scope TEXT NOT NULL, " +
        "source_scopes TEXT NOT NULL, question TEXT NOT NULL, model TEXT, " +
        "registered_by TEXT NOT NULL, status TEXT NOT NULL, error TEXT, " +
        "created_at TEXT NOT NULL, updated_at TEXT NOT NULL, " +
        "last_computed_at TEXT, derived_version INTEGER, " +
        "derived_collected_at TEXT)",
    );
    db.prepare(
      "INSERT INTO derivative_questions (question_id, derived_scope, " +
        "source_scopes, question, model, registered_by, status, error, " +
        "created_at, updated_at, last_computed_at, derived_version, " +
        "derived_collected_at) VALUES ('legacy', 'coach.weekly', " +
        "'[\"oura.sleep\"]', 'How did I sleep?', NULL, " +
        "'{\"kind\":\"owner\"}', 'ready', NULL, " +
        "'2026-08-01T00:00:00.000Z', '2026-08-01T00:00:00.000Z', " +
        "NULL, NULL, NULL)",
    ).run();

    const hasMode = (): boolean =>
      (
        db.prepare("PRAGMA table_info(derivative_questions)").all() as Array<{
          name: string;
        }>
      ).some((c) => c.name === "mode");
    expect(hasMode()).toBe(false);

    // Opening the store performs the migration.
    const store = createSqliteQuestionStore(db);
    expect(hasMode()).toBe(true);

    // The pre-existing row survives and takes the behaviour it ran under.
    const legacy = await store.get("legacy");
    expect(legacy).not.toBeNull();
    expect(legacy?.mode).toBe("completion");
    expect(legacy?.question).toBe("How did I sleep?");
    expect(legacy?.status).toBe("ready");

    // The migrated table accepts new rows in either mode.
    await store.insert(registration({ questionId: "q-new", mode: "code" }));
    expect((await store.get("q-new"))?.mode).toBe("code");

    // Idempotent: reopening must not throw on a duplicate column.
    expect(() => createSqliteQuestionStore(db)).not.toThrow();
    expect((await store.get("legacy"))?.mode).toBe("completion");
  });

  it("narrows an unrecognised mode written outside the store", async () => {
    const db = initializeDatabase(":memory:");
    const store = createSqliteQuestionStore(db);
    await store.insert(registration({ questionId: "q-x" }));
    db.prepare(
      "UPDATE derivative_questions SET mode = 'agentic' WHERE question_id = 'q-x'",
    ).run();
    // A mode this build does not know must not reach the compute path.
    expect((await store.get("q-x"))?.mode).toBe("completion");
  });
});
