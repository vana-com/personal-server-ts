import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { expect, it, vi } from "vitest";
import { runDeclarationWitness } from "./declaration-witness.js";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";

const faults = vi.hoisted(() => ({ closePath: "", attempted: [] as string[] }));
vi.mock("better-sqlite3", async (importOriginal) => {
  const { default: Actual } = await importOriginal<{
    default: typeof Database;
  }>();
  return {
    default: function FaultDatabase(
      ...args: ConstructorParameters<typeof Actual>
    ) {
      const db = new Actual(...args);
      if (db.readonly) {
        const close = db.close.bind(db);
        vi.spyOn(db, "close").mockImplementation(() => {
          faults.attempted.push(db.name);
          const closed = close();
          if (db.name === faults.closePath)
            throw new Error("SYNTHETIC_NATIVE_CLOSE_DETAIL");
          return closed;
        });
      }
      return db;
    },
  };
});

const sourceId = "https://example.invalid/witness";
async function fixture(
  run: (paths: { dbPath: string; declarationsDbPath: string }) => Promise<void>,
) {
  const root = mkdtempSync(join(tmpdir(), "witness-close-precedence-"));
  const dbPath = join(root, "records.sqlite");
  const declarationsDbPath = join(root, "declarations.sqlite");
  faults.attempted.length = 0;
  try {
    const records = new Database(dbPath);
    try {
      createSqliteRecordStore(records);
    } finally {
      records.close();
    }
    const declarations = new Database(declarationsDbPath);
    try {
      declarations.exec(
        "CREATE TABLE pdpp_current_declarations (source_id TEXT, is_current INTEGER, snapshot_json TEXT)",
      );
      declarations
        .prepare("INSERT INTO pdpp_current_declarations VALUES (?, 1, ?)")
        .run(
          sourceId,
          JSON.stringify({
            source_id: sourceId,
            streams: [{ name: "events" }],
          }),
        );
    } finally {
      declarations.close();
    }
    faults.closePath = declarationsDbPath;
    await run({ dbPath, declarationsDbPath });
    expect(faults.attempted).toEqual([declarationsDbPath, dbPath]);
  } finally {
    faults.closePath = "";
    vi.restoreAllMocks();
    rmSync(root, { recursive: true, force: true });
  }
}

it("keeps the primary refusal and separately reports a redacted close failure", async () => {
  await fixture(async (paths) => {
    const outcome: unknown = await runDeclarationWitness({
      ...paths,
      sourceId,
      stream: "undisclosed",
      nextSchema: {},
      pageSize: 1,
      budgetMs: 0,
    }).catch((error: unknown) => error);
    expect(outcome).toMatchObject({
      name: "OfflineDeclarationWitnessError",
      code: "missing_stream",
      cleanupErrorCode: "close_failed",
    });
    expect(String(outcome)).not.toContain("SYNTHETIC_NATIVE_CLOSE_DETAIL");
  });
});

it("still refuses a result when the only failure is closing a handle", async () => {
  await fixture(async (paths) => {
    await expect(
      runDeclarationWitness({
        ...paths,
        sourceId,
        stream: "events",
        nextSchema: {},
        pageSize: 1,
        budgetMs: 0,
      }),
    ).rejects.toMatchObject({ code: "close_failed" });
  });
});
