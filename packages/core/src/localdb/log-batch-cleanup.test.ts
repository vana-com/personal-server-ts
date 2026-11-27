// The cleanup of a commit's temp rows reports; it never changes the commit's
// outcome (log-batch.ts `commitStaged`).
import { expect, it } from "vitest";
import type { SqlDriver, SqlStatement } from "./driver.js";
import { commitStaged } from "./log-batch.js";

function harness(fail: { main?: Error; cleanup?: Error; warn?: Error }) {
  const warned: Record<string, unknown>[] = [];
  const cleaned: string[] = [];
  const db: SqlDriver = {
    info: { host: "node", persistent: false, sqliteVersion: "3.54.1" },
    query: async () => [],
    batch: async (statements: readonly SqlStatement[]) => {
      const isCleanup = statements.every((s) =>
        s.sql.startsWith("DELETE FROM temp.incoming"),
      );
      if (isCleanup)
        cleaned.push(...statements.map((x) => String(x.params?.[0])));
      const error = isCleanup ? fail.cleanup : fail.main;
      if (error) throw error;
      return { changes: [] };
    },
    close: async () => {},
  };
  const logger = {
    info: () => {},
    warn: (obj: Record<string, unknown>) => {
      if (fail.warn) throw fail.warn;
      warned.push(obj);
    },
  };
  return { deps: { db, logger }, warned, cleaned };
}

const staged = [{ op: "op-1", statements: [{ sql: "SELECT 1", params: [] }] }];

it("reports success when the rows committed and only the temp-row cleanup rejected", async () => {
  const { deps, warned } = harness({ cleanup: new Error("cleanup failed") });
  const begun = new Set<string>();
  await expect(commitStaged(deps, staged, begun)).resolves.toBeUndefined();
  expect(warned).toHaveLength(1);
  expect(String(warned[0]!.error)).toContain("cleanup failed");
});

it("surfaces the commit's own error when the cleanup rejects too", async () => {
  const { deps } = harness({
    main: new Error("commit failed"),
    cleanup: new Error("cleanup failed"),
  });
  await expect(commitStaged(deps, staged)).rejects.toThrow("commit failed");
});

it("cleans up and surfaces the error when assembling the statements throws", async () => {
  const { deps, cleaned } = harness({});
  const throwing = [
    {
      ...staged[0]!,
      after: async () => {
        throw new Error("after failed");
      },
    },
  ];
  await expect(commitStaged(deps, throwing)).rejects.toThrow("after failed");
  expect(cleaned).toEqual(["op-1"]);
});

it("resolves when the cleanup rejects and the warning itself throws", async () => {
  const { deps } = harness({
    cleanup: new Error("cleanup failed"),
    warn: new Error("warn failed"),
  });
  await expect(commitStaged(deps, staged)).resolves.toBeUndefined();
});

it("rejects with the commit's own error, by identity, when the warning throws", async () => {
  const commitError = new Error("A");
  const { deps } = harness({
    main: commitError,
    cleanup: new Error("B"),
    warn: new Error("C"),
  });
  await expect(commitStaged(deps, staged)).rejects.toBe(commitError);
});
