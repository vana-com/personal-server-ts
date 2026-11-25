// The staged deletion keys become `log_tombstones` rows in the same
// transaction as the import's receipt, so an import the final fence refuses
// leaves no tombstone behind.
import { afterEach, expect, it } from "vitest";
import { drivers, world } from "./late-seed-harness.test-utils.js";

afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
});

it("import-refused-by-the-final-fence-leaves-no-tombstones", async () => {
  const w = await world();
  const a = await w.device("a");
  await a.run("live", ["live"]);
  // A delete intent appears after the deletions are staged, when the import
  // reads the stream's high-water mark for its receipt (its second read: the
  // first opens the import).
  const query = a.db.query.bind(a.db);
  let reads = 0;
  let tripped = false;
  a.db.query = (async (sql: string, params?: unknown[]) => {
    if (!tripped && sql.includes("coalesce(max(seq),0)") && ++reads === 2) {
      tripped = true;
      await a.db.batch([
        {
          sql: "INSERT INTO delete_intents(connector,delete_id,intent) VALUES ('fixture','d','{}')",
        },
      ]);
    }
    return query(sql, params);
  }) as typeof a.db.query;
  const result = await a.importSource("files", (base) => ({
    ...base,
    async *records() {
      yield { id: "kept", v: "row" };
    },
    async *deletions() {
      yield { id: "gone-1" };
      yield { id: "gone-2" };
    },
  }));
  expect(tripped).toBe(true);
  expect(result).toEqual({ kind: "refused", reason: "connection_deleted" });
  expect(
    await a.db.query(
      "SELECT 1 FROM log_tombstones WHERE connection_id = 'pdpp.fixture~'",
    ),
  ).toEqual([]);
});
