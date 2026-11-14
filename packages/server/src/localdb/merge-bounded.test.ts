import { expect, it } from "vitest";
import { openLocalDb } from "../../../core/src/localdb/open.js";
import { TEMP_TABLES, mergeIncoming } from "../../../core/src/localdb/merge.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

it("looks up incoming merge updates by the complete record key", async () => {
  const db = await openLocalDb(openBetterSqlite3(":memory:"), {
    owner: "0xabc",
    network: "test",
    deviceId: "fixture",
  });
  try {
    await db.batch(TEMP_TABLES.map((sql) => ({ sql })));
    for (const statement of mergeIncoming("batch", "connection").filter((s) =>
      s.sql.startsWith("UPDATE records"),
    )) {
      const plan = await db.query<{ detail: string }>(
        "EXPLAIN QUERY PLAN " + statement.sql,
        statement.params,
      );
      // A connection-only search revisits every old row for each new row. The
      // SQLite plan must seek the incoming key, independent of total input size.
      expect(
        plan.some((row) =>
          row.detail.includes(
            "records USING PRIMARY KEY (connection_id=? AND stream=? AND pk_hash=?)",
          ),
        ),
      ).toBe(true);
    }
  } finally {
    await db.close();
  }
});
