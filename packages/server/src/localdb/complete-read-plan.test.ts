// The change check in each page of a complete body asks whether this stream
// changed after the reader pinned it. It must be one primary-key lookup of the
// stream's own mark, not a read of what was written after the pin: another
// connection may import a million records while a body waits between pages.
// Real SQLite and the real schema.
import { afterEach, describe, expect, it } from "vitest";
import { completePage } from "../../../core/src/localdb/complete-read.js";
import type { PartialHead } from "../../../core/src/localdb/partial-read.js";
import type { SqlDriver } from "../../../core/src/localdb/driver.js";
import { openLocalDb } from "../../../core/src/localdb/open.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
});

const HEAD: PartialHead = {
  connectionId: "c1",
  generation: 1,
  stream: "items",
  version: 1,
  dataHash: "h1",
};

async function open() {
  const db = await openLocalDb(openBetterSqlite3(":memory:"), {
    owner: "0xabc",
    network: "test",
    deviceId: "complete-read-plan",
  });
  drivers.push(db);
  return db;
}

type PlanStep = { id: number; parent: number; detail: string };

describe("the change check of a complete body's page", () => {
  it.each([
    ["the first page", undefined],
    ["a later page", "0x00000041"],
  ])(
    "%s is one primary-key lookup and reads no change log",
    async (_name, after) => {
      const db = await open();
      const { sql, params } = completePage(HEAD, 7, after);
      const steps = await db.query<PlanStep>(
        `EXPLAIN QUERY PLAN ${sql}`,
        params,
      );
      expect(steps.filter((s) => /record_changes/.test(s.detail))).toEqual([]);
      const reads = steps.filter((s) => /^(SEARCH|SCAN) m\b/.test(s.detail));
      expect(reads).toHaveLength(1);
      expect(reads[0]!.detail).toMatch(
        /^SEARCH m USING PRIMARY KEY \(connection_id=\? AND stream=\?\)/,
      );
    },
  );
});
