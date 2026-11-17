// The change check in each page of a complete body asks whether this stream
// has any change after the pin. It must find the answer in the stream's own
// entries, not by reading everything written after the pin: another
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
    "%s finds the stream's changes through an index led by the connection, the stream and the sequence",
    async (_name, after) => {
      const db = await open();
      const { sql, params } = completePage(HEAD, 7, after);
      const steps = await db.query<PlanStep>(
        `EXPLAIN QUERY PLAN ${sql}`,
        params,
      );
      const reads = steps.filter((s) => /\b(SEARCH|SCAN) x\b/.test(s.detail));
      expect(reads).toHaveLength(1);
      expect(reads[0]!.detail).toMatch(/^SEARCH x USING (COVERING )?INDEX /);
      // Not the table's own order: that reads every change after the pin, of
      // every stream and connection.
      expect(reads[0]!.detail).not.toMatch(/INTEGER PRIMARY KEY/);
      const index = /USING (?:COVERING )?INDEX (\w+)/.exec(
        reads[0]!.detail,
      )?.[1];
      const columns = (
        await db.query<{ seqno: number; name: string | null; key: number }>(
          `PRAGMA index_xinfo(${index})`,
        )
      )
        .filter((column) => column.key === 1)
        .sort((x, y) => x.seqno - y.seqno)
        .map((column) => column.name);
      expect(columns.slice(0, 3)).toEqual(["connection_id", "stream", "seq"]);
      // The step also bounds the sequence, so it seeks to the pin.
      expect(reads[0]!.detail).toMatch(/seq>\?/);
    },
  );
});
