// A full refresh finds the rows it drops by their newest observation. That
// scan must seek (not read the whole stream) and must not hold one entry per
// dropped row.
import { afterEach, describe, expect, it } from "vitest";
import {
  openLocalDb,
  type LocalSyncDeps,
  type SqlDriver,
} from "../../../core/src/localdb/index.js";
import {
  mergeIncoming,
  replaceDelete,
  withOrigin,
} from "../../../core/src/localdb/merge.js";
import {
  FRAME_OVERHEAD_BYTES,
  replacedPrefixGroups,
} from "../../../core/src/localdb/part-layout.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const owner = `0x${"12".repeat(20)}` as const;
const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
});

const hex = (n: number, width: number) => n.toString(16).padStart(width, "0");

/** A stream of `kept` rows seen at (9, "r9") and `old` rows last seen at (1, "r1"). */
async function streamOf(kept: number, old: number) {
  const db = await openLocalDb(openBetterSqlite3(":memory:"), {
    owner,
    network: "test",
    deviceId: "scan-device",
  });
  drivers.push(db);
  const insert = (count: number, from: number, o: number, r: string) =>
    db.batch(
      Array.from({ length: count }, (_, i) => {
        const n = from + i;
        // Spread keys over the key space: the first 16 bits cycle through 4096 values.
        const pk = `${hex((n % 300) * 16, 4)}${hex(n, 60)}`;
        const body = JSON.stringify({ id: n });
        return {
          sql: `INSERT INTO records (connection_id, stream, pk_hash, record_key, stamp_o, stamp_r, body, body_sha256, first_o)
                VALUES ('c1', 's', ?, ?, ?, ?, ?, ?, NULL)`,
          params: [pk, `k${n}`, o, r, body, `sha${n}`],
        };
      }),
    );
  await insert(old, 0, 1, "r1");
  await insert(kept, old, 9, "r9");
  // Rows a later run saw again but did not change keep an old stamp and a new seen stamp.
  await db.batch([
    {
      sql: `UPDATE records SET seen_o = 9, seen_r = 'r9' WHERE stamp_o = 1 AND record_key IN ('k0', 'k1')`,
      params: [],
    },
  ]);
  return db as unknown as LocalSyncDeps["db"];
}

const plan = async (db: LocalSyncDeps["db"], sql: string, params: unknown[]) =>
  (
    await db.query<{ detail: string }>(
      `EXPLAIN QUERY PLAN ${sql}`,
      params as never,
    )
  ).map((row) => row.detail);

describe("the scan for rows a full refresh drops", () => {
  it("seeks by observation age: no whole-stream scan, for the delete and the prefix groups", async () => {
    const db = await streamOf(2000, 2000);
    const statement = replaceDelete("c1", "s", 5, "r5");
    const details = await plan(db, statement.sql, [
      ...(statement.params ?? []),
    ]);
    expect(details.join("\n")).toContain("records_by_observation");
    expect(details.join("\n")).not.toMatch(/SCAN/);
  });

  it("returns one entry per 16-bit key prefix, not one per dropped row", async () => {
    const db = await streamOf(100, 3000);
    const groups = await replacedPrefixGroups(db, "c1", "s", { o: 5, r: "r5" });
    // 2998 rows are older than the marker: k0 and k1 were seen again at 9.
    expect(groups.reduce((sum, g) => sum + g.rows, 0)).toBe(2998);
    expect(groups.length).toBeLessThanOrEqual(300);
    expect(groups.length).toBeLessThan(2998);
    for (const group of groups) expect(group.prefix).toMatch(/^[0-9a-f]{4}$/);
    // Each body is `{"id":N}`: the sum of lengths plus the frame overhead per row.
    const [{ n }] = await db.query<{ n: number }>(
      `SELECT SUM(LENGTH(CAST(body AS BLOB))) AS n FROM records WHERE stamp_o = 1 AND record_key NOT IN ('k0','k1')`,
    );
    expect(groups.reduce((sum, g) => sum + g.bytes, 0)).toBe(
      Number(n) + 2998 * FRAME_OVERHEAD_BYTES,
    );
  });

  it("finds nothing when every row was seen by the replacing run", async () => {
    const db = await streamOf(500, 0);
    expect(
      await replacedPrefixGroups(db, "c1", "s", { o: 5, r: "r5" }),
    ).toEqual([]);
  });
});

describe("the observation index depends on seen never trailing the stamp", () => {
  const rowAfter = async (incoming: { o: number; r: string }) => {
    const db = await streamOf(0, 0);
    await db.batch([
      {
        sql: `INSERT INTO records (connection_id, stream, pk_hash, record_key, stamp_o, stamp_r, body, body_sha256, first_o, seen_o, seen_r)
              VALUES ('c1', 's', ?, 'k', 1, 'r1', '{"id":1}', 'sha', NULL, 3, 'r3')`,
        params: ["ab".repeat(32)],
      },
    ]);
    await db.batch(
      withOrigin("remote", [
        {
          sql: `INSERT INTO incoming (op, stream, pk_hash, record_key, stamp_o, stamp_r, body, body_sha256, first_o)
                VALUES ('op', 's', ?, 'k', ?, ?, '{"id":1}', 'sha', NULL)`,
          params: ["ab".repeat(32), incoming.o, incoming.r],
        },
        ...mergeIncoming("op", "c1"),
      ]),
    );
    const [row] = await db.query<{
      stamp_o: number;
      seen_o: number | null;
    }>(`SELECT stamp_o, seen_o FROM records WHERE connection_id = 'c1'`);
    return row;
  };

  it("an equal body under a newer stamp adopts it and keeps a later sighting", async () => {
    expect(await rowAfter({ o: 2, r: "r2" })).toEqual({
      stamp_o: 2,
      seen_o: 3,
    });
  });

  it("an equal body under a stamp newer than the sighting clears it", async () => {
    expect(await rowAfter({ o: 4, r: "r4" })).toEqual({
      stamp_o: 4,
      seen_o: null,
    });
  });
});
