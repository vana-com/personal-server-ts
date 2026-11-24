// The changed keys of a window, read a page at a time, are the keys the one
// grouped query named: each key once, at its last eligible change, in the
// order of those changes. That query is the oracle here; the paged read
// replaces it so a publish round no longer reads every key of the stream.
import { afterEach, describe, expect, it } from "vitest";
import {
  openLocalDb,
  type SqlDriver,
} from "../../../core/src/localdb/index.js";
import {
  CHANGE_PAGE,
  changedKeyPages,
  hasChangedKeys,
} from "../../../core/src/localdb/log-changed-keys.js";
import { ELIGIBLE_CHANGE } from "../../../core/src/localdb/publication-work.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
});

function rng(seed: number) {
  let a = seed >>> 0;
  const next = () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  return { int: (n: number) => Math.floor(next() * n) };
}

async function oracle(db: SqlDriver, stream: string, from: number, to: number) {
  const rows = await db.query<{ pk_hash: string; seq: number }>(
    `SELECT pk_hash, MAX(seq) AS seq FROM record_changes
      WHERE connection_id = ? AND stream = ? AND seq > ? AND seq <= ?
        AND ${ELIGIBLE_CHANGE}
      GROUP BY pk_hash ORDER BY MAX(seq)`,
    ["c", stream, from, to],
  );
  return rows.map((row) => ({ pk: row.pk_hash, seq: row.seq }));
}

let pages = 0;
async function paged(db: SqlDriver, stream: string, from: number, to: number) {
  const keys = [];
  for await (const page of changedKeyPages(db, "c", stream, from, to)) {
    expect(page.length).toBeLessThanOrEqual(CHANGE_PAGE);
    pages += 1;
    keys.push(...page);
  }
  return keys;
}

describe("changedKeyPages is the grouped query, a page at a time", () => {
  it("agrees on random change logs with other streams, origins and refused runs", async () => {
    for (let seed = 1; seed <= 12; seed += 1) {
      const db = await openLocalDb(openBetterSqlite3(":memory:"), {
        owner: `0x${"11".repeat(20)}`,
        network: "test",
        deviceId: "d",
      });
      drivers.push(db);
      const r = rng(seed);
      const origins = ["local", "import", "remote", "refresh", "purge"];
      // Runs 1..3 of stream s0 are refused or discarded; 4 is published.
      await db.batch([
        ...["r1", "r2", "r3", "r4"].map((run, i) => ({
          sql: `INSERT INTO runs(run_id, connection_id, o, artifact_version, collection_mode, state)
                VALUES (?, 'c', ?, 'v', 'full_refresh', 'ended')`,
          params: [run, i + 1],
        })),
        ...["r1", "r2", "r3", "r4"].map((run, i) => ({
          sql: `INSERT INTO run_streams(run_id, stream, delete_snapshot, decision)
                VALUES (?, 's0', 0, ?)`,
          params: [run, ["refused", "discarded", "refused", "publish"][i]!],
        })),
      ]);
      const rows = 2000 + r.int(2500);
      const keys = 40 + r.int(1500);
      const statements = Array.from({ length: rows }, () => {
        const run = `r${1 + r.int(4)}`;
        return {
          sql: `INSERT INTO record_changes(connection_id, stream, pk_hash, record_key, op, stamp_o, stamp_r, origin)
                VALUES (?, ?, ?, '[]', 'upsert', ?, ?, ?)`,
          params: [
            r.int(5) === 0 ? "other" : "c",
            `s${r.int(3)}`,
            `h${String(r.int(keys)).padStart(5, "0")}`,
            Number(run.slice(1)),
            run,
            origins[r.int(origins.length)]!,
          ],
        };
      });
      await db.batch(statements);
      const last = rows;
      for (const [from, to] of [
        [0, last],
        [Math.floor(last / 3), last],
        [Math.floor(last / 4), Math.floor((3 * last) / 4)],
        [last, last],
      ] as const)
        for (const stream of ["s0", "s1", "s2"]) {
          const expected = await oracle(db, stream, from, to);
          expect(await paged(db, stream, from, to), `seed ${seed}`).toEqual(
            expected,
          );
          expect(await hasChangedKeys(db, "c", stream, from, to)).toBe(
            expected.length > 0,
          );
        }
    }
    // Pages are cut by change rows, so a long window takes several.
    expect(pages).toBeGreaterThan(40);
  });
});
