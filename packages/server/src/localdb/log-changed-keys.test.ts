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
  untypedDeletePages,
} from "../../../core/src/localdb/log-changed-keys.js";
import { sName, world } from "./log-world.test-utils.js";
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

/** A database whose every query result is seen by `seen`. */
function watched(
  inner: SqlDriver,
  seen: (
    sql: string,
    params: unknown,
    rows: readonly Record<string, unknown>[],
  ) => void,
): SqlDriver {
  return {
    ...inner,
    query: async (sql: string, params?: Parameters<SqlDriver["query"]>[1]) => {
      const rows = await inner.query(sql, params);
      seen(sql, params, rows as Record<string, unknown>[]);
      return rows;
    },
  } as SqlDriver;
}

describe("the deletes the log cannot name are read from their own rows", () => {
  const OWNER = `0x${"11".repeat(20)}`;

  /** The keys of the window whose last remove change is an explicit delete with no typed key, that no row holds. */
  async function oracleUntyped(
    db: SqlDriver,
    stream: string,
    from: number,
    to: number,
  ) {
    const keys = await oracle(db, stream, from, to);
    const out: { pk: string; seq: number }[] = [];
    for (const { pk } of keys) {
      const [held] = await db.query(
        "SELECT 1 FROM records WHERE connection_id = 'c' AND stream = ? AND pk_hash = ?",
        [stream, pk],
      );
      if (held) continue;
      const [last] = await db.query<{
        seq: number;
        explicit_delete: number;
        pk_values: string | null;
      }>(
        `SELECT seq, explicit_delete, pk_values FROM record_changes
          WHERE connection_id = 'c' AND stream = ? AND seq > ? AND seq <= ?
            AND op = 'remove' AND (explicit_delete = 1 OR pk_values IS NOT NULL)
            AND pk_hash = ? ORDER BY seq DESC LIMIT 1`,
        [stream, from, to, pk],
      );
      if (last && last.explicit_delete === 1 && last.pk_values === null)
        out.push({ pk, seq: last.seq });
    }
    return out.sort((a, b) => a.seq - b.seq);
  }

  it("agrees with the grouped scan on random change logs", async () => {
    for (let seed = 1; seed <= 10; seed += 1) {
      const db = await openLocalDb(openBetterSqlite3(":memory:"), {
        owner: OWNER,
        network: "test",
        deviceId: "d",
      });
      drivers.push(db);
      const r = rng(seed * 7);
      const keys = 30 + r.int(300);
      const rows = 1500 + r.int(1500);
      await db.batch([
        {
          sql: "INSERT INTO runs(run_id, connection_id, o, artifact_version, collection_mode, state) VALUES ('r1','c',1,'v','full_refresh','ended')",
        },
        {
          sql: "INSERT INTO run_streams(run_id, stream, delete_snapshot, decision) VALUES ('r1','s0',0,'refused')",
        },
        ...Array.from({ length: rows }, () => {
          const kind = r.int(4);
          return {
            sql: `INSERT INTO record_changes(connection_id, stream, pk_hash, record_key, op, stamp_o, stamp_r, origin, explicit_delete, pk_values)
                  VALUES (?, ?, ?, '[]', ?, ?, ?, ?, ?, ?)`,
            params: [
              r.int(6) === 0 ? "other" : "c",
              `s${r.int(2)}`,
              `h${String(r.int(keys)).padStart(5, "0")}`,
              kind === 0 ? "upsert" : "remove",
              r.int(2) === 0 ? 1 : 2,
              r.int(5) === 0 ? "r1" : "r2",
              ["local", "local", "import", "remote"][r.int(4)]!,
              kind === 1 || kind === 2 ? 1 : 0,
              kind === 2 || kind === 3 ? '["k"]' : null,
            ],
          };
        }),
      ]);
      // A third of the keys are held: no row of theirs is a delete to publish.
      await db.batch(
        Array.from({ length: Math.floor(keys / 3) }, () => {
          const pk = `h${String(r.int(keys)).padStart(5, "0")}`;
          return {
            sql: `INSERT OR IGNORE INTO records(connection_id, stream, pk_hash, record_key, stamp_o, stamp_r, body, body_sha256)
                VALUES ('c', ?, ?, ?, 1, 'r2', '{}', 'x')`,
            params: [`s${r.int(2)}`, pk, pk],
          };
        }),
      );
      const [last] = await db.query<{ n: number }>(
        "SELECT MAX(seq) AS n FROM record_changes",
      );
      for (const [from, to] of [
        [0, last!.n],
        [Math.floor(last!.n / 3), last!.n],
        [Math.floor(last!.n / 4), Math.floor((3 * last!.n) / 4)],
      ] as const)
        for (const stream of ["s0", "s1"]) {
          const found = [];
          for await (const page of untypedDeletePages(
            db,
            "c",
            stream,
            from,
            to,
          )) {
            expect(page.length).toBeLessThanOrEqual(CHANGE_PAGE);
            found.push(...page.map((d) => ({ pk: d.pk, seq: d.seq })));
          }
          expect(found, `seed ${seed} ${stream} ${from}-${to}`).toEqual(
            await oracleUntyped(db, stream, from, to),
          );
        }
    }
  });

  it("is a search of the partial index, not of the window's changes", async () => {
    const plans: string[] = [];
    const raw = openBetterSqlite3(":memory:");
    const db = await openLocalDb(
      watched(raw, (sql, params) => {
        if (sql.includes("d.explicit_delete = 1"))
          plans.push(JSON.stringify([sql, params]));
      }),
      { owner: OWNER, network: "test", deviceId: "d" },
    );
    drivers.push(db);
    for await (const page of untypedDeletePages(db, "c", "s0", 0, 100))
      void page;
    expect(plans).toHaveLength(1);
    const [sql, params] = JSON.parse(plans[0]!) as [string, never[]];
    const plan = await db.query<{ detail: string }>(
      `EXPLAIN QUERY PLAN ${sql}`,
      params,
    );
    const lines = plan.map((row) => row.detail);
    expect(lines.join("\n")).toContain(
      "USING INDEX record_changes_untyped_deletes",
    );
    // The window's changes are not scanned for the delete rows.
    expect(lines.filter((line) => /^SCAN/.test(line))).toEqual([]);
  });

  it("reads no row of the changes still to publish when the stream has no such delete, across the rounds of a replacement", async () => {
    // Every round of a long replacement used to look at every key still to
    // publish before it read any body; a stream with no delete the log
    // cannot name has nothing to find, so it must read none of them.
    let changeRows = 0;
    const w = await world({
      streams: 1,
      partTargetBytes: 20_000,
      database: () =>
        watched(openBetterSqlite3(":memory:"), (sql, _params, rows) => {
          if (sql.includes("record_changes")) changeRows += rows.length;
        }),
    });
    const a = await w.device("a");
    const ids = (from: number, n: number) =>
      Array.from({ length: n }, (_, i) => ({
        stream: sName(0),
        id: `k${from + i}`,
      }));
    await a.run("run-1", ids(0, 3000));
    await a.cycle();
    const before = await a.position();
    changeRows = 0;
    // The replacing run drops 3,000 keys and adds 3,000: 6,000 changes, in
    // many rounds of a 20 KB target.
    await a.run("run-2", ids(10_000, 3000));
    await a.cycle();
    const rounds = (await a.position()) - before;
    expect(rounds).toBeGreaterThan(10);
    // A round reads the pages it needs to fill a segment: a few, whatever
    // the window holds. A sweep of every key still to publish per round reads
    // a page per `CHANGE_PAGE` changes left, 15 pages at the start of this one.
    expect(changeRows / rounds).toBeLessThan(5 * CHANGE_PAGE);
  }, 300_000);
});
