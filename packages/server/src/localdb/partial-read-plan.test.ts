// The page query of a partial body reads the key index in order and stops
// after the page. Real SQLite and the real schema; the rows are seeded
// directly, so each case sets exactly the state the query decides on.
import { afterEach, describe, expect, it } from "vitest";
import type { SqlDriver } from "../../../core/src/localdb/driver.js";
import { openLocalDb } from "../../../core/src/localdb/open.js";
import {
  partialPage,
  type PartialHead,
} from "../../../core/src/localdb/partial-read.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
});

/** The page query as it was before it read the key index in order: the reference the new one must match. */
function legacyPage(head: PartialHead, after: string | undefined) {
  const { params } = partialPage(head, after);
  return {
    params,
    sql: `WITH g AS (SELECT (
         (EXISTS (SELECT 1 FROM stream_partial p WHERE p.connection_id = ? AND p.stream = ?
                    AND p.version = ? AND p.generation = ? AND p.data_hash = ?)
          OR EXISTS (SELECT 1 FROM stream_state s WHERE s.connection_id = ? AND s.stream = ?
                    AND s.complete = 1 AND s.head_version = ? AND s.head_generation = ? AND s.head_data_hash = ?))
         AND EXISTS (SELECT 1 FROM connections c WHERE c.connection_id = ? AND c.generation = ?
                    AND c.control_state = 'active' AND c.deleted_at IS NULL
                    AND NOT EXISTS (SELECT 1 FROM delete_intents d WHERE d.connector = c.connector))) AS ok)
       SELECT g.ok AS ok, r.pk_hash AS pk_hash, r.body AS body
       FROM g LEFT JOIN records r ON g.ok = 1 AND r.connection_id = ? AND r.stream = ?
         AND NOT EXISTS (SELECT 1 FROM partial_hidden h WHERE h.connection_id = r.connection_id
                           AND h.stream = r.stream AND h.pk_hash = r.pk_hash)
         ${after === undefined ? "" : "AND r.pk_hash > ?"}
       ORDER BY r.pk_hash LIMIT ?`,
  };
}

const HEAD: PartialHead = {
  connectionId: "c1",
  generation: 1,
  stream: "items",
  version: 1,
  dataHash: "h1",
};

const hex = (n: number) => `0x${n.toString(16).padStart(8, "0")}`;

async function open() {
  const db = await openLocalDb(openBetterSqlite3(":memory:"), {
    owner: "0xabc",
    network: "test",
    deviceId: "partial-read-plan",
  });
  drivers.push(db);
  await db.batch([
    // Records of one key but two hashes are what a remote part may hold.
    { sql: "UPDATE write_ctx SET origin = 'remote'" },
    {
      sql: "INSERT INTO connections(connection_id,connector,ns,generation,control_state,control_version) VALUES ('c1','fixture-source','',1,'active',1),('c2','other-source','',1,'active',1)",
    },
    {
      sql: "INSERT INTO stream_partial(connection_id,stream,version,generation,data_hash,head_blob,observed_at,parts_applied,parts_total,records_total) VALUES ('c1','items',1,1,'h1','b',1,1,2,2)",
    },
  ]);
  return db;
}

/**
 * `count` records of `stream`, whose key hashes are a permutation of 0..count-1
 * and whose observation order runs against them, so an access path in
 * observation order is not one in key order. Every record shares its
 * `record_key` and stamps with its neighbour: ties the key order alone breaks.
 */
async function seed(
  db: SqlDriver,
  connectionId: string,
  stream: string,
  count: number,
) {
  const statements = Array.from({ length: count }, (_, i) => {
    const k = (i * 7919) % count; // a permutation when 7919 is coprime with count
    return {
      sql: "INSERT INTO records(connection_id,stream,pk_hash,record_key,stamp_o,stamp_r,body,body_sha256,seen_o,body_bytes) VALUES (?,?,?,?,?,?,?,?,?,?)",
      params: [
        connectionId,
        stream,
        hex(k),
        `key-${Math.floor(i / 2)}`,
        count - i,
        "r",
        JSON.stringify({ id: k, text: `body ${k}` }),
        "sha",
        count - i,
        20,
      ],
    };
  });
  for (let at = 0; at < statements.length; at += 500)
    await db.batch(statements.slice(at, at + 500));
}

type PlanStep = { id: number; parent: number; detail: string };

async function plan(
  db: SqlDriver,
  sql: string,
  params: readonly (string | number)[],
) {
  return db.query<PlanStep>(`EXPLAIN QUERY PLAN ${sql}`, params);
}

type Page = { ok: number; pk_hash: string | null; body: string | null };

/** Every page of a body, as the pages and cursors the reader would ask for. */
async function chain(
  db: SqlDriver,
  head: PartialHead,
  page: typeof partialPage,
) {
  const pages: Page[][] = [];
  const cursors: (string | undefined)[] = [];
  let after: string | undefined;
  for (;;) {
    const { sql, params } = page(head, after);
    const rows = await db.query<Page>(sql, params);
    cursors.push(after);
    pages.push(rows);
    const kept = rows.filter((row) => row.pk_hash !== null);
    if (rows[0]?.ok !== 1 || kept.length < 100) return { pages, cursors };
    after = kept[kept.length - 1]!.pk_hash!;
  }
}

describe("the page query of a partial body", () => {
  it.each([
    ["the first page", undefined],
    ["a later page", hex(41)],
  ])(
    "%s reads the key index in order, and sorts no more than the page",
    async (_name, after) => {
      const db = await open();
      await seed(db, "c1", "items", 250);
      const { sql, params } = partialPage(HEAD, after);
      const steps = await plan(db, sql, params);
      const rows = steps.filter((s) => /\b(SEARCH|SCAN) r\b/.test(s.detail));
      // The rows of the stream are read in one place: the subquery that takes
      // the page, which the plan names as the materialization of `r`.
      const page = steps.find((s) => s.detail === "MATERIALIZE r");
      expect(page).toBeDefined();
      const inPage = (step: PlanStep) => step.parent === page!.id;
      const reads = rows.filter(inPage);
      expect(reads).toHaveLength(1);
      expect(reads[0]!.detail).toMatch(/^SEARCH r USING /);
      // That read is not sorted: the sort the plan shows is a step of the
      // statement itself, which orders what the subquery produced (the page).
      expect(
        steps.filter((s) => inPage(s) && /TEMP B-TREE/.test(s.detail)),
      ).toEqual([]);
      expect(
        steps.filter((s) => /records_by_observation/.test(s.detail)),
      ).toEqual([]);
      expect(steps.filter((s) => /records_by_key/.test(s.detail))).toEqual([]);
      // The index it reads leads with the connection, the stream and the key
      // hash, so its entries come in the order the page is asked for.
      const index = /USING (?:COVERING )?INDEX (\w+)/.exec(
        reads[0]!.detail,
      )?.[1];
      expect(index).toBeDefined();
      const columns = (
        await db.query<{ seqno: number; name: string | null; key: number }>(
          `PRAGMA index_xinfo(${index})`,
        )
      )
        .filter((column) => column.key === 1)
        .sort((x, y) => x.seqno - y.seqno)
        .map((column) => column.name);
      expect(columns.slice(0, 3)).toEqual([
        "connection_id",
        "stream",
        "pk_hash",
      ]);
    },
  );
});

describe("the page query against the one it replaces", () => {
  const states = [
    ["a stream of 250 records", 250, async () => {}],
    ["a stream of exactly one page", 100, async () => {}],
    ["a stream of one page and one record", 101, async () => {}],
    ["a stream of one record", 1, async () => {}],
    ["an empty stream", 0, async () => {}],
    [
      "rows hidden until a part holds their key",
      250,
      async (db: SqlDriver) => {
        await db.batch([
          {
            sql: "INSERT INTO partial_hidden(connection_id,stream,pk_hash) SELECT connection_id,stream,pk_hash FROM records WHERE connection_id='c1' AND stream='items' AND rowid % 3 = 0",
          },
        ]);
      },
    ],
    [
      "records deleted after they were written",
      250,
      async (db: SqlDriver) => {
        await db.batch([
          {
            sql: "DELETE FROM records WHERE connection_id='c1' AND stream='items' AND rowid % 5 = 0",
          },
        ]);
      },
    ],
    [
      "a head that already completed",
      250,
      async (db: SqlDriver) => {
        await db.batch([
          {
            sql: "INSERT INTO stream_state(connection_id,stream,primary_key,semantics,incremental,complete,head_version,head_generation,head_data_hash) VALUES ('c1','items','[\"id\"]','mutable_state',0,1,1,1,'h1')",
          },
          { sql: "DELETE FROM stream_partial" },
        ]);
      },
    ],
    [
      "a head that moved",
      250,
      async (db: SqlDriver) => {
        await db.batch([{ sql: "UPDATE stream_partial SET data_hash = 'h2'" }]);
      },
    ],
    [
      "a connection of a later generation",
      250,
      async (db: SqlDriver) => {
        await db.batch([
          {
            sql: "UPDATE connections SET generation = 2 WHERE connection_id = 'c1'",
          },
        ]);
      },
    ],
    [
      "a connection with a delete intent",
      250,
      async (db: SqlDriver) => {
        await db.batch([
          {
            sql: "INSERT INTO delete_intents(connector,delete_id,intent) VALUES ('fixture-source','d','x')",
          },
        ]);
      },
    ],
    [
      "a deleted connection",
      250,
      async (db: SqlDriver) => {
        await db.batch([
          {
            sql: "UPDATE connections SET control_state = 'deleted', deleted_at = 5 WHERE connection_id = 'c1'",
          },
        ]);
      },
    ],
  ] as const;

  it.each(states)(
    "%s: the same rows, in the same order, at the same cursors",
    async (_name, count, change) => {
      const db = await open();
      await seed(db, "c1", "items", count);
      // The same key hashes in another stream and in another connection.
      await seed(db, "c1", "other", 120);
      await seed(db, "c2", "items", 130);
      await change(db);
      const before = await chain(db, HEAD, legacyPage);
      const now = await chain(db, HEAD, partialPage);
      expect(now.cursors).toEqual(before.cursors);
      expect(now.pages).toEqual(before.pages);
    },
  );

  it.each(states)(
    "%s: with the engine free to reverse an unordered scan, the same rows in the same order",
    async (_name, count, change) => {
      const db = await open();
      await seed(db, "c1", "items", count);
      await seed(db, "c1", "other", 120);
      await seed(db, "c2", "items", 130);
      await change(db);
      const before = await chain(db, HEAD, legacyPage);
      // A scan with no ORDER BY runs backwards: an order a statement leaves to
      // the engine is the order this makes wrong.
      await db.query("PRAGMA reverse_unordered_selects = ON");
      const now = await chain(db, HEAD, partialPage);
      expect(now.cursors).toEqual(before.cursors);
      expect(now.pages).toEqual(before.pages);
    },
  );

  it("serves every row of a stream once, in key order, across pages", async () => {
    const db = await open();
    await seed(db, "c1", "items", 250);
    const { pages } = await chain(db, HEAD, partialPage);
    const served = pages.flat().filter((row) => row.pk_hash !== null);
    expect(served.map((row) => row.pk_hash)).toEqual(
      Array.from({ length: 250 }, (_, i) => hex(i)),
    );
    expect(pages.map((page) => page.length)).toEqual([100, 100, 50]);
  });
});
