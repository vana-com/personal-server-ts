import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AdditionsSummarySchema } from "../../../core/src/additions/summary.js";
import type { LocalSyncDeps } from "../../../core/src/localdb/deps.js";
import type {
  SqlDriver,
  SqlStatement,
} from "../../../core/src/localdb/driver.js";
import { createLocalHistory } from "../../../core/src/localdb/history.js";
import { mergeIncoming, withOrigin } from "../../../core/src/localdb/merge.js";
import { openLocalDb } from "../../../core/src/localdb/open.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const NOW = Date.parse("2026-03-10T12:00:00.000Z");
const FIRST = Date.parse("2026-03-08T04:59:00.000Z");
const DST = Date.parse("2026-03-08T07:01:00.000Z");
const LATER = Date.parse("2026-03-09T04:01:00.000Z");
const INPUT = { timezone: "America/New_York", days: 4 };
const dirs: string[] = [];
const drivers: SqlDriver[] = [];

afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
  for (const dir of dirs.splice(0))
    rmSync(dir, { recursive: true, force: true });
});

// The pinned PS-1 schema predates first_o. Extend only fresh fixture CREATE
// statements, retaining all PS-1 migrations, triggers and per-connection TEMP
// tables. No production schema changes or ALTER TABLE are needed.
async function fresh(deviceId = "device-a") {
  const dir = mkdtempSync(join(process.cwd(), ".history-additions-"));
  dirs.push(dir);
  const driver = openBetterSqlite3(join(dir, "db.sqlite"));
  drivers.push(driver);
  const db: SqlDriver = {
    ...driver,
    batch: (statements) =>
      driver.batch(
        statements.map((statement) => {
          const needsFirstSeen =
            /^CREATE (?:TEMP )?TABLE (?:IF NOT EXISTS )?(?:records|incoming) \(/.test(
              statement.sql,
            ) && !/\bfirst_o\b/.test(statement.sql);
          return needsFirstSeen
            ? {
                ...statement,
                sql: statement.sql.replace(
                  "body TEXT",
                  "first_o INTEGER, body TEXT",
                ),
              }
            : statement;
        }),
      ),
  };
  return openLocalDb(db, {
    owner: "0xabc",
    network: "test-network",
    deviceId,
  });
}

function history(db: SqlDriver, behind?: (id: string) => boolean) {
  // Unused PS-2 ports are deliberate stubs: additions must only read the DB.
  const forbidden = new Proxy(
    {},
    {
      get: () => {
        throw new Error("history read used a non-database port");
      },
    },
  );
  const deps = {
    db,
    now: () => NOW,
    queue: forbidden,
    registry: forbidden,
    blobs: forbidden,
    keys: forbidden,
    signer: forbidden,
    logger: forbidden,
    newOp: () => {
      throw new Error("history read allocated an operation");
    },
    ownerAddress: "0xabc",
  } as unknown as LocalSyncDeps;
  return createLocalHistory(deps, {
    olderVersionReads: () => true,
    ...(behind ? { behind } : {}),
  });
}

async function connection(
  db: SqlDriver,
  id = "c1",
  state = "active",
  connector = "source",
  stream = "events",
  version = 7,
) {
  await db.batch([
    {
      sql: "INSERT INTO connections(connection_id,connector,ns,control_state) VALUES (?,?,?,?)",
      params: [id, connector, "", state],
    },
    {
      sql: "INSERT INTO stream_state(connection_id,stream,primary_key,semantics,incremental,head_version) VALUES (?,?,?,'mutable_state',0,?)",
      params: [id, stream, '["id"]', version],
    },
  ]);
}

type Incoming = {
  key: string;
  first: number | null;
  stamp?: number;
  run?: string;
};

// Only the absent first_o INSERT projection is supplied by this fixture.
// Conflict resolution, update selection and staging cleanup remain PS-1's
// actual mergeIncoming statements. Newer first_o-aware merges need no adapter.
function mergeStatements(op: string, id: string): SqlStatement[] {
  return mergeIncoming(op, id).map((statement) => {
    if (
      !/^INSERT INTO records /.test(statement.sql) ||
      /\bfirst_o\b/.test(statement.sql)
    ) {
      return statement;
    }
    return {
      ...statement,
      sql: statement.sql
        .replace("body_sha256)", "body_sha256, first_o)")
        .replace(
          "i.body_sha256 FROM incoming",
          "i.body_sha256, i.first_o FROM incoming",
        ),
    };
  });
}

async function collect(
  db: SqlDriver,
  rows: Incoming[],
  id = "c1",
  stream = "events",
  op = "run-a",
  remote = false,
) {
  await db.batch(
    withOrigin(remote ? "remote" : "local", [
      ...rows.map((row): SqlStatement => ({
        sql: "INSERT INTO incoming(op,stream,pk_hash,record_key,stamp_o,stamp_r,body,body_sha256,first_o) VALUES (?,?,?,?,?,?,'{}','sha',?)",
        params: [
          op,
          stream,
          row.key,
          row.key,
          row.stamp ?? row.first ?? NOW,
          row.run ?? op,
          row.first,
        ],
      })),
      ...mergeStatements(op, id),
    ]),
  );
}

describe("local history additions", () => {
  it("invalid-additions-days-are-client-errors-before-any-query", async () => {
    const db = await fresh();
    const query = vi.spyOn(db, "query");
    const reader = history(db);
    for (const days of [0, -1, 32, 999, 1.5, Number.NaN, Infinity]) {
      await expect(
        reader.additions({ timezone: "UTC", days }),
      ).rejects.toMatchObject({ code: 400 });
    }
    expect(query).not.toHaveBeenCalled();
  });

  it("additions-total-counts-rows-of-active-connections", async () => {
    const db = await fresh();
    await connection(db);
    await connection(db, "c2", "active", "source", "events", 9);
    await connection(db, "c3", "active", "other", "items", 2);
    await connection(db, "c4", "deleted");
    await connection(db, "c5", "absent");
    await connection(db, "c6", "foreign");
    await connection(db, "empty", "active", "empty", "items", 4);
    await collect(db, [
      { key: "a", first: FIRST },
      { key: "b", first: DST },
    ]);
    await collect(db, [{ key: "a", first: FIRST }], "c2");
    await collect(db, [{ key: "a", first: DST }], "c3", "items");
    for (const id of ["c4", "c5", "c6", "orphan"]) {
      await collect(db, [{ key: "hidden", first: FIRST }], id);
    }
    // A stale published record_count must never stand in for current rows.
    await db.batch([
      {
        sql: "INSERT INTO stream_versions(connection_id,stream,version,generation,head_blob,head_format,record_count,observed_at,complete,kind) VALUES ('c1','events',7,1,'blob',3,999,?,1,'published')",
        params: [NOW],
      },
    ]);
    const behind = vi.fn((id: string) => id === "empty");
    const result = await history(db, behind).additions(INPUT);
    expect(
      result.total,
      "total counts active current rows, not version record_count",
    ).toBe(4);
    expect(result.scopes.map(({ scope, total }) => [scope, total])).toEqual([
      ["empty.items", 0],
      ["other.items", 1],
      ["source.events", 3],
    ]);
    expect(result.through).toEqual({
      "empty.items": "4",
      "other.items": "2",
      "source.events": "9",
    });
    expect(result.coverage).toBe("behind");
    expect(behind.mock.calls.flat()).not.toContain("c4");
    expect(await history(db).additions(INPUT)).toMatchObject({
      coverage: "complete",
    });
  });

  it("additions-days-use-first-seen-in-local-tz", async () => {
    const db = await fresh();
    await connection(db);
    const old = Date.parse("2026-02-27T00:01:00.000Z");
    const cutoff = Date.parse("2026-02-28T00:00:00.000Z");
    await collect(db, [
      { key: "old", first: old },
      { key: "cutoff", first: cutoff },
      { key: "before", first: FIRST },
      { key: "spring-before", first: Date.parse("2026-03-08T06:59:00.000Z") },
      { key: "spring-after", first: DST },
      { key: "next", first: LATER },
    ]);
    const result = await history(db).additions({ ...INPUT, days: 14 });
    expect(result.days).toHaveLength(14);
    expect(result.days[0]).toEqual({ date: "2026-02-25", added: 0 });
    expect(result.days.find((day) => day.date === "2026-02-26")).toEqual({
      date: "2026-02-26",
      added: 1,
    });
    expect(
      result.days.slice(-4),
      "DST calendar dates use first_o in the requested timezone",
    ).toEqual([
      { date: "2026-03-07", added: 1 },
      { date: "2026-03-08", added: 2 },
      { date: "2026-03-09", added: 1 },
      { date: "2026-03-10", added: 0 },
    ]);
    expect(result.fineSince).toBe("2026-02-28T00:00:00.000Z");
    expect(result.daily).toEqual([{ date: "2026-02-27", added: 1 }]);
    expect(result.buckets).toEqual([
      { start: "2026-02-28T00:00:00.000Z", added: 1 },
      { start: "2026-03-08T04:45:00.000Z", added: 1 },
      { start: "2026-03-08T06:45:00.000Z", added: 1 },
      { start: "2026-03-08T07:00:00.000Z", added: 1 },
      { start: "2026-03-09T04:00:00.000Z", added: 1 },
    ]);
    expect(result.trackedSince).toBe(new Date(old).toISOString());
    expect(result.scopes[0]).toMatchObject({
      daily: result.daily,
      buckets: result.buckets,
      trackedSince: result.trackedSince,
    });
  });

  it("additions-fresh-device-equals-warm", async () => {
    const a = await fresh("device-a");
    const b = await fresh("device-b");
    await connection(a);
    await connection(b);
    for (const [key, first] of [
      ["a", FIRST],
      ["b", DST],
      ["c", LATER],
    ] as const) {
      await collect(a, [{ key, first }], "c1", "events", `collect-${key}`);
    }
    const incoming = await a.query<{
      key: string;
      first: number | null;
      stamp: number;
      run: string;
    }>(
      "SELECT pk_hash AS key, first_o AS first, stamp_o AS stamp, stamp_r AS run FROM records",
    );
    // B has never collected anything. Its only rows arrive through PS-1 merge.
    await collect(b, incoming, "c1", "events", "apply-a", true);
    const warm = await history(a).additions(INPUT);
    const freshResult = await history(b).additions(INPUT);
    expect(
      freshResult,
      "incoming first_o gives the same summary at the same frontier",
    ).toEqual(warm);
    expect(freshResult.total).toBe(3);
    expect(freshResult.days).toEqual([
      { date: "2026-03-07", added: 1 },
      { date: "2026-03-08", added: 1 },
      { date: "2026-03-09", added: 1 },
      { date: "2026-03-10", added: 0 },
    ]);
    expect(freshResult.buckets).toEqual([
      { start: "2026-03-08T04:45:00.000Z", added: 1 },
      { start: "2026-03-08T07:00:00.000Z", added: 1 },
      { start: "2026-03-09T04:00:00.000Z", added: 1 },
    ]);
    expect(freshResult.through).toEqual({ "source.events": "7" });
  });

  it("additions-recollect-not-new", async () => {
    const db = await fresh();
    await connection(db);
    await collect(db, [{ key: "a", first: FIRST }]);
    await collect(
      db,
      [{ key: "a", first: LATER, stamp: LATER }],
      "c1",
      "events",
      "run-b",
    );
    const result = await history(db).additions(INPUT);
    expect(result.total).toBe(1);
    expect(result.days, "newer stamps do not move the first-seen day").toEqual([
      { date: "2026-03-07", added: 1 },
      { date: "2026-03-08", added: 0 },
      { date: "2026-03-09", added: 0 },
      { date: "2026-03-10", added: 0 },
    ]);
    expect(result.trackedSince).toBe(new Date(FIRST).toISOString());
  });

  it("additions-delete-removes-contribution-at-once", async () => {
    const db = await fresh();
    await connection(db);
    await connection(db, "c2", "active", "other");
    await collect(db, [{ key: "a", first: FIRST }]);
    await collect(db, [{ key: "b", first: DST }], "c2");
    const reader = history(db);
    expect(await reader.additions(INPUT)).toMatchObject({ total: 2 });
    await db.batch([
      { sql: "DELETE FROM records WHERE connection_id = 'c1'" },
      { sql: "DELETE FROM connections WHERE connection_id = 'c1'" },
    ]);
    const removed = await reader.additions(INPUT);
    expect(removed.total).toBe(1);
    expect(
      removed.days[0],
      "deleting rows and control drops their day in the same batch",
    ).toEqual({ date: "2026-03-07", added: 0 });
    expect(removed.through).toEqual({ "other.events": "7" });
    // A retained row with a deleted control state is invisible immediately too.
    await db.batch([
      {
        sql: "UPDATE connections SET control_state = 'deleted' WHERE connection_id = 'c2'",
      },
    ]);
    const deleted = await reader.additions(INPUT);
    expect(
      deleted.total,
      "deleted control rows contribute zero even before cleanup",
    ).toBe(0);
    expect(deleted.days.every((day) => day.added === 0)).toBe(true);
    expect(deleted.scopes).toEqual([]);
    expect(deleted.through).toEqual({});
    expect(deleted.trackedSince).toBeNull();
  });

  it("additions-unknown-first-seen-is-total-only", async () => {
    const db = await fresh();
    await connection(db);
    await collect(db, [{ key: "unknown", first: null }]);
    const result = await history(db).additions(INPUT);
    expect(result.total).toBe(1);
    expect(
      result.days.every((day) => day.added === 0),
      "unknown first_o must not become today's arrival",
    ).toBe(true);
    expect(result.buckets).toEqual([]);
    expect(result.daily).toEqual([]);
    expect(result.trackedSince).toBeNull();
    expect(result.partial).toBe(false);
    expect(result.scopes).toEqual([
      {
        scope: "source.events",
        total: 1,
        daily: [],
        buckets: [],
        trackedSince: null,
        partial: false,
      },
    ]);
  });

  it("additions-matches-v1-schema", async () => {
    const db = await fresh();
    await connection(db);
    await collect(db, [
      { key: "a", first: FIRST },
      { key: "unknown", first: null },
    ]);
    const reader = history(db);
    expect(typeof reader.versions).toBe("function");
    expect(typeof reader.lineage).toBe("function");
    const result = await reader.additions(INPUT);
    expect(
      AdditionsSummarySchema.safeParse(result).success,
      "additions keeps the version-1 transport contract",
    ).toBe(true);
    expect(AdditionsSummarySchema.parse(result)).toEqual(result);
    expect(result).not.toHaveProperty("inventory");
  });
});
