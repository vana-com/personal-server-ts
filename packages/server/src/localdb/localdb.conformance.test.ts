import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  applyDelete,
  connectionQueue,
  LocalDbIdentityMismatch,
  LocalDbTooNew,
  localDatabaseName,
  mergeIncoming,
  openLocalDb,
  replaceDelete,
  withOrigin,
  type SqlDriver,
  type WriteOrigin,
} from "@opendatalabs/personal-server-ts-core/localdb";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { openSqlite3Cli } from "./sqlite3-cli-driver.test-utils.js";

// One suite, run per driver. The 3.22.0 row (Android 9's SQLite) runs only when
// LOCALDB_SQLITE3_CLI names a 3.22.0 `sqlite3` shell; CI builds one.
const CLI = process.env.LOCALDB_SQLITE3_CLI;
const rows: [string, (file: string) => SqlDriver][] = [
  ["node", (file) => openBetterSqlite3(file)],
  ...(CLI
    ? [
        ["node-sqlite-3.22.0", (file: string) => openSqlite3Cli(CLI, file)] as [
          string,
          (file: string) => SqlDriver,
        ],
      ]
    : []),
];
const ID = { owner: "0xAbC", network: "moksha", deviceId: "dev-1" };

describe.each(rows)("local database on %s", (row, factory) => {
  const dirs: string[] = [];
  const open: SqlDriver[] = [];
  const fresh = async () => {
    const dir = mkdtempSync(join(tmpdir(), "localdb-"));
    dirs.push(dir);
    const file = join(dir, "db.sqlite");
    const driver = factory(file);
    open.push(driver);
    return { file, driver, db: await openLocalDb(driver, ID) };
  };
  afterEach(async () => {
    for (const d of open.splice(0)) await d.close().catch(() => undefined);
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  });

  const write = (
    db: SqlDriver,
    origin: WriteOrigin,
    ...sql: { sql: string; params?: (string | number)[] }[]
  ) => db.batch(withOrigin(origin, sql));
  const stage = (
    op: string,
    pk: string,
    key: string,
    o: number,
    r: string,
    body = "{}",
  ) => ({
    sql: "INSERT INTO incoming (op, stream, pk_hash, record_key, stamp_o, stamp_r, body, body_sha256) VALUES (?, 's', ?, ?, ?, ?, ?, ?)",
    params: [op, pk, key, o, r, body, `sha-${body}`],
  });
  const merge = (
    db: SqlDriver,
    origin: WriteOrigin,
    op: string,
    ...rowsIn: ReturnType<typeof stage>[]
  ) => db.batch(withOrigin(origin, [...rowsIn, ...mergeIncoming(op, "c1")]));
  const keys = async (db: SqlDriver) =>
    (
      await db.query<{ k: string }>(
        "SELECT pk_hash AS k FROM records ORDER BY pk_hash",
      )
    ).map((r) => r.k);
  const log = async (db: SqlDriver) =>
    db.query<{ pk_hash: string; op: string; origin: string }>(
      "SELECT pk_hash, op, origin FROM record_changes ORDER BY seq",
    );
  const seedConnection = (db: SqlDriver) =>
    db.batch([
      {
        sql: "INSERT INTO connections(connection_id, connector, ns, control_state) VALUES ('c1','k','','active')",
      },
      {
        sql: "INSERT INTO stream_state(connection_id, stream, primary_key, semantics, incremental) VALUES ('c1','s','[\"id\"]','mutable_state',0)",
      },
    ]);

  it("reports the SQLite it runs on", async () => {
    const { driver } = await fresh();
    if (row.endsWith("3.22.0"))
      expect(driver.info.sqliteVersion).toBe("3.22.0");
    const [v] = await driver.query<{ v: string }>(
      "SELECT sqlite_version() AS v",
    );
    expect(v?.v).toMatch(/^3\./);
  });

  describe("name, migration and identity", () => {
    it("names the file by network and a hash of the lowercased owner", () => {
      expect(localDatabaseName("0xAbC", "moksha")).toBe(
        localDatabaseName("0xabc", "moksha"),
      );
      expect(localDatabaseName("0xabc", "moksha")).toMatch(
        /^vana-moksha-[0-9a-f]{32}$/,
      );
      expect(localDatabaseName("0xabc", "mainnet")).not.toBe(
        localDatabaseName("0xabc", "moksha"),
      );
    });

    it("migrates a new file to version 1 and keeps data on reopen", async () => {
      const { file, driver, db } = await fresh();
      expect(await db.query("PRAGMA user_version")).toEqual([
        { user_version: 1 },
      ]);
      await seedConnection(db);
      await driver.close();
      open.pop();
      const again = factory(file);
      open.push(again);
      await openLocalDb(again, ID);
      expect(
        await again.query("SELECT connection_id FROM connections"),
      ).toEqual([{ connection_id: "c1" }]);
    });

    it("refuses a file written by a newer build", async () => {
      const { file, driver } = await fresh();
      await driver.batch([{ sql: "PRAGMA user_version = 99" }]);
      await driver.close();
      open.pop();
      const again = factory(file);
      open.push(again);
      await expect(openLocalDb(again, ID)).rejects.toBeInstanceOf(
        LocalDbTooNew,
      );
    });

    it("refuses a file that belongs to another owner or network", async () => {
      const { file, driver } = await fresh();
      await driver.close();
      open.pop();
      const again = factory(file);
      open.push(again);
      await expect(
        openLocalDb(again, { ...ID, owner: "0xother" }),
      ).rejects.toBeInstanceOf(LocalDbIdentityMismatch);
      await expect(
        openLocalDb(again, { ...ID, network: "mainnet" }),
      ).rejects.toBeInstanceOf(LocalDbIdentityMismatch);
      await expect(openLocalDb(again, { ...ID, owner: "0xABC" })).resolves.toBe(
        again,
      );
    });

    it("rolls a failing batch back as a whole", async () => {
      const { db } = await fresh();
      await expect(
        db.batch([
          {
            sql: "INSERT INTO connections(connection_id, connector, ns) VALUES ('c1','k','')",
          },
          {
            sql: "INSERT INTO connections(connection_id, connector, ns) VALUES ('c1','k','')",
          },
        ]),
      ).rejects.toThrow();
      expect(await db.query("SELECT count(*) AS n FROM connections")).toEqual([
        { n: 0 },
      ]);
    });
  });

  describe("merge pair", () => {
    it("lets a strictly newer stamp win and ignores equal, older and replayed rows without logging", async () => {
      const { db } = await fresh();
      await seedConnection(db);
      await merge(
        db,
        "local",
        "m",
        stage("m", "aa01", "1", 1000, "run-a", '{"v":"a"}'),
      );
      expect(await log(db)).toHaveLength(1);
      await merge(
        db,
        "local",
        "m",
        stage("m", "aa01", "1", 1000, "run-a", '{"v":"x"}'),
      );
      await merge(
        db,
        "local",
        "m",
        stage("m", "aa01", "1", 999, "run-z", '{"v":"x"}'),
      );
      await merge(
        db,
        "local",
        "m",
        stage("m", "aa01", "1", 1000, "run-0", '{"v":"x"}'),
      );
      expect(await db.query("SELECT body FROM records")).toEqual([
        { body: '{"v":"a"}' },
      ]);
      expect(await log(db)).toHaveLength(1);

      await merge(
        db,
        "local",
        "m",
        stage("m", "aa01", "1", 1000, "run-b", '{"v":"b"}'),
      );
      expect(await db.query("SELECT body, stamp_r FROM records")).toEqual([
        { body: '{"v":"b"}', stamp_r: "run-b" },
      ]);
      await merge(
        db,
        "local",
        "m",
        stage("m", "aa01", "1", 1001, "run-0", '{"v":"c"}'),
      );
      expect(await db.query("SELECT body FROM records")).toEqual([
        { body: '{"v":"c"}' },
      ]);
      expect(await log(db)).toHaveLength(3);
    });

    it("clears the operation's staged rows", async () => {
      const { db } = await fresh();
      await seedConnection(db);
      await merge(db, "local", "m", stage("m", "aa01", "1", 1, "r"));
      expect(await db.query("SELECT count(*) AS n FROM incoming")).toEqual([
        { n: 0 },
      ]);
    });
  });

  describe('key collisions (typed keys 1 and "1" share a record_key)', () => {
    it("aborts a local write that reuses a record_key under another pk_hash", async () => {
      const { db } = await fresh();
      await seedConnection(db);
      await merge(db, "local", "m", stage("m", "aa01", "1", 1, "r"));
      for (const origin of ["local", "import", "refresh"] as const) {
        await expect(
          merge(db, origin, "m", stage("m", "bb02", "1", 2, "r")),
        ).rejects.toThrow(/key_type_conflict/);
      }
      expect(await keys(db)).toEqual(["aa01"]);
    });

    it("keeps both rows when a remote apply brings the colliding key", async () => {
      const { db } = await fresh();
      await seedConnection(db);
      await merge(db, "local", "m", stage("m", "aa01", "1", 1, "r"));
      await merge(db, "remote", "m", stage("m", "bb02", "1", 2, "r"));
      expect(await keys(db)).toEqual(["aa01", "bb02"]);
    });
  });

  describe("trigger origins", () => {
    it("copies the batch's origin into the change log for insert, update and delete", async () => {
      const { db } = await fresh();
      await seedConnection(db);
      await merge(db, "import", "m", stage("m", "aa01", "1", 1, "r"));
      await merge(db, "remote", "m", stage("m", "aa01", "1", 2, "r"));
      await write(db, "purge", {
        sql: "DELETE FROM records WHERE pk_hash = 'aa01'",
      });
      expect(await log(db)).toEqual([
        { pk_hash: "aa01", op: "upsert", origin: "import" },
        { pk_hash: "aa01", op: "upsert", origin: "remote" },
        { pk_hash: "aa01", op: "remove", origin: "purge" },
      ]);
    });

    it("refuses an origin outside the five names", async () => {
      const { db } = await fresh();
      await expect(
        db.batch([{ sql: "UPDATE write_ctx SET origin = 'other'" }]),
      ).rejects.toThrow();
    });

    it("drops a deleted row's blob references", async () => {
      const { db } = await fresh();
      await seedConnection(db);
      await merge(db, "local", "m", stage("m", "aa01", "1", 1, "r"));
      await db.batch([
        { sql: "INSERT INTO blob_refs VALUES ('b1','c1','s','aa01')" },
      ]);
      await write(db, "purge", { sql: "DELETE FROM records" });
      expect(await db.query("SELECT count(*) AS n FROM blob_refs")).toEqual([
        { n: 0 },
      ]);
    });
  });

  describe("operation-scoped TEMP rows", () => {
    it("merges and clears only its own operation's staged rows", async () => {
      const { db } = await fresh();
      await seedConnection(db);
      await db.batch(
        withOrigin("local", [
          stage("a", "aa01", "1", 1, "r"),
          stage("b", "bb02", "2", 1, "r"),
        ]),
      );
      await db.batch(withOrigin("local", mergeIncoming("b", "c1")));
      expect(await keys(db)).toEqual(["bb02"]);
      expect(await db.query("SELECT op FROM incoming")).toEqual([{ op: "a" }]);
    });

    it("lets a second apply clear its keys without emptying the first's", async () => {
      const { db } = await fresh();
      await seedConnection(db);
      await merge(db, "remote", "x", stage("x", "aa01", "1", 1, "r"));
      await db.batch([
        { sql: "INSERT INTO temp.apply_keys VALUES ('a', 'aa01')" },
        { sql: "INSERT INTO temp.apply_keys VALUES ('b', 'zz99')" },
      ]);
      await db.batch(withOrigin("remote", applyDelete("b", "c1", "s")));
      expect(await keys(db)).toEqual([]);
      await merge(db, "remote", "x", stage("x", "aa01", "1", 2, "r"));
      await db.batch(withOrigin("remote", applyDelete("a", "c1", "s")));
      expect(await keys(db)).toEqual(["aa01"]);
    });
  });

  describe("apply delete shape", () => {
    it("removes rows the head lacks, keeps unchanged-part ranges and unpublished local rows", async () => {
      const { db } = await fresh();
      await seedConnection(db);
      await merge(
        db,
        "local",
        "m",
        stage("m", "aa01", "1", 1, "r"),
        stage("m", "bb02", "2", 1, "r"),
        stage("m", "d001", "3", 1, "r"),
      );
      await db.batch([
        {
          sql: "UPDATE stream_state SET publish_watermark = (SELECT max(seq) FROM record_changes)",
        },
      ]);
      await merge(db, "local", "m", stage("m", "ee05", "5", 2, "r"));
      await db.batch([
        {
          sql: "INSERT INTO temp.apply_keys VALUES ('a1','aa01'), ('a1','cc03')",
        },
        { sql: "INSERT INTO temp.keep_ranges VALUES ('a1','d','e')" },
      ]);
      await db.batch(withOrigin("remote", applyDelete("a1", "c1", "s")));
      expect(await keys(db)).toEqual(["aa01", "d001", "ee05"]);
      expect(
        await db.query("SELECT count(*) AS n FROM temp.apply_keys"),
      ).toEqual([{ n: 0 }]);
      expect((await log(db)).filter((l) => l.op === "remove")).toEqual([
        { pk_hash: "bb02", op: "remove", origin: "remote" },
      ]);
    });

    it("scopes the delete to its own connection and stream", async () => {
      const { db } = await fresh();
      await seedConnection(db);
      await merge(db, "local", "m", stage("m", "aa01", "1", 1, "r"));
      await db.batch(
        withOrigin("remote", applyDelete("a1", "c1", "other-stream")),
      );
      await db.batch(withOrigin("remote", applyDelete("a1", "c2", "s")));
      expect(await keys(db)).toEqual(["aa01"]);
    });
  });

  describe("replace after the CAS", () => {
    it("drops rows stamped below the run's stamp and keeps the run's own and newer rows", async () => {
      const { db } = await fresh();
      await seedConnection(db);
      await merge(
        db,
        "local",
        "m",
        stage("m", "aa01", "1", 1000, "run-a"),
        stage("m", "bb02", "2", 5000, "run-d"),
        stage("m", "cc03", "3", 5000, "run-e"),
        stage("m", "dd04", "4", 6000, "run-f"),
      );
      await write(db, "refresh", {
        ...replaceDelete("c1", "s", 5000, "run-e"),
      });
      expect(await keys(db)).toEqual(["cc03", "dd04"]);
      expect(
        (await log(db)).filter((l) => l.op === "remove").map((l) => l.origin),
      ).toEqual(["refresh", "refresh"]);
    });
  });
});

describe("connection queue", () => {
  const gate = () => {
    let release!: () => void;
    const open = new Promise<void>((r) => (release = r));
    return { open, release };
  };

  it("runs operations on one connection one after another, even after a failure", async () => {
    const q = connectionQueue();
    const order: string[] = [];
    const g = gate();
    const first = q.run("c1", "end", async () => {
      order.push("end:start");
      await g.open;
      order.push("end:done");
      throw new Error("boom");
    });
    const second = q.run("c1", "publish", async () => {
      order.push("publish");
    });
    await Promise.resolve();
    expect(order).toEqual(["end:start"]);
    g.release();
    await expect(first).rejects.toThrow("boom");
    await second;
    expect(order).toEqual(["end:start", "end:done", "publish"]);
  });

  it("lets different connections run together", async () => {
    const q = connectionQueue();
    const g = gate();
    const started: string[] = [];
    const a = q.run("c1", "end", async () => (started.push("c1"), g.open));
    const b = q.run("c2", "end", async () => (started.push("c2"), g.open));
    await Promise.resolve();
    expect(started).toEqual(["c1", "c2"]);
    g.release();
    await Promise.all([a, b]);
  });

  it("joins an apply that is queued or running instead of starting a second", async () => {
    const q = connectionQueue();
    const g = gate();
    let runs = 0;
    const apply = () =>
      q.run("c1", "apply", async () => ((runs += 1), g.open, runs));
    const first = apply();
    const joined = apply();
    expect(joined).toBe(first);
    g.release();
    expect(await joined).toBe(1);
    expect(await apply()).toBe(2);
    expect(runs).toBe(2);
  });

  it("queues an apply behind a running end, and a joiner still shares its promise", async () => {
    const q = connectionQueue();
    const g = gate();
    const order: string[] = [];
    const end = q.run(
      "c1",
      "end",
      async () => (await g.open, order.push("end")),
    );
    const a1 = q.run("c1", "apply", async () => order.push("apply"));
    const a2 = q.run("c1", "apply", async () => order.push("apply-2"));
    expect(a2).toBe(a1);
    g.release();
    await Promise.all([end, a1]);
    expect(order).toEqual(["end", "apply"]);
  });
});
