import { describe, expect, it } from "vitest";
import {
  applyDelete,
  LocalDbIdentityMismatch,
  LocalDbTooNew,
  localDatabaseName,
  mergeIncoming,
  openLocalDb,
  replaceDelete,
  withOrigin,
  type SqlDriver,
  type SqlStatement,
  type WriteOrigin,
} from "./index.js";
import { MIGRATIONS } from "./schema.js";

import { MIGRATIONS } from "./schema.js";

const ID = { owner: "0xAbC", network: "moksha", deviceId: "dev-1" };

/**
 * Register the shared driver cases in the caller's Vitest suite.
 *
 * fresh starts an empty database and makes it the current database;
 * makeDriver opens another driver for that same database after it is closed.
 * The caller owns closing remaining drivers and removing test databases.
 * Consumers of this testing subpath must provide Vitest.
 */
export function runDriverConformance(
  makeDriver: () => Promise<SqlDriver>,
  opts: { fresh: () => Promise<SqlDriver> },
): void {
  const fresh = async () => {
    const driver = await opts.fresh();
    return { driver, db: await openLocalDb(driver, ID) };
  };

  const write = (db: SqlDriver, origin: WriteOrigin, ...sql: SqlStatement[]) =>
    db.batch(withOrigin(origin, sql));
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

    it("migrates a new file to the current schema and keeps data on reopen", async () => {
      const { driver, db } = await fresh();
      expect(await db.query("PRAGMA user_version")).toEqual([
        { user_version: MIGRATIONS.length },
      ]);
      await seedConnection(db);
      await driver.close();
      const again = await makeDriver();
      await openLocalDb(again, ID);
      expect(
        await again.query("SELECT connection_id FROM connections"),
      ).toEqual([{ connection_id: "c1" }]);
    });

    it("upgrades a version-1 database through migrations 2 and 3 in order", async () => {
      const driver = await opts.fresh();
      const steps: {
        version: number;
        receiptRevision: boolean;
        eraseIntents: boolean;
      }[] = [];
      const tracked: SqlDriver = {
        ...driver,
        async batch(statements) {
          const result = await driver.batch(statements);
          if (
            statements.some(({ sql }) => /^PRAGMA user_version = /.test(sql))
          ) {
            const [version] = await driver.query<{ user_version: number }>(
              "PRAGMA user_version",
            );
            const columns = await driver.query(
              "PRAGMA table_info(import_ledger)",
            );
            const journal = await driver.query(
              "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'legacy_erase_intents'",
            );
            steps.push({
              version: version!.user_version,
              receiptRevision: columns.some(
                (column) => column.name === "revision",
              ),
              eraseIntents: journal.length === 1,
            });
          }
          return result;
        },
      };
      await tracked.batch([
        ...MIGRATIONS[0]!.map((sql) => ({ sql })),
        { sql: "PRAGMA user_version = 1" },
      ]);
      await driver.batch([
        {
          sql: "INSERT INTO import_ledger VALUES ('fixture', 'c1', 's', 'imported', 1, 'fingerprint', NULL, 1)",
        },
      ]);
      await openLocalDb(tracked, ID);
      expect(steps).toEqual([
        { version: 1, receiptRevision: false, eraseIntents: false },
        { version: 2, receiptRevision: true, eraseIntents: false },
        { version: 3, receiptRevision: true, eraseIntents: true },
      ]);
      expect(
        await driver.query(
          "SELECT source, rows, fingerprint, revision, generation, highest_seq FROM import_ledger",
        ),
      ).toEqual([
        {
          source: "fixture",
          rows: 1,
          fingerprint: "fingerprint",
          revision: null,
          generation: null,
          highest_seq: null,
        },
      ]);
    });

    it("refuses a file written by a newer build", async () => {
      const { driver } = await fresh();
      await driver.batch([{ sql: "PRAGMA user_version = 99" }]);
      await driver.close();
      const again = await makeDriver();
      await expect(openLocalDb(again, ID)).rejects.toBeInstanceOf(
        LocalDbTooNew,
      );
    });

    it("refuses a file that belongs to another owner or network", async () => {
      const { driver } = await fresh();
      await driver.close();
      const again = await makeDriver();
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
}
