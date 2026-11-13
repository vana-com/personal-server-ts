import {
  mkdtempSync,
  readdirSync,
  readlinkSync,
  renameSync,
  rmSync,
} from "node:fs";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { afterEach, describe, expect, it } from "vitest";
import {
  connectionQueue,
  openLocalDb,
  purgeConnection,
  type LocalSyncDeps,
  type SqlDriver,
  type SqlStatement,
} from "@opendatalabs/personal-server-ts-core/localdb";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { createServerLocalSync } from "./sync.js";
import Database from "better-sqlite3";

// HTTP reads must not queue behind the writer. The writer owns one connection
// and runs a long import or publish batch in one transaction; the read
// connection is a second, read-only connection to the same WAL file, so a
// read sees the last committed state and never waits for that transaction.
// Scratch databases live under the process working directory, never the
// system temp directory.
const ID = { owner: "0xAbC", network: "moksha", deviceId: "dev-1" };

/** A write transaction that holds the writer for a few seconds: one insert,
 * then a CPU-bound statement that runs before COMMIT. */
const SLOW_WRITE: readonly SqlStatement[] = [
  {
    sql: `INSERT INTO connections (connection_id, connector, ns, control_state)
          VALUES ('pdpp.slow~', 'slow', '', 'active')`,
  },
  {
    sql: `WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 25000000)
          SELECT count(*) FROM c`,
  },
];

describe("read connection", () => {
  const dirs: string[] = [];
  const open: SqlDriver[] = [];

  afterEach(async () => {
    for (const d of open.splice(0)) await d.close().catch(() => undefined);
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  });

  const fresh = async () => {
    const dir = mkdtempSync(join(process.cwd(), ".read-connection-test-"));
    dirs.push(dir);
    const file = join(dir, "db.sqlite");
    const driver = openBetterSqlite3(file);
    open.push(driver);
    return { dir, file, db: await openLocalDb(driver, ID) };
  };

  const depsFor = (db: SqlDriver): LocalSyncDeps =>
    ({
      db,
      queue: connectionQueue(),
      ownerAddress: "0xabc",
      logger: { info: () => undefined, warn: () => undefined },
      now: () => 1_700_000_000_000,
      newOp: () => "op-read",
    }) as unknown as LocalSyncDeps;

  const localFor = (db: SqlDriver) =>
    createServerLocalSync(depsFor(db), {
      resolveArtifact: () => undefined,
      declaredStreams: () => [],
      olderVersionReads: () => true,
    });

  /** Starts the slow write and waits until the writer is inside it. */
  async function startSlowWrite(db: SqlDriver) {
    const state = { settled: false };
    const write = db.batch(SLOW_WRITE).finally(() => (state.settled = true));
    await sleep(100);
    return { state, write };
  }

  async function timed<T>(read: () => Promise<T>) {
    const started = performance.now();
    const value = await read();
    return { value, ms: performance.now() - started };
  }

  it("answers a status read within 100 ms while a long write transaction is running", async () => {
    const { db } = await fresh();
    const local = localFor(db);
    await local.listing.status(); // warm: the read connection is up
    const { state, write } = await startSlowWrite(db);

    const { value, ms } = await timed(() => local.listing.status());

    expect(state.settled).toBe(false);
    expect(ms).toBeLessThan(100);
    expect(value.connections).toEqual([]); // the write is not committed yet
    await write;
  });

  it("answers a record query within 100 ms while a long write transaction is running", async () => {
    const { db } = await fresh();
    const local = localFor(db);
    const records = local.recordsFor(() => ({
      connector: "slow",
      namespace: "",
    }));
    await records.listRecords({
      connectionId: "i",
      stream: "s",
      limit: 10,
    });
    const { state, write } = await startSlowWrite(db);

    const { value, ms } = await timed(() =>
      records.listRecords({ connectionId: "i", stream: "s", limit: 10 }),
    );

    expect(state.settled).toBe(false);
    expect(ms).toBeLessThan(100);
    expect(value.records).toEqual([]);
    await write;
  });

  it("shows the committed write to the next read", async () => {
    const { db } = await fresh();
    const local = localFor(db);
    const { write } = await startSlowWrite(db);
    expect((await local.listing.status()).connections).toEqual([]);

    await write;

    expect(
      (await local.listing.status()).connections.map((c) => c.connector),
    ).toEqual(["slow"]);
  });

  it("shows a purge to the next read", async () => {
    const { db } = await fresh();
    const local = localFor(db);
    await db.batch([
      {
        sql: `INSERT INTO connections (connection_id, connector, ns, control_state)
              VALUES ('c1', 'c', '', 'active')`,
      },
      {
        sql: `INSERT INTO records (connection_id, stream, pk_hash, record_key, stamp_o, stamp_r, body, body_sha256)
              VALUES ('c1', 's', 'h1', 'k1', 1, 'r', '{}', 'x')`,
      },
    ]);
    const count = async () =>
      (
        await db.reads!.query<{ n: number }>(
          "SELECT count(*) AS n FROM records",
        )
      )[0]!.n;
    expect(await count()).toBe(1);

    await purgeConnection(depsFor(db), "c1", { controlVersion: 2 });

    expect(await count()).toBe(0);
    expect((await local.listing.status()).connections[0]?.control).toBe(
      "deleted",
    );
  });

  it("reads in WAL mode and cannot write", async () => {
    const { db } = await fresh();
    const reads = db.reads!;
    expect(
      (await reads.query<{ journal_mode: string }>("PRAGMA journal_mode"))[0]!
        .journal_mode,
    ).toBe("wal");
    expect("batch" in reads).toBe(false);
    await expect(reads.query("DELETE FROM connections")).rejects.toThrow(
      /readonly/i,
    );
  });

  it("close() ends the read connection: no read after it, no open handle on the file", async () => {
    const { db, file } = await fresh();
    await db.reads!.query("SELECT 1");
    await db.close();

    await expect(db.reads!.query("SELECT 1")).rejects.toThrow(
      /sqlite_driver_closed/,
    );
    if (process.platform === "linux") {
      const held = readdirSync("/proc/self/fd")
        .map((fd) => {
          try {
            return readlinkSync(`/proc/self/fd/${fd}`);
          } catch {
            return "";
          }
        })
        .filter((target) => target.startsWith(file));
      expect(held).toEqual([]);
    }
  });

  it("a read connection never opened leaves nothing to close", async () => {
    const { db } = await fresh();
    await expect(db.close()).resolves.toBeUndefined();
  });

  it("does not serve a file that was deleted under the open read connection", async () => {
    const { db, file } = await fresh();
    await db.reads!.query("SELECT 1");
    for (const suffix of ["", "-wal", "-shm"])
      rmSync(file + suffix, { force: true });

    await expect(db.reads!.query("SELECT 1")).rejects.toThrow(
      /sqlite_database_replaced/,
    );
  });

  it("does not serve a file that was replaced under the open read connection", async () => {
    const { db, dir, file } = await fresh();
    await db.reads!.query("SELECT 1");
    const other = new Database(join(dir, "other.sqlite"));
    other.exec("CREATE TABLE connections (connection_id TEXT)");
    other.close();
    renameSync(join(dir, "other.sqlite"), file);

    await expect(db.reads!.query("SELECT * FROM connections")).rejects.toThrow(
      /sqlite_database_replaced/,
    );
  });

  it("opens a new database after the old one was deleted and its lock and shm files stayed behind", async () => {
    // A purge or reset that removes only the database file (not `.lock` or
    // `-shm`) must not break the next open: the lock is a kernel lock, not
    // the file's existence.
    const { db, file } = await fresh();
    await db.close();
    rmSync(file, { force: true });
    rmSync(`${file}-wal`, { force: true });

    const again = openBetterSqlite3(file);
    open.push(again);
    const reopened = await openLocalDb(again, ID);
    await expect(
      reopened.query("SELECT count(*) AS n FROM connections"),
    ).resolves.toEqual([{ n: 0 }]);
    await expect(
      reopened.reads!.query("SELECT count(*) AS n FROM connections"),
    ).resolves.toEqual([{ n: 0 }]);
  });

  it("still lets one process hold a database file at a time", async () => {
    const { file, db } = await fresh();
    const second = openBetterSqlite3(file, { lockTimeoutMs: 100 });
    open.push(second);

    await expect(second.query("SELECT 1")).rejects.toMatchObject({
      code: "SQLITE_BUSY",
    });

    await db.close();
    const third = openBetterSqlite3(file);
    open.push(third);
    await expect(third.query("SELECT 1 AS one")).resolves.toEqual([{ one: 1 }]);
  });
});
