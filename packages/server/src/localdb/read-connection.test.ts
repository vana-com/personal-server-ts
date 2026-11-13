import {
  linkSync,
  mkdtempSync,
  readdirSync,
  readlinkSync,
  renameSync,
  rmSync,
  symlinkSync,
} from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { setImmediate as yieldToLoop } from "node:timers/promises";
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

/** A write transaction held open by the test: one insert, then an insert into
 * an attached database whose write lock the test holds. The writer waits in
 * its busy handler, inside BEGIN IMMEDIATE, until the test releases the gate.
 * No sleep or CPU-bound statement sets how long it stays there. */
const HELD_WRITE: readonly SqlStatement[] = [
  {
    sql: `INSERT INTO connections (connection_id, connector, ns, control_state)
          VALUES ('pdpp.slow~', 'slow', '', 'active')`,
  },
  { sql: "INSERT INTO gate.g (x) VALUES (1)" },
];

describe("read connection", () => {
  const dirs: string[] = [];
  const open: SqlDriver[] = [];
  const gates: Database.Database[] = [];

  afterEach(async () => {
    for (const g of gates.splice(0)) if (g.open) g.close();
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

  /**
   * Holds the writer inside a write transaction, then returns. The test owns
   * a gate database and its write lock; the writer's batch enters BEGIN
   * IMMEDIATE and blocks on the gate. Entry is observed, not timed: a probe
   * connection (zero busy timeout) fails BEGIN IMMEDIATE only while the
   * writer holds the main database's write lock.
   */
  async function holdWriter(db: SqlDriver, dir: string, file: string) {
    const gatePath = join(dir, "gate.sqlite");
    const gate = new Database(gatePath);
    gates.push(gate);
    gate.exec("CREATE TABLE g (x)");
    await db.query("ATTACH DATABASE ? AS gate", [gatePath]);
    gate.exec("BEGIN IMMEDIATE");

    const state = { settled: false };
    const write = db.batch(HELD_WRITE).finally(() => (state.settled = true));
    const probe = new Database(file, { timeout: 0 });
    gates.push(probe);
    for (;;) {
      try {
        probe.exec("BEGIN IMMEDIATE");
        probe.exec("ROLLBACK");
      } catch (error) {
        if ((error as { code?: string }).code === "SQLITE_BUSY") break;
        throw error;
      }
      if (state.settled) throw new Error("write ended before it was held");
      await yieldToLoop();
    }
    probe.close();
    return { state, write, release: () => gate.exec("COMMIT") };
  }

  /** The read finished while the held write had not: the read did not wait. */
  async function readsWhileHeld<T>(
    held: { write: Promise<unknown> },
    read: () => Promise<T>,
  ): Promise<T> {
    const outcome = await Promise.race([
      read().then((value) => ({ value })),
      held.write.then(
        () => "write ended first" as const,
        () => "write ended first" as const,
      ),
    ]);
    if (outcome === "write ended first")
      throw new Error("the read waited for the write");
    return outcome.value;
  }

  it("answers a status read while a write transaction is held open", async () => {
    const { db, dir, file } = await fresh();
    const local = localFor(db);
    const held = await holdWriter(db, dir, file);

    const value = await readsWhileHeld(held, () => local.listing.status());

    expect(held.state.settled).toBe(false);
    expect(value.connections).toEqual([]); // the write is not committed yet
    held.release();
    await held.write;
  }, 20_000);

  it("answers a record query while a write transaction is held open", async () => {
    const { db, dir, file } = await fresh();
    const local = localFor(db);
    const records = local.recordsFor(() => ({
      connector: "slow",
      namespace: "",
    }));
    const held = await holdWriter(db, dir, file);

    const value = await readsWhileHeld(held, () =>
      records.listRecords({ connectionId: "i", stream: "s", limit: 10 }),
    );

    expect(held.state.settled).toBe(false);
    expect(value.records).toEqual([]);
    held.release();
    await held.write;
  }, 20_000);

  it("shows the committed write to the next read", async () => {
    const { db, dir, file } = await fresh();
    const local = localFor(db);
    const held = await holdWriter(db, dir, file);
    expect(
      (await readsWhileHeld(held, () => local.listing.status())).connections,
    ).toEqual([]);

    held.release();
    await held.write;

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

  it("does not serve a file that replaced the writer's file before the read connection first opened", async () => {
    // The reader is bound to the file the writer holds, not to whatever the
    // path names when the reader happens to open.
    const { db, dir, file } = await fresh();
    const other = new Database(join(dir, "other.sqlite"));
    other.exec("CREATE TABLE connections (connection_id TEXT)");
    other.close();
    renameSync(join(dir, "other.sqlite"), file);

    await expect(db.reads!.query("SELECT * FROM connections")).rejects.toThrow(
      /sqlite_database_replaced/,
    );
  });

  it("refuses a second owner that opens the same database through a symlink", async () => {
    const { dir, file, db } = await fresh();
    const alias = join(dir, "alias.sqlite");
    symlinkSync(file, alias);
    const second = openBetterSqlite3(alias, { lockTimeoutMs: 100 });
    open.push(second);

    await expect(second.query("SELECT 1")).rejects.toMatchObject({
      code: "SQLITE_BUSY",
    });
    await expect(second.reads!.query("SELECT 1")).rejects.toMatchObject({
      code: "SQLITE_BUSY",
    });
    await expect(db.query("SELECT 1 AS one")).resolves.toEqual([{ one: 1 }]);
  });

  it("refuses to own a database file that has a second hard link", async () => {
    const { dir, file } = await fresh();
    linkSync(file, join(dir, "hard.sqlite"));
    const second = openBetterSqlite3(join(dir, "hard.sqlite"), {
      lockTimeoutMs: 100,
    });
    open.push(second);

    await expect(second.query("SELECT 1")).rejects.toMatchObject({
      code: "SQLITE_DATABASE_HARD_LINKED",
    });
  });

  it("refuses a database file that another file replaces while it is being created", async () => {
    const dir = mkdtempSync(join(process.cwd(), ".read-connection-test-"));
    dirs.push(dir);
    // Between the writer's exclusive create and SQLite's open, the test puts
    // another file at the path. The writer must not bind to either file.
    const driver = openBetterSqlite3(join(dir, "db.sqlite"), {
      testSeam: {
        module: fileURLToPath(
          new URL("./open-seam.test-utils.cjs", import.meta.url),
        ),
        data: { replaceAfterCreate: true },
      },
    });
    open.push(driver);

    await expect(driver.query("SELECT 1")).rejects.toMatchObject({
      code: "SQLITE_DATABASE_REPLACED",
    });
    await expect(driver.reads!.query("SELECT 1")).rejects.toMatchObject({
      code: "SQLITE_DATABASE_REPLACED",
    });
  });
});
