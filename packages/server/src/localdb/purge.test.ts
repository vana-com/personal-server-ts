import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  connectionQueue,
  openLocalDb,
  purgeConnection,
  type LocalSyncDeps,
  type SqlDriver,
} from "@opendatalabs/personal-server-ts-core/localdb";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

// P11 (purge): the local purge of one connection, in the connection queue
// with kind "purge", in one batch with origin `purge`. Each test proves one
// named behaviour. Scratch databases live under the process working
// directory, never the system temp directory.
const ID = { owner: "0xAbC", network: "moksha", deviceId: "dev-1" };

describe("purgeConnection", () => {
  const dirs: string[] = [];
  const open: SqlDriver[] = [];

  afterEach(async () => {
    for (const d of open.splice(0)) await d.close().catch(() => undefined);
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  });

  const fresh = async () => {
    const dir = mkdtempSync(join(process.cwd(), ".purge-test-"));
    dirs.push(dir);
    const driver = openBetterSqlite3(join(dir, "db.sqlite"));
    open.push(driver);
    const db = await openLocalDb(driver, ID);
    return { db };
  };

  const depsFor = (db: SqlDriver): LocalSyncDeps =>
    ({
      db,
      queue: connectionQueue(),
      ownerAddress: "0xabc",
      logger: { info: () => undefined, warn: () => undefined },
      now: () => 1_700_000_000_000,
      newOp: () => "op-purge",
    }) as unknown as LocalSyncDeps;

  /**
   * Two connections. c1 is purged; c2 must be untouched. c1 holds two
   * records, one run row, one head part, and refs to a shared blob and a
   * blob only it references; it also holds one blob ref whose record does
   * not exist, so only the explicit `blob_refs` delete removes it. One
   * blob has no refs at all.
   */
  const seed = async (db: SqlDriver) => {
    await db.batch([
      {
        sql: "INSERT INTO connections(connection_id, connector, ns, control_state, control_version, checkpoint) VALUES ('c1','k','','active',3,'ck-1'), ('c2','k','','active',4,'ck-2')",
      },
      {
        sql: "INSERT INTO stream_state(connection_id, stream, primary_key, semantics, incremental, head_version) VALUES ('c1','s','[\"id\"]','mutable_state',0,3), ('c1','t','[\"id\"]','mutable_state',0,0), ('c2','s','[\"id\"]','mutable_state',0,5)",
      },
      {
        sql: "INSERT INTO records(connection_id, stream, pk_hash, record_key, stamp_o, stamp_r, body, body_sha256) VALUES ('c1','s','aa01','1',1000,'run-a','{}','sha-{}'), ('c1','s','aa02','2',1000,'run-a','{}','sha-{}'), ('c2','s','bb01','1',1000,'run-a','{}','sha-{}')",
      },
      {
        sql: "INSERT INTO runs(run_id, connection_id, o, artifact_version, collection_mode, state) VALUES ('r1','c1',1000,'1','incremental','ended'), ('r2','c2',1000,'1','incremental','ended')",
      },
      {
        sql: "INSERT INTO run_streams(run_id, stream, delete_snapshot) VALUES ('r1','s',0), ('r2','s',0)",
      },
      {
        sql: "INSERT INTO run_rows(run_id, stream, pk_hash, record_key, body, body_sha256) VALUES ('r1','s','aa01','1','{}','sha-{}'), ('r2','s','bb01','1','{}','sha-{}')",
      },
      {
        sql: "INSERT INTO head_parts VALUES ('c1','s','0',0,'h0',10,1), ('c2','s','0',0,'h1',10,1)",
      },
      {
        sql: "INSERT INTO blobs(blob_id, mime_type, size_bytes) VALUES ('b-shared','text/plain',4), ('b-only-c1','text/plain',4), ('b-only-c2','text/plain',4), ('b-orphan','text/plain',4)",
      },
      {
        sql: "INSERT INTO blob_refs VALUES ('b-shared','c1','s','aa01'), ('b-only-c1','c1','s','aa02'), ('b-only-c1','c1','s','zz99'), ('b-shared','c2','s','bb01'), ('b-only-c2','c2','s','bb01')",
      },
    ]);
  };

  const purge = (db: SqlDriver) =>
    purgeConnection(depsFor(db), "c1", { controlVersion: 7 });

  it("deletes the connection's records and logs the removal with origin purge", async () => {
    const { db } = await fresh();
    await seed(db);
    await purge(db);
    expect(
      await db.query(
        "SELECT pk_hash FROM records WHERE connection_id = 'c1' ORDER BY pk_hash",
      ),
    ).toEqual([]);
    expect(
      await db.query<{ pk_hash: string; op: string; origin: string }>(
        "SELECT pk_hash, op, origin FROM record_changes WHERE op = 'remove' ORDER BY seq",
      ),
    ).toEqual([
      { pk_hash: "aa01", op: "remove", origin: "purge" },
      { pk_hash: "aa02", op: "remove", origin: "purge" },
    ]);
  });

  it("deletes the connection's run_rows", async () => {
    const { db } = await fresh();
    await seed(db);
    await purge(db);
    expect(
      await db.query("SELECT run_id FROM run_rows WHERE run_id = 'r1'"),
    ).toEqual([]);
    expect(
      await db.query(
        "SELECT run_id, pk_hash FROM run_rows WHERE run_id = 'r2'",
      ),
    ).toEqual([{ run_id: "r2", pk_hash: "bb01" }]);
  });

  it("deletes the connection's head_parts", async () => {
    const { db } = await fresh();
    await seed(db);
    await purge(db);
    expect(
      await db.query(
        "SELECT prefix FROM head_parts WHERE connection_id = 'c1'",
      ),
    ).toEqual([]);
    expect(
      await db.query(
        "SELECT prefix FROM head_parts WHERE connection_id = 'c2'",
      ),
    ).toEqual([{ prefix: "0" }]);
  });

  it("deletes the connection's blob_refs and unreferenced blobs, and keeps blobs another connection still references", async () => {
    const { db } = await fresh();
    await seed(db);
    await purge(db);
    expect(
      await db.query(
        "SELECT blob_id FROM blob_refs WHERE connection_id = 'c1'",
      ),
    ).toEqual([]);
    expect(
      await db.query(
        "SELECT blob_id FROM blob_refs WHERE connection_id = 'c2' ORDER BY blob_id",
      ),
    ).toEqual([{ blob_id: "b-only-c2" }, { blob_id: "b-shared" }]);
    expect(
      await db.query("SELECT blob_id FROM blobs ORDER BY blob_id"),
    ).toEqual([{ blob_id: "b-only-c2" }, { blob_id: "b-shared" }]);
  });

  it("sets control_state=deleted and last_delete_version and clears the checkpoint", async () => {
    const { db } = await fresh();
    await seed(db);
    await purge(db);
    expect(
      await db.query(
        "SELECT control_state, control_version, checkpoint FROM connections WHERE connection_id = 'c1'",
      ),
    ).toEqual([
      { control_state: "deleted", control_version: 3, checkpoint: null },
    ]);
    expect(
      await db.query<{ stream: string; last_delete_version: number }>(
        "SELECT stream, last_delete_version FROM stream_state WHERE connection_id = 'c1' ORDER BY stream",
      ),
    ).toEqual([
      { stream: "s", last_delete_version: 7 },
      { stream: "t", last_delete_version: 7 },
    ]);
  });

  it("leaves another connection untouched", async () => {
    const { db } = await fresh();
    await seed(db);
    await purge(db);
    expect(
      await db.query("SELECT pk_hash FROM records WHERE connection_id = 'c2'"),
    ).toEqual([{ pk_hash: "bb01" }]);
    expect(
      await db.query(
        "SELECT control_state, control_version, checkpoint FROM connections WHERE connection_id = 'c2'",
      ),
    ).toEqual([
      { control_state: "active", control_version: 4, checkpoint: "ck-2" },
    ]);
    expect(
      await db.query(
        "SELECT last_delete_version FROM stream_state WHERE connection_id = 'c2'",
      ),
    ).toEqual([{ last_delete_version: 0 }]);
  });
});
