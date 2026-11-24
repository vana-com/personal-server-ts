// The fold workspace and the spool hold a connection's record bodies, delete
// keys and sealed objects in the local database while an operation runs. They
// are scratch: nothing of them may outlive the operation, a crash, or the
// connection. Each place that must leave none is one test here: the process
// ends mid-operation and the database opens again, the connection is purged,
// an operation fails.
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  LOG_FORMAT,
  type Segment,
  type WireOperation,
} from "@opendatalabs/personal-server-ts-stream-sync";
import {
  connectionQueue,
  openLocalDb,
  purgeConnection,
  type LocalSyncDeps,
  type SqlDriver,
} from "../../../core/src/localdb/index.js";
import { openFoldWorkspace } from "../../../core/src/localdb/log-fold-workspace.js";
import { openSpool } from "../../../core/src/localdb/log-spool.js";
import { publishLog } from "../../../core/src/localdb/log-publish.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import {
  CONNECTION_ID,
  closeWorldDrivers,
  sName,
  world,
} from "./log-world.test-utils.js";

const ID = { owner: "0xAbC", network: "moksha", deviceId: "dev-1" };

describe("scratch tables of the log", () => {
  const dirs: string[] = [];
  const open: SqlDriver[] = [];
  afterEach(async () => {
    for (const d of open.splice(0)) await d.close().catch(() => undefined);
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  });

  const file = () => {
    const dir = mkdtempSync(join(process.cwd(), ".scratch-test-"));
    dirs.push(dir);
    return join(dir, "db.sqlite");
  };
  const database = async (path: string) => {
    const db = await openLocalDb(openBetterSqlite3(path), ID);
    open.push(db);
    return db;
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

  const segment: Segment<WireOperation> = {
    format: LOG_FORMAT,
    connector: "k",
    ns: "",
    generation: 1,
    keyCheck: "k",
    position: 1,
    observedAt: 1,
    base: 0,
    snapshot: null,
    refs: [],
    streams: [
      {
        stream: "s",
        primaryKey: ["id"],
        profile: { key: null, version: "1" },
        complete: true,
      },
    ],
    operations: [
      {
        kind: "upsert",
        stream: "s",
        pkHash: "a".repeat(64),
        stamp: { o: 1, r: "run" },
        firstSeen: null,
        value: { id: 1, secret: "plain text of a record" },
      },
      {
        kind: "delete",
        stream: "s",
        pkHash: "b".repeat(64),
        stamp: { o: 1, r: "run" },
        key: ["a deleted key"],
      },
    ],
  };

  /** What a process that ended mid-operation leaves for a connection. */
  const leave = async (db: SqlDriver, connectionId: string) => {
    const workspace = await openFoldWorkspace(db, connectionId, "compact");
    await workspace.addSegment(segment);
    const spool = openSpool(db, connectionId, "op-1");
    await spool.add("q-0", new Uint8Array([1, 2, 3, 4]));
    await spool.add("v-0", new Uint8Array(3_000_000).fill(7));
  };
  const rows = async (db: SqlDriver, connectionId?: string) => {
    const where = connectionId === undefined ? "" : " WHERE connection_id = ?";
    const params = connectionId === undefined ? [] : [connectionId];
    const count = async (table: string) =>
      (
        await db.query<{ n: number }>(
          `SELECT COUNT(*) AS n FROM ${table}${where}`,
          params,
        )
      )[0]!.n;
    return {
      cells: await count("log_fold_cells"),
      spool: await count("log_spool"),
    };
  };

  it("a database that opens after a crash has none of the crashed operation's rows", async () => {
    const path = file();
    const first = await database(path);
    await leave(first, "c1");
    await leave(first, "c2");
    expect((await rows(first)).cells).toBe(4);
    expect((await rows(first)).spool).toBeGreaterThanOrEqual(4);
    // The process ends. Nothing closed the workspace or discarded the spool.
    await first.close();
    open.splice(open.indexOf(first), 1);
    const second = await database(path);
    expect(await rows(second)).toEqual({ cells: 0, spool: 0 });
  });

  it("a purge deletes the connection's scratch rows, whatever a crash left, and only its own", async () => {
    const db = await database(file());
    await db.batch([
      {
        sql: "INSERT INTO connections(connection_id, connector, ns, control_state, control_version) VALUES ('c1','k','','active',3), ('c2','k','','active',4)",
      },
    ]);
    await leave(db, "c1");
    await leave(db, "c2");
    const other = await rows(db, "c2");
    expect((await rows(db, "c1")).cells).toBeGreaterThan(0);
    expect((await rows(db, "c1")).spool).toBeGreaterThan(0);
    await purgeConnection(depsFor(db), "c1", { controlVersion: 7 });
    expect(await rows(db, "c1")).toEqual({ cells: 0, spool: 0 });
    expect(await rows(db, "c2")).toEqual(other);
  });

  it("a workspace that is closed leaves none, and one that is reopened starts empty", async () => {
    const db = await database(file());
    await leave(db, "c1");
    const again = await openFoldWorkspace(db, "c1", "compact");
    expect((await rows(db, "c1")).cells).toBe(0);
    await again.addSegment(segment);
    await again.close();
    expect((await rows(db, "c1")).cells).toBe(0);
  });
});

describe("a publish that fails after it spooled leaves no rows", () => {
  afterEach(closeWorldDrivers);

  /** A database whose first query after a write to the spool fails. */
  const failingAfterSpool = (inner: SqlDriver, seen: { failed: boolean }) => {
    let armed = false;
    return {
      ...inner,
      batch: async (statements: Parameters<SqlDriver["batch"]>[0]) => {
        const result = await inner.batch(statements);
        if (statements.some((s) => s.sql.includes("INSERT INTO log_spool")))
          armed = true;
        return result;
      },
      query: async (
        sql: string,
        params?: Parameters<SqlDriver["query"]>[1],
      ) => {
        if (armed) {
          armed = false;
          seen.failed = true;
          throw new Error("the read after the spool failed");
        }
        return inner.query(sql, params);
      },
    } as SqlDriver;
  };

  it("clears the spool when the read that follows the spool writes fails", async () => {
    const seen = { failed: false };
    const w = await world({
      streams: 1,
      partTargetBytes: 1000,
      database: (deviceId) =>
        deviceId === "a"
          ? failingAfterSpool(openBetterSqlite3(":memory:"), seen)
          : openBetterSqlite3(":memory:"),
    });
    const a = await w.device("a");
    // A body over the part target goes out of line: its pieces are spooled.
    await a.run("r1", [{ stream: sName(0), id: "x", pad: 5000 }]);
    await expect(publishLog(a.deps, CONNECTION_ID)).rejects.toThrow(
      "the read after the spool failed",
    );
    expect(seen.failed).toBe(true);
    const [spool] = await a.db.query<{ n: number }>(
      "SELECT COUNT(*) AS n FROM log_spool",
    );
    expect(spool!.n).toBe(0);
  });
});
