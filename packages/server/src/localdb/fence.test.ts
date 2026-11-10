import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  checkRunFence,
  connectionQueue,
  mergeIncoming,
  openLocalDb,
  withOrigin,
  type LocalSyncDeps,
  type SqlDriver,
} from "@opendatalabs/personal-server-ts-core/localdb";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const ID = { owner: "0xAbC", network: "moksha", deviceId: "dev-1" };

describe("fence", () => {
  const dirs: string[] = [];
  const open: SqlDriver[] = [];

  const fresh = async () => {
    // Scratch lives under the working directory, never the system temp
    // directory (brief).
    const dir = mkdtempSync(join(process.cwd(), "fence-test-"));
    dirs.push(dir);
    const file = join(dir, "db.sqlite");
    const driver = openBetterSqlite3(file);
    open.push(driver);
    const db = await openLocalDb(driver, ID);
    return { db, deps: depsFor(db) };
  };
  afterEach(async () => {
    for (const d of open.splice(0)) await d.close().catch(() => undefined);
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  });

  const depsFor = (db: SqlDriver): LocalSyncDeps => ({
    db,
    queue: connectionQueue(),
    ownerAddress: "0xabc",
    registry: {} as LocalSyncDeps["registry"],
    blobs: {} as LocalSyncDeps["blobs"],
    keys: {} as LocalSyncDeps["keys"],
    signer: {} as LocalSyncDeps["signer"],
    logger: { info: () => undefined, warn: () => undefined },
    now: () => 1000,
    newOp: () => "op-test",
  });

  const seed = (
    db: SqlDriver,
    opts: {
      generation?: number;
      controlState?: string;
      lastDeleteVersion?: number;
    } = {},
  ) =>
    db.batch([
      {
        sql: "INSERT INTO connections(connection_id, connector, ns, generation, control_state) VALUES ('c1','k','',?,?)",
        params: [opts.generation ?? 1, opts.controlState ?? "active"],
      },
      {
        sql: "INSERT INTO stream_state(connection_id, stream, primary_key, semantics, incremental, last_delete_version) VALUES ('c1','s','[\"id\"]','mutable_state',1,?)",
        params: [opts.lastDeleteVersion ?? 0],
      },
    ]);

  const seedStream = (
    db: SqlDriver,
    stream: string,
    lastDeleteVersion: number,
  ) =>
    db.batch([
      {
        sql: "INSERT INTO stream_state(connection_id, stream, primary_key, semantics, incremental, last_delete_version) VALUES ('c1',?,'[\"id\"]','mutable_state',1,?)",
        params: [stream, lastDeleteVersion],
      },
    ]);

  const startRun = (
    db: SqlDriver,
    runId: string,
    generation: number,
    snapshots: readonly (readonly [string, number])[],
  ) =>
    db.batch([
      {
        sql: "INSERT INTO runs(run_id, connection_id, o, generation, artifact_version, collection_mode, state, last_batch) VALUES (?, 'c1', 1000, ?, 'art-v1', 'incremental', 'collecting', -1)",
        params: [runId, generation],
      },
      ...snapshots.map(([stream, snapshot]) => ({
        sql: "INSERT INTO run_streams(run_id, stream, delete_snapshot) VALUES (?, ?, ?)",
        params: [runId, stream, snapshot],
      })),
    ]);

  const bumpDeleteVersion = (db: SqlDriver, stream: string, version: number) =>
    db.batch([
      {
        sql: "UPDATE stream_state SET last_delete_version = ? WHERE connection_id = 'c1' AND stream = ?",
        params: [version, stream],
      },
    ]);

  it("trips at batch, per stream, when a delete version passes the snapshot", async () => {
    const { db, deps } = await fresh();
    await seed(db, { lastDeleteVersion: 4 });
    await seedStream(db, "t", 4);
    await startRun(db, "run-1", 1, [
      ["s", 3],
      ["t", 4],
    ]);
    expect(await checkRunFence(deps, "run-1", "batch")).toEqual([
      { stream: "s", trip: "stream_deleted_after_start" },
    ]);
  });

  it("trips at end when the control row is deleted", async () => {
    const { db, deps } = await fresh();
    await seed(db, { controlState: "deleted", lastDeleteVersion: 5 });
    await startRun(db, "run-1", 1, [["s", 5]]);
    expect(await checkRunFence(deps, "run-1", "end")).toEqual([
      { stream: "s", trip: "control_deleted" },
    ]);
  });

  it("trips at publish when the generation moved past the run generation", async () => {
    const { db, deps } = await fresh();
    await seed(db, { generation: 2, lastDeleteVersion: 5 });
    await startRun(db, "run-1", 1, [["s", 5]]);
    expect(await checkRunFence(deps, "run-1", "publish")).toEqual([
      { stream: "s", trip: "generation_moved_by_delete" },
    ]);
  });

  it("never publishes a run that started before a delete's pinned version (#563)", async () => {
    const { db, deps } = await fresh();
    await seed(db, { lastDeleteVersion: 5 });
    await startRun(db, "run-1", 1, [["s", 5]]);
    expect(await checkRunFence(deps, "run-1", "publish")).toEqual([]);
    await bumpDeleteVersion(db, "s", 6);
    expect(await checkRunFence(deps, "run-1", "publish")).toEqual([
      { stream: "s", trip: "stream_deleted_after_start" },
    ]);
  });

  it("keeps a run started after a reconnect (#563)", async () => {
    const { db, deps } = await fresh();
    await seed(db, { generation: 2, lastDeleteVersion: 2 });
    await startRun(db, "run-1", 2, [["s", 2]]);
    expect(await checkRunFence(deps, "run-1", "publish")).toEqual([]);
  });

  it("discards a run whose stream row was tombstoned after collection (#563)", async () => {
    const { db, deps } = await fresh();
    await seed(db, { lastDeleteVersion: 0 });
    await startRun(db, "run-1", 1, [["s", 0]]);
    expect(await checkRunFence(deps, "run-1", "end")).toEqual([]);
    await bumpDeleteVersion(db, "s", 1);
    expect(await checkRunFence(deps, "run-1", "end")).toEqual([
      { stream: "s", trip: "stream_deleted_after_start" },
    ]);
  });

  it("keeps a run whose stream row was already tombstoned at collection (#563)", async () => {
    const { db, deps } = await fresh();
    await seed(db, { lastDeleteVersion: 1 });
    await startRun(db, "run-1", 1, [["s", 1]]);
    expect(await checkRunFence(deps, "run-1", "publish")).toEqual([]);
  });

  it("retry-pending-keeps-progress: a run that ends retry_pending keeps its rows and its cursor", async () => {
    const { db, deps } = await fresh();
    await seed(db, {});
    const pk = (i: number) => `r${String(i).padStart(2, "0")}`;
    const pks = (from: number, to: number) =>
      Array.from({ length: to - from + 1 }, (_, k) => pk(from + k));
    const receive = (runId: string, from: number, to: number) =>
      db.batch([
        {
          sql: "INSERT INTO runs(run_id, connection_id, o, generation, artifact_version, collection_mode, state, last_batch) VALUES (?, 'c1', 1000, 1, 'art-v1', 'incremental', 'collecting', -1)",
          params: [runId],
        },
        {
          sql: "INSERT INTO run_streams(run_id, stream, delete_snapshot) VALUES (?, 's', 0)",
          params: [runId],
        },
        ...pks(from, to).map((p) => ({
          sql: "INSERT INTO run_rows(run_id, stream, pk_hash, record_key, body, body_sha256) VALUES (?, 's', ?, ?, ?, ?)",
          params: [runId, p, p, `{"v":${p}}`, `sha-{"v":${p}}`],
        })),
      ]);
    // End a run the way `retry_pending` does (C.1 §3): merge every received
    // row in the same batch, never replace, and save the cursor of every
    // stream in the checkpoint candidate, including streams that received
    // records.
    const endMerging = (runId: string, op: string, stampR: string) =>
      db.batch(
        withOrigin("local", [
          {
            sql: "INSERT INTO incoming (op, stream, pk_hash, record_key, stamp_o, stamp_r, body, body_sha256) SELECT ?, stream, pk_hash, record_key, CAST(substr(record_key, 2) AS INTEGER), ?, body, body_sha256 FROM run_rows WHERE run_id = ?",
            params: [op, stampR, runId],
          },
          ...mergeIncoming(op, "c1"),
        ]),
      );
    const keys = async () =>
      (
        await db.query<{ k: string }>(
          "SELECT pk_hash AS k FROM records ORDER BY pk_hash",
        )
      ).map((r) => r.k);

    // Run A, incremental, receives r1..r50 and ends retry_pending with C50.
    await receive("run-a", 1, 50);
    await endMerging("run-a", "op-a", "run-a");
    await db.batch([
      {
        sql: "UPDATE connections SET checkpoint = 'C50' WHERE connection_id = 'c1'",
      },
      { sql: "UPDATE runs SET state = 'ended' WHERE run_id = 'run-a'" },
    ]);
    // r1..r50 were readable after A's end.
    expect(await keys()).toEqual(pks(1, 50));

    // Run B begins from C50, receives r51..r60 and ends succeeded.
    const [checkpoint] = await db.query<{ checkpoint: string | null }>(
      "SELECT checkpoint FROM connections WHERE connection_id = 'c1'",
    );
    expect(checkpoint?.checkpoint).toBe("C50");
    await receive("run-b", 51, 60);
    await endMerging("run-b", "op-b", "run-b");
    await db.batch([
      { sql: "UPDATE runs SET state = 'ended' WHERE run_id = 'run-b'" },
    ]);

    // The stream head holds r1..r60.
    expect(await keys()).toEqual(pks(1, 60));
    // Each of r1..r50 has exactly one origin='local' change, and B received
    // none of r1..r50.
    const changes = await db.query<{ pk_hash: string; n: number }>(
      "SELECT pk_hash, count(*) AS n FROM record_changes WHERE origin = 'local' GROUP BY pk_hash ORDER BY pk_hash",
    );
    expect(changes).toEqual(pks(1, 60).map((p) => ({ pk_hash: p, n: 1 })));
    const receivedB = await db.query<{ pk_hash: string }>(
      "SELECT pk_hash FROM run_rows WHERE run_id = 'run-b' ORDER BY pk_hash",
    );
    expect(receivedB.map((r) => r.pk_hash)).toEqual(pks(51, 60));
    // The fence kept run B: nothing about the retry tripped it.
    expect(await checkRunFence(deps, "run-b", "publish")).toEqual([]);
  });
});
