import { afterEach, expect, it, vi } from "vitest";
import {
  createLocalSync,
  openLocalDb,
  connectionQueue,
  type SqlDriver,
} from "../../../core/src/localdb/index.js";
import {
  createMemoryStreamSyncRegistry,
  createMemoryStreamSyncBlobs,
} from "../../../core/src/stream-sync/index.js";
import { endRequest } from "../../../core/src/test-utils/run-end.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

// Publish while collecting (default-off flag `publishWhileCollecting`): a batch
// is admitted into `records` in the transaction that stages it, so the
// publisher relays rows during a run. Run end keeps the omission deletes, the
// explicit deletes and the checkpoint.

const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
});
const owner = `0x${"11".repeat(20)}` as const;
const connectionId = "pdpp.fixture~";

type Row = Record<string, unknown>;

/** Digest `v1`/`v2` pick a connector version; `v2` also keys on (id, kind). */
const versions: Record<string, { version: string; primaryKey: string[] }> = {
  fixture: { version: "1", primaryKey: ["id"] },
  v1: { version: "1", primaryKey: ["id"] },
  v2: { version: "2", primaryKey: ["id"] },
  v3pk: { version: "3", primaryKey: ["id", "kind"] },
};

async function world(
  flagOn: boolean,
  coverageStrategy: "full_inventory" | "checkpoint_window" = "full_inventory",
) {
  const registry = createMemoryStreamSyncRegistry();
  const blobs = createMemoryStreamSyncBlobs();
  let now = 1000;
  // `again` builds the device over a database an earlier sync held: a restart
  // keeps what the database holds and nothing in memory.
  const make = async (
    deviceId: string,
    again?: { db: SqlDriver; flag: boolean },
  ) => {
    const db =
      again?.db ??
      (await openLocalDb(openBetterSqlite3(":memory:"), {
        owner,
        network: "test",
        deviceId,
      }));
    if (!again) drivers.push(db);
    const flag = again ? again.flag : flagOn;
    let op = 0;
    const wake = vi.fn();
    const deps = {
      db,
      queue: connectionQueue(),
      registry,
      blobs,
      ownerAddress: owner,
      keys: {
        namespaceHmac: async () => new Uint8Array(32),
        encrypt: async (_s, b) => b,
        encryptPart: async (_s, b) => b,
        decrypt: async (_s, b) => b,
      },
      signer: { signAddData: async () => "0x00" },
      logger: { info: vi.fn(), warn: vi.fn() },
      now: () => now,
      newOp: () => `${deviceId}-${++op}`,
      recordsCommitted: wake,
      ...(flag ? { publishWhileCollecting: true } : {}),
    };
    const sync = createLocalSync(deps, {
      resolveArtifact: (digest) => {
        const v = versions[digest] ?? versions.fixture!;
        return {
          connector: "fixture",
          version: v.version,
          streams: [
            {
              name: "items",
              semantics: "mutable_state",
              primaryKey: v.primaryKey,
              coverageStrategy,
            },
          ],
        };
      },
    });
    const begin = (
      id: string,
      options: {
        digest?: string;
        observedAt?: number;
        wantFull?: boolean;
      } = {},
    ) => {
      now++;
      return sync.intake.begin(id, {
        connector: "fixture",
        artifactDigest: options.digest ?? "fixture",
        wantFull: options.wantFull ?? true,
        observedAt: options.observedAt,
        owner: { address: owner, leaseId: null },
      });
    };
    /** What each run sent, for its end. */
    const sent = new Map<string, { live: boolean; deleted: boolean }>();
    const batch = (
      id: string,
      n: number,
      rows: Array<string | { id: string; body?: string; remove?: boolean }>,
      kind?: string,
    ) =>
      sync.intake.batch(id, {
        batch: n,
        records: rows.map((r) => {
          const row = typeof r === "string" ? { id: r } : r;
          const seen = sent.get(id) ?? { live: false, deleted: false };
          if (row.remove) seen.deleted = true;
          else seen.live = true;
          sent.set(id, seen);
          return {
            stream: "items",
            ...(row.remove ? { op: "delete" as const } : {}),
            data: {
              id: row.id,
              ...(kind ? { kind } : {}),
              ...(row.body === undefined ? {} : { body: row.body }),
            },
          };
        }),
      });
    const end = (
      id: string,
      lastBatch: number,
      extra: {
        outcome?: "succeeded" | "failed";
        proven?: boolean;
        checkpoint?: string;
      } = {},
    ) =>
      sync.intake.end(
        id,
        endRequest({
          lastBatch,
          streams: ["items"],
          ...(sent.get(id)?.live ? { live: ["items"] } : {}),
          ...(sent.get(id)?.deleted ? { deleted: ["items"] } : {}),
          // A failed run: the connector skipped its one stream.
          ...(extra.outcome === "failed" ? { skipped: ["items"] } : {}),
          ...(extra.proven ? { provenFullStreams: ["items"] } : {}),
          ...(extra.checkpoint
            ? { checkpoints: { items: extra.checkpoint } }
            : {}),
        }),
      );
    return {
      db,
      sync,
      // Flip the flag while runs are open. A run keeps the mode it began in.
      setFlag: (on: boolean) => {
        (deps as { publishWhileCollecting?: boolean }).publishWhileCollecting =
          on;
      },
      wake,
      begin,
      batch,
      end,
      async run(
        id: string,
        rows: Parameters<typeof batch>[2],
        options: {
          digest?: string;
          observedAt?: number;
          proven?: boolean;
          checkpoint?: string;
        } = {},
      ) {
        await begin(id, options);
        await batch(id, 0, rows);
        return end(id, 0, options);
      },
      async publish() {
        expect(
          (await sync.cycle()).connections.every((c) => c.error === null),
        ).toBe(true);
      },
      query: (sql: string, params: unknown[] = []) =>
        db.query<Row>(sql, params as never[]),
      async keys() {
        return (
          await sync.query.listRecords({
            connectionId,
            stream: "items",
            limit: 100,
          })
        ).records
          .map((r) => r.recordKey)
          .sort();
      },
      async body(key: string) {
        const [row] = await db.query<{ body: string }>(
          "SELECT body FROM records WHERE stream='items' AND record_key=?",
          [key],
        );
        return row === undefined ? null : (JSON.parse(row.body).body ?? "");
      },
      async checkpoint() {
        const [row] = await db.query<{ checkpoint: string | null }>(
          "SELECT checkpoint FROM connections WHERE connection_id=?",
          [connectionId],
        );
        return row?.checkpoint ?? null;
      },
      async tombstones() {
        return (
          await db.query<{ n: number }>(
            "SELECT COUNT(*) AS n FROM record_tombstones",
          )
        )[0]!.n;
      },
    };
  };
  let restarts = 0;
  return {
    a: await make("a"),
    b: await make("b"),
    registry,
    // The process restarts: a new sync over the same database, no bindings.
    restart: (device: { db: SqlDriver }, flag: boolean) =>
      make(`restart-${++restarts}`, { db: device.db, flag }),
  };
}

it("a batch is readable through the read path before the run ends", async () => {
  const { a } = await world(true);
  await a.begin("r1");
  await a.batch("r1", 0, ["x", "y"]);
  expect(await a.keys()).toEqual(["x", "y"]);
});

it("record_changes holds the batch's rows before run end and the publisher is woken", async () => {
  const { a } = await world(true);
  await a.begin("r1");
  expect(a.wake).not.toHaveBeenCalled();
  await a.batch("r1", 0, ["x", "y"]);
  expect(
    await a.query(
      "SELECT record_key, op, origin FROM record_changes WHERE stream='items' ORDER BY record_key",
    ),
  ).toEqual([
    { record_key: "x", op: "upsert", origin: "local" },
    { record_key: "y", op: "upsert", origin: "local" },
  ]);
  expect(a.wake).toHaveBeenCalledTimes(1);
});

it("rows publish to another device while the run is still collecting", async () => {
  const { a, b } = await world(true);
  await a.begin("r1");
  await a.batch("r1", 0, ["x"]);
  await a.publish();
  await b.sync.apply();
  expect(await b.keys()).toEqual(["x"]);
  await a.batch("r1", 1, ["y"]);
  await a.end("r1", 1);
  await a.publish();
  await b.sync.apply();
  expect(await b.keys()).toEqual(["x", "y"]);
});

it("with the flag off a batch stays staged until the run ends", async () => {
  const { a } = await world(false);
  await a.begin("r1");
  await a.batch("r1", 0, ["x"]);
  expect(await a.keys()).toEqual([]);
  expect(await a.query("SELECT 1 FROM record_changes")).toEqual([]);
  expect(a.wake).not.toHaveBeenCalled();
  await a.end("r1", 0);
  expect(await a.keys()).toEqual(["x"]);
});

it("a later batch of the same run wins, before and after run end", async () => {
  const { a } = await world(true);
  await a.begin("r1");
  await a.batch("r1", 0, [{ id: "k", body: "first" }, "filler"]);
  await a.batch("r1", 1, [{ id: "k", body: "second" }]);
  expect(await a.body("k")).toBe("second");
  await a.end("r1", 1);
  expect(await a.body("k")).toBe("second");
});

it("the same key in batch 1 and batch 3 ends as batch 3's body", async () => {
  const { a } = await world(true);
  await a.begin("r1");
  await a.batch("r1", 0, ["filler"]);
  await a.batch("r1", 1, [{ id: "k", body: "one" }]);
  await a.batch("r1", 2, ["other"]);
  await a.batch("r1", 3, [{ id: "k", body: "three" }]);
  await a.end("r1", 3);
  expect(await a.body("k")).toBe("three");
});

it("an unchanged row seen in batch 0 still takes a changed body from a later batch", async () => {
  const { a } = await world(true);
  await a.run("seed", [{ id: "k", body: "same" }], { observedAt: 1100 });
  await a.begin("r2", { observedAt: 1200 });
  await a.batch("r2", 0, [{ id: "k", body: "same" }]);
  await a.batch("r2", 1, [{ id: "k", body: "changed" }]);
  await a.end("r2", 1);
  expect(await a.body("k")).toBe("changed");
});

it("upsert, delete, upsert ends as the last upsert; upsert, delete ends deleted", async () => {
  const { a } = await world(true);
  await a.begin("r1");
  await a.batch("r1", 0, [{ id: "k", body: "one" }]);
  await a.batch("r1", 1, [{ id: "k", remove: true }]);
  await a.batch("r1", 2, [{ id: "k", body: "three" }]);
  await a.end("r1", 2);
  expect(await a.body("k")).toBe("three");

  await a.begin("r2", { observedAt: 1500 });
  await a.batch("r2", 0, [{ id: "j", body: "one" }]);
  await a.batch("r2", 1, [{ id: "j", remove: true }]);
  expect(await a.body("j")).toBe("one");
  await a.end("r2", 1);
  expect(await a.body("j")).toBeNull();
});

it("a run refused at end keeps its upserts and withholds omission deletes and the cursor", async () => {
  const { a } = await world(true);
  await a.run("seed", ["old"], { observedAt: 1100 });
  await a.publish();
  await a.begin("older", { observedAt: 1200 });
  await a.batch("older", 0, ["late"]);
  await a.run("newer", ["old", "new"], { observedAt: 3000, checkpoint: "c1" });
  const cursor = await a.checkpoint();
  // The older run saw only `late`: it is out of order and may not omit `old`.
  const result = await a.end("older", 0, { proven: true, checkpoint: "c2" });
  expect(result.result).not.toBe("queued");
  expect(await a.checkpoint()).toBe(cursor);
  await a.publish();
  expect(await a.keys()).toEqual(["late", "new", "old"]);
});

it("a failed run keeps its admitted upserts and moves nothing else", async () => {
  const { a } = await world(true);
  await a.run("seed", ["old"], { observedAt: 1100, checkpoint: "c1" });
  await a.publish();
  const cursor = await a.checkpoint();
  await a.begin("failing", { observedAt: 1500 });
  await a.batch("failing", 0, ["partial"]);
  await a.end("failing", 0, {
    outcome: "failed",
    proven: true,
    checkpoint: "c2",
  });
  await a.publish();
  expect(await a.keys()).toEqual(["old", "partial"]);
  expect(await a.checkpoint()).toBe(cursor);
});

it("a connection delete after a batch purges the batch's rows and fences the run", async () => {
  const { a } = await world(true);
  await a.begin("r1");
  await a.batch("r1", 0, ["x"]);
  expect(await a.keys()).toEqual(["x"]);
  await a.sync.deleter.requestConnectionDelete("fixture");
  expect(await a.keys()).toEqual([]);
  await expect(a.batch("r1", 1, ["y"])).rejects.toMatchObject({
    code: expect.stringMatching(/connection_stopped|gone/),
  });
  expect(await a.keys()).toEqual([]);
});

it("a connection delete clears the tombstones of the lifetime it ended", async () => {
  const { a } = await world(true, "checkpoint_window");
  await a.run("seed", ["gone"], { observedAt: 1100 });
  await a.begin("older", { observedAt: 1200 });
  await a.begin("newer", { observedAt: 3000 });
  await a.batch("newer", 0, [{ id: "gone", remove: true }]);
  await a.end("newer", 0);
  expect(await a.tombstones()).toBeGreaterThan(0);
  await a.sync.deleter.requestConnectionDelete("fixture");
  expect(await a.tombstones()).toBe(0);
});

it("a fenced batch is rejected and merges nothing", async () => {
  const { a } = await world(true);
  await a.begin("r1");
  await a.db.batch([
    {
      sql: "INSERT INTO delete_intents(connector,delete_id,intent) VALUES ('fixture','d1','{}')",
    },
  ]);
  await expect(a.batch("r1", 0, ["x"])).rejects.toMatchObject({
    code: "connection_stopped",
  });
  expect(await a.query("SELECT 1 FROM records")).toEqual([]);
  expect(await a.query("SELECT 1 FROM record_changes")).toEqual([]);
});

it("an older stamp never replaces a newer writer, in either arrival order", async () => {
  const { a } = await world(true);
  await a.begin("older", { observedAt: 1100 });
  await a.run("newer", [{ id: "k", body: "new" }], { observedAt: 2000 });
  await a.batch("older", 0, [{ id: "k", body: "old" }]);
  expect(await a.body("k")).toBe("new");
  await a.end("older", 0);
  expect(await a.body("k")).toBe("new");

  await a.begin("early", { observedAt: 2100 });
  await a.batch("early", 0, [{ id: "j", body: "early" }]);
  await a.run("late", [{ id: "j", body: "late" }], { observedAt: 2200 });
  expect(await a.body("j")).toBe("late");
  await a.end("early", 0);
  expect(await a.body("j")).toBe("late");
});

it("an older run's late upsert does not bring back a row a newer run dropped by omission", async () => {
  const { a, b } = await world(true);
  await a.run("seed", ["gone", "kept"], { observedAt: 1100 });
  await a.publish();
  await b.sync.apply();
  await a.begin("older", { observedAt: 1200 });
  // The newer full inventory omits `gone`; its omission publishes.
  await a.run("newer", ["kept"], { observedAt: 3000, proven: true });
  await a.publish();
  await b.sync.apply();
  expect(await a.keys()).toEqual(["kept"]);
  const skipped = await a.batch("older", 0, ["gone", "fresh"]);
  expect(skipped).toMatchObject({ accepted: 2, tombstoned: 1 });
  expect(await a.keys()).toEqual(["fresh", "kept"]);
  await a.end("older", 0);
  await a.publish();
  await b.sync.apply();
  expect(await a.keys()).toEqual(["fresh", "kept"]);
  expect(await b.keys()).toEqual(["fresh", "kept"]);
});

it("an older run's late upsert does not bring back a row a newer run deleted explicitly", async () => {
  const { a, b } = await world(true, "checkpoint_window");
  await a.run("seed", ["gone"], { observedAt: 1100 });
  await a.publish();
  await b.sync.apply();
  await a.begin("older", { observedAt: 1200 });
  await a.begin("deleter", { observedAt: 3000 });
  await a.batch("deleter", 0, [{ id: "gone", remove: true }]);
  await a.end("deleter", 0);
  await a.publish();
  await b.sync.apply();
  expect(await a.keys()).toEqual([]);
  expect(await a.batch("older", 0, ["gone"])).toMatchObject({
    tombstoned: 1,
  });
  expect(await a.keys()).toEqual([]);
  await a.end("older", 0);
  await a.publish();
  await b.sync.apply();
  expect(await a.keys()).toEqual([]);
  expect(await b.keys()).toEqual([]);
});

it("compaction keeps a tombstone while an older run is open and drops it once none is", async () => {
  const { a } = await world(true, "checkpoint_window");
  await a.run("seed", ["gone"], { observedAt: 1100 });
  await a.begin("older", { observedAt: 1200 });
  await a.begin("deleter", { observedAt: 3000 });
  await a.batch("deleter", 0, [{ id: "gone", remove: true }]);
  await a.end("deleter", 0);
  expect(await a.tombstones()).toBe(1);
  await a.end("older", -1, { outcome: "failed" });
  expect(await a.tombstones()).toBe(0);

  // With no older run open, a delete's tombstone goes at its own end.
  await a.run("seed2", ["gone2"], { observedAt: 3100 });
  await a.begin("alone", { observedAt: 3200 });
  await a.batch("alone", 0, [{ id: "gone2", remove: true }]);
  await a.end("alone", 0);
  expect(await a.tombstones()).toBe(0);
});

it("a batch from a connector older than the version floor is not admitted and marks the run", async () => {
  const { a } = await world(true, "checkpoint_window");
  await a.begin("old-run", { digest: "v1", observedAt: 1100 });
  await a.batch("old-run", 0, ["admitted-early"]);
  await a.run("new-run", ["from-v2"], { digest: "v2", observedAt: 1500 });
  const refused = await a.batch("old-run", 1, ["too-late"]);
  expect(refused).toMatchObject({ updateRequired: true });
  expect(await a.keys()).toEqual(["admitted-early", "from-v2"]);
  const ended = await a.end("old-run", 1);
  expect(ended.updateRequired).toBe(true);
  expect(await a.keys()).toEqual(["admitted-early", "from-v2"]);
});

/**
 * Run `effect` once, right before the next batch that admits rows reaches the
 * database: after the connector check read the stream state, before the
 * transaction writes. That is the window a concurrent commit can use.
 */
function raceOnce(
  db: { batch: (...args: never[]) => Promise<unknown> },
  effect: () => Promise<void>,
) {
  const original = db.batch.bind(db) as (
    statements: Array<{ sql: string }>,
  ) => Promise<unknown>;
  let fired = false;
  (db as { batch: unknown }).batch = async (
    statements: Array<{ sql: string }>,
  ) => {
    if (!fired && statements.some((s) => s.sql.includes("INTO incoming"))) {
      fired = true;
      await effect();
    }
    return original(statements);
  };
}

it("a newer connector committing between the check and the write leaves the batch staged, not admitted", async () => {
  const { a } = await world(true, "checkpoint_window");
  await a.begin("old-run", { digest: "v1", observedAt: 1100 });
  await a.batch("old-run", 0, ["early"]);
  raceOnce(a.db as never, async () => {
    // A v2 commit lands: the floor rises and the head version moves.
    await a.db.batch([
      {
        sql: "UPDATE stream_state SET floor_version='2', head_version=head_version+1 WHERE stream='items'",
      },
    ]);
  });
  const result = await a.batch("old-run", 1, ["raced"]);
  expect(result).toMatchObject({ applied: true, accepted: 1, tombstoned: 0 });
  expect(await a.keys()).toEqual(["early"]);
  expect(
    await a.query(
      "SELECT record_key FROM run_rows WHERE record_key='raced' UNION ALL SELECT record_key FROM records WHERE record_key='raced'",
    ),
  ).toHaveLength(1);
  const ended = await a.end("old-run", 1);
  expect(ended.updateRequired).toBe(true);
  expect(await a.keys()).toEqual(["early"]);
});

it("a change of stream state that does not refuse the run leaves the batch staged, and run end merges it", async () => {
  const { a } = await world(true, "checkpoint_window");
  await a.begin("run", { observedAt: 1100 });
  await a.batch("run", 0, ["early"]);
  raceOnce(a.db as never, async () => {
    await a.db.batch([
      {
        sql: "UPDATE stream_state SET head_version=head_version+1 WHERE stream='items'",
      },
    ]);
  });
  await a.batch("run", 1, ["raced"]);
  expect(await a.keys()).toEqual(["early"]);
  expect(
    await a.query(
      "SELECT unadmitted FROM run_streams WHERE run_id='run' AND stream='items'",
    ),
  ).toEqual([{ unadmitted: 1 }]);
  await a.batch("run", 2, ["after"]);
  expect(await a.keys()).toEqual(["after", "early"]);
  await a.end("run", 2);
  expect(await a.keys()).toEqual(["after", "early", "raced"]);
});

it("a run that begins with an old observedAt after a delete's tombstone was compacted is stamped above it", async () => {
  const { a, b } = await world(true, "checkpoint_window");
  await a.run("seed", ["gone"], { observedAt: 1100 });
  await a.begin("deleter", { observedAt: 3000 });
  await a.batch("deleter", 0, [{ id: "gone", remove: true }]);
  await a.end("deleter", 0);
  // No run is open: the tombstone is compacted, its stamp is the watermark.
  expect(await a.tombstones()).toBe(0);
  expect(
    await a.query(
      "SELECT tombstone_wm_o AS o, tombstone_wm_r AS r FROM connections",
    ),
  ).toEqual([{ o: 3000, r: "deleter" }]);

  // Ahead of the watermark by run id: the stamp is already above, o is kept
  // only when it is.
  await a.begin("late", { observedAt: 1200 });
  await a.begin("alpha", { observedAt: 1300 });
  const stamps = await a.query(
    "SELECT run_id, o FROM runs WHERE run_id IN ('late','alpha') ORDER BY run_id",
  );
  // 'late' sorts after 'deleter': o is raised to the watermark's o.
  // 'alpha' sorts before it: o goes one above.
  expect(stamps).toEqual([
    { run_id: "alpha", o: 3001 },
    { run_id: "late", o: 3000 },
  ]);

  // The row it brings back carries a stamp above the delete's, so every
  // device orders the delete before it.
  await a.batch("late", 0, ["gone"]);
  const [row] = await a.query(
    "SELECT stamp_o, stamp_r FROM records WHERE record_key='gone'",
  );
  expect(
    row!.stamp_o! > 3000 ||
      (row!.stamp_o === 3000 && row!.stamp_r! > "deleter"),
  ).toBe(true);
  await a.end("late", 0);
  await a.end("alpha", -1, { outcome: "failed" });
  await a.publish();
  await b.sync.apply();
  expect(await b.keys()).toEqual(await a.keys());
});

it("compaction at run begin drops a tombstone whose older run ended without compacting", async () => {
  const { a } = await world(true, "checkpoint_window");
  await a.run("seed", ["gone"], { observedAt: 1100 });
  await a.begin("older", { observedAt: 1200 });
  await a.begin("deleter", { observedAt: 3000 });
  await a.batch("deleter", 0, [{ id: "gone", remove: true }]);
  await a.end("deleter", 0);
  expect(await a.tombstones()).toBe(1);
  // The older run ends by a path that does not compact (a discard, a crash
  // recovery). The next begin must still drop the tombstone.
  await a.db.batch([
    { sql: "UPDATE runs SET state='ended' WHERE run_id='older'" },
  ]);
  expect(await a.tombstones()).toBe(1);
  await a.begin("next", { observedAt: 4000 });
  expect(await a.tombstones()).toBe(0);
  expect(await a.query("SELECT tombstone_wm_o AS o FROM connections")).toEqual([
    { o: 3000 },
  ]);
});

it("turning the flag off while a run is admitting does not let that run bring back a delete", async () => {
  const { a } = await world(true, "checkpoint_window");
  await a.run("seed", ["gone"], { observedAt: 1100 });
  await a.publish();
  // Run `older` begins with the flag on: it stays an admitting run.
  await a.begin("older", { observedAt: 1200 });
  // The flag goes off. A newer run deletes the key and publishes.
  a.setFlag(false);
  await a.begin("deleter", { observedAt: 3000 });
  await a.batch("deleter", 0, [{ id: "gone", remove: true }]);
  await a.end("deleter", 0);
  await a.publish();
  expect(await a.keys()).toEqual([]);
  // The older run's late batch still admits: its mode is persisted.
  await a.batch("older", 0, ["gone"]);
  expect(await a.keys()).toEqual([]);
  expect(await a.tombstones()).toBe(1);
  await a.end("older", 0);
  await a.publish();
  expect(await a.keys()).toEqual([]);
  // Compaction runs with the flag off too: the tombstone goes with the run.
  expect(await a.tombstones()).toBe(0);
});

it("with the flag off and no admitting run, deletes write no tombstone", async () => {
  const { a } = await world(false, "checkpoint_window");
  await a.run("seed", ["gone"], { observedAt: 1100 });
  await a.begin("deleter", { observedAt: 3000 });
  await a.batch("deleter", 0, [{ id: "gone", remove: true }]);
  await a.end("deleter", 0);
  expect(await a.tombstones()).toBe(0);
});

it("a late publish refusal of an accepted admitting run keeps rows a newer collecting run also admitted", async () => {
  const { a, b } = await world(true, "full_inventory");
  await a.run("seed", ["s"], { observedAt: 1050 });
  await a.publish();
  await b.sync.apply();
  // Run A admits K and ends accepted locally. Newer run B still collects and
  // admits the same body, so K's seen stamp moves to B.
  await a.begin("A", { digest: "v1", observedAt: 1100 });
  await a.batch("A", 0, ["K"]);
  await a.end("A", 0);
  await a.begin("B", { digest: "v1", observedAt: 1500 });
  await a.batch("B", 0, ["K"]);
  // A newer connector publishes elsewhere and raises the floor.
  await b.run("R", ["other"], {
    digest: "v2",
    observedAt: 2000,
    proven: true,
  });
  await b.publish();
  // Publication replans A against that head and refuses it.
  await a.publish();
  expect(
    await a.query(
      "SELECT decision, reason FROM run_streams WHERE run_id='A' AND stream='items'",
    ),
  ).toEqual([{ decision: "refused", reason: "connector_update_required" }]);
  expect(await a.keys()).toContain("K");
  await a.end("B", 0);
  expect(await a.keys()).toContain("K");
});

it("a restart ends the runs the old process left collecting, and compaction moves past them", async () => {
  const { a, restart } = await world(true, "checkpoint_window");
  await a.run("seed", ["gone"], { observedAt: 1100 });
  await a.begin("orphan", { observedAt: 1200 });
  await a.batch("orphan", 0, ["early"]);
  await a.begin("deleter", { observedAt: 3000 });
  await a.batch("deleter", 0, [{ id: "gone", remove: true }]);
  await a.end("deleter", 0);
  // The open older run holds the tombstone.
  expect(await a.tombstones()).toBe(1);

  const again = await restart(a, true);
  await again.begin("fresh", { observedAt: 4000 });
  expect(
    await again.query("SELECT run_id, state FROM runs WHERE run_id = 'orphan'"),
  ).toEqual([{ run_id: "orphan", state: "ended" }]);
  // Ended as a failed run: its staged rows are gone, nothing was decided for
  // omissions or the cursor, and what it admitted stays.
  expect(
    await again.query(
      "SELECT decision, reason FROM run_streams WHERE run_id = 'orphan'",
    ),
  ).toEqual([{ decision: "discarded", reason: "failed" }]);
  expect(
    await again.query("SELECT 1 FROM run_rows WHERE run_id = 'orphan'"),
  ).toEqual([]);
  expect(await again.keys()).toEqual(["early"]);
  expect(await again.checkpoint()).toBeNull();
  // Nothing older than the live run is open: the tombstone is gone.
  expect(await again.tombstones()).toBe(0);
  // The host that ends the orphan after the restart reads its outcome.
  expect(await again.end("orphan", 0)).toMatchObject({ result: "aborted" });
});

it("after a restart a newer run's delete still beats the orphan's late rows", async () => {
  const { a, restart } = await world(true, "checkpoint_window");
  await a.run("seed", ["gone"], { observedAt: 1100 });
  await a.publish();
  await a.begin("orphan", { observedAt: 1200 });
  await a.begin("deleter", { observedAt: 3000 });
  await a.batch("deleter", 0, [{ id: "gone", remove: true }]);
  await a.end("deleter", 0);
  await a.publish();

  const again = await restart(a, true);
  await again.begin("fresh", { observedAt: 4000 });
  // No batch of the orphan can arrive: its binding died with the process.
  await expect(again.batch("orphan", 0, ["gone"])).rejects.toMatchObject({
    code: "gone",
  });
  expect(await again.keys()).toEqual([]);
});

it("a restart with the flag off ends a run that never admitted", async () => {
  const { a, restart } = await world(false, "checkpoint_window");
  await a.begin("orphan", { observedAt: 1200 });
  await a.batch("orphan", 0, ["staged"]);
  const again = await restart(a, false);
  await again.begin("fresh", { observedAt: 4000 });
  expect(
    await again.query(
      "SELECT r.state, (SELECT COUNT(*) FROM run_rows w WHERE w.run_id = r.run_id) AS staged FROM runs r WHERE r.run_id = 'orphan'",
    ),
  ).toEqual([{ state: "ended", staged: 0 }]);
  expect(await again.keys()).toEqual([]);
  expect(await again.end("orphan", 0)).toMatchObject({ result: "aborted" });
});

it("a restart with the flag off still ends a run that admitted while the flag was on", async () => {
  const { a, restart } = await world(true, "checkpoint_window");
  await a.begin("orphan", { observedAt: 1200 });
  await a.batch("orphan", 0, ["early"]);
  const again = await restart(a, false);
  await again.begin("fresh", { observedAt: 4000 });
  expect(
    await again.query("SELECT state FROM runs WHERE run_id = 'orphan'"),
  ).toEqual([{ state: "ended" }]);
  expect(await again.keys()).toEqual(["early"]);
});

it("a restart with no run left collecting changes nothing", async () => {
  const { a, restart } = await world(false, "checkpoint_window");
  await a.run("r1", ["x"], { observedAt: 1100 });
  const read = async () => ({
    runs: await a.query(
      "SELECT * FROM runs WHERE run_id <> 'fresh' ORDER BY run_id",
    ),
    streams: await a.query(
      "SELECT * FROM run_streams WHERE run_id <> 'fresh' ORDER BY run_id, stream",
    ),
    records: await a.query("SELECT * FROM records ORDER BY pk_hash"),
    changes: await a.query("SELECT * FROM record_changes ORDER BY seq"),
  });
  const before = await read();
  const again = await restart(a, false);
  await again.begin("fresh", { observedAt: 4000 });
  expect(await read()).toEqual(before);
});

/**
 * The driver of a restarted process with faults armed from the start, so they
 * hit the sweep that runs when the sync is built: `snapshot` fails that many
 * reads of the orphans (the one at start and one more), `end` fails the first batch that ends a run.
 */
function faulty(db: SqlDriver, faults: { snapshot?: number; end?: boolean }) {
  const handler: ProxyHandler<SqlDriver> = {
    get(target, key) {
      if (key === "query")
        return (sql: string, params?: never) => {
          if (
            faults.snapshot &&
            sql.includes("FROM runs WHERE state = 'collecting'")
          ) {
            faults.snapshot -= 1;
            return Promise.reject(new Error("fault: orphan read"));
          }
          return target.query(sql, params);
        };
      if (key === "batch")
        return (statements: readonly { sql: string }[]) => {
          if (
            faults.end &&
            statements.some((x) => x.sql.includes("SET state = 'ended'"))
          ) {
            faults.end = false;
            return Promise.reject(new Error("fault: end batch"));
          }
          return target.batch(statements);
        };
      const value = Reflect.get(target, key);
      return typeof value === "function" ? value.bind(target) : value;
    },
  };
  return new Proxy(db, handler);
}

async function openRunAfterFaultedSweep(faults: {
  snapshot?: number;
  end?: boolean;
}) {
  const { a, restart } = await world(true, "checkpoint_window");
  await a.run("seed", ["gone"], { observedAt: 1100 });
  await a.begin("O1", { observedAt: 1200 });
  await a.batch("O1", 0, ["o1"]);
  await a.begin("O2", { observedAt: 1300 });
  await a.batch("O2", 0, ["o2"]);
  const again = await restart({ db: faulty(a.db, faults) }, true);
  return { a, again };
}

const stateOf = (d: {
  query: (sql: string) => Promise<Record<string, unknown>[]>;
}) => d.query("SELECT run_id, state FROM runs ORDER BY o, run_id");

it("a sweep that could not end every orphan retries only those, never a run begun after it", async () => {
  const { again } = await openRunAfterFaultedSweep({ end: true });
  // The first orphan's end fails; the second ends. A new run still begins.
  await again.begin("A", { observedAt: 4000 });
  await again.batch("A", 0, ["a1"]);
  // The fault is spent. The next begin retries the orphan, and only it.
  await again.begin("B", { observedAt: 5000 });
  expect(await stateOf(again)).toEqual([
    { run_id: "seed", state: "ended" },
    { run_id: "O1", state: "ended" },
    { run_id: "O2", state: "ended" },
    { run_id: "A", state: "collecting" },
    { run_id: "B", state: "collecting" },
  ]);
  await again.batch("A", 1, ["a2"]);
  expect(await again.end("A", 1)).not.toMatchObject({ result: "aborted" });
  expect(await again.keys()).toEqual(expect.arrayContaining(["a1", "a2"]));
  expect(
    await again.query(
      "SELECT decision FROM run_streams WHERE run_id = 'A' AND stream = 'items'",
    ),
  ).not.toEqual([{ decision: "discarded" }]);
});

it("a sweep that cannot read the orphans fails the begin, and the retry never reaches a later run", async () => {
  const { again } = await openRunAfterFaultedSweep({ snapshot: 2 });
  // Without the list of orphans the sweep cannot tell them from a live run, so
  // no run begins until it has the list.
  await expect(again.begin("A", { observedAt: 4000 })).rejects.toThrow(
    /orphan read/,
  );
  expect(
    await again.query("SELECT run_id FROM runs WHERE run_id = 'A'"),
  ).toEqual([]);
  await again.begin("A", { observedAt: 4000 });
  await again.batch("A", 0, ["a1"]);
  await again.begin("B", { observedAt: 5000 });
  expect(await stateOf(again)).toEqual([
    { run_id: "seed", state: "ended" },
    { run_id: "O1", state: "ended" },
    { run_id: "O2", state: "ended" },
    { run_id: "A", state: "collecting" },
    { run_id: "B", state: "collecting" },
  ]);
  await again.batch("A", 1, ["a2"]);
  expect(await again.end("A", 1)).not.toMatchObject({ result: "aborted" });
});

// GAP, not fixed here: a head commit that changes the primary key does not move
// the connection generation (only delete + reconnect does, bootstrap.ts), so
// the fence never trips an older connector's run that is already collecting,
// and its rows admitted under the old pk_hash stay in `records`. When the
// generation moves on a primary-key change this test starts passing; then drop
// `.fails`.
it.fails(
  "a primary-key change fences older runs and clears their admitted rows",
  async () => {
    const { a } = await world(true, "checkpoint_window");
    await a.begin("old-pk", { digest: "v1", observedAt: 1100 });
    await a.batch("old-pk", 0, ["a"]);
    await a.begin("new-pk", { digest: "v3pk", observedAt: 1500 });
    await a.batch("new-pk", 0, [{ id: "b" }], "kind1");
    await a.end("new-pk", 0);
    await a.publish();
    await expect(a.batch("old-pk", 1, ["c"])).rejects.toMatchObject({
      code: "connection_stopped",
    });
    expect(
      await a.query("SELECT record_key FROM records WHERE record_key='a'"),
    ).toEqual([]);
  },
);

it("run end honors a delete admitted after its zero-delete read and retains history across runs", async () => {
  const { a } = await world(true, "checkpoint_window");
  await a.run("seed-skip-check", ["keep", "remove"]);
  await a.begin("older-skip-check", { observedAt: 1100 });
  await a.batch("older-skip-check", 0, ["remove"]);
  await a.begin("end-skip-check", { observedAt: 1200 });
  await a.batch("end-skip-check", 0, ["keep"]);
  const original = a.db.batch.bind(a.db);
  let raced = false;
  a.db.batch = async (statements) => {
    if (!raced && statements.some((s) => s.sql.includes("decision = ?"))) {
      raced = true;
      // Another admitted batch commits after the end planner read its counts.
      // Keep the same batch boundary: the race changes only the durable fold.
      await original([
        {
          sql: `INSERT OR REPLACE INTO run_rows(run_id,stream,pk_hash,record_key,body,body_sha256,op,pk_values)
          SELECT 'end-skip-check',stream,pk_hash,record_key,'{}','digest','delete',pk_values
          FROM run_rows WHERE run_id='older-skip-check'`,
        },
      ]);
    }
    return original(statements);
  };
  await a.end("end-skip-check", 0);
  expect(raced).toBe(true);
  expect(await a.keys()).toEqual(["keep"]);
  expect(await a.tombstones()).toBe(1);
  await a.end("older-skip-check", 0);
  expect(await a.keys()).toEqual(["keep"]);
  expect(await a.tombstones()).toBe(0);
  await a.run("later-zero-delete", ["keep"]);
  expect(await a.keys()).toEqual(["keep"]);
});
