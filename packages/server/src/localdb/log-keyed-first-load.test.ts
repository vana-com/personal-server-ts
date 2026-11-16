// A first load of a log too big for one commit loads key by key (core
// localdb/log-keyed.ts). What a reader may see does not change: it ends in the
// rows, tombstones, heads and position a segment-by-segment apply ends in, the
// position moves with the last of the rows and not before, and a load that
// stops (a crash, a segment it cannot fetch) leaves nothing a reader trusts and
// ends right when it runs again. Real publisher, real gateway adapter, real
// SQLite (log-world.test-utils.ts).
import { afterEach, describe, expect, it } from "vitest";
import { applyConnection } from "../../../core/src/localdb/index.js";
import {
  CONNECTION_ID,
  closeWorldDrivers,
  sName,
  world,
} from "./log-world.test-utils.js";

afterEach(closeWorldDrivers);

type World = Awaited<ReturnType<typeof world>>;
type Device = Awaited<ReturnType<World["device"]>>;
type RunRecords = Parameters<Device["run"]>[1];

const S0 = sName(0);
const S1 = sName(1);
const WRITES_POSITION = "INSERT OR REPLACE INTO log_state";

async function connected(w: World, id: string, hooks = {}) {
  const d = await w.device(id, true, hooks);
  await d.db.batch([
    {
      sql: "INSERT INTO connections(connection_id,connector,ns,generation,control_state,control_version) VALUES (?,?,'',1,'active',1)",
      params: [CONNECTION_ID, "fixture"],
    },
  ]);
  return d;
}

/** One run and its segment: `full` runs omit the keys they do not carry. */
async function step(
  d: Device,
  n: number,
  records: RunRecords,
  opts: { full?: boolean } = {},
) {
  await d.run(`run-${n}`, records, {
    full: opts.full ?? false,
    covered: [S0, S1],
    observedAt: 1000 + n,
  });
  await d.cycle();
}

/**
 * Every kind of key history a log holds: a key written once, rewritten, deleted,
 * brought back, omitted by a full run, and written again after the omission.
 */
async function history(w: World, segments = 12) {
  const a = await w.device("a");
  const pad = 4_000;
  for (let n = 1; n <= segments; n++) {
    const records: RunRecords[number][] = [
      { stream: n % 2 ? S0 : S1, id: `once-${n}`, pad },
      { stream: S0, id: "shared", v: n },
    ];
    if (n === 3) records.push({ stream: S0, id: "gone", pad });
    if (n === 5) records.push({ stream: S0, id: "gone", remove: true });
    if (n === 7) records.push({ stream: S0, id: "gone", v: 7, pad });
    if (n === 6) records.push({ stream: S1, id: "dropped", pad });
    await step(a, n, records);
  }
  // A full run that carries only some keys omits the others it did not see.
  const kept: RunRecords[number][] = [{ stream: S0, id: "shared", v: 99 }];
  for (let n = 1; n <= segments; n++)
    if (n % 4 !== 0)
      kept.push({ stream: n % 2 ? S0 : S1, id: `once-${n}`, pad });
  await step(a, segments + 1, kept, { full: true });
  await step(a, segments + 2, [{ stream: S1, id: "dropped", v: 99 }]);
  return a;
}

/** The length of each segment, the head's too. */
const segmentWeights = async (w: World) =>
  Promise.all(
    [...(await w.segmentKeys()).values()].map(
      async (key) => (await w.innerBlobs.get(key))!.length,
    ),
  );

/** A budget that splits the log into several key ranges. */
const splitting = async (w: World) =>
  2 * Math.max(...(await segmentWeights(w)));

async function tables(d: Device) {
  const q = <T extends Record<string, unknown>>(sql: string) =>
    d.db.query<T>(sql);
  const changes = await q<{
    stream: string;
    pk_hash: string;
    op: string;
    stamp_o: number;
    stamp_r: string;
    origin: string;
  }>(
    "SELECT stream, pk_hash, op, stamp_o, stamp_r, origin FROM record_changes ORDER BY seq",
  );
  const perKey = new Map<string, string[]>();
  for (const c of changes) {
    const key = `${c.stream}/${c.pk_hash}`;
    const list = perKey.get(key) ?? [];
    list.push(`${c.op}@${c.stamp_o}.${c.stamp_r}:${c.origin}`);
    perKey.set(key, list);
  }
  return {
    records: await q("SELECT * FROM records ORDER BY stream, pk_hash"),
    tombstones: await q(
      "SELECT * FROM log_tombstones ORDER BY stream, pk_hash",
    ),
    streams: await q(
      `SELECT stream, primary_key, profile_key, profile_version, complete,
              head_generation, head_data_hash, head_blob
         FROM stream_state ORDER BY stream`,
    ),
    heads: await q(
      `SELECT v.stream, v.generation, v.head_blob, v.head_format, v.record_count, v.observed_at, v.complete
         FROM stream_versions v
        WHERE v.version = (SELECT MAX(version) FROM stream_versions h
                            WHERE h.connection_id = v.connection_id AND h.stream = v.stream)
        ORDER BY v.stream`,
    ),
    state: await q("SELECT * FROM log_state"),
    changes: [...perKey.entries()].sort(([x], [y]) => (x < y ? -1 : 1)),
  };
}

const stageTables = async (d: Device) =>
  (
    await d.db.query<{ name: string }>(
      "SELECT name FROM sqlite_master WHERE name LIKE 'log\\_stage\\_%' ESCAPE '\\'",
    )
  ).map((r) => r.name);

/** The statements each commit of `d` runs, for a test to look at or stop. */
function onCommit(
  d: Device,
  before: (statements: { sql: string }[], index: number) => Promise<void>,
) {
  const db = d.db as unknown as { batch: Device["db"]["batch"] };
  const batch = db.batch.bind(db);
  let index = 0;
  db.batch = async (statements) => {
    await before(statements, index++);
    return batch(statements);
  };
}

describe("log first load, key by key", () => {
  it("ends in what a segment-by-segment apply ends in, for every kind of key history", async () => {
    const w = await world({ streams: 2, logProtocol: true });
    await history(w);
    const reference = await connected(w, "reference", {
      keyedFirstLoad: false,
    });
    await applyConnection(reference.deps, CONNECTION_ID);

    const keyed = await connected(w, "keyed", {
      maxBytesInFlight: await splitting(w),
    });
    const stages: string[] = [];
    onCommit(keyed, async (statements) => {
      for (const s of statements)
        if (s.sql.startsWith("CREATE TABLE log_stage_")) stages.push(s.sql);
    });
    await applyConnection(keyed.deps, CONNECTION_ID);

    // It loaded key by key: more than one key range, all gone afterwards.
    expect(stages.length).toBeGreaterThan(1);
    expect(await stageTables(keyed)).toEqual([]);
    const expected = await tables(reference);
    const got = await tables(keyed);
    expect(got.records).toEqual(expected.records);
    expect(got.tombstones).toEqual(expected.tombstones);
    expect(got.streams).toEqual(expected.streams);
    expect(got.heads).toEqual(expected.heads);
    expect(got.state).toEqual(expected.state);
    // The same changes to each key, in the same order; across keys the order differs.
    expect(got.changes).toEqual(expected.changes);
    // The shape the history makes: an omitted key is gone, a resurrected one is back.
    expect(expected.records.length).toBeGreaterThan(5);
    expect(expected.tombstones.length).toBeGreaterThan(0);
  });

  it("keeps a first load's streams unreadable and its position at 0 until its last commit", async () => {
    const w = await world({ streams: 2, logProtocol: true });
    await history(w);
    const keyed = await connected(w, "keyed", {
      maxBytesInFlight: await splitting(w),
    });
    const seen: { versions: number; position: number; writes: boolean }[] = [];
    onCommit(keyed, async (statements) => {
      seen.push({
        versions: (
          await keyed.db.query<{ n: number }>(
            "SELECT COUNT(*) AS n FROM stream_versions",
          )
        )[0]!.n,
        position: await keyed.position(),
        writes: statements.some((s) => s.sql.includes(WRITES_POSITION)),
      });
    });
    await applyConnection(keyed.deps, CONNECTION_ID);
    const last = seen.findIndex((s) => s.writes);
    expect(last).toBeGreaterThan(0);
    // Every commit before the one that writes the position sees neither.
    for (const s of seen.slice(0, last + 1))
      expect(s).toMatchObject({ versions: 0, position: 0 });
    expect(await keyed.position()).toBeGreaterThan(0);
  });

  it("holds at most its memory budget (a segment more when the budget is under one)", async () => {
    const w = await world({ streams: 2, logProtocol: true });
    await history(w);
    const budget = await splitting(w);
    const keyed = await connected(w, "keyed", { maxBytesInFlight: budget });
    // A request above the budget waits to run alone, so the peak is the budget
    // or the largest request, whichever is more.
    const asked: number[] = [];
    const { governor } = keyed.deps.blobs;
    const reserve = governor.reserve.bind(governor);
    governor.reserve = (bytes, objectBytes) => {
      asked.push(bytes);
      return reserve(bytes, objectBytes);
    };
    const window = governor.window();
    await applyConnection(keyed.deps, CONNECTION_ID);
    const peak = window.end().peakBytesInFlight;
    expect(peak).toBeGreaterThan(0);
    expect(peak).toBeLessThanOrEqual(Math.max(budget, ...asked));
  });

  it("ends right when it runs again after a stop at any commit", async () => {
    const w = await world({ streams: 2, logProtocol: true });
    await history(w);
    const reference = await connected(w, "reference", {
      keyedFirstLoad: false,
    });
    await applyConnection(reference.deps, CONNECTION_ID);
    const expected = await tables(reference);

    // How many commits a keyed load makes: stop at each of them in turn.
    const count = await connected(w, "count", {
      maxBytesInFlight: await splitting(w),
    });
    let commits = 0;
    onCommit(count, async () => void commits++);
    await applyConnection(count.deps, CONNECTION_ID);
    expect(commits).toBeGreaterThan(4);

    for (let stopAt = 0; stopAt < commits; stopAt++) {
      const d = await connected(w, `stop-${stopAt}`, {
        maxBytesInFlight: await splitting(w),
      });
      // The process stops at this commit: it and every write after it fail.
      let armed = true;
      onCommit(d, async (_s, index) => {
        if (armed && index >= stopAt) throw new Error("stopped");
      });
      await expect(applyConnection(d.deps, CONNECTION_ID)).rejects.toThrow();
      armed = false;
      // A reader trusts the streams only with the position: both or neither
      // (the last stop is the clean-up after the last commit).
      const versions = (
        await d.db.query<{ n: number }>(
          "SELECT COUNT(*) AS n FROM stream_versions",
        )
      )[0]!.n;
      expect(versions > 0).toBe((await d.position()) > 0);
      await applyConnection(d.deps, CONNECTION_ID);
      expect(await stageTables(d)).toEqual([]);
      const got = await tables(d);
      expect(got.records).toEqual(expected.records);
      expect(got.tombstones).toEqual(expected.tombstones);
      expect(got.heads).toEqual(expected.heads);
      expect(got.state).toEqual(expected.state);
    }
  });

  it("keeps what precedes a segment it cannot fetch, raises the error, and goes on when it is there", async () => {
    const w = await world({ streams: 2, logProtocol: true });
    await history(w);
    const keys = await w.segmentKeys();
    const missing = keys.get(6)!;
    const bytes = (await w.innerBlobs.get(missing))!;
    await w.innerBlobs.delete(missing);

    // The segment-by-segment apply stops at 5 with 1..5 in.
    const reference = await connected(w, "reference", {
      keyedFirstLoad: false,
    });
    await expect(
      applyConnection(reference.deps, CONNECTION_ID),
    ).rejects.toThrow();
    const keyed = await connected(w, "keyed", {
      maxBytesInFlight: await splitting(w),
    });
    await expect(applyConnection(keyed.deps, CONNECTION_ID)).rejects.toThrow();
    expect(await keyed.position()).toBe(5);
    const expected = await tables(reference);
    const got = await tables(keyed);
    expect(got.records).toEqual(expected.records);
    expect(got.heads).toEqual(expected.heads);
    expect(got.state).toEqual(expected.state);
    expect(await stageTables(keyed)).toEqual([]);

    // It is there now: the next pass takes the segments after 5.
    await w.innerBlobs.put(missing, bytes);
    await applyConnection(keyed.deps, CONNECTION_ID);
    const whole = await connected(w, "whole", { keyedFirstLoad: false });
    await applyConnection(whole.deps, CONNECTION_ID);
    expect((await tables(keyed)).records).toEqual(
      (await tables(whole)).records,
    );
    expect(await keyed.position()).toBe(await whole.position());
  });

  it("loads the segment-by-segment way when the log fits one commit or the device holds streams", async () => {
    const w = await world({ streams: 2, logProtocol: true });
    await history(w);
    // The default budget holds the whole log: nothing to split.
    const fits = await connected(w, "fits");
    const stages: string[] = [];
    onCommit(fits, async (statements) => {
      for (const s of statements)
        if (s.sql.startsWith("CREATE TABLE log_stage_")) stages.push(s.sql);
    });
    await applyConnection(fits.deps, CONNECTION_ID);
    expect(stages).toEqual([]);

    // A device that holds a version of a stream does not load key by key.
    const holds = await connected(w, "holds", {
      maxBytesInFlight: await splitting(w),
    });
    await holds.db.batch([
      {
        sql: `INSERT INTO stream_state (connection_id, stream, primary_key, semantics, incremental)
              VALUES (?, ?, '["id"]', 'mutable_state', 1)`,
        params: [CONNECTION_ID, S0],
      },
      {
        sql: `INSERT INTO stream_versions (connection_id, stream, version, generation, head_blob,
                head_format, record_count, observed_at, complete, kind)
              VALUES (?, ?, 1, 1, 'h', 1, 0, 1, 1, 'applied')`,
        params: [CONNECTION_ID, S0],
      },
    ]);
    const heldStages: string[] = [];
    onCommit(holds, async (statements) => {
      for (const s of statements)
        if (s.sql.startsWith("CREATE TABLE log_stage_")) heldStages.push(s.sql);
    });
    await applyConnection(holds.deps, CONNECTION_ID);
    expect(heldStages).toEqual([]);
    expect(await holds.position()).toBeGreaterThan(0);
  });
});
