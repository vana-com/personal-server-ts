// A first load of a log too big for one commit loads key by key (core
// localdb/log-keyed.ts). What a reader may see does not change: it ends in the
// rows, tombstones, heads and position a segment-by-segment apply ends in, the
// position moves with the last of the rows and not before, and a load that
// stops (a crash, a segment it cannot fetch) leaves nothing a reader trusts and
// ends right when it runs again. Real publisher, real gateway adapter, real
// SQLite (log-world.test-utils.ts).
import { afterEach, describe, expect, it } from "vitest";
import { keccak_256 } from "@noble/hashes/sha3";
import {
  controlHashes,
  deriveKeyCheck,
  logScope,
} from "@opendatalabs/personal-server-ts-stream-sync";
import {
  applyConnection,
  applyLog,
  applyStream,
  publishConnection,
  LogDivergedError,
} from "../../../core/src/localdb/index.js";
import {
  complexPages,
  keyedLoadBlocked,
  pendingAdmits,
} from "../../../core/src/localdb/log-keyed.js";
import { withOrigin } from "../../../core/src/localdb/merge.js";
import {
  CONNECTION_ID,
  LOG,
  OWNER,
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

  it("loads key by key on a host that shows streams while they load, and ends in the same tables", async () => {
    const w = await world({ streams: 2, logProtocol: true });
    await history(w);
    const reference = await connected(w, "reference", {
      keyedFirstLoad: false,
    });
    await applyConnection(reference.deps, CONNECTION_ID);

    const progressive = await connected(w, "progressive", {
      maxBytesInFlight: await splitting(w),
      progressiveFirstLoad: true,
    });
    const stages: string[] = [];
    let partialMarks = 0;
    onCommit(progressive, async (statements) => {
      for (const s of statements) {
        if (s.sql.startsWith("CREATE TABLE log_stage_")) stages.push(s.sql);
        if (s.sql.includes("INTO stream_partial")) partialMarks++;
      }
    });
    await applyConnection(progressive.deps, CONNECTION_ID);

    // Key by key: several ranges, and no segment-by-segment partial view.
    expect(stages.length).toBeGreaterThan(1);
    expect(partialMarks).toBe(0);
    const expected = await tables(reference);
    const got = await tables(progressive);
    expect(got.records).toEqual(expected.records);
    expect(got.tombstones).toEqual(expected.tombstones);
    expect(got.streams).toEqual(expected.streams);
    expect(got.heads).toEqual(expected.heads);
    expect(got.state).toEqual(expected.state);
    expect(got.changes).toEqual(expected.changes);
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

/** Count the commits that apply a key range (each drops its stage table). */
const dropsStage = (statements: { sql: string }[]) =>
  statements.some((s) => s.sql.startsWith("DROP TABLE log_stage_"));
const stagesRows = (statements: { sql: string }[]) =>
  statements.some((s) => s.sql.startsWith("INSERT INTO log_stage_"));

describe("log first load, key by key: a run that emits a key again at its stamp", () => {
  it("keeps the batch ordinal of a key, and the body the order picks, as a segment-by-segment load does", async () => {
    const w = await world({
      streams: 2,
      logProtocol: true,
      publishWhileCollecting: true,
    });
    const a = await w.device("a");
    for (let n = 1; n <= 8; n++)
      await step(a, n, [{ stream: S0, id: `fill-${n}`, pad: 4_000 }]);
    const run = "ordinal-run";
    await a.sync.intake.begin(run, {
      connector: "fixture",
      artifactDigest: "fixture",
      wantFull: false,
      observedAt: 2000,
      owner: { address: OWNER, leaseId: null },
    });
    const send = (batch: number, records: object[]) =>
      a.sync.intake.batch(run, {
        batch,
        records: records.map((data) => ({ stream: S0, data })),
      });
    // Key "twice" has two bodies at the run's one stamp; "later" first appears
    // in batch 1 (a single upsert that carries ordinal 1).
    await send(0, [
      { id: "twice", v: 1 },
      { id: "once-0", pad: 4_000 },
    ]);
    await a.cycle();
    await send(1, [
      { id: "twice", v: 2 },
      { id: "later", v: 1, pad: 4_000 },
    ]);
    await a.sync.intake.end(run, {
      outcome: "succeeded",
      coveredStreams: [S0],
      provenFullStreams: [],
      lastBatch: 1,
    });
    await a.cycle();

    const plain = await connected(w, "plain", { keyedFirstLoad: false });
    await applyConnection(plain.deps, CONNECTION_ID);
    const keyed = await connected(w, "keyed", {
      maxBytesInFlight: await splitting(w),
    });
    await applyConnection(keyed.deps, CONNECTION_ID);

    const expected = await tables(plain);
    const got = await tables(keyed);
    expect(got.records).toEqual(expected.records);
    expect(got.tombstones).toEqual(expected.tombstones);
    expect(got.heads).toEqual(expected.heads);
    expect(got.state).toEqual(expected.state);
    // The ordinal is in the rows, not only equal by chance.
    const row = (key: string) =>
      expected.records
        .map((r) => JSON.stringify(r))
        .find((r) => r.includes(`${key}`)) ?? "";
    expect(row("later")).toContain('"stamp_n":1');
    expect(row("twice")).toContain('\\"v\\":2');
  });
});

/**
 * A load that stopped after its first key range committed: rows of the whole
 * log are in `records` (those of that range), and the position is 0.
 */
async function stoppedAfterFirstRange(w: World, id: string, hooks = {}) {
  const d = await connected(w, id, {
    maxBytesInFlight: await splitting(w),
    ...hooks,
  });
  let ranges = 0;
  let armed = true;
  onCommit(d, async (statements) => {
    if (armed && ranges >= 1 && (dropsStage(statements) || ranges > 1))
      throw new Error("stopped");
    if (dropsStage(statements)) ranges++;
  });
  await expect(applyConnection(d.deps, CONNECTION_ID)).rejects.toThrow();
  armed = false;
  return d;
}

describe("log first load, key by key: what an unfinished load leaves", () => {
  it("publishes nothing from a retry that holds a shorter prefix than the rows it left", async () => {
    const w = await world({ streams: 2, logProtocol: true });
    await history(w);
    const keys = await w.segmentKeys();
    const missing = keys.get(6)!;
    const bytes = (await w.innerBlobs.get(missing))!;

    // What a load of the first five segments ends in.
    await w.innerBlobs.delete(missing);
    const reference = await connected(w, "reference", {
      keyedFirstLoad: false,
    });
    await expect(
      applyConnection(reference.deps, CONNECTION_ID),
    ).rejects.toThrow();
    const prefix = await tables(reference);
    await w.innerBlobs.put(missing, bytes);

    // A load that wrote its first key range and stopped: rows from beyond
    // position 5 are in `records`, and the position is 0.
    const d = await stoppedAfterFirstRange(w, "retry");
    expect(await d.position()).toBe(0);
    const left = (await tables(d)).records;
    expect(left.length).toBeGreaterThan(0);
    const pending = await d.db.query<{ position: number }>(
      "SELECT position FROM log_keyed_pending",
    );
    expect(pending[0]!.position).toBeGreaterThan(5);

    // The retry cannot fetch segment 6: the log it holds is 1..5.
    await w.innerBlobs.delete(missing);
    await expect(applyConnection(d.deps, CONNECTION_ID)).rejects.toThrow();
    // It publishes no prefix: the rows beyond 5 would show under position 5.
    expect(await d.position()).toBe(0);
    expect(
      (
        await d.db.query<{ n: number }>(
          "SELECT COUNT(*) AS n FROM stream_versions",
        )
      )[0]!.n,
    ).toBe(0);
    // Rows the stopped load wrote are not the plain prefix, which is the point.
    expect(left).not.toEqual(prefix.records);

    // With the segment back, the retry covers them and ends in the whole log.
    await w.innerBlobs.put(missing, bytes);
    await applyConnection(d.deps, CONNECTION_ID);
    const whole = await connected(w, "whole", { keyedFirstLoad: false });
    await applyConnection(whole.deps, CONNECTION_ID);
    const expected = await tables(whole);
    const got = await tables(d);
    expect(got.records).toEqual(expected.records);
    expect(got.tombstones).toEqual(expected.tombstones);
    expect(got.heads).toEqual(expected.heads);
    expect(got.state).toEqual(expected.state);
    expect(await d.db.query("SELECT * FROM log_keyed_pending")).toEqual([]);
  });

  it("keeps the position it means to publish from its first key range to its last", async () => {
    const w = await world({ streams: 2, logProtocol: true });
    await history(w);
    const d = await connected(w, "keyed", {
      maxBytesInFlight: await splitting(w),
    });
    const seen: number[] = [];
    onCommit(d, async (statements) => {
      if (dropsStage(statements))
        seen.push(
          (
            await d.db.query<{ n: number }>(
              "SELECT COUNT(*) AS n FROM log_keyed_pending",
            )
          )[0]!.n,
        );
    });
    await applyConnection(d.deps, CONNECTION_ID);
    // Before the first range commits it is not written yet; before every
    // later one it is; after the last it is gone.
    expect(seen.length).toBeGreaterThan(2);
    expect(seen[0]).toBe(0);
    for (const n of seen.slice(1)) expect(n).toBe(1);
    expect(await d.db.query("SELECT * FROM log_keyed_pending")).toEqual([]);
    expect(await d.position()).toBeGreaterThan(0);
  });

  it("rebaselines over rows of another log, and ends in the log it reads", async () => {
    const w = await world({ streams: 2, logProtocol: true });
    await history(w);
    const d = await stoppedAfterFirstRange(w, "other");
    // The same position, named by a segment this log does not have.
    const [row] = await d.db.query<{ refs: string }>(
      "SELECT refs FROM log_keyed_pending",
    );
    const refs = (JSON.parse(row!.refs) as { dataHash: string }[]).map(
      (ref, i) =>
        i === 0 ? { ...ref, dataHash: `0x${"ab".repeat(32)}` } : ref,
    );
    await d.db.batch([
      {
        sql: "UPDATE log_keyed_pending SET refs = ?",
        params: [JSON.stringify(refs)],
      },
    ]);
    await applyConnection(d.deps, CONNECTION_ID);
    await endsInTheLog(w, d);
  });

  it("rebaselines when the flag is off, and loads segment by segment", async () => {
    const w = await world({ streams: 2, logProtocol: true });
    await history(w);
    const d = await stoppedAfterFirstRange(w, "switched");
    // A host that turned the flag off now: the marker names rows no
    // segment-by-segment load can tell from the log's own.
    const off = await connected(w, "off", { keyedFirstLoad: false });
    await off.db.batch(
      (
        await d.db.query<{ position: number; base: number; refs: string }>(
          "SELECT position, base, refs FROM log_keyed_pending",
        )
      ).map((r) => ({
        sql: "INSERT INTO log_keyed_pending (connection_id, position, base, refs) VALUES (?, ?, ?, ?)",
        params: [CONNECTION_ID, r.position, r.base, r.refs],
      })),
    );
    await applyConnection(off.deps, CONNECTION_ID);
    await endsInTheLog(w, off);
  });
});

/**
 * A device that holds nothing of the log's streams ends, whatever a stopped
 * load left, in the rows, tombstones, heads and position of a device that read
 * the log segment by segment: the marker is gone, so are the stage tables.
 */
async function endsInTheLog(w: World, d: Device) {
  const reference = await connected(w, "reference-end", {
    keyedFirstLoad: false,
  });
  await applyConnection(reference.deps, CONNECTION_ID);
  const expected = await tables(reference);
  const got = await tables(d);
  expect(got.records).toEqual(expected.records);
  expect(got.tombstones).toEqual(expected.tombstones);
  expect(got.streams).toEqual(expected.streams);
  expect(got.heads).toEqual(expected.heads);
  expect(got.state).toEqual(expected.state);
  expect(await d.db.query("SELECT * FROM log_keyed_pending")).toEqual([]);
  expect(await stageTables(d)).toEqual([]);
  expect(await d.position()).toBeGreaterThan(0);
  expect(expected.records.length).toBeGreaterThan(5);
}

/** The writer publishes until the log's newest segment holds a snapshot. */
async function compactLog(w: World, a: Device, from: number) {
  for (let n = from; ; n++) {
    const segments = await w.segments();
    if (segments.get(Math.max(...segments.keys()))!.snapshot !== null) return;
    await step(a, n, [{ stream: S0, id: `later-${n}`, pad: 4_000 }]);
  }
}

describe("log first load, key by key: a log that can no longer finish it", () => {
  it("serves the snapshot and the tail when the log compacts after a stopped load", async () => {
    const w = await world({ streams: 2, logProtocol: true });
    const a = await history(w);
    const d = await stoppedAfterFirstRange(w, "retry");
    expect((await tables(d)).records.length).toBeGreaterThan(0);
    expect(await d.db.query("SELECT * FROM log_keyed_pending")).toHaveLength(1);

    await compactLog(w, a, 100);
    const head = [...(await w.segments()).values()].at(-1)!;
    expect(head.snapshot).not.toBeNull();
    expect(head.base).toBeGreaterThan(0);

    await applyConnection(d.deps, CONNECTION_ID);
    await endsInTheLog(w, d);
  });

  it("serves a log whose base moved by a rewrite that holds the marker's positions under other segments", async () => {
    const w = await world({ streams: 2, logProtocol: true });
    await history(w);
    const d = await stoppedAfterFirstRange(w, "rewritten");
    // The marker's base is not the log's.
    await d.db.batch([
      { sql: "UPDATE log_keyed_pending SET base = base + 1000", params: [] },
    ]);
    await applyConnection(d.deps, CONNECTION_ID);
    await endsInTheLog(w, d);
  });

  it("keeps the writes the device has not published, and publishes them after", async () => {
    const w = await world({ streams: 2, logProtocol: true });
    const a = await history(w);
    const d = await stoppedAfterFirstRange(w, "local");
    await compactLog(w, a, 100);

    // What a device that read the log and then ran a local run holds, and the
    // rows that run wrote: a key of its own, and one the log has.
    const mine = [
      { stream: S0, id: "mine", v: 1 },
      { stream: S1, id: "mine-too", v: 2 },
      { stream: S0, id: "shared", v: 777 },
    ];
    const when = { full: false, covered: [S0, S1], observedAt: 5000 };
    const pure = await connected(w, "pure", { keyedFirstLoad: false });
    await applyConnection(pure.deps, CONNECTION_ID);
    const reference = await connected(w, "reference", {
      keyedFirstLoad: false,
    });
    await applyConnection(reference.deps, CONNECTION_ID);
    await reference.run("local-run", mine, when);
    const logRows = new Set(await pure.rows());
    const written = (
      await reference.db.query<Record<string, string | number | null>>(
        "SELECT * FROM records ORDER BY stream, record_key",
      )
    ).filter(
      (r) =>
        !logRows.has(
          JSON.stringify({
            stream: r.stream,
            record_key: r.record_key,
            body: r.body,
            stamp_o: r.stamp_o,
            stamp_r: r.stamp_r,
            stamp_n: r.stamp_n,
            first_o: r.first_o,
          }),
        ),
    );
    expect(written.length).toBeGreaterThanOrEqual(mine.length);

    // The device wrote the same rows before it could reach the log again: a
    // local write, as the run's own commit makes it (origin `local`).
    const columns = Object.keys(written[0]!);
    await d.db.batch(
      withOrigin(
        "local",
        written.map((row) => ({
          sql: `INSERT OR REPLACE INTO records (${columns.join(",")}) VALUES (${columns.map(() => "?").join(",")})`,
          params: columns.map((c) => row[c]!),
        })),
      ),
    );
    const unpublished = () =>
      d.db.query<{ stream: string; pk_hash: string; op: string }>(
        `SELECT ch.stream, ch.pk_hash, ch.op FROM record_changes ch
          WHERE ch.origin IN ('local','import','refresh')
            AND ch.seq > COALESCE((SELECT publish_watermark FROM stream_state s
                                    WHERE s.connection_id = ch.connection_id AND s.stream = ch.stream), 0)
          ORDER BY ch.seq`,
      );
    const before = await unpublished();
    expect(before).toHaveLength(written.length);
    expect(await d.db.query("SELECT * FROM log_keyed_pending")).toHaveLength(1);
    expect(await d.position()).toBe(0);

    await applyConnection(d.deps, CONNECTION_ID);
    expect(await d.db.query("SELECT * FROM log_keyed_pending")).toEqual([]);
    expect(await unpublished()).toEqual(before);
    expect(await d.rows()).toEqual(await reference.rows());
    expect((await d.records()).filter((r) => r.includes("/mine"))).toHaveLength(
      2,
    );

    // They publish: another device reads them from the log.
    await d.cycle();
    expect(await unpublished()).toEqual([]);
    const late = await connected(w, "late", { keyedFirstLoad: false });
    await late.cycle();
    expect(await late.rows()).toEqual(await d.rows());
    expect(
      (await late.records()).filter((r) => r.includes("/mine")),
    ).toHaveLength(2);
  });

  it("drops a row of the stopped load that a local write does not stand behind", async () => {
    const w = await world({ streams: 2, logProtocol: true });
    const a = await history(w);
    const d = await stoppedAfterFirstRange(w, "all-remote");
    const left = (await tables(d)).records.length;
    expect(left).toBeGreaterThan(0);
    await compactLog(w, a, 100);
    // Nothing unpublished: the rebaseline leaves no row of the stopped load.
    let rebaselined = -1;
    onCommit(d, async (statements) => {
      if (
        statements.some((s) =>
          s.sql.startsWith("DELETE FROM log_keyed_pending"),
        ) &&
        statements.some((s) => s.sql.startsWith("DELETE FROM records"))
      )
        rebaselined = (
          await d.db.query<{ n: number }>("SELECT COUNT(*) AS n FROM records")
        )[0]!.n;
    });
    await applyConnection(d.deps, CONNECTION_ID);
    expect(rebaselined).toBe(left);
    await endsInTheLog(w, d);
  });

  it("drops the rows, the tombstones and the marker together or not at all", async () => {
    const w = await world({ streams: 2, logProtocol: true });
    const a = await history(w);
    const d = await stoppedAfterFirstRange(w, "atomic");
    await compactLog(w, a, 100);
    const before = await tables(d);
    const marker = await d.db.query("SELECT * FROM log_keyed_pending");
    let armed = true;
    onCommit(d, async (statements) => {
      if (
        armed &&
        statements.some((s) =>
          s.sql.startsWith("DELETE FROM log_keyed_pending"),
        ) &&
        statements.some((s) => s.sql.startsWith("DELETE FROM records"))
      ) {
        armed = false;
        throw new Error("stopped in the rebaseline");
      }
    });
    await expect(applyConnection(d.deps, CONNECTION_ID)).rejects.toThrow();
    // The batch was refused as a whole: the stopped load is as it was.
    expect(armed).toBe(false);
    const after = await tables(d);
    expect(after.records).toEqual(before.records);
    expect(after.tombstones).toEqual(before.tombstones);
    expect(await d.db.query("SELECT * FROM log_keyed_pending")).toEqual(marker);
    // And the retry rebaselines and ends in the log.
    await applyConnection(d.deps, CONNECTION_ID);
    await endsInTheLog(w, d);
  });

  describe("keyedLoadBlocked", () => {
    const ref = (position: number, hash: string) => ({
      position,
      dataHash: `0x${hash.repeat(32)}` as `0x${string}`,
      bytes: 10,
    });
    const state = (
      position: number,
      base: number,
      refs: ReturnType<typeof ref>[],
    ) => ({ position, base, refs, snapshot: null });
    const pending = state(3, 0, [ref(1, "aa"), ref(2, "bb"), ref(3, "cc")]);
    const same = {
      snapshotPresent: false,
      target: state(5, 0, [
        ref(1, "aa"),
        ref(2, "bb"),
        ref(3, "cc"),
        ref(4, "dd"),
        ref(5, "ee"),
      ]),
    };
    const on = { keyedFirstLoad: true };

    it("is not blocked by a log that holds the marker's segments, longer or equal", () => {
      expect(keyedLoadBlocked(on, pending, same)).toBeNull();
      expect(keyedLoadBlocked({}, pending, same)).toBeNull();
      expect(
        keyedLoadBlocked(on, pending, {
          snapshotPresent: false,
          target: state(3, 0, pending.refs),
        }),
      ).toBeNull();
    });

    it("is not blocked by a log that is shorter and agrees (a registry that lags)", () => {
      const lagging = {
        snapshotPresent: false,
        target: state(2, 0, pending.refs.slice(0, 2)),
      };
      expect(keyedLoadBlocked(on, pending, lagging)).toBeNull();
      // The load that cannot cover the marker is refused at publication.
      expect(pendingAdmits(pending, lagging.target)).toBe(false);
    });

    it("is blocked by each thing no key-ordered load can finish", () => {
      const reasons = [
        keyedLoadBlocked({ keyedFirstLoad: false }, pending, same),
        keyedLoadBlocked(on, pending, { ...same, snapshotPresent: true }),
        keyedLoadBlocked(on, pending, { snapshotPresent: false, target: null }),
        keyedLoadBlocked(on, pending, {
          snapshotPresent: false,
          target: state(5, 2, same.target.refs),
        }),
        keyedLoadBlocked(on, pending, {
          snapshotPresent: false,
          target: state(5, 0, [
            ref(1, "aa"),
            ref(2, "ff"),
            ref(3, "cc"),
            ref(4, "dd"),
            ref(5, "ee"),
          ]),
        }),
        // The log is at or past a position the marker names and does not name it.
        keyedLoadBlocked(on, pending, {
          snapshotPresent: false,
          target: state(5, 0, [ref(1, "aa"), ref(3, "cc"), ref(5, "ee")]),
        }),
      ];
      for (const reason of reasons) expect(reason).toEqual(expect.any(String));
      expect(new Set(reasons).size).toBe(5);
    });
  });
});

describe("log first load, key by key: the marker stops every other way to move the position", () => {
  /** `applyLog` as the connection's apply calls it, with the read overridden. */
  async function direct(
    d: Awaited<ReturnType<typeof stoppedAfterFirstRange>>,
    generation: number,
    override: (read: {
      version: number;
      dataHash: string;
      metadataHash: string;
    }) => object,
  ) {
    const keyCheck = await deriveKeyCheck(async () => new Uint8Array(32));
    const hashes = await controlHashes(async (b) => keccak_256(b), keyCheck);
    const real = await d.deps.registry.read(logScope("fixture", ""));
    if (!real.found) throw new Error("the log has no registry row");
    return applyLog(d.deps, CONNECTION_ID, {
      connector: "fixture",
      ns: "",
      generation,
      keyCheck,
      hashes,
      read: { ...real, ...override(real) } as typeof real,
    });
  }
  async function stopped(id: string) {
    const w = await world({ streams: 2, logProtocol: true });
    await history(w);
    const d = await stoppedAfterFirstRange(w, id);
    expect(await d.position()).toBe(0);
    return d;
  }
  async function untouched(d: Awaited<ReturnType<typeof stopped>>) {
    expect(await d.position()).toBe(0);
    expect(
      (
        await d.db.query<{ n: number }>(
          "SELECT COUNT(*) AS n FROM log_keyed_pending",
        )
      )[0]!.n,
    ).toBe(1);
    expect(
      (
        await d.db.query<{ n: number }>(
          "SELECT COUNT(*) AS n FROM stream_versions",
        )
      )[0]!.n,
    ).toBe(0);
  }

  it("does not move the position past rows it left when the log reads as ended", async () => {
    const d = await stopped("ended");
    await expect(
      direct(d, 1, (real) => ({ deleted: true, version: real.version + 50 })),
    ).rejects.toBeInstanceOf(LogDivergedError);
    await untouched(d);
  });

  it("does not move the position past rows it left when the log is of an earlier lifetime", async () => {
    const d = await stopped("earlier");
    // The connection is at generation 2; the log's newest segment is of 1.
    await expect(direct(d, 2, () => ({}))).rejects.toBeInstanceOf(
      LogDivergedError,
    );
    await untouched(d);
  });

  it("does not apply on a device that holds a cursor and the marker", async () => {
    const d = await stopped("both");
    await d.db.batch([
      {
        sql: "INSERT OR REPLACE INTO log_state (connection_id, position, base, refs, snapshot) VALUES (?, 1, 0, '[]', NULL)",
        params: [CONNECTION_ID],
      },
    ]);
    const before = await d.db.query("SELECT * FROM log_state");
    await expect(direct(d, 1, () => ({}))).rejects.toBeInstanceOf(
      LogDivergedError,
    );
    expect(await d.db.query("SELECT * FROM log_state")).toEqual(before);
    expect(
      (
        await d.db.query<{ n: number }>(
          "SELECT COUNT(*) AS n FROM log_keyed_pending",
        )
      )[0]!.n,
    ).toBe(1);
  });
});

describe("log first load, key by key: what it holds", () => {
  /** What the load asks the governor for after it has staged the whole log. */
  async function holds(w: World, id: string, budget: number) {
    const d = await connected(w, id, { maxBytesInFlight: budget });
    const events: (number | "commit")[] = [];
    const { governor } = d.deps.blobs;
    const reserve = governor.reserve.bind(governor);
    governor.reserve = (bytes, objectBytes) => {
      events.push(bytes);
      return reserve(bytes, objectBytes);
    };
    onCommit(d, async (statements) => {
      if (stagesRows(statements)) events.push("commit");
    });
    await applyConnection(d.deps, CONNECTION_ID);
    const lastStaged = events.lastIndexOf("commit");
    return {
      d,
      asked: events
        .slice(lastStaged + 1)
        .filter((e): e is number => e !== "commit"),
    };
  }

  /** A log that only deletes: keys the log never held, `n` of them, each `id`. */
  async function deletes(w: World, ids: string[]) {
    const a = await w.device("a");
    // Padding segments so the log is big enough to split into key ranges.
    for (let n = 1; n <= 6; n++)
      await step(a, n, [{ stream: S0, id: `fill-${n}`, pad: 4_000 }]);
    await step(
      a,
      7,
      ids.map((id) => ({ stream: S0, id, remove: true })),
    );
    await step(a, 8, [{ stream: S0, id: "last", v: 1 }]);
  }

  it("counts the rows of keys that are only deleted", async () => {
    const w = await world({ streams: 2, logProtocol: true });
    const ids = Array.from({ length: 60 }, (_, i) => `gone-${i}`);
    await deletes(w, ids);
    const { asked } = await holds(w, "keyed", await splitting(w));
    // Each deletion is a row that holds at least its key hash (64 bytes).
    expect(asked.reduce((sum, n) => sum + n, 0)).toBeGreaterThanOrEqual(
      2 * ids.length * 64,
    );
  });

  it("weighs a row by its UTF-8 bytes, and a deletion by its keys", async () => {
    const w = await world({ streams: 2, logProtocol: true });
    const d = await connected(w, "weigh");
    const utf8 = (text: string | null) =>
      text === null ? 0 : new TextEncoder().encode(text).length;
    const rows = [
      // A deletion: no body, a key of non-ASCII text.
      { hash: "1".repeat(64), key: "ключ", kind: "d", body: null, sha: null },
      // Two upserts of one key (so it is complex), a non-ASCII body.
      { hash: "2".repeat(64), key: "k", kind: "u", body: "жжжж", sha: "abc" },
      { hash: "2".repeat(64), key: "k", kind: "u", body: "{}", sha: "def" },
    ];
    await d.db.batch([
      {
        sql: `CREATE TABLE t (position INTEGER NOT NULL, kind TEXT NOT NULL, stream TEXT NOT NULL,
                pk_hash TEXT NOT NULL, record_key TEXT NOT NULL, stamp_o INTEGER NOT NULL,
                stamp_r TEXT NOT NULL, body TEXT, body_sha256 TEXT, first_o INTEGER, stamp_n INTEGER NOT NULL DEFAULT 0)`,
      },
      ...rows.map((r, i) => ({
        sql: `INSERT INTO t (position, kind, stream, pk_hash, record_key, stamp_o, stamp_r, body, body_sha256, first_o)
              VALUES (?, ?, 's', ?, ?, 1, 'r', ?, ?, 1)`,
        params: [i + 1, r.kind, r.hash, r.key, r.body, r.sha],
      })),
    ]);
    const expected = rows.reduce(
      (sum, r) =>
        sum +
        utf8(r.kind) +
        utf8("s") +
        utf8(r.hash) +
        utf8(r.key) +
        utf8("r") +
        utf8(r.body) +
        utf8(r.sha) +
        4 * 8,
      0,
    );
    const pages = await complexPages(d.deps, "t", 2 * expected);
    expect(pages.length).toBe(1);
    expect(pages[0]!.bytes).toBe(expected);
  });

  it("applies a key whose history is over the budget a slice at a time, to the same rows", async () => {
    const w = await world({ streams: 2, logProtocol: true });
    const a = await w.device("a");
    // One key rewritten in every segment, each rewrite as big as a segment's rest.
    for (let n = 1; n <= 14; n++)
      await step(a, n, [
        { stream: S0, id: "hot", v: n, pad: 6_000 },
        { stream: S1, id: `once-${n}`, pad: 2_000 },
      ]);
    await step(a, 15, [{ stream: S0, id: "hot", remove: true }]);
    const reference = await connected(w, "reference", {
      keyedFirstLoad: false,
    });
    await applyConnection(reference.deps, CONNECTION_ID);

    const budget = await splitting(w);
    const { d, asked } = await holds(w, "keyed", budget);
    const got = await tables(d);
    const expected = await tables(reference);
    expect(got.records).toEqual(expected.records);
    expect(got.tombstones).toEqual(expected.tombstones);
    expect(got.heads).toEqual(expected.heads);
    expect(got.state).toEqual(expected.state);
    // The hot key's rows are 14 x 6 KB at least: held whole, they would be
    // asked for at once; a slice holds a part and stays in the room.
    const room = Math.max(budget, 2 * Math.max(...(await segmentWeights(w))));
    expect(Math.max(...asked)).toBeLessThanOrEqual(room);
    expect(asked.length).toBeGreaterThan(1);
  });

  it("splits a range whose keys share a hash prefix by the next digits", async () => {
    const w = await world({ streams: 2, logProtocol: true });
    const d = await connected(w, "pages");
    const row = (hash: string, position: number, body: string) => ({
      sql: `INSERT INTO t (position, kind, stream, pk_hash, record_key, stamp_o, stamp_r, body, body_sha256, first_o)
            VALUES (?, 'u', 's', ?, 'k', 1, 'r', ?, 'h', 1)`,
      params: [position, hash, body],
    });
    const hash = (tail: string) => `00000000${tail.padEnd(56, "0")}`;
    await d.db.batch([
      {
        sql: `CREATE TABLE t (position INTEGER NOT NULL, kind TEXT NOT NULL, stream TEXT NOT NULL,
                pk_hash TEXT NOT NULL, record_key TEXT NOT NULL, stamp_o INTEGER NOT NULL,
                stamp_r TEXT NOT NULL, body TEXT, body_sha256 TEXT, first_o INTEGER)`,
      },
      // Three keys under one 8-digit prefix, each written twice (so each is complex).
      ...["1", "5", "9"].flatMap((digit) => [
        row(hash(digit), 1, "x".repeat(1_000)),
        row(hash(digit), 2, "y".repeat(1_000)),
      ]),
    ]);
    // A room for one key at a time (two rows of about 1,100 bytes, twice).
    const pages = await complexPages(d.deps, "t", 5_000);
    expect(pages.length).toBe(3);
    const [total] = await d.db.query<{ n: number }>(
      "SELECT COUNT(*) AS n FROM t",
    );
    let covered = 0;
    for (const page of pages) {
      expect(2 * page.bytes).toBeLessThanOrEqual(5_000);
      const [rows] = await d.db.query<{ n: number }>(
        "SELECT COUNT(*) AS n FROM t WHERE pk_hash >= ? AND pk_hash < ? AND position BETWEEN ? AND ?",
        [page.from, page.to, page.firstPosition, page.lastPosition],
      );
      covered += rows!.n;
    }
    expect(covered).toBe(total!.n);
  });
});

describe("log first load, key by key: a per-stream head admitted while a load is unfinished", () => {
  const rowKeys = async (d: Device) =>
    (
      await d.db.query<{ record_key: string }>(
        "SELECT record_key FROM records ORDER BY record_key",
      )
    ).map((r) => r.record_key);

  /**
   * A build that does not follow the log (one without the gate in the cycle)
   * publishes a head of each stream after a keyed load stopped: with `full` it
   * omits the keys of the log it did not carry. `publishConnection` is what such
   * a build does (see mixed-fleet.test.ts).
   */
  async function lateHeads(w: World, full: boolean) {
    const legacy = await w.device("legacy", false);
    // The gateway refuses a per-stream head once the log row exists, so the
    // build writes while it cannot see the row: it read the registry just
    // before the log's first write.
    const log = w.gateway.versions.get(LOG);
    w.gateway.versions.delete(LOG);
    try {
      for (const [n, stream] of [S0, S1].entries()) {
        await legacy.run(`run-L${n}`, [{ stream, id: `late-${n}`, v: 1 }], {
          full,
          covered: [stream],
          observedAt: 5000 + n,
        });
        await publishConnection(legacy.deps, CONNECTION_ID);
      }
    } finally {
      if (log) w.gateway.versions.set(LOG, log);
    }
  }

  for (const full of [true, false]) {
    it(`ends in the rows a device that read the head and then the log ends in (head run full: ${full})`, async () => {
      const w = await world({ streams: 2, logProtocol: true });
      await history(w);
      const d = await stoppedAfterFirstRange(w, "late");
      const written = await rowKeys(d);
      expect(written.length).toBeGreaterThan(0);
      await lateHeads(w, full);

      // Each stream's head is admitted on its own, as a stream's apply does,
      // and the apply reads the log over it before it returns: the stopped
      // load's rows beyond the cursor are the head's to drop, and the log's
      // to bring back.
      for (const stream of [S0, S1])
        expect((await applyStream(d.deps, CONNECTION_ID, stream)).outcome).toBe(
          "applied",
        );
      await applyConnection(d.deps, CONNECTION_ID);

      const reference = await connected(w, "reference", {
        keyedFirstLoad: false,
      });
      await applyConnection(reference.deps, CONNECTION_ID);
      const want = await tables(reference);
      const got = await tables(d);
      expect(got.records).toEqual(want.records);
      expect(got.tombstones).toEqual(want.tombstones);
      expect(await d.db.query("SELECT * FROM log_keyed_pending")).toEqual([]);
      expect(await d.position()).toBe(await reference.position());
    });
  }

  it("a log pass that cannot finish after a head is admitted publishes no position, and the obligation stays", async () => {
    const w = await world({ streams: 2, logProtocol: true });
    await history(w);
    const keys = await w.segmentKeys();
    const missing = keys.get(6)!;
    const bytes = (await w.innerBlobs.get(missing))!;
    const d = await stoppedAfterFirstRange(w, "short");
    await lateHeads(w, false);

    // The apply of a stream admits its head and reads the log over it. It
    // cannot fetch segment 6. Rows from beyond 5 are in `records` whatever the
    // head dropped, so the marker must still refuse position 5.
    await w.innerBlobs.delete(missing);
    await expect(applyStream(d.deps, CONNECTION_ID, S0)).rejects.toThrow();
    expect(await d.position()).toBe(0);
    expect(await d.db.query("SELECT * FROM log_state")).toEqual([]);
    expect((await d.db.query("SELECT * FROM log_keyed_pending")).length).toBe(
      1,
    );
    // The head batch left the marker alone and stored the replay it owes.
    expect((await d.db.query("SELECT * FROM log_replay")).length).toBe(1);

    await w.innerBlobs.put(missing, bytes);
    await applyStream(d.deps, CONNECTION_ID, S1);
    await applyConnection(d.deps, CONNECTION_ID);
    const reference = await connected(w, "reference", {
      keyedFirstLoad: false,
    });
    await applyConnection(reference.deps, CONNECTION_ID);
    expect((await tables(d)).records).toEqual(
      (await tables(reference)).records,
    );
    expect(await d.db.query("SELECT * FROM log_keyed_pending")).toEqual([]);
    expect(await d.db.query("SELECT * FROM log_replay")).toEqual([]);
  });
});
