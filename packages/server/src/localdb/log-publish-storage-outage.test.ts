// Storage that keeps refusing past its retry budget is an outage, not a fault
// in the data (`StorageDeferredError`). The publish leaves the connection's
// changes queued and reports `backoff`; the next cycle sends them.
import { afterEach, describe, expect, it } from "vitest";
import {
  decodeSegment,
  type WireOperation,
} from "@opendatalabs/personal-server-ts-stream-sync";
// The world runs core from source: the error class must be that module's.
import { StorageDeferredError } from "../../../core/src/stream-sync/storage-retry.js";
import { publishLog } from "../../../core/src/localdb/log-publish.js";
import type { SqlDriver } from "../../../core/src/localdb/index.js";
import {
  CONNECTION_ID,
  LOG,
  closeWorldDrivers,
  idHash,
  sName,
  tempDbFile,
  world,
} from "./log-world.test-utils.js";

afterEach(closeWorldDrivers);

describe("log publish: a storage outage", () => {
  it("backs off without an error and publishes on the next cycle", async () => {
    const w = await world({ streams: 1 });
    let down = true;
    const a = await w.device("a", {
      beforePut: async () => {
        if (down)
          throw new StorageDeferredError(
            180_000,
            new Error("Storage PUT failed (503)"),
          );
      },
    });
    await a.run("r1", [{ stream: sName(0), id: "x" }]);
    const report = await a.sync.cycle();
    expect(report.connections.map((c) => c.error)).toEqual([null]);
    expect(await a.position()).toBe(0);

    down = false;
    await a.cycle();
    expect(await a.position()).toBe(1);
    const b = await w.device("b");
    await b.cycle();
    expect(await b.records()).toEqual(await a.records());
  });
});

it("keeps storage backoff after an earlier round published the same stream", async () => {
  const w = await world({ streams: 1, partTargetBytes: 1000 });
  let segments = 0;
  const a = await w.device("a", {
    beforePut: async (key) => {
      if (key.includes("/s-") && ++segments === 2)
        throw new StorageDeferredError(
          180_000,
          new Error("Storage PUT failed (503)"),
        );
    },
  });
  await a.run(
    "many",
    Array.from({ length: 12 }, (_, i) => ({
      stream: sName(0),
      id: `r${i}`,
      pad: 500,
    })),
    { full: false },
  );
  const result = await publishLog(a.deps, CONNECTION_ID);
  expect(await a.position()).toBe(1);
  expect(w.gateway.batches()).toHaveLength(1);
  expect(
    await a.db.query<{ n: number }>(
      `SELECT COUNT(*) AS n FROM record_changes c JOIN stream_state s
       ON s.connection_id=c.connection_id AND s.stream=c.stream
      WHERE c.connection_id=? AND c.seq > s.publish_watermark`,
      [CONNECTION_ID],
    ),
  ).toEqual([{ n: 11 }]);
  expect(result?.map((r) => r.outcome)).toEqual(["backoff"]);
});

/**
 * The operations of each segment the remote registered for the log, in
 * registry order, decoded in full: key hash, payload and the whole stamp.
 */
async function registered(w: Awaited<ReturnType<typeof world>>) {
  const out: WireOperation[][] = [];
  for (const version of w.gateway.versions.get(LOG) ?? []) {
    const bytes = await w.innerBlobs.get(
      `${LOG}/s-${version.dataHash.slice(2)}`,
    );
    const decoded = decodeSegment(bytes!);
    if (decoded.kind !== "ok") throw new Error("segment did not decode");
    out.push(decoded.segment.operations);
  }
  return out;
}

/** An upsert of stream s0's record `value`, as the log carries it. */
const upsert = async (
  value: { id: string; v?: number },
  stamp: { o: number; r: string },
  firstSeen: number,
): Promise<WireOperation> => ({
  kind: "upsert",
  stream: sName(0),
  pkHash: await idHash(value.id),
  stamp,
  firstSeen,
  value,
});

/** The record keys a device holds changes for that the publisher has not acknowledged. */
const pendingKeys = async (db: SqlDriver) =>
  (
    await db.query<{ key: string }>(
      `SELECT c.record_key AS key FROM record_changes c JOIN stream_state s
         ON s.connection_id=c.connection_id AND s.stream=c.stream
        WHERE c.connection_id=? AND c.seq > s.publish_watermark ORDER BY c.seq`,
      [CONNECTION_ID],
    )
  ).map((r) => r.key);

it("loses nothing when the remote accepted a run before a cold restart: the run is sent once more beside the newer run", async () => {
  const w = await world({ streams: 1 });
  const a = await w.device("a", { dbFile: tempDbFile() });
  await a.run("r1", [{ stream: sName(0), id: "old" }]);
  // The remote accepts the append; the process stops before its local batch commits.
  w.gateway.dropNextBatchReply = true;
  let calls = 0;
  w.gateway.beforeBatch = async () => {
    // The process cannot reach the remote again before it stops.
    if (++calls > 1) throw new TypeError("fetch failed");
  };
  await a.sync.cycle();
  expect(w.gateway.dropNextBatchReply).toBe(false);
  expect(w.gateway.versions.get(LOG)).toHaveLength(1);
  expect(await pendingKeys(a.db)).toEqual(["old"]);
  // A newer local run ends while the first is still unacknowledged.
  await a.run("r2", [{ stream: sName(0), id: "new" }], { full: false });
  // Fresh process state, and the remote is reachable again.
  const fresh = await a.restart();
  w.gateway.beforeBatch = undefined;
  expect(await pendingKeys(fresh.db)).toEqual(["old", "new"]);
  const report = await fresh.sync.cycle();
  expect(report.connections.map((c) => c.error)).toEqual([null]);
  expect(await pendingKeys(fresh.db)).toEqual([]);
  // Two registered versions. The process lost its local acknowledgement, so
  // the second version repeats run r1's record (same stamp, same data) next to
  // run r2's: write amplification of one record, no change to any reader's
  // result.
  const old = await upsert({ id: "old" }, { o: 1001, r: "r1" }, 1001);
  expect(await registered(w)).toEqual([
    [
      old,
      {
        kind: "complete",
        stream: sName(0),
        cutoff: { o: 1001, r: "r1" },
        omitted: [],
      },
    ],
    [old, await upsert({ id: "new" }, { o: 1002, r: "r2" }, 1002)],
  ]);
  const b = await w.device("b");
  await b.cycle();
  expect(await b.records()).toEqual([
    's0/new={"id":"new"}',
    's0/old={"id":"old"}',
  ]);
});

describe("a cold restart after another device built on the accepted run", () => {
  /**
   * Device `a` publishes run r1 (k = 1); the remote accepts, but `a`'s process
   * stops before it records that. A later local run r3 (m) is also still
   * unpublished. `a`'s database lists both as unpublished.
   */
  async function acceptedThenLost(w: Awaited<ReturnType<typeof world>>) {
    const a = await w.device("a", { dbFile: tempDbFile() });
    await a.run("r1", [{ stream: sName(0), id: "k", v: 1 }]);
    w.gateway.dropNextBatchReply = true;
    let calls = 0;
    w.gateway.beforeBatch = async () => {
      // The process cannot reach the remote again before it stops.
      if (++calls > 1) throw new TypeError("fetch failed");
    };
    await a.sync.cycle();
    expect(w.gateway.dropNextBatchReply).toBe(false);
    expect(w.gateway.versions.get(LOG)).toHaveLength(1);
    w.gateway.beforeBatch = undefined;
    await a.run("r3", [{ stream: sName(0), id: "m" }], { full: false });
    expect(await pendingKeys(a.db)).toEqual(["k", "m"]);
    return a;
  }
  const bodiesOf = async (d: { db: SqlDriver }, key: string) =>
    (
      await d.db.query<{ body: string }>(
        "SELECT body FROM records WHERE stream = ? AND record_key = ?",
        [sName(0), key],
      )
    ).map((r) => r.body);
  const k1 = () => upsert({ id: "k", v: 1 }, { o: 1001, r: "r1" }, 1001);
  const m = () => upsert({ id: "m" }, { o: 1002, r: "r3" }, 1002);

  it("every replica reads the newer value, not the accepted run's", async () => {
    const w = await world({ streams: 1 });
    const a = await acceptedThenLost(w);
    const b = await w.device("b");
    await b.cycle();
    expect(await bodiesOf(b, "k")).toEqual(['{"id":"k","v":1}']);
    await b.run("r2", [{ stream: sName(0), id: "k", v: 2 }], { full: false });
    await b.cycle();
    const k2 = await upsert({ id: "k", v: 2 }, { o: 1003, r: "r2" }, 1001);
    expect(await registered(w)).toHaveLength(2);
    // A is still stopped, and still holds both unpublished changes.
    expect(await pendingKeys(a.db)).toEqual(["k", "m"]);

    const fresh = await a.restart();
    expect(await pendingKeys(fresh.db)).toEqual(["k", "m"]);
    const report = await fresh.sync.cycle();
    expect(report.connections.map((c) => c.error)).toEqual([null]);
    // Recovery ran on A's pending work: it is acknowledged, and what A sent is
    // exactly B's newer record (not the accepted run's k = 1) and its own m.
    expect(await pendingKeys(fresh.db)).toEqual([]);
    expect(await registered(w)).toEqual([
      [
        await k1(),
        {
          kind: "complete",
          stream: sName(0),
          cutoff: { o: 1001, r: "r1" },
          omitted: [],
        },
      ],
      [k2],
      [k2, await m()],
    ]);
    await fresh.sync.cycle();
    await b.cycle();
    const c = await w.device("c");
    await c.cycle();
    for (const replica of [fresh, b, c]) {
      expect(await bodiesOf(replica, "k")).toEqual(['{"id":"k","v":2}']);
      expect(await bodiesOf(replica, "m")).toEqual(['{"id":"m"}']);
    }
  });

  it("a key another device deleted stays deleted on every replica", async () => {
    const w = await world({ streams: 1 });
    const a = await acceptedThenLost(w);
    const b = await w.device("b");
    await b.cycle();
    expect(await bodiesOf(b, "k")).toEqual(['{"id":"k","v":1}']);
    await b.run("r2", [{ stream: sName(0), id: "k", remove: true }], {
      full: false,
    });
    await b.cycle();
    expect(await bodiesOf(b, "k")).toEqual([]);
    const del: WireOperation = {
      kind: "delete",
      stream: sName(0),
      pkHash: await idHash("k"),
      key: ["k"],
      stamp: { o: 1003, r: "r2" },
    };
    expect(await registered(w)).toHaveLength(2);
    // A is still stopped, and still holds both unpublished changes.
    expect(await pendingKeys(a.db)).toEqual(["k", "m"]);

    const fresh = await a.restart();
    expect(await pendingKeys(fresh.db)).toEqual(["k", "m"]);
    const report = await fresh.sync.cycle();
    expect(report.connections.map((c) => c.error)).toEqual([null]);
    // Recovery ran on A's pending work: it is acknowledged, and A sent only
    // its own m. It did not send k again, so the delete stands.
    expect(await pendingKeys(fresh.db)).toEqual([]);
    expect(await registered(w)).toEqual([
      [
        await k1(),
        {
          kind: "complete",
          stream: sName(0),
          cutoff: { o: 1001, r: "r1" },
          omitted: [],
        },
      ],
      [del],
      [await m()],
    ]);
    await fresh.sync.cycle();
    await b.cycle();
    const c = await w.device("c");
    await c.cycle();
    for (const replica of [fresh, b, c]) {
      expect(await bodiesOf(replica, "k")).toEqual([]);
      expect(await bodiesOf(replica, "m")).toEqual(['{"id":"m"}']);
    }
  });
});
