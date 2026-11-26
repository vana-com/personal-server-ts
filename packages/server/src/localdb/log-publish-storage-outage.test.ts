// Storage that keeps refusing past its retry budget is an outage, not a fault
// in the data (`StorageDeferredError`). The publish leaves the connection's
// changes queued and reports `backoff`; the next cycle sends them.
import { afterEach, describe, expect, it } from "vitest";
import { decodeSegment } from "@opendatalabs/personal-server-ts-stream-sync";
// The world runs core from source: the error class must be that module's.
import { StorageDeferredError } from "../../../core/src/stream-sync/storage-retry.js";
import { publishLog } from "../../../core/src/localdb/log-publish.js";
import type { SqlDriver } from "../../../core/src/localdb/index.js";
import {
  CONNECTION_ID,
  LOG,
  closeWorldDrivers,
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

/** The segments the remote registered for the log, in registry order. */
async function registered(w: Awaited<ReturnType<typeof world>>) {
  const out: string[][] = [];
  for (const version of w.gateway.versions.get(LOG) ?? []) {
    const bytes = await w.innerBlobs.get(
      `${LOG}/s-${version.dataHash.slice(2)}`,
    );
    const decoded = decodeSegment(bytes!);
    if (decoded.kind !== "ok") throw new Error("segment did not decode");
    out.push(
      decoded.segment.operations.map((op) =>
        op.kind === "upsert"
          ? `upsert ${(op.value as { id: string }).id}@${op.stamp.r}`
          : op.kind,
      ),
    );
  }
  return out;
}

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
  const pending = async (db: typeof a.db) =>
    (
      await db.query<{ key: string }>(
        `SELECT c.record_key AS key FROM record_changes c JOIN stream_state s
           ON s.connection_id=c.connection_id AND s.stream=c.stream
          WHERE c.connection_id=? AND c.seq > s.publish_watermark ORDER BY c.seq`,
        [CONNECTION_ID],
      )
    ).map((r) => r.key);
  expect(await pending(a.db)).toEqual(["old"]);
  // A newer local run ends while the first is still unacknowledged.
  await a.run("r2", [{ stream: sName(0), id: "new" }], { full: false });
  // Fresh process state, and the remote is reachable again.
  const fresh = await a.restart();
  w.gateway.beforeBatch = undefined;
  expect(await pending(fresh.db)).toEqual(["old", "new"]);
  const report = await fresh.sync.cycle();
  expect(report.connections.map((c) => c.error)).toEqual([null]);
  expect(await pending(fresh.db)).toEqual([]);
  // Two registered versions. The process lost its local acknowledgement, so
  // the second version repeats run r1's record (same stamp, same data) next to
  // run r2's: write amplification of one record, no change to any reader's
  // result.
  expect(await registered(w)).toEqual([
    ["upsert old@r1", "complete"],
    ["upsert old@r1", "upsert new@r2"],
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
   * stops before it records that. `a`'s database still lists k as unpublished.
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
    return a;
  }
  const bodiesOfK = async (d: { db: SqlDriver }) =>
    (
      await d.db.query<{ body: string }>(
        "SELECT body FROM records WHERE stream = ? AND record_key = ?",
        [sName(0), "k"],
      )
    ).map((r) => r.body);
  /** The restarted process publishes with no error and leaves nothing unpublished. */
  const catchUp = async (fresh: {
    sync: { cycle(): Promise<{ connections: { error: string | null }[] }> };
  }) => {
    const report = await fresh.sync.cycle();
    expect(report.connections.map((c) => c.error)).toEqual([null]);
    await fresh.sync.cycle();
  };

  it("every replica reads the newer value, not the accepted run's", async () => {
    const w = await world({ streams: 1 });
    const a = await acceptedThenLost(w);
    const b = await w.device("b");
    await b.cycle();
    expect(await bodiesOfK(b)).toEqual(['{"id":"k","v":1}']);
    await b.run("r2", [{ stream: sName(0), id: "k", v: 2 }], { full: false });
    await b.cycle();
    expect(w.gateway.versions.get(LOG)).toHaveLength(2);

    const fresh = await a.restart();
    await catchUp(fresh);
    await b.cycle();
    const c = await w.device("c");
    await c.cycle();
    for (const replica of [fresh, b, c])
      expect(await bodiesOfK(replica)).toEqual(['{"id":"k","v":2}']);
  });

  it("a key another device deleted stays deleted on every replica", async () => {
    const w = await world({ streams: 1 });
    const a = await acceptedThenLost(w);
    const b = await w.device("b");
    await b.cycle();
    expect(await bodiesOfK(b)).toEqual(['{"id":"k","v":1}']);
    await b.run("r2", [{ stream: sName(0), id: "k", remove: true }], {
      full: false,
    });
    await b.cycle();
    expect(await bodiesOfK(b)).toEqual([]);
    expect(w.gateway.versions.get(LOG)).toHaveLength(2);

    const fresh = await a.restart();
    await catchUp(fresh);
    await b.cycle();
    const c = await w.device("c");
    await c.cycle();
    for (const replica of [fresh, b, c])
      expect(await bodiesOfK(replica)).toEqual([]);
  });
});
