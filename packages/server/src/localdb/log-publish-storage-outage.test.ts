// Storage that keeps refusing past its retry budget is an outage, not a fault
// in the data (`StorageDeferredError`). The publish leaves the connection's
// changes queued and reports `backoff`; the next cycle sends them.
import { afterEach, describe, expect, it } from "vitest";
// The world runs core from source: the error class must be that module's.
import { StorageDeferredError } from "../../../core/src/stream-sync/storage-retry.js";
import { publishLog } from "../../../core/src/localdb/log-publish.js";
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

it("acknowledges a run the remote accepted before a cold restart exactly once, and publishes a newer run after it", async () => {
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
  // One segment per run: the accepted append is not written a second time.
  expect(w.gateway.versions.get(LOG)).toHaveLength(2);
  expect((await w.segments()).size).toBe(2);
  const b = await w.device("b");
  await b.cycle();
  expect(await b.records()).toEqual([
    's0/new={"id":"new"}',
    's0/old={"id":"old"}',
  ]);
});
