// Publish is three phases: SNAPSHOT under the connection's queue slot,
// TRANSFER (every upload) outside it, COMMIT under the slot again. These tests
// use the real connection queue and hold storage on promises, so each ordering
// is exact: no sleeps, no timers.
import { afterEach, describe, expect, it } from "vitest";
import { unwriteRefusedRun } from "../../../core/src/localdb/unwrite.js";
import {
  closeDrivers,
  makeDevice,
  receiptRunIds,
  sharedStores,
  streamRows,
  webDeleteAndReconnect,
  type Device,
} from "./publish-split.test-utils.js";

afterEach(closeDrivers);

/** Run a cycle to the end and fail if the connection errored. */
async function settle(device: Device) {
  const report = await device.cycle();
  expect(report.connections.map((c) => c.error)).toEqual(
    report.connections.map(() => null),
  );
  return report;
}

/** A device with one published seed row: registry head v1 in lifetime 1. */
async function started() {
  const stores = sharedStores();
  const a = await makeDevice(stores, "a");
  await a.run("seed", ["seed-row"]);
  await settle(a);
  return { stores, a };
}

/** The rows a fresh device reads from the registry. */
async function readerKeys(
  stores: Awaited<ReturnType<typeof started>>["stores"],
) {
  const reader = await makeDevice(stores, "reader");
  await reader.sync.apply();
  return reader.keys();
}

const putting = (op: string) => op === "put";

describe("a publish upload does not hold the queue slot", () => {
  it("admits a run's begin while an upload is blocked", async () => {
    const { stores, a } = await started();
    await a.run("r1", ["seed-row", "one"]);
    const hold = stores.storage.holdNext(putting);
    const cycle = a.cycle();
    await hold.reached;
    const request = a.nextRequest();
    const began = a.begin("r2");
    try {
      // On the old code this begin queues behind the whole publish.
      expect(await request).toMatchObject({ kind: "end", behind: 0 });
    } finally {
      hold.release();
    }
    await began;
    await cycle;
    expect(await a.head()).toMatchObject({ version: 2 });
  });

  it("publishes a run begun and ended during an upload later, never past the candidate's W", async () => {
    const { stores, a } = await started();
    await a.run("r1", ["seed-row", "one"]);
    const w1 = await a.newestChange();
    const hold = stores.storage.holdNext(putting);
    const cycle = a.cycle();
    await hold.reached;
    // "two" lies in no prefix the candidate re-encodes.
    await a.run("r2", ["two"]);
    const w2 = await a.newestChange();
    expect(w2).toBeGreaterThan(w1);
    hold.release();
    const first = await cycle;
    expect(first.connections[0]?.error).toBeNull();
    expect(receiptRunIds(first)).toContain("r1");
    expect(receiptRunIds(first)).not.toContain("r2");
    expect(await a.watermark()).toBe(w1);
    expect(await a.head()).toMatchObject({ version: 2 });
    // The late run's rows are local and still queued above W.
    expect(await a.keys()).toEqual(["one", "seed-row", "two"]);

    const second = await settle(a);
    expect(receiptRunIds(second)).toContain("r2");
    expect(await a.watermark()).toBe(w2);
    expect(await a.head()).toMatchObject({ version: 3 });
    expect(await readerKeys(stores)).toEqual(["one", "seed-row", "two"]);
  });

  it("sends the candidate's rows when a late run rewrites a row of a prefix being sent", async () => {
    const { stores, a } = await started();
    await a.run("r1", ["seed-row", "one"]);
    const w1 = await a.newestChange();
    const hold = stores.storage.holdNext(putting);
    const cycle = a.cycle();
    await hold.reached;
    // r2 re-stamps "one", which the candidate re-encodes. The transfer reads
    // its own copy, so this cannot stale it.
    await a.run("r2", ["seed-row", "one", "two"]);
    hold.release();
    const first = await cycle;
    expect(first.connections[0]?.error).toBeNull();
    // One new head, built from r1's rows; r2 is pending above W.
    expect(await streamRows(stores)).toEqual([{ version: 2, state: "head" }]);
    expect(receiptRunIds(first)).toContain("r1");
    expect(receiptRunIds(first)).not.toContain("r2");
    expect(await a.watermark()).toBe(w1);
    expect(await readerKeys(stores)).toEqual(["one", "seed-row"]);
    // The next cycle publishes r2 and leaves nothing pending.
    expect(receiptRunIds(await settle(a))).toContain("r2");
    expect(await a.head()).toMatchObject({ version: 3 });
    expect(receiptRunIds(await settle(a))).toEqual([]);
    expect(await readerKeys(stores)).toEqual(["one", "seed-row", "two"]);
  });

  it("keeps the same bound when the head equals the registry head (no CAS)", async () => {
    const { stores, a } = await started();
    await a.run("r1", ["seed-row", "one"]);
    // The CAS lands, its reply is lost: the registry holds v2, local is at v1.
    stores.registry.failNextStreamPost("after");
    const lost = await a.cycle();
    expect(lost.connections[0]?.error).toMatch(/post reply lost/);
    expect(await a.head()).toMatchObject({ version: 1 });
    expect(await streamRows(stores)).toEqual([{ version: 2, state: "head" }]);
    const w1 = await a.newestChange();

    // The retry rebuilds the identical head, so its hash equals the
    // registry's. Hold its first transfer step, which is outside the slot.
    const hold = stores.storage.holdNext(() => !a.inSlot());
    const cycle = a.cycle();
    await hold.reached;
    await a.run("r2", ["two"]);
    const w2 = await a.newestChange();
    hold.release();
    const retry = await cycle;
    expect(retry.connections[0]?.error).toBeNull();
    // No new registry version; the watermark is the candidate's.
    expect(await streamRows(stores)).toEqual([{ version: 2, state: "head" }]);
    expect(await a.watermark()).toBe(w1);
    expect(await a.head()).toMatchObject({ version: 2 });

    const last = await settle(a);
    expect(receiptRunIds(last)).toContain("r2");
    expect(await a.watermark()).toBe(w2);
    expect(await readerKeys(stores)).toEqual(["one", "seed-row", "two"]);
  });
});

describe("a publish sends from a spool", () => {
  const spoolRows = async (a: Device) =>
    (
      await a.query<{ n: number }>("SELECT count(*) AS n FROM publish_spool")
    )[0]!.n;
  const attempts = async (a: Device) =>
    (
      await a.query<{ n: number }>(
        "SELECT count(DISTINCT attempt) AS n FROM publish_spool",
      )
    )[0]!.n;

  it("publishes in the cycle that began when unread rows are restamped during its transfers", async () => {
    const { stores, a } = await started();
    await a.run("r1", ["seed-row", "one"]);
    const w1 = await a.newestChange();
    let hold = stores.storage.holdNext(putting);
    const cycle = a.cycle();
    // A collector re-emits unchanged rows (new stamps) during every transfer
    // the cycle starts. Up to five: more than the invalidation budget.
    const restamped: string[] = [];
    for (let n = 1; n <= 5; n++) {
      const reached = await Promise.race([
        hold.reached.then(() => true),
        cycle.then(() => false),
      ]);
      if (!reached) break;
      await a.run(`late-${n}`, ["seed-row", "one"]);
      restamped.push(`late-${n}`);
      const next = stores.storage.holdNext(putting);
      hold.release();
      hold = next;
    }
    const first = await cycle;
    expect(first.connections[0]?.error).toBeNull();
    // The first candidate published: the cycle was not starved.
    expect(await a.head()).toMatchObject({ version: 2 });
    expect(await a.watermark()).toBe(w1);
    expect(receiptRunIds(first)).toContain("r1");
    expect(await readerKeys(stores)).toEqual(["one", "seed-row"]);
    // The restamps are pending above W and publish in the next cycle.
    hold.release();
    const second = await settle(a);
    expect(restamped.length).toBeGreaterThanOrEqual(1);
    expect(receiptRunIds(second)).toEqual(expect.arrayContaining(restamped));
    expect(await readerKeys(stores)).toEqual(["one", "seed-row"]);
  });

  it("holds the candidate's rows in the spool during the transfer and none after the commit", async () => {
    const { stores, a } = await started();
    await a.run("r1", ["seed-row", "one"]);
    expect(await spoolRows(a)).toBe(0);
    const hold = stores.storage.holdNext(putting);
    const cycle = a.cycle();
    await hold.reached;
    expect(await spoolRows(a)).toBe(2);
    expect(await attempts(a)).toBe(1);
    hold.release();
    await cycle;
    expect(await a.head()).toMatchObject({ version: 2 });
    expect(await spoolRows(a)).toBe(0);
  });

  it("drops the spool of a candidate the commit discards, and of its replacement", async () => {
    const { stores, a } = await started();
    await a.run("r1", ["seed-row", "one", "x"]);
    const first = stores.storage.holdNext(putting);
    const cycle = a.cycle();
    await first.reached;
    // A rewrite the transfer ignores and a delete the commit must catch.
    await a.run("r2", ["seed-row", "one"]);
    await a.remove("r3", ["x"]);
    const second = stores.storage.holdNext(putting);
    first.release();
    await second.reached;
    // The discarded candidate's rows are gone; only the new attempt's remain.
    expect(await attempts(a)).toBe(1);
    second.release();
    const report = await cycle;
    expect(report.connections[0]?.error).toBeNull();
    expect(await readerKeys(stores)).not.toContain("x");
    expect(await spoolRows(a)).toBe(0);
    await settle(a);
    expect(await readerKeys(stores)).toEqual(["one", "seed-row"]);
    expect(await spoolRows(a)).toBe(0);
  });

  it("drops the spool of a transfer that failed", async () => {
    const { stores, a } = await started();
    await a.run("r1", ["seed-row", "one"]);
    stores.storage.failNextPut();
    const failed = await a.cycle();
    expect(failed.connections[0]?.error).toMatch(/put failed/);
    expect(await spoolRows(a)).toBe(0);
    await settle(a);
    expect(await readerKeys(stores)).toEqual(["one", "seed-row"]);
    expect(await spoolRows(a)).toBe(0);
  });

  it("keeps no copy of a connection's rows once the connection is deleted", async () => {
    const { stores, a } = await started();
    await a.run("r1", ["seed-row", "one"]);
    const hold = stores.storage.holdNext(putting);
    const cycle = a.cycle();
    await hold.reached;
    expect(await spoolRows(a)).toBe(2);
    await a.sync.deleter.requestConnectionDelete("fixture");
    // The purge took the copy with the records.
    expect(await spoolRows(a)).toBe(0);
    hold.release();
    const report = await cycle;
    expect(receiptRunIds(report)).toEqual([]);
    expect(await spoolRows(a)).toBe(0);
    expect(await readerKeys(stores)).toEqual([]);
  });
});

describe("run publication evidence follows the candidate's runs", () => {
  /** A run's publication state, as the intake answers it. */
  const stateOf = async (device: Device, runId: string) =>
    (await device.sync.intake.publicationStatus(runId)).state;

  it("keeps a run that ended during the upload pending until a later cycle publishes it", async () => {
    const { stores, a } = await started();
    await a.run("r1", ["seed-row", "one"]);
    const hold = stores.storage.holdNext(putting);
    const cycle = a.cycle();
    await hold.reached;
    // "two" lies in no prefix the candidate re-encodes, so the candidate stands.
    await a.run("r2", ["two"]);
    hold.release();
    const first = await cycle;
    expect(first.connections[0]?.error).toBeNull();
    expect(receiptRunIds(first)).toContain("r1");
    expect(receiptRunIds(first)).not.toContain("r2");
    // The head the commit wrote covers r1, not r2.
    expect(await stateOf(a, "r1")).toBe("published");
    expect(await stateOf(a, "r2")).toBe("pending");

    await settle(a);
    expect(await stateOf(a, "r2")).toBe("published");
  });

  it("writes no evidence for a candidate a record delete invalidated, until the re-snapshot commits", async () => {
    const { stores, a } = await started();
    await a.run("r1", ["seed-row", "one", "x"]);
    const first = stores.storage.holdNext(putting);
    const cycle = a.cycle();
    await first.reached;
    // The delete invalidates the candidate that r1 was captured in. Hold the
    // re-snapshot's first upload so the state between the two can be read.
    await a.remove("r2", ["x"]);
    const second = stores.storage.holdNext(putting);
    first.release();
    await second.reached;
    expect(await a.head()).toMatchObject({ version: 1 });
    expect(await stateOf(a, "r1")).toBe("pending");
    expect(await stateOf(a, "r2")).toBe("pending");
    second.release();
    const report = await cycle;
    expect(report.connections[0]?.error).toBeNull();
    expect(receiptRunIds(report)).toEqual(expect.arrayContaining(["r1", "r2"]));
    expect(await stateOf(a, "r1")).toBe("published");
    expect(await stateOf(a, "r2")).toBe("published");
    expect(await readerKeys(stores)).toEqual(["one", "seed-row"]);
  });
});

describe("another device publishing during an upload", () => {
  it("discards the stale candidate and converges on the newer head", async () => {
    const { stores, a } = await started();
    const b = await makeDevice(stores, "b");
    await b.sync.apply();
    await a.run("r1", ["seed-row", "one"]);
    const hold = stores.storage.holdNext(putting);
    const cycle = a.cycle();
    await hold.reached;
    // b publishes v2 while a's candidate (built over v1) is in flight.
    await b.run("rb", ["seed-row", "bee"]);
    await settle(b);
    expect(await streamRows(stores)).toEqual([{ version: 2, state: "head" }]);
    hold.release();
    expect((await cycle).connections[0]?.error).toBeNull();
    await settle(a);
    await settle(b);
    // Both devices and a fresh reader agree, and a's row survived.
    const keys = await a.keys();
    expect(keys).toContain("one");
    expect(await b.keys()).toEqual(keys);
    expect(await readerKeys(stores)).toEqual(keys);
  });
});

describe("a delete during an upload wins", () => {
  it("does not publish a candidate whose connection was deleted", async () => {
    const { stores, a } = await started();
    await a.run("r1", ["seed-row", "one"]);
    const hold = stores.storage.holdNext(putting);
    const cycle = a.cycle();
    await hold.reached;
    await a.sync.deleter.requestConnectionDelete("fixture");
    hold.release();
    const report = await cycle;
    // The candidate was not posted: no receipt, whatever else the cycle did.
    expect(receiptRunIds(report)).toEqual([]);
    expect(report.connections[0]?.published[0]?.outcome).not.toBe("published");
    // Nothing is resurrected, locally or for a reader.
    await a.cycle();
    expect(await a.keys()).toEqual([]);
    expect(await readerKeys(stores)).toEqual([]);
  });

  it("does not publish a candidate whose rows a purge removed", async () => {
    const { stores, a } = await started();
    await a.run("r1", ["seed-row", "one"]);
    const hold = stores.storage.holdNext(putting);
    const cycle = a.cycle();
    await hold.reached;
    await a.deps.queue.run(a.connectionId, "purge", () =>
      unwriteRefusedRun(a.deps, {
        connectionId: a.connectionId,
        stream: "items",
        runId: "r1",
        reason: "out_of_order",
      }),
    );
    hold.release();
    await cycle;
    // The frozen rows included "one"; the registry never saw that head.
    expect(await streamRows(stores)).toEqual([{ version: 1, state: "head" }]);
    await settle(a);
    expect(await a.keys()).not.toContain("one");
    expect(await readerKeys(stores)).not.toContain("one");
  });
});

describe("an explicit record delete during an upload", () => {
  it("does not publish the frozen head that still holds the deleted record", async () => {
    const { stores, a } = await started();
    await a.run("r1", ["seed-row", "one", "x"]);
    const hold = stores.storage.holdNext(putting);
    const cycle = a.cycle();
    await hold.reached;
    // A real intake delete of x, begun and ended while the part PUT is held.
    await a.remove("r2", ["x"]);
    expect(await a.keys()).not.toContain("x");
    hold.release();
    const report = await cycle;
    expect(report.connections[0]?.error).toBeNull();
    // No head the registry holds shows x, as a fresh reader sees it.
    expect(await readerKeys(stores)).not.toContain("x");
    await settle(a);
    expect(await a.keys()).not.toContain("x");
    expect(await readerKeys(stores)).toEqual(["one", "seed-row"]);
  });

  it("publishes the delete in the next cycle when a later upsert did not stop it", async () => {
    const { stores, a } = await started();
    await a.run("r1", ["seed-row", "one", "x"]);
    const hold = stores.storage.holdNext(putting);
    const cycle = a.cycle();
    await hold.reached;
    await a.remove("r2", ["x"]);
    hold.release();
    await cycle;
    await settle(a);
    expect(await readerKeys(stores)).not.toContain("x");
  });
});

describe("a failed or interrupted transfer converges", () => {
  it("leaves head and watermark unchanged after a failed part PUT, then retries", async () => {
    const { stores, a } = await started();
    await a.run("r1", ["seed-row", "one"]);
    const w1 = await a.newestChange();
    const before = { head: await a.head(), watermark: await a.watermark() };
    stores.storage.failNextPut();
    const failed = await a.cycle();
    expect(failed.connections[0]?.error).toMatch(/put failed/);
    expect(await a.head()).toEqual(before.head);
    expect(await a.watermark()).toBe(before.watermark);
    expect(await streamRows(stores)).toEqual([{ version: 1, state: "head" }]);

    await settle(a);
    expect(await a.head()).toMatchObject({ version: 2 });
    expect(await a.watermark()).toBe(w1);
    expect(await readerKeys(stores)).toEqual(["one", "seed-row"]);
  });

  it("converges after a crash with the uploads done and the CAS not posted", async () => {
    const { stores, a } = await started();
    await a.run("r1", ["seed-row", "one"]);
    stores.registry.failNextStreamPost("before");
    const crashed = await a.cycle();
    expect(crashed.connections[0]?.error).toMatch(/post lost/);
    expect(await a.head()).toMatchObject({ version: 1 });
    const uploaded = stores.storage.puts.length;

    await settle(a);
    // The objects were already there: the retry uploads none of them again.
    expect(stores.storage.puts.length).toBe(uploaded);
    expect(await a.head()).toMatchObject({ version: 2 });
    expect(await streamRows(stores)).toEqual([{ version: 2, state: "head" }]);
    expect(await readerKeys(stores)).toEqual(["one", "seed-row"]);
  });

  it("converges after a crash between the CAS and the local commit", async () => {
    const { stores, a } = await started();
    await a.run("r1", ["seed-row", "one"]);
    const w1 = await a.newestChange();
    stores.registry.failNextStreamPost("after");
    const crashed = await a.cycle();
    expect(crashed.connections[0]?.error).toMatch(/post reply lost/);
    expect(await a.head()).toMatchObject({ version: 1 });

    await settle(a);
    // Re-read: the registry's v2 is ours. No v3, watermark caught up.
    expect(await streamRows(stores)).toEqual([{ version: 2, state: "head" }]);
    expect(await a.head()).toMatchObject({ version: 2 });
    expect(await a.watermark()).toBe(w1);
    expect(await readerKeys(stores)).toEqual(["one", "seed-row"]);
  });
});

describe("connections do not wait on each other", () => {
  it("publishes another connection while one connection's upload is blocked", async () => {
    const { stores, a } = await started();
    const other = a.connection("other");
    await a.run("r1", ["seed-row", "one"]);
    await other.run("o1", ["only"]);
    const hold = stores.storage.holdNext(
      (op, key) => op === "put" && key.includes("fixture"),
    );
    const blocked = a.sync.syncConnection(a.connectionId);
    await hold.reached;
    const done = await a.sync.syncConnection(other.connectionId);
    expect(done.error).toBeNull();
    expect(await other.head()).toMatchObject({ version: 1 });
    expect(await a.head()).toMatchObject({ version: 1 });
    hold.release();
    expect((await blocked).error).toBeNull();
    expect(await a.head()).toMatchObject({ version: 2 });
  });
});

describe("a run never publishes into a later connection lifetime", () => {
  it("DEFECT: a first run ended before another writer deleted and reconnected is discarded", async () => {
    const stores = sharedStores();
    const a = await makeDevice(stores, "a");
    // Control is absent at begin, so the run has no generation of its own.
    await a.run("R", ["deleted-row"]);
    await webDeleteAndReconnect(stores);
    const reports = [await settle(a), await settle(a)];
    expect(reports.flatMap(receiptRunIds)).not.toContain("R");
    expect(await a.keys()).not.toContain("deleted-row");
    expect(await a.decisions()).toEqual([
      { run_id: "R", decision: "discarded", reason: "lifetime_changed" },
    ]);
    expect(await readerKeys(stores)).not.toContain("deleted-row");
  });

  it("still publishes a first run into lifetime 1 when nothing was deleted", async () => {
    const stores = sharedStores();
    const a = await makeDevice(stores, "a");
    await a.run("R", ["kept-row"]);
    const report = await settle(a);
    expect(receiptRunIds(report)).toEqual(["R"]);
    expect(await a.head()).toMatchObject({ version: 1, generation: 1 });
    expect(await readerKeys(stores)).toEqual(["kept-row"]);
  });

  it("a run ended before a local connection delete and reconnect is not published", async () => {
    const { stores, a } = await started();
    await a.run("R", ["seed-row", "deleted-row"]);
    await a.sync.deleter.requestConnectionDelete("fixture");
    await a.begin("life2", true);
    await a.sync.intake.batch("life2", {
      batch: 0,
      records: [{ stream: "items", data: { id: "fresh" } }],
    });
    await a.end("life2");
    const reports = [await settle(a), await settle(a)];
    expect(reports.flatMap(receiptRunIds)).not.toContain("R");
    expect(await a.keys()).not.toContain("deleted-row");
    expect(await readerKeys(stores)).not.toContain("deleted-row");
  });
});

describe("a collecting run keeps the lifetime it began in", () => {
  it("is discarded at its end when another writer moved the lifetime while it collected", async () => {
    const stores = sharedStores();
    const a = await makeDevice(stores, "a");
    // Control is absent at begin: the run has no generation and stays collecting.
    await a.begin("R");
    expect(
      await a.query("SELECT generation FROM runs WHERE run_id = 'R'"),
    ).toEqual([{ generation: null }]);
    await webDeleteAndReconnect(stores);
    // A cycle learns the new lifetime while R is still collecting.
    await settle(a);
    await a.sync.intake.batch("R", {
      batch: 0,
      records: [{ stream: "items", data: { id: "old-lifetime-row" } }],
    });
    await a.end("R");
    const reports = [await settle(a), await settle(a)];
    expect(reports.flatMap(receiptRunIds)).not.toContain("R");
    expect(await a.keys()).not.toContain("old-lifetime-row");
    expect(await readerKeys(stores)).not.toContain("old-lifetime-row");
  });
});

describe("a generation-bound run is dropped when another writer deletes and reconnects mid-publish", () => {
  /** R began with the control row observed: bound to lifetime 1. */
  async function bound() {
    const { stores, a } = await started();
    await a.run("R", ["seed-row", "deleted-row"]);
    expect(
      await a.query("SELECT generation FROM runs WHERE run_id = 'R'"),
    ).toEqual([{ generation: 1 }]);
    return { stores, a };
  }

  async function expectGone(
    stores: Awaited<ReturnType<typeof started>>["stores"],
    a: Device,
    reports: Parameters<typeof receiptRunIds>[0][],
  ) {
    expect(reports.flatMap(receiptRunIds)).not.toContain("R");
    // Only the seed's v1 head ever existed in the registry.
    expect(await streamRows(stores)).toEqual([{ version: 1, state: "head" }]);
    for (let i = 0; i < 2; i++) await settle(a);
    expect(await a.keys()).not.toContain("deleted-row");
    expect(await readerKeys(stores)).not.toContain("deleted-row");
  }

  it("with the delete after the snapshot and before the CAS", async () => {
    const { stores, a } = await bound();
    const hold = stores.storage.holdNext(putting);
    const cycle = a.cycle();
    await hold.reached;
    await webDeleteAndReconnect(stores);
    hold.release();
    const report = await cycle;
    await expectGone(stores, a, [report]);
  });

  it("with the delete before the snapshot", async () => {
    const { stores, a } = await bound();
    // A cycle's publish slot requests are apply, preamble, snapshot, commit.
    const uploaded = stores.storage.puts.length;
    const pause = a.pausePublish(3);
    const cycle = a.cycle();
    await pause.reached;
    expect(stores.storage.puts).toHaveLength(uploaded);
    await webDeleteAndReconnect(stores);
    pause.release();
    const report = await cycle;
    await expectGone(stores, a, [report]);
  });
});
