// A registry restored from a backup can be behind the devices: the log rows of
// the newest positions are gone, while the segments they named are still in
// storage and their effects are in the rows of every device that applied them.
// A device that applied them puts them back, in order, each against the
// registry's current position. A registry that names another history at a
// position the device applied gets what only the device's history held as the
// device's own changes, on top of its own (`log-rebase.ts`).
import { afterEach, describe, expect, it } from "vitest";
import {
  closeWorldDrivers,
  CONNECTION_ID,
  LOG,
  sName,
  world,
} from "./log-world.test-utils.js";

afterEach(closeWorldDrivers);

const s = sName(0);

describe("log apply: a registry behind this device", () => {
  it("puts back two rolled-back positions, so another device reads every record and every delete", async () => {
    const w = await world({ streams: 1 });
    const a = await w.device("a");
    await a.run("r1", [
      { stream: s, id: "x" },
      { stream: s, id: "y" },
    ]);
    await a.cycle();
    const b = await w.device("b");
    await b.cycle();
    expect(await b.position()).toBe(1);

    // Position 2 deletes x; position 3 adds z.
    await a.run("r2", [{ stream: s, id: "x", remove: true }], { full: false });
    await a.cycle();
    await a.run("r3", [{ stream: s, id: "z" }], { full: false });
    await a.cycle();
    expect(await a.position()).toBe(3);

    // The registry loses its two newest log rows.
    w.gateway.versions.get(LOG)!.splice(-2);

    // No user action: the next cycle recovers.
    const report = await a.sync.cycle();
    expect(report.connections.map((c) => c.error)).toEqual([null]);
    expect(await a.position()).toBe(3);
    expect(w.gateway.rowsOf(LOG)).toBe(3);

    // The device keeps publishing after it.
    await a.run("r4", [{ stream: s, id: "w" }], { full: false });
    await a.cycle();
    expect(await a.position()).toBe(4);

    // The device that read position 1 gets the delete of x, which a snapshot
    // of a's records would not carry; a new device reads the same.
    await b.cycle();
    const c = await w.device("c");
    await c.cycle();
    const ids = (await a.records()).map((r) => r.split("=")[0]);
    expect(ids).toEqual([`${s}/w`, `${s}/y`, `${s}/z`]);
    expect(await b.rows()).toEqual(await a.rows());
    expect(await c.rows()).toEqual(await a.rows());
  });

  it("a registry that names another segment at a position this device applied gets that device's records, deletes and omissions back", async () => {
    const w = await world({ streams: 1 });
    const a = await w.device("a");
    await a.run(
      "r1",
      [
        { stream: s, id: "x" },
        { stream: s, id: "v" },
        { stream: s, id: "w" },
      ],
      { observedAt: 1100 },
    );
    await a.cycle();
    const b = await w.device("b");
    await b.cycle();
    // Position 2 deletes x; position 3 is a full pass that no longer lists v.
    await a.run("r2", [{ stream: s, id: "x", remove: true }], {
      full: false,
      observedAt: 1300,
    });
    await a.cycle();
    await a.run(
      "r3",
      [
        { stream: s, id: "w" },
        { stream: s, id: "z" },
      ],
      { observedAt: 1400 },
    );
    await a.cycle();
    expect(await a.position()).toBe(3);

    // Rolled back to position 1, then b writes another position 2: q, and x
    // and v as seen before a deleted and dropped them.
    w.gateway.versions.get(LOG)!.splice(-2);
    await b.run(
      "rb",
      [
        { stream: s, id: "q" },
        { stream: s, id: "x", v: 2 },
        { stream: s, id: "v", v: 2 },
      ],
      { full: false, observedAt: 1200 },
    );
    await b.cycle();
    expect(await b.position()).toBe(2);

    const report = await a.sync.cycle();
    expect(report.connections.map((c) => c.error)).toEqual([null]);
    const ids = (await a.records()).map((r) => r.split("=")[0]);
    expect(ids).toEqual([`${s}/q`, `${s}/w`, `${s}/z`]);

    await b.cycle();
    const c = await w.device("c");
    await c.cycle();
    expect(await b.rows()).toEqual(await a.rows());
    expect(await c.rows()).toEqual(await a.rows());
  });
});

describe("log rebase: a deterministic convergence trace", () => {
  // The model's RebaseLive check did not finish; this is one bad schedule run
  // to the end. Two devices rest on a compacted snapshot. The registry goes
  // back below it (fork 0) and another device writes a different position 1.
  // The first device's repair commits but its reply is lost, and while the
  // second repairs, the registry is rolled back again and written again.
  // Then nobody writes, and the devices must settle.
  it("two stale devices, fork 0 after compaction, a lost reply and a second divergence settle in a bounded number of cycles", async () => {
    const w = await world({ streams: 1 });
    const a = await w.device("a");
    const b = await w.device("b");
    const c = await w.device("c");
    await a.run(
      "r1",
      [
        { stream: s, id: "x" },
        { stream: s, id: "y" },
        { stream: s, id: "v" },
      ],
      { observedAt: 1100 },
    );
    await a.cycle();
    await b.cycle();
    await a.run("r2", [{ stream: s, id: "x", remove: true }], {
      full: false,
      observedAt: 1200,
    });
    await a.cycle();
    // A full pass that no longer lists v.
    await a.run(
      "r3",
      [
        { stream: s, id: "y" },
        { stream: s, id: "w" },
      ],
      { observedAt: 1300 },
    );
    await a.cycle();
    for (let i = 0; ; i++) {
      const segments = await w.segments();
      if (segments.get(Math.max(...segments.keys()))!.snapshot !== null) break;
      expect(i).toBeLessThan(200);
      await a.run(`g${i}`, [{ stream: s, id: "g", v: i }], {
        full: false,
        observedAt: 2000 + i,
      });
      await a.cycle();
    }
    await b.cycle();
    const snapshotOf = async (d: typeof a) =>
      (
        await d.db.query<{ snapshot: string | null }>(
          "SELECT snapshot FROM log_state WHERE connection_id = ?",
          [CONNECTION_ID],
        )
      )[0]?.snapshot ?? null;
    expect(await snapshotOf(a)).not.toBeNull();
    expect(await snapshotOf(b)).not.toBeNull();
    expect(await b.rows()).toEqual(await a.rows());

    // Fork 0: the registry holds no position either device applied, and c
    // writes another position 1.
    w.gateway.versions.get(LOG)!.splice(0);
    await c.run(
      "rc",
      [
        { stream: s, id: "q" },
        { stream: s, id: "y", v: 5 },
      ],
      { full: false, observedAt: 1250 },
    );
    await c.cycle();
    expect(w.gateway.rowsOf(LOG)).toBe(1);

    // a repairs; its commit lands but the reply is lost.
    w.gateway.dropNextBatchReply = true;
    await a.sync.cycle();
    expect(w.gateway.dropNextBatchReply).toBe(false);
    const afterLost = w.gateway.rowsOf(LOG);
    expect(afterLost).toBeGreaterThan(1);

    // b repairs; before its first log commit is looked at, the registry goes
    // back to c's position 1 again and c writes a different position 2.
    let diverged = false;
    w.gateway.beforeBatch = async (call) => {
      if (diverged || !call.body.rows.some((r) => r.scope === LOG)) return;
      diverged = true;
      w.gateway.versions.get(LOG)!.splice(1);
      await c.run("rc2", [{ stream: s, id: "p" }], {
        full: false,
        observedAt: 9000,
      });
      await c.sync.cycle();
    };
    await b.sync.cycle();
    w.gateway.beforeBatch = undefined;
    expect(diverged).toBe(true);

    // Quiet: nobody collects. Cycle every device until the registry stops
    // moving and the devices agree, within a bound.
    const devices = [a, b, c];
    const tombstones = async (d: typeof a) =>
      (
        await d.db.query<Record<string, unknown>>(
          "SELECT stream, pk_hash, record_key, stamp_o, stamp_r, rank FROM log_tombstones ORDER BY stream, pk_hash",
        )
      ).map((r) => JSON.stringify(r));
    const BOUND = 8;
    let settledAt = -1;
    let last = w.gateway.rowsOf(LOG);
    for (let round = 1; round <= BOUND; round++) {
      for (const d of devices) {
        const report = await d.sync.cycle();
        expect(report.connections.map((x) => x.error)).toEqual([null]);
      }
      const now = w.gateway.rowsOf(LOG);
      const rows = await a.rows();
      const agree =
        JSON.stringify(await b.rows()) === JSON.stringify(rows) &&
        JSON.stringify(await c.rows()) === JSON.stringify(rows) &&
        JSON.stringify(await tombstones(b)) ===
          JSON.stringify(await tombstones(a));
      if (now === last && agree) {
        settledAt = round;
        break;
      }
      last = now;
    }
    expect(settledAt).toBeGreaterThan(0);

    // Nothing either history held is lost and nothing deleted comes back:
    // x's delete and v's omission hold, c's q and p and a's y, w and g stay.
    const ids = (await a.records()).map((r) => r.split("=")[0]);
    expect(ids).toEqual([`${s}/g`, `${s}/p`, `${s}/q`, `${s}/w`, `${s}/y`]);
    expect(await b.rows()).toEqual(await a.rows());
    expect(await tombstones(b)).toEqual(await tombstones(a));
    const fresh = await w.device("d");
    await fresh.cycle();
    expect(await fresh.rows()).toEqual(await a.rows());

    // Settled: more cycles publish nothing and the registry does not move.
    const position = w.gateway.rowsOf(LOG);
    const batches = w.writes().batches;
    for (let round = 0; round < 3; round++)
      for (const d of [...devices, fresh]) await d.cycle();
    expect(w.gateway.rowsOf(LOG)).toBe(position);
    expect(w.writes().batches).toBe(batches);
    expect(await a.position()).toBe(position);
    expect(await b.position()).toBe(position);
  });
});
