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
