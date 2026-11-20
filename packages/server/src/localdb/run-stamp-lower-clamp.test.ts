import { afterEach, describe, expect, it } from "vitest";
import { clampRunStart } from "../../../core/src/localdb/admit.js";
import { closeWorldDrivers, sName, world } from "./log-world.test-utils.js";

// A run's start stamp `o` comes from the device clock, and the newest stamp
// wins. A run that begins on a device that already holds a stamp must start
// above it, or a correct clock loses to a fast one and its body is dropped
// without a report.

afterEach(closeWorldDrivers);

const S0 = sName(0);
const DAY = 24 * 60 * 60 * 1000;
const T = 2000;

type Device = Awaited<ReturnType<Awaited<ReturnType<typeof world>>["device"]>>;

const runStart = async (d: Device, runId: string) =>
  (
    await d.db.query<{ o: number }>("SELECT o FROM runs WHERE run_id = ?", [
      runId,
    ])
  )[0]!.o;
const bodies = async (d: Device) =>
  (await d.records()).map((r) => r.split("=").slice(1).join("="));
const body = (v: number) => JSON.stringify({ id: "K", v });

describe.each([false, true])(
  "a run starts above the stamps its device holds (publishWhileCollecting %s)",
  (publishWhileCollecting) => {
    it("a body written after a fast-clock device's wins on both devices", async () => {
      const w = await world({ streams: 1, publishWhileCollecting });
      const a = await w.device("a");
      const b = await w.device("b");

      // a's clock is a day fast when it publishes the first body.
      w.setClock(T + DAY);
      await a.run("a1", [{ stream: S0, id: "K", v: 1 }]);
      await a.cycle();

      // b's clock is right. It applies a's segment, then collects newer data.
      w.setClock(T);
      await b.cycle();
      expect(await bodies(b)).toEqual([body(1)]);
      await b.run("b1", [{ stream: S0, id: "K", v: 2 }]);
      await b.cycle();
      await a.cycle();

      expect(await bodies(a)).toEqual([body(2)]);
      expect(await bodies(b)).toEqual([body(2)]);
      expect(await b.rows()).toEqual(await a.rows());
      // b's run began at the stamp it learned from a's segment; its id sorts
      // after a's, so the pair is above it.
      expect(await runStart(b, "b1")).toBe(await runStart(a, "a1"));
    });

    it("a key deleted by a fast-clock device comes back when a correct clock collects it again", async () => {
      const w = await world({ streams: 1, publishWhileCollecting });
      const a = await w.device("a");
      const b = await w.device("b");
      w.setClock(T);
      await a.run("a0", [{ stream: S0, id: "K", v: 1 }]);
      await a.cycle();
      w.setClock(T + DAY);
      await a.run("a1", [{ stream: S0, id: "K", remove: true }]);
      await a.cycle();

      // b learns the delete only as a tombstone: it holds no row for K.
      w.setClock(T);
      await b.cycle();
      expect(await bodies(b)).toEqual([]);
      await b.run("0b", [{ stream: S0, id: "K", v: 3 }]);
      await b.cycle();
      await a.cycle();

      expect(await bodies(a)).toEqual([body(3)]);
      expect(await bodies(b)).toEqual([body(3)]);
      // b's run began above the delete's stamp, which it holds only as a
      // tombstone. Its id sorts before a's, so `o` is one above.
      expect(await runStart(b, "0b")).toBe((await runStart(a, "a1")) + 1);
    });
  },
);

describe("a run that holds no newer stamp keeps its clock start", () => {
  it("a device with no stamps starts at its clock, or at the observed time it is given", async () => {
    const w = await world({ streams: 1 });
    const a = await w.device("a");
    w.setClock(T);
    await a.begin("r1");
    expect(await runStart(a, "r1")).toBe(T + 1);
    await a.begin("r2", { observedAt: 5000 });
    expect(await runStart(a, "r2")).toBe(5000);
  });

  it("a device whose clock is past every stamp it holds keeps its clock", async () => {
    const w = await world({ streams: 1 });
    const a = await w.device("a");
    const b = await w.device("b");
    w.setClock(T);
    await a.run("a1", [{ stream: S0, id: "K", v: 1 }]);
    await a.cycle();
    w.setClock(T + 10_000);
    await b.cycle();
    await b.begin("b1");
    expect(await runStart(b, "b1")).toBe(T + 10_001);
    // a wrote the row itself and starts at its own later clock too.
    w.setClock(T + 20_000);
    await a.begin("a2");
    expect(await runStart(a, "a2")).toBe(T + 20_001);
  });
});

describe("the stamps a device holds are read from indexes", () => {
  it("a run that stamped a stream's floor holds its stamp when no row carries it", async () => {
    const w = await world({ streams: 1 });
    const a = await w.device("a");
    w.setClock(T + DAY);
    await a.run("a1", []);
    // The clock goes back; the run's stamp is left only in the stream's floor.
    w.setClock(T);
    await a.begin("a2");
    expect(await runStart(a, "a2")).toBe(await runStart(a, "a1"));
  });

  it("the begin statement scans neither the rows nor the log tombstones", async () => {
    const w = await world({ streams: 1 });
    const a = await w.device("a");
    await a.run("a1", [{ stream: S0, id: "K", v: 1 }]);
    await a.run("a2", [{ stream: S0, id: "K", remove: true }]);
    await a.cycle();
    const { sql, params } = clampRunStart("a2");
    const plan = (
      await a.db.query<{ detail: string }>(
        `EXPLAIN QUERY PLAN ${sql}`,
        params as never,
      )
    ).map((r) => r.detail);
    expect(
      plan.filter((d) => /^SCAN (records|log_tombstones|runs)\b/.test(d)),
    ).toEqual([]);
    expect(plan).toEqual(
      expect.arrayContaining([
        expect.stringContaining("records_by_observation"),
        expect.stringContaining("log_tombstones_by_stamp"),
      ]),
    );
  });
});
