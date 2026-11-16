// The connection log is the only protocol: nothing is switched on to start one.
// A connection with no log gets one on its first publish, and that first write
// carries every record the device holds, so a device that has only the log
// misses nothing (there is no per-stream head left to read what the log lacks).
import { afterEach, describe, expect, it } from "vitest";
import {
  CONNECTION_ID,
  LOG,
  closeWorldDrivers,
  sName,
  world,
} from "./log-world.test-utils.js";

afterEach(closeWorldDrivers);

const rows = (prefix: string) =>
  [0, 1].flatMap((i) => [
    { stream: sName(i), id: `${prefix}${i}-1` },
    { stream: sName(i), id: `${prefix}${i}-2` },
  ]);

describe("the first publish of a connection", () => {
  it("writes a new log with no flag set, and a second device reads the rows from it", async () => {
    const w = await world({ streams: 2 });
    expect(w.gateway.versions.get(LOG)).toBeUndefined();
    const a = await w.device("a");
    await a.run("r1", rows("a"));
    await a.cycle();

    // One log row, at position 1, written by the batch route.
    expect(w.gateway.versions.get(LOG)).toHaveLength(1);
    expect(w.writes().batches).toBe(1);
    expect((await w.segments()).size).toBe(1);

    const b = await w.device("b");
    await b.cycle();
    expect(await b.records()).toEqual(await a.records());
    expect((await b.records()).length).toBe(4);
  });

  it("carries the records a device holds from before any log, as a full first write", async () => {
    const w = await world({ streams: 2 });
    const old = await w.device("old");
    await old.run("r1", rows("o"));
    await old.cycle();
    // What a device that published through per-stream heads holds: its
    // records and complete stream rows, nothing pending, no log in the
    // registry and none applied.
    w.gateway.versions.delete(LOG);
    await old.db.batch([
      {
        sql: "DELETE FROM log_state WHERE connection_id = ?",
        params: [CONNECTION_ID],
      },
      { sql: "DELETE FROM record_changes", params: [] },
    ]);
    expect(
      await old.db.query("SELECT 1 FROM record_changes WHERE connection_id=?", [
        CONNECTION_ID,
      ]),
    ).toEqual([]);

    await old.cycle();
    expect(w.gateway.versions.get(LOG)).toHaveLength(1);

    // A device that has only the log reads every record, and the streams are
    // whole (a reader shows a complete stream, not a partial one).
    const fresh = await w.device("fresh");
    await fresh.cycle();
    expect(await fresh.records()).toEqual(await old.records());
    expect((await fresh.records()).length).toBe(4);
    expect(
      await fresh.db.query<{ complete: number }>(
        "SELECT complete FROM stream_state WHERE connection_id=? ORDER BY stream",
        [CONNECTION_ID],
      ),
    ).toEqual([{ complete: 1 }, { complete: 1 }]);
  });

  it("a device with records from before the log meets a connection that already has one: the log's rows and its own end up in both, once", async () => {
    const w = await world({ streams: 2 });
    const old = await w.device("old");
    await old.run("r1", rows("o"));
    await old.cycle();
    // The old device's state, as in the test above ...
    w.gateway.versions.delete(LOG);
    await old.db.batch([
      {
        sql: "DELETE FROM log_state WHERE connection_id = ?",
        params: [CONNECTION_ID],
      },
      { sql: "DELETE FROM record_changes", params: [] },
    ]);
    // ... and a device that never saw it starts the log without its records.
    const a = await w.device("a");
    await a.run("r2", rows("a"), { full: false });
    await a.cycle();
    expect(w.gateway.versions.get(LOG)).toHaveLength(1);

    await old.cycle();
    const fresh = await w.device("fresh");
    await fresh.cycle();
    await a.cycle();
    const want = await old.records();
    expect(want.length).toBe(8);
    expect(await fresh.records()).toEqual(want);
    expect(await a.records()).toEqual(want);
  });
});
