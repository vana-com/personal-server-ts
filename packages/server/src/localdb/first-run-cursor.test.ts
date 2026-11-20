import { afterEach, describe, expect, it } from "vitest";
import { closeWorldDrivers, sName, world } from "./log-world.test-utils.js";

// A completed run's cursor must be resumable by the next begin on the same
// device, whether or not a full cycle ran in between.

afterEach(closeWorldDrivers);

const S0 = sName(0);

describe("the first run of a new connection", () => {
  it("leaves its cursor for the next begin after only an early publish", async () => {
    const w = await world({ streams: 1 });
    const a = await w.device("a");
    await a.run("run-0", [{ stream: S0, id: "x" }], {
      full: false,
      checkpoints: { [S0]: "c1" },
    });
    await a.sync.publish();
    const begun = await a.begin("run-1", { full: false });
    expect(begun.start).toEqual({
      collection_mode: "incremental",
      state: { [S0]: "c1" },
    });
  });

  it("holds the cursor back until the publication carries it", async () => {
    const w = await world({ streams: 1 });
    const a = await w.device("a");
    await a.run("run-0", [{ stream: S0, id: "x" }], {
      full: false,
      checkpoints: { [S0]: "c1" },
    });
    const begun = await a.begin("run-1", { full: false });
    expect(begun.start.state).toBeNull();
  });
});

describe("a run refused at publish", () => {
  it("leaves no checkpoint ahead of the rows the device holds", async () => {
    const w = await world({ streams: 1 });
    const a = await w.device("a");
    await a.run("run-0", [{ stream: S0, id: "x" }], {
      full: false,
      checkpoints: { [S0]: "c0" },
    });
    await a.cycle();
    await a.run("run-1", [{ stream: S0, id: "y" }], {
      full: false,
      checkpoints: { [S0]: "c1" },
    });
    // The stream is deleted after run-1 pinned its snapshot: publish fences it.
    await a.db.batch([
      { sql: "UPDATE stream_state SET last_delete_version = 99" },
    ]);
    await a.cycle();
    expect(
      await a.db.query("SELECT reason FROM run_streams WHERE run_id = 'run-1'"),
    ).toEqual([{ reason: "stream_deleted_after_start" }]);
    const begun = await a.begin("run-2", { full: false });
    expect(begun.start.state).not.toEqual({ [S0]: "c1" });
  });
});
