import { afterEach, describe, expect, it } from "vitest";
import { closeWorldDrivers, sName, world } from "./log-world.test-utils.js";

// Two devices run one connector against one log. The cursor is a position in
// the source: a run reads from its start state to the position it ends with.

afterEach(closeWorldDrivers);

const S0 = sName(0);
const at = (since: number) => ({ [S0]: { since } });

describe("two devices share a stream's cursor through the log", () => {
  it("a device reads on from another's cursor, and an older run that commits last loses no row", async () => {
    const w = await world({ streams: 1 });
    const a = await w.device("a");
    await a.run("run-0", [{ stream: S0, id: "seed" }]);
    await a.cycle();
    await a.run("run-1", [{ stream: S0, id: "w" }], {
      full: false,
      checkpoints: at(10),
    });
    await a.cycle();

    // b syncs and reads on from a's cursor.
    const b = await w.device("b");
    await b.cycle();
    expect((await b.begin("run-b-0", { full: false })).start).toEqual({
      collection_mode: "incremental",
      state: at(10),
    });

    // Both run from 10. a's run begins first and ends last, at 20; b's
    // reads to 30 and publishes while a's still collects.
    const older = await a.run("run-a", [{ stream: S0, id: "x" }], {
      full: false,
      checkpoints: at(20),
      during: async () => {
        await b.run("run-b", [{ stream: S0, id: "y" }], {
          full: false,
          checkpoints: at(30),
        });
        await b.cycle();
      },
    });
    expect(older.start.state).toEqual(at(10));
    await a.cycle();
    await b.cycle();

    // No row is lost: both devices hold both runs' rows.
    for (const d of [a, b]) {
      const ids = (await d.records()).map((r) => r.split("=")[0]);
      expect(ids).toEqual(
        expect.arrayContaining([`${S0}/w`, `${S0}/x`, `${S0}/y`]),
      );
    }
    expect(await b.rows()).toEqual(await a.rows());
    // The log's last cursor is the older run's, so the next run on either
    // device reads again only from 20 to 30, not the stream in full.
    for (const [name, d] of [
      ["a", a],
      ["b", b],
    ] as const)
      expect(
        (await d.begin(`run-${name}-next`, { full: false })).start,
      ).toEqual({ collection_mode: "incremental", state: at(20) });
  });
});
