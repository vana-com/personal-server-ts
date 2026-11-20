import { afterEach, describe, expect, it } from "vitest";
import { closeWorldDrivers, sName, world } from "./log-world.test-utils.js";

// A stream's cursor carries the version of the connector that wrote it. A
// connector older than that may not understand it; one whose order against it
// is unknown reads the stream again.

afterEach(closeWorldDrivers);

const S0 = sName(0);

/** Device a's run, at `version`, leaves cursor `c1` in the log. */
async function written(version: string) {
  const w = await world({ streams: 1 });
  const a = await w.device("a");
  await a.run("run-0", [{ stream: S0, id: "seed" }], { version });
  await a.cycle();
  await a.run("run-1", [{ stream: S0, id: "x" }], {
    full: false,
    version,
    checkpoints: { [S0]: "c1" },
  });
  await a.cycle();
  return { w, b: await w.device("b") };
}

describe("the connector version a cursor carries", () => {
  it("a connector older than the cursor's writer is refused before the run writes anything", async () => {
    const { b } = await written("2.0.0");
    await expect(
      b.begin("run-b", { full: false, version: "1.0.0" }),
    ).rejects.toMatchObject({
      code: "connector_update_required",
      status: 409,
    });
    expect(
      await b.db.query("SELECT run_id FROM runs WHERE run_id = ?", ["run-b"]),
    ).toEqual([]);
  });

  it("a newer connector reads on from an older one's cursor", async () => {
    const { b } = await written("1.0.0");
    const begun = await b.begin("run-b", { full: false, version: "2.0.0" });
    expect(begun.start).toEqual({
      collection_mode: "incremental",
      state: { [S0]: "c1" },
    });
  });

  it("a cursor whose version order is unknown reads that stream in full", async () => {
    const { b } = await written("2024-build-7");
    const begun = await b.begin("run-b", { full: false, version: "1.0.0" });
    expect(begun.start.state).toBeNull();
    expect(begun.streams.find((s) => s.name === S0)?.mode).toBe("full_refresh");
  });
});
