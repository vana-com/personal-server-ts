// `LocalSync.publish()`: what a save awaits. It ends at the registry commit and
// reads nothing the commit does not need; the cycle's listing and apply are the
// next `cycle()`'s.
import { afterEach, describe, expect, it } from "vitest";
import {
  CONNECTION_ID,
  closeWorldDrivers,
  world,
} from "./log-world.test-utils.js";

afterEach(closeWorldDrivers);

describe("publish", () => {
  it("returns the run's receipt at the commit, with no registry listing or apply", async () => {
    const w = await world({ streams: 1, logProtocol: true });
    const d = await w.device("d1");
    await d.run("r1", [{ stream: "s0", id: "a" }]);
    const report = await d.sync.publish();
    expect(report.connections).toHaveLength(1);
    const [connection] = report.connections;
    expect(connection).toMatchObject({
      connectionId: CONNECTION_ID,
      error: null,
      applied: [],
    });
    expect(
      connection!.published.flatMap((r) => r.publication?.runIds ?? []),
    ).toEqual(["r1"]);
    expect(w.gateway.calls.filter((c) => c.kind === "list")).toEqual([]);
    expect(w.gateway.batches()).toHaveLength(1);
  });

  it("publishes what the cycle would, so the next cycle finds nothing to send", async () => {
    const w = await world({ streams: 1, logProtocol: true });
    const d = await w.device("d1");
    await d.run("r1", [{ stream: "s0", id: "a" }]);
    await d.sync.publish();
    const report = await d.cycle();
    expect(
      report.connections.flatMap((c) => c.published).map((r) => r.outcome),
    ).not.toContain("published");
    expect(w.gateway.batches()).toHaveLength(1);
  });

  it("runs the whole cycle on a device without the log protocol", async () => {
    const w = await world({ streams: 1, logProtocol: false });
    const d = await w.device("d1");
    await d.run("r1", [{ stream: "s0", id: "a" }]);
    await d.sync.publish();
    expect(w.gateway.calls.some((c) => c.kind === "list")).toBe(true);
  });
});
