// `LocalSync.publish()`: what a save awaits. It ends at the registry commit and
// reads nothing the commit does not need; the cycle's listing and apply are the
// next `cycle()`'s.
import { afterEach, describe, expect, it } from "vitest";
import type { StreamSyncRegistry } from "../../../core/src/stream-sync/registry.js";
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

  it("does not report a save as durable when the registry has no batch route", async () => {
    const w = await world({ streams: 1, logProtocol: true });
    const d = await w.device("d1");
    await d.run("r1", [{ stream: "s0", id: "a" }]);
    await d.cycle();
    delete (d.deps.registry as StreamSyncRegistry).postBatch;
    await d.run("r2", [{ stream: "s0", id: "b" }]);
    const report = await d.sync.publish();
    // The connection has a log, so nothing is published until the registry has
    // the route: the report says so and does not come back empty.
    expect(report.connections).toHaveLength(1);
    expect(report.connections[0]!.error).toMatch(/no batch route/);
  });

  it("publishes a new connection per stream when the registry has no batch route", async () => {
    const w = await world({ streams: 1, logProtocol: true });
    const d = await w.device("d1");
    delete (d.deps.registry as StreamSyncRegistry).postBatch;
    await d.run("r1", [{ stream: "s0", id: "a" }]);
    const report = await d.sync.publish();
    expect(report.connections).toHaveLength(1);
    expect(report.connections[0]!.error).toBeNull();
    expect(report.connections[0]!.published.map((r) => r.outcome)).toContain(
      "published",
    );
  });

  it("names the runs of both when a second publish waits behind the first", async () => {
    const w = await world({ streams: 1, logProtocol: true });
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let held = false;
    const d = await w.device("d1", true, {
      beforePut: async () => {
        if (held) return;
        held = true;
        await gate;
      },
    });
    await d.run("r1", [{ stream: "s0", id: "a" }]);
    const first = d.sync.publish();
    // The first publish holds its upload; a run that ends meanwhile is what
    // the second publish sends.
    while (!held) await new Promise((r) => setImmediate(r));
    await d.run("r2", [{ stream: "s0", id: "b" }]);
    const second = d.sync.publish();
    release();
    await first;
    const report = await second;
    const runIds = report.connections
      .flatMap((c) => c.published)
      .flatMap((r) => r.publication?.runIds ?? []);
    expect(runIds.sort()).toEqual(["r1", "r2"]);
  });
});
