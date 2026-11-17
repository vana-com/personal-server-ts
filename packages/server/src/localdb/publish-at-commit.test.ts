// `LocalSync.publish()`: what a save awaits. It ends at the registry commit and
// reads nothing the commit does not need; the cycle's listing and apply are the
// next `cycle()`'s.
import { afterEach, describe, expect, it, vi } from "vitest";
import { publishLog } from "../../../core/src/localdb/log-publish.js";
import type { StreamSyncRegistry } from "../../../core/src/stream-sync/registry.js";
import {
  CONNECTION_ID,
  closeWorldDrivers,
  world,
} from "./log-world.test-utils.js";

afterEach(closeWorldDrivers);

describe("publish", () => {
  it("returns the run's receipt at the commit, with no registry listing or apply", async () => {
    const w = await world({ streams: 1 });
    const d = await w.device("d1");
    await d.run("r1", [{ stream: "s0", id: "a" }]);
    const report = await d.sync.publish();
    expect(report.connections).toHaveLength(1);
    const [connection] = report.connections;
    expect(connection).toMatchObject({
      connectionId: CONNECTION_ID,
      error: null,
    });
    expect(
      connection!.published.flatMap((r) => r.publication?.runIds ?? []),
    ).toEqual(["r1"]);
    expect(w.gateway.calls.filter((c) => c.kind === "list")).toEqual([]);
    expect(w.gateway.batches()).toHaveLength(1);
  });

  it("publishes what the cycle would, so the next cycle finds nothing to send", async () => {
    const w = await world({ streams: 1 });
    const d = await w.device("d1");
    await d.run("r1", [{ stream: "s0", id: "a" }]);
    await d.sync.publish();
    const report = await d.cycle();
    expect(
      report.connections.flatMap((c) => c.published).map((r) => r.outcome),
    ).not.toContain("published");
    expect(w.gateway.batches()).toHaveLength(1);
  });

  it("does not report a save as durable when the registry has no batch route", async () => {
    const w = await world({ streams: 1 });
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

  it("reconciles a timed-out commit before re-uploading its segment", async () => {
    const w = await world({ streams: 1 });
    const d = await w.device("d1");
    await d.run("r1", [{ stream: "s0", id: "a" }]);
    // Both attempts inside postBatchOnce land, but neither reply reaches us.
    w.gateway.beforeBatch = () => {
      w.gateway.dropNextBatchReply = true;
    };
    await expect(publishLog(d.deps, CONNECTION_ID)).rejects.toThrow(/no reply/);
    expect(await d.position()).toBe(0);
    w.gateway.beforeBatch = undefined;
    const encrypt = vi.spyOn(d.deps.keys, "encrypt");
    const result = await publishLog(d.deps, CONNECTION_ID);
    expect(encrypt).not.toHaveBeenCalled();
    encrypt.mockRestore();
    expect(result?.flatMap((r) => r.publication?.runIds ?? [])).toEqual(["r1"]);
    expect(d.puts.filter((key) => key.includes("/s-"))).toHaveLength(1);
    expect(await d.position()).toBe(1);
  });

  it("skips a stored segment after its transfer acknowledgement is lost", async () => {
    const w = await world({ streams: 1 });
    const d = await w.device("d1");
    await d.run("r1", [{ stream: "s0", id: "a" }]);
    const put = d.deps.blobs.put.bind(d.deps.blobs);
    let lost = false;
    d.deps.blobs.put = async (key, bytes) => {
      await put(key, bytes);
      if (!lost && key.includes("/s-")) {
        lost = true;
        throw new Error("transfer acknowledgement lost");
      }
    };
    await expect(publishLog(d.deps, CONNECTION_ID)).rejects.toThrow(
      "transfer acknowledgement lost",
    );
    expect(w.gateway.batches()).toHaveLength(0);
    const result = await publishLog(d.deps, CONNECTION_ID);
    expect(result?.flatMap((r) => r.publication?.runIds ?? [])).toEqual(["r1"]);
    expect(d.puts.filter((key) => key.includes("/s-"))).toHaveLength(1);
  });

  it("returns the runs of both to a publish that waits behind another", async () => {
    const w = await world({ streams: 1 });
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let held = false;
    const d = await w.device("d1", {
      beforePut: async () => {
        if (held) return;
        held = true;
        await gate;
      },
    });
    await d.run("r1", [{ stream: "s0", id: "a" }]);
    const first = d.sync.publish();
    // The first publish holds its upload; a run that ends meanwhile joins its
    // next round, and the second publish, which waits for the first, must
    // still return the receipt that names both runs. (`mergeResults` keeps
    // the runs of both receipts when each publish sent one; no run order in
    // the fake world makes the second publish send a run of its own, so that
    // union is not pinned by a test.)
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
