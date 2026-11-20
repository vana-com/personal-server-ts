import { afterEach, describe, expect, it } from "vitest";
import type { WireSegment } from "@opendatalabs/personal-server-ts-stream-sync";
import {
  LOG,
  closeWorldDrivers,
  sName,
  world,
} from "./log-world.test-utils.js";

// A device that reads a stream's rows from the log takes the stream's cursor
// with them, so its next run reads on from where the writer's run stopped.

afterEach(closeWorldDrivers);

const S0 = sName(0);

type World = Awaited<ReturnType<typeof world>>;
type Device = Awaited<ReturnType<World["device"]>>;

/**
 * A connection's first run saves no checkpoint: its generation is bound by its
 * first publish. Each test starts after that.
 */
async function started(d: Device): Promise<void> {
  await d.run("run-0", [{ stream: S0, id: "seed" }]);
  await d.cycle();
}

const cursorOf = (segment: WireSegment) =>
  segment.streams.find((m) => m.stream === S0)?.cursor;

/** The log's head: the segment at the highest position. */
async function headOf(w: World): Promise<WireSegment> {
  const segments = await w.segments();
  return segments.get(Math.max(...segments.keys()))!;
}

describe("a device that reads the log takes the stream's cursor", () => {
  it("a device that applies another's segment begins incremental from its cursor", async () => {
    const w = await world({ streams: 1 });
    const a = await w.device("a");
    await started(a);
    await a.run("run-1", [{ stream: S0, id: "x" }], {
      full: false,
      checkpoints: { [S0]: "c1" },
    });
    await a.cycle();

    const b = await w.device("b");
    const begun = await b.begin("run-b", { full: false });
    expect(begun.start).toEqual({
      collection_mode: "incremental",
      state: { [S0]: "c1" },
    });
  });

  it("a device behind the snapshot begins incremental from the cursor the snapshot carries", async () => {
    const w = await world({ streams: 1 });
    const a = await w.device("a");
    await started(a);
    await a.run("run-1", [{ stream: S0, id: "x" }], {
      full: false,
      checkpoints: { [S0]: "c1" },
    });
    await a.cycle();
    // Runs that save no new cursor, until the head carries a snapshot.
    for (let i = 0; (await headOf(w)).snapshot === null; i++) {
      await a.run(`run-g${i}`, [{ stream: S0, id: "y", v: i }], {
        full: false,
      });
      await a.cycle();
    }
    const head = await headOf(w);
    const parts = await w.snapshotParts(head);
    expect(parts[0]!.streams.find((m) => m.stream === S0)?.cursor).toEqual({
      state: "c1",
      connectorVersion: "1",
    });

    const b = await w.device("b");
    const begun = await b.begin("run-b", { full: false });
    expect(begun.start).toEqual({
      collection_mode: "incremental",
      state: { [S0]: "c1" },
    });
  });

  // A first load reads the log in ranges; the cursor rides an early segment
  // and later ones name the stream without one.
  const firstLoads = {
    "segment by segment, readable while it fills": {
      hooks: { progressiveFirstLoad: true, keyedFirstLoad: false },
      budget: () => 1,
      bootstrap: false,
    },
    "key by key": {
      hooks: { progressiveFirstLoad: true },
      budget: async (w: World) =>
        2 *
        Math.max(
          ...(await Promise.all(
            [...(await w.segmentKeys()).values()].map(
              async (key) => (await w.innerBlobs.get(key))!.length,
            ),
          )),
        ),
      bootstrap: false,
    },
    "disk-backed": {
      hooks: { progressiveFirstLoad: true, keyedFirstLoad: false },
      budget: () => undefined,
      bootstrap: true,
    },
  } as const;
  for (const [name, load] of Object.entries(firstLoads))
    it(`a first load (${name}) takes the cursor an earlier segment carried`, async () => {
      const w = await world({ streams: 1 });
      const a = await w.device("a");
      await started(a);
      await a.run(
        "run-1",
        [
          { stream: S0, id: "x", pad: 400 },
          { stream: S0, id: "y", pad: 400 },
        ],
        { full: false, checkpoints: { [S0]: "c1" } },
      );
      await a.cycle();
      for (let i = 0; i < 3; i++) {
        await a.run(`run-g${i}`, [{ stream: S0, id: `g${i}`, pad: 400 }], {
          full: false,
        });
        await a.cycle();
      }
      expect(cursorOf(await headOf(w))).toBeUndefined();

      const budget = await load.budget(w);
      const b = await w.device("b", {
        ...load.hooks,
        ...(budget === undefined ? {} : { maxBytesInFlight: budget }),
      });
      if (load.bootstrap) Object.assign(b.deps, { bootstrapFirstLoad: true });
      const begun = await b.begin("run-b", { full: false });
      expect(begun.start).toEqual({
        collection_mode: "incremental",
        state: { [S0]: "c1" },
      });
    });

  it("every device ends at the cursor the log published last", async () => {
    const w = await world({ streams: 1 });
    const a = await w.device("a");
    await started(a);
    const b = await w.device("b");
    await b.cycle();
    // a's cursor waits to publish while b publishes its own.
    await a.run("run-a", [{ stream: S0, id: "x" }], {
      full: false,
      checkpoints: { [S0]: "ca" },
    });
    await b.run("run-b", [{ stream: S0, id: "y" }], {
      full: false,
      checkpoints: { [S0]: "cb" },
    });
    await b.cycle();
    // a reads b's segment, then publishes its own cursor after it.
    await a.cycle();
    await b.cycle();
    for (const [name, d] of [
      ["a", a],
      ["b", b],
    ] as const)
      expect((await d.begin(`run-${name}-2`, { full: false })).start).toEqual({
        collection_mode: "incremental",
        state: { [S0]: "ca" },
      });
  });

  it("a run that ends after another device's cursor is applied keeps its own", async () => {
    const w = await world({ streams: 1 });
    const a = await w.device("a");
    await started(a);
    const b = await w.device("b");
    await b.cycle();
    await a.run("run-a", [{ stream: S0, id: "x" }], {
      full: false,
      checkpoints: { [S0]: "ca" },
      // While a collects, it applies b's segment and b's cursor with it.
      during: async () => {
        await b.run("run-b", [{ stream: S0, id: "y" }], {
          full: false,
          checkpoints: { [S0]: "cb" },
        });
        await b.cycle();
        await a.cycle();
      },
    });
    expect((await a.begin("run-a-2", { full: false })).start).toEqual({
      collection_mode: "incremental",
      state: { [S0]: "ca" },
    });
  });

  it("a rebase publishes the cursor again after the rows it queues again", async () => {
    const w = await world({ streams: 1 });
    const a = await w.device("a");
    await started(a);
    const b = await w.device("b");
    await b.cycle();
    await a.run("run-1", [{ stream: S0, id: "x" }], {
      full: false,
      checkpoints: { [S0]: "c1" },
    });
    await a.cycle();
    await a.run("run-2", [{ stream: S0, id: "z" }], {
      full: false,
      checkpoints: { [S0]: "c2" },
    });
    await a.cycle();
    expect(await a.position()).toBe(3);

    // The registry loses the two positions that carried a's cursors, and b
    // writes another position 2: a's history is no longer the log's.
    w.gateway.versions.get(LOG)!.splice(-2);
    await b.run("run-b", [{ stream: S0, id: "q" }], {
      full: false,
      checkpoints: { [S0]: "cb" },
    });
    await b.cycle();
    expect(await b.position()).toBe(2);
    // a queues x and z again and publishes them after b's position, with
    // the cursor that covers them.
    await a.cycle();
    expect(await a.position()).toBe(3);

    const c = await w.device("c");
    const begun = await c.begin("run-c", { full: false });
    expect(begun.start).toEqual({
      collection_mode: "incremental",
      state: { [S0]: "c2" },
    });
    const ids = (await c.records()).map((r) => r.split("=")[0]);
    expect(ids).toEqual(
      expect.arrayContaining([`${S0}/q`, `${S0}/x`, `${S0}/z`]),
    );
  });
});
