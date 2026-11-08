/**
 * A covered full refresh replaces what a stream holds; every other run merges.
 * The real writer publishes from one or two devices, the real reader imports,
 * and the owner and a grant read the same published set.
 */

import { describe, expect, it } from "vitest";
import { Rig, type RunSpec } from "./writer-rig.js";

const run = (spec: Partial<RunSpec> & { runId: string }): RunSpec => ({
  key: "id",
  version: "1.0.0",
  rows: [],
  full: false,
  ...spec,
});

const SCOPE = "pdpp.acme.items";
const A = { id: "a", v: 1 };
const B = { id: "b", v: 1 };
const C = { id: "c", v: 1 };
const A2 = { id: "a", v: 2 };

async function read(rig: Rig, isOwnerView: boolean) {
  const decision = await rig.service.resolve({
    scope: SCOPE,
    connection: null,
    cursor: null,
    legacyFile: false,
    isOwnerView,
  });
  if (decision.kind !== "view" && decision.kind !== "local_pending") {
    return { ids: [] as string[], withheld: [] as string[] };
  }
  const envelope = JSON.parse(await new Response(decision.body).text()) as {
    data: { records: { id: string }[] };
  };
  return {
    ids: envelope.data.records.map((r) => r.id).sort(),
    withheld: (decision.withheld ?? []).map((w) => `${w.runId}:${w.reason}`),
  };
}

async function baseRig(): Promise<Rig> {
  const rig = new Rig();
  await rig.open();
  await rig.collect(run({ runId: "base", full: true, rows: [A, B], at: 1000 }));
  await rig.publish();
  await rig.sync();
  return rig;
}

describe("covered full refresh", () => {
  it("drops a record the refresh omits, on the owner's other device", async () => {
    const rig = await baseRig();
    await rig.collect(
      run({
        runId: "refresh",
        otherDevice: true,
        full: true,
        replace: true,
        rows: [A2],
        at: 5000,
      }),
    );
    await rig.sync();
    expect((await read(rig, true)).ids).toEqual(["a"]);
    expect((await read(rig, false)).ids).toEqual(["a"]);
    expect((await rig.registeredHead())?.recordCount).toBe(1);
  });

  it("keeps a record when the same run is not marked covered", async () => {
    const rig = await baseRig();
    await rig.collect(
      run({
        runId: "partial",
        otherDevice: true,
        full: true,
        rows: [A2],
        at: 5000,
      }),
    );
    await rig.sync();
    expect((await read(rig, true)).ids).toEqual(["a", "b"]);
    expect((await read(rig, false)).ids).toEqual(["a", "b"]);
  });

  it("keeps a record written after the refresh was collected, and drops an older one", async () => {
    const rig = await baseRig();
    await rig.collect(run({ runId: "late", rows: [C], at: 9000 }));
    await rig.publish();
    await rig.collect(
      run({
        runId: "refresh",
        otherDevice: true,
        full: true,
        replace: true,
        rows: [A2],
        at: 5000,
      }),
    );
    await rig.sync();
    // b is older than the refresh and omitted; c is newer than the refresh.
    expect((await read(rig, true)).ids).toEqual(["a", "c"]);
    expect((await read(rig, false)).ids).toEqual(["a", "c"]);
  });

  it("a refresh older than the head's newest write cannot remove it, and a merge run after it adds", async () => {
    const rig = await baseRig();
    await rig.collect(
      run({
        runId: "refresh",
        otherDevice: true,
        full: true,
        replace: true,
        rows: [A2],
        at: 5000,
      }),
    );
    await rig.collect(run({ runId: "after", rows: [C], at: 6000 }));
    await rig.publish();
    await rig.sync();
    expect((await read(rig, true)).ids).toEqual(["a", "c"]);
  });

  it("shows the old set, with the run withheld, until the owner's own refresh is imported", async () => {
    const rig = await baseRig();
    await rig.collect(
      run({ runId: "mine", full: true, replace: true, rows: [A2], at: 5000 }),
    );
    const before = await read(rig, true);
    expect(before.ids).toEqual(["a", "b"]);
    expect(before.withheld).toEqual(["mine:key_reset_pending"]);
    expect((await read(rig, false)).ids).toEqual(["a", "b"]);

    await rig.publish();
    await rig.sync();
    expect((await read(rig, true)).ids).toEqual(["a"]);
    expect((await read(rig, false)).ids).toEqual(["a"]);
  });

  it("gives the same result after a crash between the registry post and the plan commit", async () => {
    const rig = await baseRig();
    await rig.collect(
      run({ runId: "mine", full: true, replace: true, rows: [A2], at: 5000 }),
    );
    let crashed = false;
    rig.gateway.afterPost = async () => {
      crashed = true;
      rig.gateway.afterPost = undefined;
      throw new Error("crash after the registry committed");
    };
    await rig.publish().catch(() => undefined);
    // The hook must have fired, or the restart below proves nothing.
    expect(crashed).toBe(true);
    await rig.restart();
    await rig.publish();
    await rig.sync();
    expect((await read(rig, true)).ids).toEqual(["a"]);
    expect((await read(rig, false)).ids).toEqual(["a"]);
    // Replaying a second time changes nothing.
    const version = await rig.registeredVersion();
    await rig.restart();
    await rig.publish();
    expect(await rig.registeredVersion()).toBe(version);
  });

  // The skew trace: this device queues a covered refresh stamped 5000 and
  // holds it; another device, whose clock is slower, publishes a newer
  // covered refresh stamped 4000 that keeps c. The queued refresh started
  // before c existed, so it must not delete c.
  const skew =
    (queued: string, other: string, queuedAt: number, otherAt: number) =>
    async (merge: boolean) => {
      const rig = await baseRig();
      await rig.collect(
        run({
          runId: queued,
          full: true,
          ...(merge ? {} : { replace: true }),
          rows: [A2],
          at: queuedAt,
        }),
      );
      await rig.collect(
        run({
          runId: other,
          otherDevice: true,
          full: true,
          replace: true,
          rows: [A2, C],
          at: otherAt,
        }),
      );
      await rig.sync();
      expect((await read(rig, false)).ids).toEqual(["a", "c"]);
      await rig.publish();
      await rig.sync();
      return {
        owner: (await read(rig, true)).ids,
        grant: (await read(rig, false)).ids,
      };
    };

  it("keeps a record another device published after this device's queued refresh began (skewed clocks)", async () => {
    const result = await skew("mine", "other", 5000, 4000)(false);
    expect(result.owner).toEqual(["a", "c"]);
    expect(result.grant).toEqual(["a", "c"]);
  });

  it("keeps the record when observedAt ties and run ids sort against the queued refresh", async () => {
    const result = await skew("z-refresh", "a-new", 5000, 5000)(false);
    expect(result.owner).toEqual(["a", "c"]);
    expect(result.grant).toEqual(["a", "c"]);
  });

  it("merges the same skewed trace when the queued run carries no replace marker", async () => {
    const result = await skew("mine", "other", 5000, 4000)(true);
    expect(result.owner).toEqual(["a", "c"]);
    expect(result.grant).toEqual(["a", "c"]);
  });

  it("replaces when no other device published since the refresh began", async () => {
    const rig = await baseRig();
    await rig.collect(
      run({ runId: "mine", full: true, replace: true, rows: [A2], at: 5000 }),
    );
    await rig.publish();
    await rig.sync();
    expect((await read(rig, true)).ids).toEqual(["a"]);
    expect((await read(rig, false)).ids).toEqual(["a"]);
  });

  it("does not bring back a seed row the refresh omits", async () => {
    const rig = new Rig({
      key: "id",
      version: "1.0.0",
      rows: [{ id: "s", v: 1 }],
    });
    await rig.open();
    await rig.collect(
      run({ runId: "mine", full: true, replace: true, rows: [A], at: 5000 }),
    );
    await rig.publish();
    await rig.sync();
    expect((await read(rig, true)).ids).toEqual(["a"]);
    expect((await read(rig, false)).ids).toEqual(["a"]);
  });
});
