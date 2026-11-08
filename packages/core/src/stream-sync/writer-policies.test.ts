/**
 * Writer policies that decide what a stream's head becomes, driven through
 * the real `StreamSyncWriter` against a registry fake:
 *
 * - version floor: a stream remembers the highest connector version that
 *   registered on it, and a changed key is checked against that floor, not
 *   against the version of the last writer;
 * - commit order: commits follow (observedAt, runId); a retry never commits
 *   an older run after a newer one;
 * - re-projection: a run that changes the projector profile publishes, even
 *   when its rows change nothing.
 */

import { describe, expect, it } from "vitest";
import { Rig, type RunSpec } from "../stream-sync-read/writer-rig.js";

const run = (spec: Partial<RunSpec> & { runId: string }): RunSpec => ({
  key: "id",
  version: "1.0.0",
  rows: [],
  full: false,
  ...spec,
});

async function rigWithBase(version: string): Promise<Rig> {
  const rig = new Rig();
  await rig.open();
  await rig.collect(
    run({
      runId: "base",
      version,
      full: true,
      rows: [
        { id: "a", v: 1 },
        { id: "b", v: 1 },
      ],
    }),
  );
  await rig.publish();
  return rig;
}

function problemOf(
  statuses: Awaited<ReturnType<Rig["publish"]>>,
  runId: string,
): string | null {
  return (
    statuses.find((s) => s.runId === runId)?.streams["items"]?.problem ?? null
  );
}

describe("writer policy: version floor", () => {
  it("refuses a changed key older than the highest version that registered, even after an older writer", async () => {
    const rig = await rigWithBase("2.0.0");
    // An older connector with the same key writes: the head's last writer is
    // now 1.0.0, but 2.0.0 registered on this stream before it.
    await rig.collect(run({ runId: "rA", rows: [{ id: "x", v: 1 }] }));
    // 1.5.0 is newer than the last writer and older than the floor.
    await rig.collect(
      run({
        runId: "rB",
        key: "uid",
        version: "1.5.0",
        full: true,
        rows: [{ uid: "u1" }],
      }),
    );
    const statuses = await rig.publish();
    expect(problemOf(statuses, "rB")).toBe("connector_update_required");
    const head = await rig.registeredHead();
    expect(head?.primaryKey).toEqual(["id"]);
  });
});

describe("writer policy: commit order", () => {
  it("never commits an older run after a newer run committed on the stream", async () => {
    const rig = await rigWithBase("2.0.0");
    // B is older than C. B's key change is refused against 2.0.0; C's newer
    // key change commits and leaves the head at B's key.
    await rig.collect(
      run({
        runId: "rB",
        key: "uid",
        version: "1.5.0",
        full: true,
        rows: [{ uid: "u1" }],
      }),
    );
    await rig.collect(
      run({
        runId: "rC",
        key: "uid",
        version: "3.0.0",
        full: true,
        rows: [{ uid: "u3" }],
      }),
    );
    await rig.publish();
    const afterC = await rig.registeredHead();
    expect(afterC?.profile.version).toBe("3.0.0");
    const version = await rig.registeredVersion();
    // B retries: its key now matches the head, but it is older than C.
    const retry = await rig.publish();
    expect(await rig.registeredVersion()).toBe(version);
    const head = await rig.registeredHead();
    expect(head?.profile.version).toBe("3.0.0");
    expect(head?.observedAt).toBe(afterC?.observedAt);
    expect(
      retry.find((s) => s.runId === "rB")?.streams["items"]?.state,
    ).not.toBe("committed");
  });
});

describe("writer policy: re-projection", () => {
  it("publishes a run that changes the projector profile even when no row changes", async () => {
    const rig = await rigWithBase("1.0.0");
    const version = await rig.registeredVersion();
    await rig.collect(run({ runId: "r1", profileKey: "projector-2" }));
    const statuses = await rig.publish();
    expect(
      statuses.find((s) => s.runId === "r1")?.streams["items"]?.state,
    ).toBe("committed");
    expect(await rig.registeredVersion()).toBe(version + 1);
    const head = await rig.registeredHead();
    expect(head?.profile).toEqual({ key: "projector-2", version: "1.0.0" });
    expect(head?.recordCount).toBe(2);
  });
});
