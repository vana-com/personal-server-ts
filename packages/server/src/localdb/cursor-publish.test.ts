import { afterEach, describe, expect, it } from "vitest";
import type {
  LogStreamMeta,
  WireSegment,
} from "@opendatalabs/personal-server-ts-stream-sync";
import {
  LOG,
  closeWorldDrivers,
  sName,
  world,
} from "./log-world.test-utils.js";

// A stream's connector cursor travels in the log segment that closes the rows
// it covers, never in an earlier round of the same publication.

afterEach(closeWorldDrivers);

const S0 = sName(0);
const S1 = sName(1);

/** Every segment after `after`, by position. */
async function segmentsAfter(
  w: Awaited<ReturnType<typeof world>>,
  after: number,
): Promise<WireSegment[]> {
  const all = await w.segments();
  return [...all.keys()]
    .filter((p) => p > after)
    .sort((x, y) => x - y)
    .map((p) => all.get(p)!);
}
const metaOf = (segment: WireSegment, stream: string) =>
  segment.streams.find((m: LogStreamMeta) => m.stream === stream);
const cursorOf = (segment: WireSegment, stream: string) =>
  metaOf(segment, stream)?.cursor;
/** The cursor a reader of every segment through `upTo` holds for `stream`. */
function foldedCursor(segments: readonly WireSegment[], stream: string) {
  let cursor: LogStreamMeta["cursor"];
  for (const segment of segments) cursor = cursorOf(segment, stream) ?? cursor;
  return cursor;
}
/**
 * A connection's first run saves no checkpoint: its generation is bound by its
 * first publish. Each test starts after that, at the returned position.
 */
async function started(
  d: Awaited<ReturnType<Awaited<ReturnType<typeof world>>["device"]>>,
  streams: readonly string[] = [S0],
): Promise<number> {
  await d.run(
    "run-0",
    streams.map((stream) => ({ stream, id: "seed" })),
  );
  await d.cycle();
  return d.position();
}
const ids = (n: number, prefix = "id") =>
  Array.from(
    { length: n },
    (_, i) => `${prefix}-${String(i).padStart(3, "0")}`,
  );

describe("publish carries the cursor on the closing round", () => {
  it("a stream that needs several rounds carries its cursor only on the last", async () => {
    const w = await world({ streams: 1, partTargetBytes: 3000 });
    const a = await w.device("a");
    const before = await started(a);
    await a.run(
      "run-1",
      ids(60).map((id) => ({ stream: S0, id, pad: 200 })),
      { full: false, checkpoints: { [S0]: { since: "c1" } } },
    );
    await a.cycle();
    const segments = await segmentsAfter(w, before);
    expect(segments.length).toBeGreaterThan(2);
    const touching = segments.filter((s) => metaOf(s, S0) !== undefined);
    expect(touching.slice(0, -1).map((s) => cursorOf(s, S0))).toEqual(
      touching.slice(0, -1).map(() => undefined),
    );
    expect(cursorOf(touching.at(-1)!, S0)).toEqual({
      state: { since: "c1" },
      connectorVersion: "1",
    });
  });

  it("a run that read nothing still publishes its new cursor", async () => {
    const w = await world({ streams: 1 });
    const a = await w.device("a");
    await started(a);
    await a.run("run-1", [{ stream: S0, id: "x" }], {
      full: false,
      checkpoints: { [S0]: "c1" },
    });
    await a.cycle();
    const before = await a.position();
    await a.run("run-2", [], { full: false, checkpoints: { [S0]: "c2" } });
    await a.cycle();
    const segments = await segmentsAfter(w, before);
    expect(segments).toHaveLength(1);
    expect(segments[0]!.operations).toEqual([]);
    expect(cursorOf(segments[0]!, S0)).toEqual({
      state: "c2",
      connectorVersion: "1",
    });
    // Published once: the next cycle has nothing to say.
    await a.cycle();
    expect(await segmentsAfter(w, before)).toHaveLength(1);
  });

  it("a crash after the first round leaves the log's cursor where it was", async () => {
    let puts = 0;
    let armed = false;
    const w = await world({ streams: 1, partTargetBytes: 3000 });
    const a = await w.device("a", {
      beforePut: async (key) => {
        if (armed && key.includes(`${LOG}/s-`) && ++puts === 2)
          throw new Error("the device is gone");
      },
    });
    await started(a);
    await a.run("run-1", [{ stream: S0, id: "x" }], {
      full: false,
      checkpoints: { [S0]: "c1" },
    });
    await a.cycle();
    const before = await a.position();
    armed = true;
    await a.run(
      "run-2",
      ids(60).map((id) => ({ stream: S0, id, pad: 200 })),
      { full: false, checkpoints: { [S0]: "c2" } },
    );
    await expect(a.cycle()).rejects.toThrow();
    // Round one landed; the device and its unpublished rows are lost here.
    const after = await segmentsAfter(w, before);
    expect(after).toHaveLength(1);
    expect(cursorOf(after[0]!, S0)).toBeUndefined();
    expect(foldedCursor(await segmentsAfter(w, 0), S0)).toEqual({
      state: "c1",
      connectorVersion: "1",
    });
  });

  it("a parent's cursor travels only in a round that also closes its child", async () => {
    const w = await world({
      streams: 2,
      partTargetBytes: 3000,
      stateParents: { [S1]: [S0] },
    });
    const a = await w.device("a");
    const before = await started(a, [S0, S1]);
    await a.run(
      "run-1",
      [
        { stream: S0, id: "p" },
        ...ids(60).map((id) => ({ stream: S1, id, pad: 200 })),
      ],
      { full: false, checkpoints: { [S0]: "p1", [S1]: "k1" } },
    );
    await a.cycle();
    const segments = await segmentsAfter(w, before);
    expect(segments.length).toBeGreaterThan(2);
    const parentAt = segments.findIndex((s) => cursorOf(s, S0) !== undefined);
    const lastChild = segments.findLastIndex(
      (s) => metaOf(s, S1) !== undefined,
    );
    expect(parentAt).toBeGreaterThanOrEqual(lastChild);
    expect(cursorOf(segments[lastChild]!, S1)).toEqual({
      state: "k1",
      connectorVersion: "1",
    });
    expect(foldedCursor(segments, S0)).toEqual({
      state: "p1",
      connectorVersion: "1",
    });
  });
});

describe("a parent's cursor waits for its children (state_parents)", () => {
  // S1 lists S0 in state_parents: a run reads S1's rows through S0's cursor,
  // so S0's cursor claims S1's rows too.
  const family = (partTargetBytes?: number) =>
    world({
      streams: 2,
      stateParents: { [S1]: [S0] },
      ...(partTargetBytes ? { partTargetBytes } : {}),
    });

  it("a round that takes all of the parent but not the child carries no parent cursor; the round that closes the child carries both", async () => {
    const w = await family(3000);
    const a = await w.device("a");
    const before = await started(a, [S0, S1]);
    // Each record fills most of a round: the first round takes the parent's
    // only record, the child's does not fit after it.
    await a.run(
      "run-1",
      [
        { stream: S0, id: "p", pad: 2000 },
        { stream: S1, id: "k", pad: 2000 },
      ],
      { full: false, checkpoints: { [S0]: "p1", [S1]: "k1" } },
    );
    await a.cycle();
    const segments = await segmentsAfter(w, before);
    expect(segments).toHaveLength(2);
    const [first, second] = segments as [WireSegment, WireSegment];
    expect(first.operations.map((o) => o.stream)).toEqual([S0]);
    expect(cursorOf(first, S0)).toBeUndefined();
    expect(cursorOf(first, S1)).toBeUndefined();
    expect(second.operations.map((o) => o.stream)).toEqual([S1]);
    expect(cursorOf(second, S0)).toEqual({
      state: "p1",
      connectorVersion: "1",
    });
    expect(cursorOf(second, S1)).toEqual({
      state: "k1",
      connectorVersion: "1",
    });
  });

  it("a child the publisher holds back holds back its parent's cursor, not the parent's rows", async () => {
    const w = await family();
    const a = await w.device("a");
    await a.run("run-0", [
      { stream: S0, id: "seed" },
      { stream: S1, id: 7 },
    ]);
    await a.cycle();
    const before = await a.position();
    await a.run(
      "run-1",
      [
        { stream: S0, id: "p" },
        { stream: S1, id: 7, remove: true },
      ],
      { full: false, checkpoints: { [S0]: "p1", [S1]: "k1" } },
    );
    // The child's delete cannot be written to the log (its typed key is not
    // known), so the publisher defers the child.
    await a.db.query(
      "UPDATE record_changes SET pk_values = NULL WHERE op = 'remove'",
    );
    await a.cycle();
    await a.cycle();
    const held = await segmentsAfter(w, before);
    expect(held.flatMap((g) => g.operations.map((o) => o.stream))).toEqual([
      S0,
    ]);
    expect(held.map((g) => cursorOf(g, S0))).toEqual(held.map(() => undefined));
    expect(held.map((g) => cursorOf(g, S1))).toEqual(held.map(() => undefined));

    // Once the child's delete can be written, both cursors follow it.
    await a.db.query(
      "UPDATE record_changes SET pk_values = '[7]' WHERE op = 'remove' AND pk_values IS NULL",
    );
    await a.cycle();
    const all = await segmentsAfter(w, before);
    expect(foldedCursor(all, S0)).toEqual({
      state: "p1",
      connectorVersion: "1",
    });
    expect(foldedCursor(all, S1)).toEqual({
      state: "k1",
      connectorVersion: "1",
    });
  });

  it("a run that does not cover the child never publishes the parent's cursor", async () => {
    const w = await family();
    const a = await w.device("a");
    const before = await started(a, [S0, S1]);
    await a.run("run-1", [{ stream: S0, id: "p" }], {
      full: false,
      covered: [S0],
      checkpoints: { [S0]: "p1", [S1]: "k1" },
    });
    await a.cycle();
    await a.cycle();
    const segments = await segmentsAfter(w, before);
    expect(segments.flatMap((g) => g.operations.map((o) => o.stream))).toEqual([
      S0,
    ]);
    expect(foldedCursor(segments, S0)).toBeUndefined();
    expect(foldedCursor(segments, S1)).toBeUndefined();
  });
});
