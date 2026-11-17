// A replacing run (a full run, or a replace) publishes its rows and its
// completion. The rows can be more than one segment holds, so they go out in
// rounds like any other changes, and the completion (with the keys the run
// dropped) goes in the last round. Until that round no segment says the
// stream is complete, so a reader never takes a half-published replace for a
// complete stream.
import { afterEach, describe, expect, it } from "vitest";
import { closeWorldDrivers, sName, world } from "./log-world.test-utils.js";

afterEach(closeWorldDrivers);

const s = sName(0);
const MiB = 1024 * 1024;
// 40,000 records of 600 bytes: about 24 MiB, over the 16 MiB segment limit.
const COUNT = 40_000;
const PAD = 600;

/** What every segment said about the stream, oldest first. */
async function streamHistory(w: Awaited<ReturnType<typeof world>>) {
  const segments = await w.segments();
  return [...segments.keys()]
    .sort((x, y) => x - y)
    .map((position) => {
      const segment = segments.get(position)!;
      return {
        position,
        complete: segment.streams.find((m) => m.stream === s)?.complete,
        completions: segment.operations.filter(
          (op) => op.kind === "complete" && op.stream === s,
        ).length,
        upserts: segment.operations.filter(
          (op) =>
            (op.kind === "upsert" || op.kind === "upsert-ref") &&
            op.stream === s,
        ).length,
      };
    });
}

describe("log publish of a replacing run larger than one segment", () => {
  it("publishes a 24 MiB full run of small records in rounds, and a twin device reads every record", async () => {
    const w = await world({ streams: 1 });
    const a = await w.device("a");
    await a.run(
      "r1",
      Array.from({ length: COUNT }, (_, i) => ({
        stream: s,
        id: i,
        pad: PAD,
      })),
    );
    await a.cycle();

    const b = await w.device("b");
    await b.cycle();
    const theirs = await b.records();
    expect(theirs).toHaveLength(COUNT);
    expect(theirs).toEqual(await a.records());

    const history = (await streamHistory(w)).filter(
      (h) => h.complete !== undefined,
    );
    // More than one segment carried the rows, and each is under the limit.
    expect(history.length).toBeGreaterThan(1);
    expect(history.reduce((n, h) => n + h.upserts, 0)).toBe(COUNT);
    expect(await b.rows()).toEqual(await a.rows());
  }, 600_000);

  it("a full run that drops records says complete only in its last round, with every dropped key", async () => {
    const w = await world({ streams: 1 });
    const a = await w.device("a");
    await a.run("r1", [
      { stream: s, id: "gone-1" },
      { stream: s, id: "gone-2" },
      { stream: s, id: "kept" },
    ]);
    await a.cycle();
    const before = (await w.segments()).size;

    // The next full pass sees "kept" again and 40,000 new records, so it
    // drops the two "gone" records.
    await a.run(
      "r2",
      [
        { stream: s, id: "kept" },
        ...Array.from({ length: COUNT }, (_, i) => ({
          stream: s,
          id: i,
          pad: PAD,
        })),
      ],
      { observedAt: 5000 },
    );
    await a.cycle();

    const rounds = (await streamHistory(w))
      .slice(before)
      .filter((h) => h.complete !== undefined);
    expect(rounds.length).toBeGreaterThan(1);
    // Only the last round completes the stream, and it is the one that
    // names the dropped keys.
    expect(rounds.map((r) => r.complete)).toEqual([
      ...rounds.slice(0, -1).map(() => false),
      true,
    ]);
    expect(rounds.map((r) => r.completions)).toEqual([
      ...rounds.slice(0, -1).map(() => 0),
      1,
    ]);
    const segments = await w.segments();
    const last = segments.get(Math.max(...segments.keys()))!;
    const completion = last.operations.find((op) => op.kind === "complete");
    if (completion?.kind !== "complete") throw new Error("no completion");
    expect(completion.omitted).toHaveLength(2);

    const b = await w.device("b");
    await b.cycle();
    const theirs = await b.records();
    expect(theirs).toHaveLength(COUNT + 1);
    expect(theirs.some((r) => r.startsWith(`${s}/gone-`))).toBe(false);
    expect(theirs).toEqual(await a.records());
    expect(await b.rows()).toEqual(await a.rows());
    expect(theirs.join("").length).toBeGreaterThan(16 * MiB);
  }, 600_000);
});
