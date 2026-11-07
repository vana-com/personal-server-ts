/**
 * Writer parity: the owner's read of a stream before its pending runs are
 * published equals the read after the real writer publishes them and the
 * reader imports the result: the same rows, the same completeness, the same
 * withheld runs. The writer here is the real `StreamSyncWriter`; the overlay
 * describes its pending runs the way an overlay source would.
 */

import { describe, expect, it } from "vitest";
import { ask } from "./service-fixture.js";
import { foldContributions } from "./fold.js";
import { liveStreamCounts } from "./service.js";
import { CONNECTOR, Rig, type RunSpec, type SeedRows } from "./writer-rig.js";

const base: RunSpec = {
  runId: "base",
  key: "id",
  version: "1.0.0",
  rows: [
    { id: "a", v: 1 },
    { id: "b", v: 1 },
  ],
  full: true,
};

const run = (spec: Partial<RunSpec> & { runId: string }): RunSpec => ({
  key: "id",
  version: "1.0.0",
  rows: [],
  full: false,
  ...spec,
});

interface Observed {
  /** Records the owner sees. */
  readonly rows: number;
  /** The records themselves; null when an incomplete head is not a view. */
  readonly records: string[] | null;
  readonly complete: boolean | undefined;
  readonly withheld: string[];
}

async function observe(rig: Rig): Promise<Observed> {
  const decision = await rig.service.resolve(ask("pdpp.acme.items"));
  let records: string[] | null = null;
  if (decision.kind === "view" || decision.kind === "local_pending") {
    const envelope = JSON.parse(await new Response(decision.body).text());
    records = envelope.data.records
      .map((r: unknown) => JSON.stringify(r))
      .sort();
  }
  const snapshot = await rig.overlay.snapshot(CONNECTOR);
  const complete = rig.service
    .connectionViews(CONNECTOR, snapshot)
    .find((c) => c.ns === rig.ns)?.streams["items"]?.complete;
  snapshot.release();
  const withheld =
    decision.kind === "view" || decision.kind === "local_pending"
      ? (decision.withheld ?? []).map((w) => w.runId).sort()
      : [];
  // An incomplete imported head is not served as a view (§2.10): count what
  // it holds instead, which is what the owner read before it was published.
  const imported = liveStreamCounts(rig.service.status()).find(
    (c) => c.stream === "items",
  )?.records;
  return {
    rows: records?.length ?? imported ?? 0,
    records,
    complete,
    withheld,
  };
}

async function compare(input: {
  base?: RunSpec;
  runs: RunSpec[];
  seed?: SeedRows;
}) {
  const rig = new Rig(input.seed);
  await rig.open();
  if (input.base) {
    await rig.collect(input.base);
    await rig.publish();
    await rig.sync();
  }
  for (const spec of input.runs) await rig.collect(spec);
  rig.overlay.runs = input.runs.map((spec) => rig.describe(spec));
  const before = await observe(rig);

  const statuses = await rig.publish();
  await rig.sync();
  const refused = statuses
    .filter((s) => s.streams["items"]?.problem === "connector_update_required")
    .map((s) => s.runId)
    .sort();
  rig.overlay.runs = input.runs
    .filter((spec) => refused.includes(spec.runId))
    .map((spec) => rig.describe(spec));
  const after = await observe(rig);
  return { before, after, refused };
}

describe("the overlay read equals the read after the real writer publishes", () => {
  it.each<
    [string, number, { base: RunSpec; runs: RunSpec[]; seed?: SeedRows }]
  >([
    [
      "the same key",
      3,
      { base, runs: [run({ runId: "r1", rows: [{ id: "c", v: 1 }] })] },
    ],
    [
      "a newer connector with a changed key, full run",
      1,
      {
        base,
        runs: [
          run({
            runId: "r1",
            key: "uid",
            version: "2.0.0",
            full: true,
            rows: [{ uid: "u1" }],
          }),
        ],
      },
    ],
    [
      "a newer connector with a changed key, partial run",
      1,
      {
        base,
        runs: [
          run({
            runId: "r1",
            key: "uid",
            version: "2.0.0",
            rows: [{ uid: "u1" }],
          }),
        ],
      },
    ],
    [
      "an older connector with a changed key",
      2,
      {
        base: { ...base, version: "2.0.0" },
        runs: [
          run({
            runId: "r1",
            key: "uid",
            version: "1.0.0",
            full: true,
            rows: [{ uid: "u1" }],
          }),
        ],
      },
    ],
    [
      "a key change and back",
      1,
      {
        base,
        runs: [
          run({
            runId: "r1",
            key: "uid",
            version: "2.0.0",
            full: true,
            rows: [{ uid: "u1" }],
          }),
          run({
            runId: "r2",
            key: "id",
            version: "3.0.0",
            full: true,
            rows: [{ id: "c", v: 1 }],
          }),
        ],
      },
    ],
    [
      "an older no-op run, then an older changed key",
      2,
      {
        base: { ...base, version: "2.0.0" },
        runs: [
          run({ runId: "r1", version: "1.0.0" }),
          run({
            runId: "r2",
            key: "uid",
            version: "1.5.0",
            full: true,
            rows: [{ uid: "u1" }],
          }),
        ],
      },
    ],
    [
      "a newer no-op run, then a newer changed key",
      1,
      {
        base: { ...base, version: "2.0.0" },
        runs: [
          run({ runId: "r1", version: "3.0.0" }),
          run({
            runId: "r2",
            key: "uid",
            version: "2.5.0",
            full: true,
            rows: [{ uid: "u1" }],
          }),
        ],
      },
    ],
    [
      "a checkpoint from another namespace",
      3,
      {
        base,
        runs: [
          run({
            runId: "r1",
            otherNamespace: true,
            rows: [{ id: "c", v: 1 }],
          }),
        ],
      },
    ],
  ])("%s", async (_name, heads, input) => {
    const { before, after, refused } = await compare(input);
    expect(before.records).not.toBeNull();
    expect(before.complete).toBe(after.complete);
    expect(after.rows).toBe(heads);
    if (before.complete) {
      expect(before.rows).toBe(heads);
      expect(before.records).toEqual(after.records);
    } else {
      // An incomplete head is not a view: the owner reads this device's own
      // rows, which the published head holds.
      expect(before.rows).toBeLessThanOrEqual(heads);
    }
    expect(before.withheld).toEqual(refused);
    expect(after.withheld).toEqual(refused);
  });
});

describe("a seeded first publish", () => {
  it("is complete before and after, whatever the run read", async () => {
    // The seed (a host's retained history) merges into the first publish, so
    // the head is complete although the run resumed from a checkpoint. An
    // overlay source reports that as `complete`. The seed's rows are read by
    // the writer at publish time, so only the run's own rows are in the
    // overlay before it.
    const rig = new Rig({
      key: "id",
      version: "1.0.0",
      rows: [{ id: "seed" }],
    });
    await rig.open();
    const spec = run({
      runId: "r1",
      rows: [{ id: "c", v: 1 }],
      complete: true,
    });
    await rig.collect(spec);
    rig.overlay.runs = [rig.describe(spec)];
    const snapshot = await rig.overlay.snapshot(CONNECTOR);
    const pending = snapshot.runs[0]!;
    const folded = foldContributions(null, [
      { run: pending, stream: pending.streams[0]! },
    ]);
    snapshot.release();

    await rig.publish();
    await rig.sync();
    rig.overlay.runs = [];
    const head = rig.service
      .connectionViews(CONNECTOR)
      .find((c) => c.ns === rig.ns)?.streams["items"];
    expect(head?.live).toBe(true);
    expect(folded.complete).toBe(true);
    expect(head?.complete).toBe(folded.complete);
    const read = await observe(rig);
    expect(read.records).toContain(JSON.stringify({ id: "c", v: 1 }));
    expect(read.records).toContain(JSON.stringify({ id: "seed" }));
  });
});

describe("where the overlay cannot tell, it withholds more than the writer", () => {
  it("an older same-key run with a row may be skipped by the writer, so the profile stays high", async () => {
    // The writer publishes r1 (its row is new), so the head's profile drops
    // to 1.0.0 and it then publishes r2 (1.5.0 is newer). The overlay cannot
    // see that r1's row wins, so it keeps 2.0.0 and withholds r2. It never
    // does the reverse: it never shows a run the writer refuses.
    const { before, refused } = await compare({
      base: { ...base, version: "2.0.0" },
      runs: [
        run({ runId: "r1", version: "1.0.0", rows: [{ id: "c", v: 1 }] }),
        run({
          runId: "r2",
          key: "uid",
          version: "1.5.0",
          full: true,
          rows: [{ uid: "u1" }],
        }),
      ],
    });
    expect(refused).toEqual([]);
    expect(before.withheld).toEqual(["r2"]);
  });
});
