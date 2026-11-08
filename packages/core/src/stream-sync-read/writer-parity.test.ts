/**
 * Writer parity: the owner's read of a stream before its pending runs are
 * published, against the read after the real writer publishes them and the
 * reader imports the result. The writer here is the real `StreamSyncWriter`;
 * the reader reads the writer's own publish plan through its overlay source.
 *
 * Where the read shows every run, it equals the published read: the same rows,
 * the same completeness. Where it withholds a run the writer will publish (a
 * key reset over the base, or a step whose seed is not resolved), the owner
 * keeps the base, marked incomplete. A run the writer refuses is withheld
 * before and after, with the same reason.
 */

import { describe, expect, it } from "vitest";
import { ask } from "./service-fixture.js";
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
  /** `runId:reason`, sorted. */
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
      ? (decision.withheld ?? []).map((w) => `${w.runId}:${w.reason}`).sort()
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
  const before = await observe(rig);

  const statuses = await rig.publish();
  await rig.sync();
  const refused = statuses
    .flatMap((s) => {
      const problem = s.streams["items"]?.problem;
      return problem === "connector_update_required" ||
        problem === "out_of_order"
        ? [`${s.runId}:${problem}`]
        : [];
    })
    .sort();
  const after = await observe(rig);
  return { before, after, refused };
}

describe("the overlay read equals the read after the real writer publishes", () => {
  it.each<
    [
      string,
      number,
      string[],
      { base: RunSpec; runs: RunSpec[]; seed?: SeedRows },
    ]
  >([
    [
      "the same key",
      3,
      [],
      { base, runs: [run({ runId: "r1", rows: [{ id: "c", v: 1 }] })] },
    ],
    [
      "a newer connector with a changed key, full run",
      1,
      ["r1:key_reset_pending"],
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
      ["r1:key_reset_pending"],
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
      ["r1:connector_update_required"],
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
      ["r1:key_reset_pending", "r2:earlier_run_pending"],
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
      ["r2:connector_update_required"],
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
      "a newer no-op run raises the floor above a later changed key",
      2,
      ["r2:connector_update_required"],
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
      [],
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
    [
      "an older run with a row does not lower the floor",
      3,
      ["r2:connector_update_required"],
      {
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
      },
    ],
  ])("%s", async (_name, heads, withheldBefore, input) => {
    const { before, after, refused } = await compare(input);
    expect(before.records).not.toBeNull();
    expect(after.rows).toBe(heads);
    expect(before.withheld).toEqual(withheldBefore);
    expect(after.withheld).toEqual(refused);
    // Every run the writer refuses, the read withheld with the same reason.
    expect(before.withheld).toEqual(expect.arrayContaining(refused));
    if (before.withheld.every((w) => refused.includes(w))) {
      expect(before.complete).toBe(after.complete);
      expect(before.records).toEqual(after.records);
    } else {
      // A run the writer publishes is withheld: the owner keeps the base.
      expect(before.complete).toBe(false);
      expect(before.rows).toBe(input.base.rows.length);
    }
  });
});

describe("a seeded first publish", () => {
  it("is withheld before admission resolves the seed, complete after", async () => {
    // The seed (a host's retained history) merges into the first publish, so
    // the head is complete although the run resumed from a checkpoint. Before
    // admission the plan cannot tell whether a seed merges, so it defers the
    // run; the read withholds it.
    const rig = new Rig({
      key: "id",
      version: "1.0.0",
      rows: [{ id: "seed" }],
    });
    await rig.open();
    await rig.collect(run({ runId: "r1", rows: [{ id: "c", v: 1 }] }));
    const snapshot = await rig.overlay.snapshot(CONNECTOR);
    const steps = snapshot.plan(rig.ns, "items", null, ["r1"]);
    snapshot.release();
    expect(steps.map((s) => s.decision)).toEqual([
      { kind: "deferred", reason: "seed_unresolved" },
    ]);

    await rig.publish();
    await rig.sync();
    const head = rig.service
      .connectionViews(CONNECTOR)
      .find((c) => c.ns === rig.ns)?.streams["items"];
    expect(head?.live).toBe(true);
    expect(head?.complete).toBe(true);
    const read = await observe(rig);
    expect(read.records).toContain(JSON.stringify({ id: "c", v: 1 }));
    expect(read.records).toContain(JSON.stringify({ id: "seed" }));
  });
});
