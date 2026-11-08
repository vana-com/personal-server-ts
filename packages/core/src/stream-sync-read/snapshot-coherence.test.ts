/**
 * A read pins one imported base with one writer plan. An import that lands
 * between the writer's snapshot and the base lease would plan a run the
 * snapshot holds over a head the snapshot does not know, so the owner would
 * read a row the live writer refuses.
 */

import { describe, expect, it } from "vitest";
import type { SignedRegistryPost } from "../stream-sync/index.js";
import { Rig, type RunSpec } from "./writer-rig.js";

const run = (spec: Partial<RunSpec> & { runId: string }): RunSpec => ({
  key: "id",
  version: "1.0.0",
  rows: [],
  full: false,
  ...spec,
});

const SCOPE = "pdpp.acme.items";

async function read(rig: Rig) {
  const decision = await rig.service.resolve({
    scope: SCOPE,
    connection: null,
    cursor: null,
    legacyFile: false,
    isOwnerView: true,
  });
  if (decision.kind !== "view" && decision.kind !== "local_pending") {
    return {
      kind: decision.kind,
      ids: [] as string[],
      withheld: [] as string[],
    };
  }
  const envelope = JSON.parse(await new Response(decision.body).text()) as {
    data: { records: { id: string }[] };
  };
  return {
    kind: decision.kind,
    ids: envelope.data.records.map((r) => r.id).sort(),
    withheld: (decision.withheld ?? []).map((w) => `${w.runId}:${w.reason}`),
  };
}

describe("a read pins one base and one plan", () => {
  it("does not merge an older run over a head the writer's snapshot predates", async () => {
    const rig = new Rig();
    await rig.open();
    await rig.collect(
      run({ runId: "base", full: true, rows: [{ id: "a" }, { id: "b" }] }),
    );
    await rig.publish();
    await rig.sync();

    // C (newer) starts to publish; its POST waits at the registry.
    await rig.collect(run({ runId: "rC", at: 20_000, rows: [{ id: "c" }] }));
    let release!: () => void;
    let reached!: () => void;
    const held = new Promise<void>((resolve) => (release = resolve));
    const arrived = new Promise<void>((resolve) => (reached = resolve));
    rig.gateway.beforePost = async (_request: SignedRegistryPost) => {
      rig.gateway.beforePost = undefined;
      reached();
      await held;
    };
    const publishing = rig.publish();
    await arrived;
    // B (older) finishes while C is in flight.
    await rig.collect(run({ runId: "rB", at: 10_000, rows: [{ id: "b2" }] }));

    // The owner's snapshot is taken now; before the read leases its base,
    // C commits and the reader imports it.
    rig.afterSnapshot = async () => {
      release();
      await publishing;
      await rig.sync();
    };
    const owner = await read(rig);
    expect(owner.ids).toEqual(["a", "b", "c"]);
    expect(owner.withheld).toEqual(["rB:out_of_order"]);

    // The live writer agrees: B never commits.
    const statuses = await rig.publish();
    expect(
      statuses.find((s) => s.runId === "rB")?.streams["items"]?.problem,
    ).toBe("out_of_order");
    expect((await rig.registeredHead())?.recordCount).toBe(3);
  });
});
