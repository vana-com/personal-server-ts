/**
 * A stream-only owner reads rows from the last complete head, but the writer
 * plans an unpublished run from the registry head. The read takes completeness
 * and any refusal from that registry head, as the writer does.
 */

import { describe, expect, it } from "vitest";
import type { Line } from "@opendatalabs/personal-server-ts-stream-sync";
import { ask, body, Fixture, masterKey } from "./service-fixture.js";
import { testOwnerKey } from "./testing.js";

const T = Date.parse("2026-11-01T00:00:00Z");
const line = (id: string): Line => ({ o: T, r: "r1", v: { id } });

/** v1 complete (key id, row a); v2 incomplete (key `v2Key`) naming v1; a non-full local run R. */
async function setup(
  seed: number,
  v2Key: string,
  v2: { profileVersion?: string; generation?: number } = {},
  runGeneration = 1,
) {
  const f = new Fixture(await testOwnerKey(masterKey(seed)));
  const ns = await f.key.ns("acme", "account-1");
  await f.activate("acme", ns);
  const v1 = await f.publish({
    connector: "acme",
    ns,
    stream: "items",
    generation: 1,
    complete: true,
    records: [{ id: "a" }],
  });
  await f.publish({
    connector: "acme",
    ns,
    stream: "items",
    generation: v2.generation ?? 1,
    complete: false,
    primaryKey: [v2Key],
    ...(v2.profileVersion ? { profileVersion: v2.profileVersion } : {}),
    records: [{ [v2Key]: "p" }],
    lastComplete: { version: 1, dataHash: v1.dataHash },
  });
  f.overlay.runs = [
    {
      runId: "r1",
      ns,
      generation: runGeneration,
      full: false,
      streams: [{ name: "items", rows: [line("R")], complete: false }],
    },
  ];
  const service = await f.service();
  await f.sync(service);
  const snapshot = await f.overlay.snapshot("acme");
  const stream = service
    .connectionViews("acme", snapshot, true)
    .find((c) => c.ns === ns)?.streams["items"];
  snapshot.release();
  const decision = await service.resolve(
    ask("pdpp.acme.items", { streamOnly: true }),
  );
  const records =
    decision.kind === "view" || decision.kind === "local_pending"
      ? (await body(decision)).data.records.map((r: any) => r.id).sort()
      : decision.kind;
  const withheld =
    decision.kind === "view" || decision.kind === "local_pending"
      ? (decision.withheld ?? []).map((w) => `${w.runId}:${w.reason}`)
      : [];
  return { stream, records, withheld };
}

describe("stream-only owner plans a local run from the registry head", () => {
  it("is incomplete while the registry head is incomplete, though the rows come from the complete base", async () => {
    const { stream, records } = await setup(110, "id");
    expect(stream?.complete).toBe(false);
    expect(records).toEqual(["R", "a"]);
  });

  it("does not show a run the writer refuses over the registry head", async () => {
    const { records, withheld } = await setup(111, "uid");
    expect(records).toEqual(["a"]);
    expect(withheld).toEqual(["r1:connector_update_required"]);
  });

  it("does not show a run below the registry head's connector version", async () => {
    const { records, withheld } = await setup(112, "id", {
      profileVersion: "2.0.0",
    });
    expect(records).toEqual(["a"]);
    expect(withheld).toEqual(["r1:connector_update_required"]);
  });

  it("does not show a run of an older generation than the registry head", async () => {
    // The control row is at generation 2 (two activations), and so are both
    // heads. A run recorded under generation 1 is discarded by admission, not
    // planned over the generation 2 head; stale generations are never planned.
    const f = new Fixture(await testOwnerKey(masterKey(113)));
    const ns = await f.key.ns("acme", "account-1");
    await f.activate("acme", ns);
    await f.activate("acme", ns);
    const v1 = await f.publish({
      connector: "acme",
      ns,
      stream: "items",
      generation: 2,
      complete: true,
      records: [{ id: "a" }],
    });
    await f.publish({
      connector: "acme",
      ns,
      stream: "items",
      generation: 2,
      complete: false,
      records: [{ id: "p" }],
      lastComplete: { version: 1, dataHash: v1.dataHash },
    });
    f.overlay.runs = [
      {
        runId: "r1",
        ns,
        generation: 1,
        full: false,
        streams: [{ name: "items", rows: [line("R")], complete: false }],
      },
    ];
    const service = await f.service();
    await f.sync(service);
    const decision = await service.resolve(
      ask("pdpp.acme.items", { streamOnly: true }),
    );
    expect(decision.kind).toBe("view");
    expect((await body(decision)).data.records.map((r: any) => r.id)).toEqual([
      "a",
    ]);
  });

  it("with no local run, completeness comes from the rows head, as a grant reads it", async () => {
    const f = new Fixture(await testOwnerKey(masterKey(114)));
    const ns = await f.key.ns("acme", "account-1");
    await f.activate("acme", ns);
    const v1 = await f.publish({
      connector: "acme",
      ns,
      stream: "items",
      generation: 1,
      complete: true,
      records: [{ id: "a" }],
    });
    await f.publish({
      connector: "acme",
      ns,
      stream: "items",
      generation: 1,
      complete: false,
      records: [{ id: "p" }],
      lastComplete: { version: 1, dataHash: v1.dataHash },
    });
    const service = await f.service();
    await f.sync(service);
    const stream = () =>
      service.connectionViews("acme", undefined, true).find((c) => c.ns === ns)
        ?.streams["items"];
    expect(stream()?.complete).toBe(true);
    const decision = await service.resolve(
      ask("pdpp.acme.items", { streamOnly: true }),
    );
    expect(decision.kind).toBe("view");
  });

  it("withholds every local run while the registry head is observed but not imported", async () => {
    const f = new Fixture(await testOwnerKey(masterKey(115)));
    const ns = await f.key.ns("acme", "account-1");
    await f.activate("acme", ns);
    const v1 = await f.publish({
      connector: "acme",
      ns,
      stream: "items",
      generation: 1,
      complete: true,
      records: [{ id: "a" }],
    });
    const service = await f.service();
    await f.sync(service);
    await f.publish({
      connector: "acme",
      ns,
      stream: "items",
      generation: 1,
      complete: false,
      primaryKey: ["uid"],
      records: [{ uid: "p" }],
      lastComplete: { version: 1, dataHash: v1.dataHash },
    });
    // v2 is observed and not imported: no importPending.
    await service.observe([...f.rows.values()], {
      fromStart: true,
      lastPage: true,
    });
    f.overlay.runs = [
      {
        runId: "r1",
        ns,
        generation: 1,
        full: true,
        streams: [{ name: "items", rows: [line("R")], complete: true }],
      },
    ];
    const snapshot = await f.overlay.snapshot("acme");
    const view = service
      .connectionViews("acme", snapshot, true)
      .find((c) => c.ns === ns)?.streams["items"];
    snapshot.release();
    expect(view?.complete).toBe(false);
    const decision = await service.resolve(
      ask("pdpp.acme.items", { streamOnly: true }),
    );
    expect(
      decision.kind === "view" || decision.kind === "local_pending"
        ? (await body(decision)).data.records.map((r: any) => r.id)
        : decision.kind,
    ).toEqual(["a"]);
    expect(
      decision.kind === "view" || decision.kind === "local_pending"
        ? (decision.withheld ?? []).map((w) => `${w.runId}:${w.reason}`)
        : [],
    ).toEqual(["r1:registry_head_unimported"]);
  });

  describe("after a re-activation, an older-generation head is not a newer registry head", () => {
    async function reactivated(seed: number, importBefore: boolean) {
      const f = new Fixture(await testOwnerKey(masterKey(seed)));
      const ns = await f.key.ns("acme", "account-1");
      await f.activate("acme", ns);
      await f.publish({
        connector: "acme",
        ns,
        stream: "items",
        generation: 1,
        complete: true,
        records: [{ id: "old" }],
      });
      const service = await f.service();
      if (importBefore) await f.sync(service);
      await f.activate("acme", ns);
      await service.observe([...f.rows.values()], {
        fromStart: true,
        lastPage: true,
      });
      await service.importPending();
      f.overlay.runs = [
        {
          runId: "r2",
          ns,
          generation: 2,
          full: true,
          streams: [{ name: "items", rows: [line("R")], complete: true }],
        },
      ];
      const decision = await service.resolve(
        ask("pdpp.acme.items", { streamOnly: true }),
      );
      return decision.kind === "view" || decision.kind === "local_pending"
        ? {
            ids: (await body(decision)).data.records.map((r: any) => r.id),
            withheld: (decision.withheld ?? []).map((w) => w.reason),
          }
        : { ids: decision.kind, withheld: [] };
    }

    it.each([
      ["imported before the re-activation", true],
      ["never imported on this device", false],
    ])("shows the owner's own run (%s)", async (_label, importBefore) => {
      const out = await reactivated(importBefore ? 116 : 117, importBefore);
      expect(out.withheld).not.toContain("registry_head_unimported");
      expect(out.ids).toContain("R");
    });
  });
});
