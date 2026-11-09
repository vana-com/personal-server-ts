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
async function setup(seed: number, v2Key: string) {
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
    generation: 1,
    complete: false,
    primaryKey: [v2Key],
    records: [{ [v2Key]: "p" }],
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
});
