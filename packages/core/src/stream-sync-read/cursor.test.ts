/**
 * A cursor records the exact composition it served: the imported version (or
 * its absence) and the overlay members (run, content revision). It replays
 * exactly that or answers cursor_stale; new runs never join it.
 */

import { describe, expect, it } from "vitest";
import type { Line } from "@opendatalabs/personal-server-ts-stream-sync";
import type { FakeRun } from "./service-fixture.js";
import { ask, body, Fixture, masterKey } from "./service-fixture.js";
import { testOwnerKey } from "./testing.js";

const T = Date.parse("2026-11-01T00:00:00Z");
const line = (id: string, v: number, r: string): Line => ({
  o: T,
  r,
  v: { id, v },
});
const fakeRun = (
  ns: string,
  runId: string,
  rows: Line[],
  contentRevision = "c1",
): FakeRun => ({
  runId,
  ns,
  generation: 1,
  streams: [{ name: "items", rows, complete: true, contentRevision }],
});

async function setup(seed: number, imported: boolean) {
  const f = new Fixture(await testOwnerKey(masterKey(seed)));
  const ns = await f.key.ns("acme", "account-1");
  await f.activate("acme", ns);
  if (imported) {
    await f.publish({
      connector: "acme",
      ns,
      stream: "items",
      generation: 1,
      records: [{ id: "a", v: 1 }],
      observedAt: T - 1000,
    });
  }
  const service = await f.service();
  await f.sync(service);
  return { f, ns, service };
}

async function first(service: Awaited<ReturnType<typeof setup>>["service"]) {
  const decision = await service.resolve(ask("pdpp.acme.items"));
  if (decision.kind !== "view") throw new Error(decision.kind);
  const cursor = decision.cursor;
  await body(decision);
  return cursor;
}

const ids = async (
  service: Awaited<ReturnType<typeof setup>>["service"],
  cursor: string,
) => {
  const decision = await service.resolve(ask("pdpp.acme.items", { cursor }));
  if (decision.kind !== "view") return decision.kind;
  return (await body(decision)).data.records.map((r: any) => r.id).sort();
};

describe("cursor over the overlay", () => {
  it("replays exactly its members; a new run does not join", async () => {
    const { f, ns, service } = await setup(81, true);
    f.overlay.runs = [fakeRun(ns, "r1", [line("one", 1, "r1")])];
    const cursor = await first(service);
    f.overlay.runs = [
      ...f.overlay.runs,
      fakeRun(ns, "r2", [line("two", 1, "r2")]),
    ];
    expect(await ids(service, cursor)).toEqual(["a", "one"]);
    // A latest read still sees both.
    const latest = await service.resolve(ask("pdpp.acme.items"));
    expect(
      (await body(latest)).data.records.map((r: any) => r.id).sort(),
    ).toEqual(["a", "one", "two"]);
  });

  it("is stale once a member is retired", async () => {
    const { f, ns, service } = await setup(82, true);
    f.overlay.runs = [fakeRun(ns, "r1", [line("one", 1, "r1")])];
    const cursor = await first(service);
    f.overlay.runs = [];
    expect(await ids(service, cursor)).toBe("cursor_stale");
    expect(f.overlay.open).toBe(0);
  });

  it("is stale when a member's content revision changed", async () => {
    const { f, ns, service } = await setup(83, true);
    f.overlay.runs = [fakeRun(ns, "r1", [line("one", 1, "r1")])];
    const cursor = await first(service);
    f.overlay.runs = [fakeRun(ns, "r1", [line("one", 2, "r1")], "c2")];
    expect(await ids(service, cursor)).toBe("cursor_stale");
  });

  it("replays an overlay-only view and goes stale once a head is imported", async () => {
    const { f, ns, service } = await setup(84, false);
    f.overlay.runs = [fakeRun(ns, "r1", [line("one", 1, "r1")])];
    const cursor = await first(service);
    expect(
      JSON.parse(atob(cursor.replace(/-/g, "+").replace(/_/g, "/"))),
    ).toMatchObject({
      s: { items: { b: null } },
    });
    expect(await ids(service, cursor)).toEqual(["one"]);
    await f.publish({
      connector: "acme",
      ns,
      stream: "items",
      generation: 1,
      records: [{ id: "one", v: 1 }],
      observedAt: T,
    });
    await f.sync(service);
    expect(await ids(service, cursor)).toBe("cursor_stale");
  });

  it("still decodes a cursor that names registry versions only", async () => {
    const { f, ns, service } = await setup(85, true);
    f.overlay.runs = [fakeRun(ns, "r1", [line("one", 1, "r1")])];
    const legacy = btoa(JSON.stringify({ c: "acme", ns, v: { items: 1 } }));
    // It pinned the imported version alone: no overlay member joins it.
    expect(await ids(service, legacy)).toEqual(["a"]);
  });
});
