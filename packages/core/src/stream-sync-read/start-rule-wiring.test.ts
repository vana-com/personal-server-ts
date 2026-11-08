/**
 * The reader's wiring of the start-to-current rule, with the rule's inputs
 * set directly on the overlay run. These pin what the reader does with the
 * run's recorded `userConnect`, and with the non-pending guard, so that a
 * change to either fails here and not only in decide's table.
 */

import { describe, expect, it } from "vitest";
import type { Line } from "@opendatalabs/personal-server-ts-stream-sync";
import type { FakeRun } from "./service-fixture.js";
import { ask, body, Fixture, masterKey } from "./service-fixture.js";
import { testOwnerKey } from "./testing.js";
import type { StreamSyncReadService } from "./service.js";

const T = Date.parse("2026-11-01T00:00:00Z");
const row = (id: string, v: number): Line => ({
  o: T,
  r: "r1",
  v: { id, v },
});

type Start = FakeRun["start"];

const run = (
  ns: string,
  start: Start,
  generation: number,
  flags: { userConnect: boolean; full: boolean },
): FakeRun => ({
  runId: "r1",
  ns,
  generation,
  start,
  userConnect: flags.userConnect,
  full: flags.full,
  streams: [{ name: "items", rows: [row("b", 2)], complete: true }],
});

async function setup(seed: number, activate: boolean) {
  const f = new Fixture(await testOwnerKey(masterKey(seed)));
  const ns = await f.key.ns("acme", "account-1");
  if (activate) await f.activate("acme", ns);
  return { f, ns };
}

/** What the owner's read serves: the decision kind and the record ids. */
async function served(service: StreamSyncReadService) {
  const decision = await service.resolve(ask("pdpp.acme.items"));
  if (decision.kind !== "view" && decision.kind !== "local_pending") {
    return { kind: decision.kind, ids: [] as string[] };
  }
  const envelope = await body(decision);
  return {
    kind: decision.kind,
    ids: envelope.data.records.map((r: { id: string }) => r.id),
  };
}

describe("reader wiring of the start rule", () => {
  it("does not show a deleted-start run that was not a connect", async () => {
    const { f, ns } = await setup(61, true);
    const version = await f.deleteConnection("acme", ns);
    // A scheduled run after the delete: userConnect false, full. The writer
    // discards it, so the owner must not see its rows.
    f.overlay.runs = [
      run(ns, { kind: "deleted", version }, version + 1, {
        userConnect: false,
        full: true,
      }),
    ];
    const service = await f.service();
    await f.sync(service);
    expect((await served(service)).ids).not.toContain("b");
  });

  // A published view is served only for an active connection (eligible), so
  // a pending run under a non-active control is never published. The imported
  // row `a` is the precondition that a view is served at all. This pins the
  // served output; it does not kill the non-pending guard in service.ts.
  it("does not serve a pending full connect in the published view while the connection is deleted", async () => {
    const { f, ns } = await setup(62, true);
    await f.publish({
      connector: "acme",
      ns,
      stream: "items",
      generation: 1,
      records: [{ id: "a", v: 1 }],
      observedAt: T - 1000,
    });
    const version = await f.deleteConnection("acme", ns);
    f.overlay.runs = [
      run(ns, { kind: "deleted", version }, version + 1, {
        userConnect: true,
        full: true,
      }),
    ];
    const service = await f.service();
    await f.sync(service);
    // Under a non-active control the owner sees the run as pending, never as
    // a published view.
    expect((await served(service)).kind).not.toBe("view");
  });

  it("does not serve a pending absent-start run in the published view while the connection is absent", async () => {
    const { f, ns } = await setup(63, false);
    await f.publish({
      connector: "acme",
      ns,
      stream: "items",
      generation: 1,
      records: [{ id: "a", v: 1 }],
      observedAt: T - 1000,
    });
    f.overlay.runs = [
      run(ns, { kind: "absent" }, 1, { userConnect: true, full: true }),
    ];
    const service = await f.service();
    await f.sync(service);
    // Under a non-active control the owner sees the run as pending, never as
    // a published view.
    expect((await served(service)).kind).not.toBe("view");
  });
});
