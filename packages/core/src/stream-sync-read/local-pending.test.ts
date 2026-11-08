/**
 * The owner reads runs of this device that no verified activation covers yet
 * (a first run made offline): a distinct, marked, owner-only decision with no
 * registry entry. Deletion stays authoritative; once activation is verified
 * the normal view takes over and the marker goes.
 */

import { describe, expect, it } from "vitest";
import type { Line } from "@opendatalabs/personal-server-ts-stream-sync";
import { ask, body, Fixture, masterKey } from "./service-fixture.js";
import type { FakeRun } from "./service-fixture.js";
import { testOwnerKey } from "./testing.js";

const T = Date.parse("2026-11-01T00:00:00Z");
const row = (id: string): Line => ({ o: T, r: "r1", v: { id } });
const run = (
  ns: string | null,
  generation: number | null,
  extra: { complete?: boolean } = {},
): FakeRun => ({
  runId: "r1",
  ns,
  generation,
  streams: [
    { name: "items", rows: [row("local")], complete: extra.complete ?? false },
  ],
});

async function setup(seed: number) {
  const f = new Fixture(await testOwnerKey(masterKey(seed)));
  const ns = await f.key.ns("acme", "account-1");
  return { f, ns };
}

async function read(f: Fixture, extra = {}) {
  const service = await f.service();
  await f.sync(service);
  const decision = await service.resolve(ask("pdpp.acme.items", extra));
  if (decision.kind !== "view" && decision.kind !== "local_pending") {
    return { kind: decision.kind } as const;
  }
  const envelope = await body(decision);
  return {
    kind: decision.kind,
    served: decision.kind === "view" ? decision.served : undefined,
    origin: envelope.origin as string | undefined,
    ids: envelope.data.records.map((r: any) => r.id),
  };
}

describe("local pending reads", () => {
  it("(a) shows the owner an unactivated run, marked as local and pending", async () => {
    const { f, ns } = await setup(101);
    f.overlay.runs = [run(ns, null)];
    expect(await read(f)).toEqual({
      kind: "local_pending",
      served: undefined,
      origin: "local-pending",
      ids: ["local"],
    });
    expect(f.overlay.open).toBe(0);
  });

  it("(a) also shows a run bound to a generation that has no control row yet", async () => {
    const { f, ns } = await setup(102);
    f.overlay.runs = [run(ns, 1, { complete: true })];
    expect((await read(f)).kind).toBe("local_pending");
  });

  it("(b) answers pass to a grantee or non-owner and never serves the rows", async () => {
    const { f, ns } = await setup(103);
    f.overlay.runs = [run(ns, null)];
    expect(await read(f, { isOwnerView: false })).toEqual({ kind: "pass" });
    expect(await read(f, { isOwnerView: false, legacyFile: true })).toEqual({
      kind: "pass",
    });
    expect(f.overlay.open).toBe(0);
  });

  it("(c) shows nothing on another device, which has its own home", async () => {
    const { f, ns } = await setup(104);
    f.overlay.runs = [run(ns, null)];
    expect((await read(f)).kind).toBe("local_pending");
    const other = new Fixture(f.key);
    expect(await read(other)).toEqual({ kind: "pass" });
  });

  it("(d) drops the marker once activation is verified for the run's generation", async () => {
    const { f, ns } = await setup(105);
    f.overlay.runs = [run(ns, 1, { complete: true })];
    expect((await read(f)).kind).toBe("local_pending");
    await f.activate("acme", ns);
    expect(await read(f)).toEqual({
      kind: "view",
      served: null,
      origin: undefined,
      ids: ["local"],
    });
  });

  it("does not displace an existing legacy body", async () => {
    const { f, ns } = await setup(106);
    f.overlay.runs = [run(ns, null)];
    expect(await read(f, { legacyFile: true })).toEqual({ kind: "pass" });
  });

  it("stays hidden by a deleted connection", async () => {
    const { f, ns } = await setup(107);
    await f.deleteConnection("acme", ns);
    f.overlay.runs = [run(ns, null)];
    expect((await read(f)).kind).toBe("unavailable");
  });

  it("stays hidden by a connection written with another key", async () => {
    const { f } = await setup(108);
    const foreign = await testOwnerKey(masterKey(99));
    const ns = await foreign.ns("acme", "account-1");
    await f.activate("acme", ns, foreign);
    f.overlay.runs = [run(ns, null)];
    expect((await read(f)).kind).not.toBe("local_pending");
  });

  it("excludes a run with no namespace", async () => {
    const { f } = await setup(109);
    f.overlay.runs = [run(null, null)];
    expect(await read(f)).toEqual({ kind: "pass" });
  });

  it("excludes a run of an older generation than the active one", async () => {
    const { f, ns } = await setup(110);
    await f.activate("acme", ns);
    await f.activate("acme", ns); // generation 2
    f.overlay.runs = [run(ns, 1, { complete: true })];
    expect((await read(f)).kind).not.toBe("local_pending");
  });
});
