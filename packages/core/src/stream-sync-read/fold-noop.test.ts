/**
 * The fold advances the effective key and profile only on a step where the
 * writer publishes a new head. The writer skips a run whose parts and
 * completeness equal the base's (isNoop), so its head keeps the profile it
 * had; a run that adds no row and changes no completeness must not move the
 * profile the next run is judged against.
 */

import { describe, expect, it } from "vitest";
import type { Line } from "@opendatalabs/personal-server-ts-stream-sync";
import type { FakeRun } from "./service-fixture.js";
import { ask, body, Fixture, masterKey } from "./service-fixture.js";
import { testOwnerKey } from "./testing.js";

const T = Date.parse("2026-11-01T00:00:00Z");

interface Spec {
  runId: string;
  observedAt: number;
  key: string;
  version: string;
  complete: boolean;
  rows: Record<string, unknown>[];
}

const fakeRun = (ns: string, s: Spec): FakeRun => ({
  runId: s.runId,
  ns,
  generation: 1,
  observedAt: s.observedAt,
  streams: [
    {
      name: "items",
      complete: s.complete,
      primaryKey: [s.key],
      version: s.version,
      rows: s.rows.map((v): Line => ({
        o: s.observedAt,
        r: s.runId,
        v: v as never,
      })),
    },
  ],
});

async function read(
  seed: number,
  base: { version: string; complete: boolean },
  specs: (ns: string) => Spec[],
) {
  const f = new Fixture(await testOwnerKey(masterKey(seed)));
  const ns = await f.key.ns("acme", "account-1");
  await f.activate("acme", ns);
  await f.publish({
    connector: "acme",
    ns,
    stream: "items",
    generation: 1,
    records: [
      { id: "base-a", v: 1 },
      { id: "base-b", v: 1 },
    ],
    observedAt: T - 1000,
    profileVersion: base.version,
    complete: base.complete,
  });
  f.overlay.runs = specs(ns).map((s) => fakeRun(ns, s));
  const service = await f.service();
  await f.sync(service);
  const decision = await service.resolve(ask("pdpp.acme.items"));
  if (decision.kind !== "view" && decision.kind !== "local_pending") {
    return { kind: decision.kind, ids: [] as string[], withheld: undefined };
  }
  const envelope = await body(decision);
  return {
    kind: decision.kind,
    ids: envelope.data.records
      .map((r: any) => r.id ?? r.uid)
      .sort() as string[],
    withheld: (decision.withheld ?? []).map((w) => w.runId),
  };
}

const noRows = (version: string, extra: Partial<Spec> = {}): Spec => ({
  runId: "a",
  observedAt: T,
  key: "id",
  version,
  complete: false,
  rows: [],
  ...extra,
});

const keyChange = (version: string): Spec => ({
  runId: "b",
  observedAt: T + 1,
  key: "uid",
  version,
  complete: true,
  rows: [{ uid: "local-b" }],
});

describe("a run the writer would skip does not move the fold's profile", () => {
  it("an older no-op run does not make a later older key change look newer", async () => {
    // Base 2.0.0 (key id). Run a: key id, 1.0.0, no rows, not full: the
    // writer skips it and the head stays 2.0.0. Run b: key uid, 1.5.0 is older
    // than that head, so the writer will not publish it.
    const out = await read(701, { version: "2.0.0", complete: true }, () => [
      noRows("1.0.0"),
      keyChange("1.5.0"),
    ]);
    expect(out.kind).toBe("view");
    expect(out.ids).toEqual(["base-a", "base-b"]);
    expect(out.withheld).toEqual(["b"]);
  });

  it("a newer no-op run does not make a later newer key change look older", async () => {
    // Base 2.0.0. Run a: key id, 3.0.0, no rows: skipped, head stays 2.0.0.
    // Run b: key uid, 2.5.0 is newer than that head: the writer publishes it
    // over an empty base.
    const out = await read(702, { version: "2.0.0", complete: true }, () => [
      noRows("3.0.0"),
      keyChange("2.5.0"),
    ]);
    expect(out.kind).toBe("view");
    expect(out.ids).toEqual(["local-b"]);
    expect(out.withheld).toEqual([]);
  });

  it("a run that completes an incomplete base is published, and moves the profile", async () => {
    // Base 2.0.0, incomplete. Run a: older connector, no rows, but full: the
    // head's completeness changes, so the writer publishes it with 1.0.0.
    const out = await read(703, { version: "2.0.0", complete: false }, () => [
      noRows("1.0.0", { complete: true }),
      keyChange("1.5.0"),
    ]);
    expect(out.kind).toBe("view");
    expect(out.ids).toEqual(["local-b"]);
    expect(out.withheld).toEqual([]);
  });

  it("a run with rows may be skipped too, so the profile stays at the higher of the two", async () => {
    // Base 2.0.0. Run a: key id, 1.0.0, one row, not full. If its row loses
    // to the base's, the writer skips it and the head stays 2.0.0; the
    // overlay cannot tell, and takes the side that withholds more.
    const out = await read(704, { version: "2.0.0", complete: true }, () => [
      noRows("1.0.0", { rows: [{ id: "base-a", v: 0 }] }),
      keyChange("1.5.0"),
    ]);
    expect(out.ids).toEqual(["base-a", "base-b"]);
    expect(out.withheld).toEqual(["b"]);
  });
});
