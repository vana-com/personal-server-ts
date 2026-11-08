/**
 * A key change is judged against the stream's version floor: the highest
 * connector version that registered on it, not the profile of the last head.
 * A run the writer skips (isNoop) or one from an older connector that
 * publishes cannot lower the floor, so neither can let a later older key
 * change through. The read shows what the writer's plan publishes.
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
    withheld: (decision.withheld ?? []).map((w) => `${w.runId}:${w.reason}`),
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

describe("the version floor judges a key change", () => {
  it("an older no-op run does not make a later older key change look newer", async () => {
    // Base 2.0.0 (key id). Run a: key id, 1.0.0, no rows, not full: a no-op.
    // Run b: key uid, 1.5.0 is below the floor 2.0.0: refused.
    const out = await read(701, { version: "2.0.0", complete: true }, () => [
      noRows("1.0.0"),
      keyChange("1.5.0"),
    ]);
    expect(out.kind).toBe("view");
    expect(out.ids).toEqual(["base-a", "base-b"]);
    expect(out.withheld).toEqual(["b:connector_update_required"]);
  });

  it("a newer no-op run raises the floor above a later key change", async () => {
    // Base 2.0.0. Run a: key id, 3.0.0, no rows: a no-op, but a 3.0.0
    // connector ran on the stream, so the floor is 3.0.0. Run b: key uid,
    // 2.5.0 is below it: refused. (Conservative: the floor counts a no-op.)
    const out = await read(702, { version: "2.0.0", complete: true }, () => [
      noRows("3.0.0"),
      keyChange("2.5.0"),
    ]);
    expect(out.kind).toBe("view");
    expect(out.ids).toEqual(["base-a", "base-b"]);
    expect(out.withheld).toEqual(["b:connector_update_required"]);
  });

  it("a newer key change above the floor publishes", async () => {
    // Base 2.0.0. Run b: key uid, 2.5.0 is above the floor. It replaces the
    // base, which a grant reads until it is imported: the owner keeps the
    // base, marked incomplete, and is told b is pending.
    const out = await read(705, { version: "2.0.0", complete: true }, () => [
      keyChange("2.5.0"),
    ]);
    expect(out.kind).toBe("local_pending");
    expect(out.ids).toEqual(["base-a", "base-b"]);
    expect(out.withheld).toEqual(["b:key_reset_pending"]);
  });

  it("an older run that completes an incomplete base publishes, and does not lower the floor", async () => {
    // Base 2.0.0, incomplete. Run a: older connector, no rows, but full: the
    // head's completeness changes, so the writer publishes it. The floor
    // stays 2.0.0, so run b (1.5.0, key uid) is refused.
    const out = await read(703, { version: "2.0.0", complete: false }, () => [
      noRows("1.0.0", { complete: true }),
      keyChange("1.5.0"),
    ]);
    expect(out.ids).toEqual(["base-a", "base-b"]);
    expect(out.withheld).toEqual(["b:connector_update_required"]);
  });

  it("an older run with rows does not lower the floor", async () => {
    const out = await read(704, { version: "2.0.0", complete: true }, () => [
      noRows("1.0.0", { rows: [{ id: "base-a", v: 0 }] }),
      keyChange("1.5.0"),
    ]);
    expect(out.ids).toEqual(["base-a", "base-b"]);
    expect(out.withheld).toEqual(["b:connector_update_required"]);
  });
});
