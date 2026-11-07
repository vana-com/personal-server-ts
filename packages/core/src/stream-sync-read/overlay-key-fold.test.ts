/**
 * The overlay shows exactly what the writer will publish. Local runs fold
 * onto the base in publish order (observedAt, then runId) under the writer's
 * own compatible-writer rule (`writerCompatibility`): a changed primary key
 * from a newer connector starts from an empty base; from an older or equal
 * connector the run is withheld, never merged and never dropped silently.
 */

import { describe, expect, it } from "vitest";
import type { Line } from "@opendatalabs/personal-server-ts-stream-sync";
import type { FakeRun } from "./service-fixture.js";
import { ask, body, Fixture, masterKey } from "./service-fixture.js";
import type { ReadDecision } from "./service.js";
import { testOwnerKey } from "./testing.js";

const T = Date.parse("2026-11-01T00:00:00Z");

interface Spec {
  runId: string;
  rows: Record<string, unknown>[];
  primaryKey?: string[];
  version?: string;
  complete?: boolean;
  observedAt?: number;
}

const fakeRun = (ns: string, spec: Spec): FakeRun => ({
  runId: spec.runId,
  ns,
  generation: 1,
  observedAt: spec.observedAt ?? T,
  streams: [
    {
      name: "items",
      complete: spec.complete ?? false,
      ...(spec.primaryKey ? { primaryKey: spec.primaryKey } : {}),
      ...(spec.version ? { version: spec.version } : {}),
      rows: spec.rows.map((v): Line => ({
        o: spec.observedAt ?? T,
        r: spec.runId,
        v: v as never,
      })),
    },
  ],
});

async function setup(seed: number) {
  const f = new Fixture(await testOwnerKey(masterKey(seed)));
  const ns = await f.key.ns("acme", "account-1");
  await f.activate("acme", ns);
  return { f, ns };
}

const publishBase = (
  f: Fixture,
  ns: string,
  extra: { version?: string; primaryKey?: string[]; complete?: boolean } = {},
) =>
  f.publish({
    connector: "acme",
    ns,
    stream: "items",
    generation: 1,
    records: [
      { id: "a", v: 1 },
      { id: "b", v: 1 },
    ],
    observedAt: T - 1000,
    profileVersion: extra.version ?? "1.0.0",
    ...(extra.primaryKey ? { primaryKey: extra.primaryKey } : {}),
    ...(extra.complete !== undefined ? { complete: extra.complete } : {}),
  });

async function read(
  f: Fixture,
  extra: Partial<Parameters<typeof ask>[1]> = {},
  options: Parameters<Fixture["service"]>[0] = {},
) {
  const service = await f.service(options);
  await f.sync(service);
  const decision: ReadDecision = await service.resolve(
    ask("pdpp.acme.items", extra),
  );
  if (decision.kind !== "view" && decision.kind !== "local_pending") {
    return { kind: decision.kind, ids: [] as string[], decision };
  }
  const envelope = await body(decision);
  return {
    kind: decision.kind,
    ids: envelope.data.records
      .map((r: any) => r.id ?? r.uid)
      .sort() as string[],
    envelope,
    decision: decision as ReadDecision & { withheld?: unknown },
  };
}

describe("overlay fold under the writer's compatible-writer rule", () => {
  it("merges a run of the same primary key onto the base", async () => {
    const { f, ns } = await setup(301);
    await publishBase(f, ns);
    f.overlay.runs = [
      fakeRun(ns, { runId: "r1", rows: [{ id: "new", v: 1 }] }),
    ];
    const out = await read(f);
    expect(out.kind).toBe("view");
    expect(out.ids).toEqual(["a", "b", "new"]);
    expect((out.decision as any).withheld).toBeUndefined();
  });

  it("starts from an empty base when a newer connector changed the key (full run: complete view)", async () => {
    const { f, ns } = await setup(302);
    await publishBase(f, ns);
    f.overlay.runs = [
      fakeRun(ns, {
        runId: "r1",
        rows: [{ uid: "u1" }],
        primaryKey: ["uid"],
        version: "2.0.0",
        complete: true,
      }),
    ];
    const out = await read(f);
    expect(out.kind).toBe("view");
    expect(out.ids).toEqual(["u1"]);
  });

  it("starts from an empty base when a newer connector changed the key (partial run: not a complete view)", async () => {
    const { f, ns } = await setup(303);
    await publishBase(f, ns);
    f.overlay.runs = [
      fakeRun(ns, {
        runId: "r1",
        rows: [{ uid: "u1" }],
        primaryKey: ["uid"],
        version: "2.0.0",
        complete: false,
      }),
    ];
    // The writer would publish complete:false over an empty base. The owner
    // still sees the run's rows, marked pending; a grant gets the old path.
    const owner = await read(f);
    expect(owner.kind).toBe("local_pending");
    expect(owner.ids).toEqual(["u1"]);
    expect((await read(f, { isOwnerView: false })).kind).toBe("pass");
  });

  it.each(["1.0.0", "0.9.0"])(
    "keeps the base and reports the run withheld when connector %s changed the key (base 1.0.0)",
    async (version) => {
      const { f, ns } = await setup(304);
      await publishBase(f, ns);
      f.overlay.runs = [
        fakeRun(ns, {
          runId: "r1",
          rows: [{ uid: "u1" }],
          primaryKey: ["uid"],
          version,
          complete: true,
        }),
      ];
      const owner = await read(f);
      expect(owner.kind).toBe("view");
      expect(owner.ids).toEqual(["a", "b"]);
      const withheld = [
        { runId: "r1", stream: "items", reason: "connector_update_required" },
      ];
      expect((owner.decision as any).withheld).toEqual(withheld);
      expect(owner.envelope.withheld).toEqual(withheld);
      // A grant sees neither the rows nor the marker.
      const grant = await read(f, { isOwnerView: false });
      expect(grant.kind).toBe("view");
      expect(grant.ids).toEqual(["a", "b"]);
      expect((grant.decision as any).withheld).toBeUndefined();
      expect(grant.envelope.withheld).toBeUndefined();
    },
  );

  it("logs the withheld runs once per read, as a count with no row data", async () => {
    const { f, ns } = await setup(305);
    await publishBase(f, ns);
    f.overlay.runs = [
      fakeRun(ns, {
        runId: "r1",
        rows: [{ uid: "secret-row" }],
        primaryKey: ["uid"],
        version: "0.9.0",
      }),
    ];
    const calls: unknown[][] = [];
    const log = (...args: unknown[]) => void calls.push(args);
    await read(f, {}, { logger: { info: log, warn: log, error: log } });
    const withheldLogs = calls.filter((c) =>
      JSON.stringify(c).includes("withheld"),
    );
    expect(withheldLogs).toHaveLength(1);
    expect(JSON.stringify(withheldLogs[0])).toMatch(/"withheld":1/);
    expect(JSON.stringify(withheldLogs)).not.toContain("secret-row");
  });

  it("folds two runs with a key change between them, in publish order", async () => {
    const { f, ns } = await setup(306);
    await publishBase(f, ns);
    const runs = [
      fakeRun(ns, {
        runId: "a",
        observedAt: T + 1,
        rows: [{ id: "a2", v: 1 }],
      }),
      fakeRun(ns, {
        runId: "b",
        observedAt: T + 2,
        rows: [{ uid: "u1" }],
        primaryKey: ["uid"],
        version: "2.0.0",
        complete: true,
      }),
      fakeRun(ns, {
        runId: "c",
        observedAt: T + 3,
        rows: [{ uid: "u2" }],
        primaryKey: ["uid"],
        version: "2.0.0",
      }),
    ];
    for (const order of [
      runs,
      [...runs].reverse(),
      [runs[1]!, runs[2]!, runs[0]!],
    ]) {
      f.overlay.runs = order;
      const out = await read(f);
      // a merges onto the base; b empties it; c merges onto b. Complete came
      // from b's full run and survives c.
      expect(out.kind).toBe("view");
      expect(out.ids).toEqual(["u1", "u2"]);
      expect((out.decision as any).withheld).toBeUndefined();
    }
  });

  it("orders runs of the same observedAt by runId, whatever the snapshot order", async () => {
    const { f, ns } = await setup(307);
    await publishBase(f, ns);
    const z = fakeRun(ns, { runId: "z", rows: [{ id: "z1", v: 1 }] });
    const b = fakeRun(ns, {
      runId: "b",
      rows: [{ uid: "u1" }],
      primaryKey: ["uid"],
      version: "2.0.0",
      complete: true,
    });
    // b publishes first (empty base, key uid); z then meets key uid with an
    // older connector and is withheld.
    for (const order of [
      [z, b],
      [b, z],
    ]) {
      f.overlay.runs = order;
      const out = await read(f);
      expect(out.ids).toEqual(["u1"]);
      expect((out.decision as any).withheld).toEqual([
        { runId: "z", stream: "items", reason: "connector_update_required" },
      ]);
    }
  });
});
