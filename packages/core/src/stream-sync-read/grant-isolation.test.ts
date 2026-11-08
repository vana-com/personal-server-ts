/**
 * Audience isolation: a person's unpublished local rows are theirs alone. A
 * grant (any reader that is not the owner view) is answered from the imported
 * heads only, so whatever local runs exist, its result is the result it would
 * get with no local runs at all.
 */

import { describe, expect, it } from "vitest";
import type { Line } from "@opendatalabs/personal-server-ts-stream-sync";
import type { FakeRun } from "./service-fixture.js";
import { ask, body, Fixture, masterKey } from "./service-fixture.js";
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
  await f.publish({
    connector: "acme",
    ns,
    stream: "items",
    generation: 1,
    records: [
      { id: "a", v: 1 },
      { id: "b", v: 1 },
    ],
    observedAt: T - 1000,
    profileVersion: "1.0.0",
  });
  return { f, ns };
}

/** What a grant is told: the decision's shape and the rows. */
async function grantRead(f: Fixture, extra: Record<string, unknown> = {}) {
  const service = await f.service();
  await f.sync(service);
  const decision = await service.resolve(
    ask("pdpp.acme.items", { isOwnerView: false, ...extra }),
  );
  if (decision.kind !== "view") return { kind: decision.kind };
  const envelope = await body(decision);
  const { body: _body, cursor, ...rest } = decision;
  return {
    ...rest,
    cursorPinsMembers: cursor.length > 0 && !!decodeMembers(cursor),
    envelope,
  };
}

function decodeMembers(cursor: string): boolean {
  const parsed = JSON.parse(atob(cursor.replace(/-/g, "+").replace(/_/g, "/")));
  return Object.values(parsed.s as Record<string, { m?: unknown[] }>).some(
    (s) => (s.m?.length ?? 0) > 0,
  );
}

const LOCAL_RUNS: [string, (ns: string) => FakeRun[]][] = [
  [
    "a full replacement-key run",
    (ns) => [
      fakeRun(ns, {
        runId: "r1",
        rows: [{ uid: "local-private" }],
        primaryKey: ["uid"],
        version: "2.0.0",
        complete: true,
      }),
    ],
  ],
  [
    "a partial replacement-key run",
    (ns) => [
      fakeRun(ns, {
        runId: "r1",
        rows: [{ uid: "local-private" }],
        primaryKey: ["uid"],
        version: "2.0.0",
        complete: false,
      }),
    ],
  ],
  [
    "same-key pending rows",
    (ns) => [
      fakeRun(ns, { runId: "r1", rows: [{ id: "local-private", v: 9 }] }),
    ],
  ],
  [
    "a withheld older-connector run",
    (ns) => [
      fakeRun(ns, {
        runId: "r1",
        rows: [{ uid: "local-private" }],
        primaryKey: ["uid"],
        version: "0.9.0",
        complete: true,
      }),
    ],
  ],
];

describe("a grant never sees the owner's overlay", () => {
  it.each(LOCAL_RUNS)(
    "reads the same with %s as with no local runs",
    async (_name, runs) => {
      const { f, ns } = await setup(501);
      f.overlay.runs = [];
      const without = await grantRead(f);
      expect(without.kind).toBe("view");
      f.overlay.runs = runs(ns);
      const withRuns = await grantRead(f);
      expect(withRuns).toEqual(without);
      expect(JSON.stringify(withRuns)).not.toContain("local-private");
    },
  );

  it("refuses an owner-issued cursor that names overlay members on a grant read", async () => {
    const { f, ns } = await setup(502);
    f.overlay.runs = [
      fakeRun(ns, { runId: "r1", rows: [{ id: "local-private", v: 9 }] }),
    ];
    const service = await f.service();
    await f.sync(service);
    const owner = await service.resolve(ask("pdpp.acme.items"));
    if (owner.kind !== "view") throw new Error(owner.kind);
    const cursor = owner.cursor;
    expect(await body(owner)).toMatchObject({
      data: {
        records: expect.arrayContaining([{ id: "local-private", v: 9 }]),
      },
    });
    const grant = await service.resolve(
      ask("pdpp.acme.items", { cursor, isOwnerView: false }),
    );
    expect(grant.kind).toBe("cursor_stale");
  });
});
