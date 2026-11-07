/**
 * A cursor replays exactly the rows of its first response or answers
 * cursor_stale; it never mixes in rows the first response had already
 * replaced. The first response's fold had two steps that changed the shape:
 * a key change away from the base key and one back to it. The cursor must
 * remember the whole fold, not only its last members.
 */

import { describe, expect, it } from "vitest";
import type { Line } from "@opendatalabs/personal-server-ts-stream-sync";
import type { FakeRun } from "./service-fixture.js";
import { ask, body, Fixture, masterKey } from "./service-fixture.js";
import { testOwnerKey } from "./testing.js";

const T = Date.parse("2026-11-01T00:00:00Z");

const fakeRun = (
  ns: string,
  spec: {
    runId: string;
    observedAt: number;
    key: string;
    version: string;
    row: Record<string, unknown>;
    revision?: string;
  },
): FakeRun => ({
  runId: spec.runId,
  ns,
  generation: 1,
  observedAt: spec.observedAt,
  streams: [
    {
      name: "items",
      complete: true,
      primaryKey: [spec.key],
      version: spec.version,
      ...(spec.revision ? { contentRevision: spec.revision } : {}),
      rows: [
        { o: spec.observedAt, r: spec.runId, v: spec.row as never } as Line,
      ],
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
      { id: "base-a", v: 1 },
      { id: "base-b", v: 1 },
    ],
    observedAt: T - 1000,
    profileVersion: "1.0.0",
  });
  const service = await f.service();
  await f.sync(service);
  return { f, ns, service };
}

const runs = (ns: string, revisionOfA = "a1") => [
  fakeRun(ns, {
    runId: "a",
    observedAt: T,
    key: "uid",
    version: "2.0.0",
    row: { uid: "local-a" },
    revision: revisionOfA,
  }),
  fakeRun(ns, {
    runId: "b",
    observedAt: T + 1,
    key: "id",
    version: "3.0.0",
    row: { id: "local-b" },
  }),
];

const rows = async (
  service: Awaited<ReturnType<typeof setup>>["service"],
  cursor: string | null,
) => {
  const decision = await service.resolve(ask("pdpp.acme.items", { cursor }));
  if (decision.kind !== "view") return { kind: decision.kind, ids: [] };
  const envelope = await body(decision);
  return {
    kind: decision.kind,
    cursor: decision.cursor,
    ids: envelope.data.records.map((r: any) => r.id ?? r.uid).sort(),
  };
};

describe("cursor replay after a key change away from the base key and back", () => {
  it("serves the first response's rows again", async () => {
    const { f, ns, service } = await setup(601);
    f.overlay.runs = runs(ns);
    const first = await rows(service, null);
    expect(first.ids).toEqual(["local-b"]);
    const replay = await rows(service, first.cursor!);
    expect(replay.kind).toBe("view");
    expect(replay.ids).toEqual(first.ids);
  });

  it("answers cursor_stale when a step that shaped the first response changed", async () => {
    const { f, ns, service } = await setup(602);
    f.overlay.runs = runs(ns);
    const first = await rows(service, null);
    f.overlay.runs = runs(ns, "a2");
    expect((await rows(service, first.cursor!)).kind).toBe("cursor_stale");
    f.overlay.runs = runs(ns).filter((r) => r.runId === "b");
    expect((await rows(service, first.cursor!)).kind).toBe("cursor_stale");
  });
});
