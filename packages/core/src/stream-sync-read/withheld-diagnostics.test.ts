/**
 * The owner is told about every local run the writer will not publish, on
 * every path of the answer, including the paths that serve no view: a read
 * whose every pending run is withheld, with or without a legacy body and with
 * an explicit connection. A grant is told nothing.
 */

import { describe, expect, it } from "vitest";
import type { Line } from "@opendatalabs/personal-server-ts-stream-sync";
import type { FakeRun } from "./service-fixture.js";
import { ask, Fixture, masterKey } from "./service-fixture.js";
import { testOwnerKey } from "./testing.js";

const T = Date.parse("2026-11-01T00:00:00Z");

const WITHHELD = [
  { runId: "r1", stream: "items", reason: "connector_update_required" },
];

async function setup(seed: number) {
  const f = new Fixture(await testOwnerKey(masterKey(seed)));
  const ns = await f.key.ns("acme", "account-1");
  await f.activate("acme", ns);
  // An incomplete base at 2.0.0 (key id), and one full local run of an older
  // connector with a changed key: the writer will not publish it.
  await f.publish({
    connector: "acme",
    ns,
    stream: "items",
    generation: 1,
    records: [{ id: "a", v: 1 }],
    observedAt: T - 1000,
    profileVersion: "2.0.0",
    complete: false,
  });
  const run: FakeRun = {
    runId: "r1",
    ns,
    generation: 1,
    observedAt: T,
    streams: [
      {
        name: "items",
        complete: true,
        primaryKey: ["uid"],
        version: "1.0.0",
        rows: [{ o: T, r: "r1", v: { uid: "u1" } } as Line],
      },
    ],
  };
  f.overlay.runs = [run];
  return { f, ns };
}

async function resolve(
  seed: number,
  extra: Record<string, unknown> = {},
  warns?: unknown[][],
) {
  const { f, ns } = await setup(seed);
  const log = (...args: unknown[]) => void warns?.push(args);
  const service = await f.service(
    warns ? { logger: { info() {}, warn: log, error() {} } } : {},
  );
  await f.sync(service);
  return service.resolve(
    ask("pdpp.acme.items", {
      ...extra,
      ...(extra.connection === "ns" ? { connection: ns } : {}),
    }),
  );
}

describe("withheld runs reach the owner on a read that serves no view", () => {
  it("passes with the withheld run when no legacy body exists", async () => {
    const warns: unknown[][] = [];
    const decision = await resolve(801, {}, warns);
    expect(decision.kind).toBe("pass");
    expect((decision as { withheld?: unknown }).withheld).toEqual(WITHHELD);
    const logs = warns.filter((c) => JSON.stringify(c).includes("withheld"));
    expect(logs).toHaveLength(1);
    expect(JSON.stringify(logs[0])).toMatch(/"withheld":1/);
  });

  it("answers legacy with the withheld run when a legacy body exists", async () => {
    const decision = await resolve(802, { legacyFile: true });
    expect(decision.kind).toBe("legacy");
    expect((decision as { withheld?: unknown }).withheld).toEqual(WITHHELD);
  });

  it("names the withheld run when an explicit connection finds no view", async () => {
    const decision = await resolve(803, { connection: "ns" });
    expect(decision.kind).toBe("unavailable");
    expect((decision as { withheld?: unknown }).withheld).toEqual(WITHHELD);
  });

  it("tells a grant nothing", async () => {
    const decision = await resolve(804, { isOwnerView: false });
    expect(decision).toEqual({ kind: "pass" });
    const legacy = await resolve(805, { isOwnerView: false, legacyFile: true });
    expect(legacy).toEqual({ kind: "legacy" });
  });
});
