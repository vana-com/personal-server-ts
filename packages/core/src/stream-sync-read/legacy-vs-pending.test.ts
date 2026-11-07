/**
 * A legacy body answers the owner as before own-writes. Its collectedAt is an
 * ingest stamp of some server, not a time comparable with a run's observedAt,
 * so no time decides between the two. When pending rows that the legacy body
 * does not supersede exist (a pending run with records), the owner is told:
 * a count of pending runs on the decision. A grant is told nothing. With no
 * legacy body the pending run is served as local_pending.
 */

import { describe, expect, it } from "vitest";
import type { Line } from "@opendatalabs/personal-server-ts-stream-sync";
import type { FakeRun } from "./service-fixture.js";
import { ask, body, Fixture, masterKey } from "./service-fixture.js";
import { testOwnerKey } from "./testing.js";

const T = Date.parse("2026-11-01T00:00:00Z");

const pendingRun = (
  ns: string,
  generation: number | null,
  runId: string,
  rows: Line[],
  observedAt = T,
): FakeRun => ({
  runId,
  ns,
  generation,
  observedAt,
  streams: [{ name: "items", rows, complete: false }],
});

async function setup(seed: number, activate: boolean) {
  const f = new Fixture(await testOwnerKey(masterKey(seed)));
  const ns = await f.key.ns("acme", "account-1");
  if (activate) await f.activate("acme", ns);
  return { f, ns, generation: activate ? 1 : null };
}

async function read(
  f: Fixture,
  extra: Record<string, unknown>,
  warns?: unknown[][],
) {
  const log = (...args: unknown[]) => void warns?.push(args);
  const service = await f.service(
    warns ? { logger: { info: log, warn: log, error: log } } : {},
  );
  await f.sync(service);
  return service.resolve(ask("pdpp.acme.items", extra));
}

const line = (id: string, runId: string, o = T): Line => ({
  o,
  r: runId,
  v: { id },
});

describe.each([
  ["unactivated", false, "pass"],
  ["activated", true, "legacy"],
] as const)(
  "legacy body against pending runs (%s)",
  (_name, activate, kept) => {
    const seed = activate ? 410 : 420;

    it("keeps the legacy body and tells the owner of a newer pending run", async () => {
      const { f, ns, generation } = await setup(seed + 1, activate);
      f.overlay.runs = [pendingRun(ns, generation, "r1", [line("x", "r1")])];
      const warns: unknown[][] = [];
      const decision = await read(f, { legacyFile: true }, warns);
      expect(decision).toEqual({ kind: kept, pending: { runs: 1 } });
      const logs = warns.filter((c) => JSON.stringify(c).includes("pending"));
      expect(logs).toHaveLength(1);
      expect(JSON.stringify(logs[0])).toMatch(/"pending":1/);
      expect(JSON.stringify(logs)).not.toContain('"id"');
    });

    it("tells the owner the same whatever the legacy body's time or the run's", async () => {
      const { f, ns, generation } = await setup(seed + 2, activate);
      f.overlay.runs = [
        pendingRun(ns, generation, "r1", [line("x", "r1", T - 9e9)], T - 9e9),
      ];
      expect(await read(f, { legacyFile: true })).toEqual({
        kind: kept,
        pending: { runs: 1 },
      });
    });

    it("keeps the legacy body without a marker when the pending run is empty", async () => {
      const { f, ns, generation } = await setup(seed + 3, activate);
      f.overlay.runs = [
        pendingRun(ns, generation, "r1", [], T + 100),
        pendingRun(ns, generation, "r2", [], T + 200),
      ];
      expect(await read(f, { legacyFile: true })).toEqual({ kind: kept });
      // A caller that still sends the legacy ingest stamp changes nothing: an
      // empty run newer than it must not select older rows over the body.
      const stamped = { legacyFile: true, legacyCollectedAt: T } as never;
      expect(await read(f, stamped)).toEqual({ kind: kept });
    });

    it("counts only the pending runs that hold records", async () => {
      const { f, ns, generation } = await setup(seed + 4, activate);
      f.overlay.runs = [
        pendingRun(ns, generation, "r1", [line("x", "r1")]),
        pendingRun(ns, generation, "r2", [], T + 5),
        pendingRun(ns, generation, "r3", [line("y", "r3", T + 9)], T + 9),
      ];
      expect(await read(f, { legacyFile: true })).toEqual({
        kind: kept,
        pending: { runs: 2 },
      });
    });

    it("serves the pending run as local_pending when there is no legacy body", async () => {
      const { f, ns, generation } = await setup(seed + 5, activate);
      f.overlay.runs = [pendingRun(ns, generation, "r1", [line("x", "r1")])];
      const decision = await read(f, { legacyFile: false });
      expect(decision.kind).toBe("local_pending");
      expect((await body(decision)).data.records).toEqual([{ id: "x" }]);
      expect((decision as { pending?: unknown }).pending).toBeUndefined();
    });

    it("leaves a grantee unchanged", async () => {
      const { f, ns, generation } = await setup(seed + 6, activate);
      f.overlay.runs = [pendingRun(ns, generation, "r1", [line("x", "r1")])];
      expect(await read(f, { legacyFile: true, isOwnerView: false })).toEqual({
        kind: kept,
      });
    });
  },
);
