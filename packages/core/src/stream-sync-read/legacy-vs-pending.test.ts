/**
 * The owner reads whichever source holds the newer collection: the legacy
 * body or the device's pending local run. Compared by the legacy body's
 * collection time and the run's observedAt. On a tie, or when either time is
 * missing, the legacy body answers as before. The two are never merged. A
 * grantee is unaffected.
 */

import { describe, expect, it } from "vitest";
import type { Line } from "@opendatalabs/personal-server-ts-stream-sync";
import { ask, body, Fixture, masterKey } from "./service-fixture.js";
import { testOwnerKey } from "./testing.js";

const T = Date.parse("2026-11-01T00:00:00Z");
const line: Line = { o: T, r: "r1", v: { id: "local" } };

async function setup(seed: number, activate: boolean) {
  const f = new Fixture(await testOwnerKey(masterKey(seed)));
  const ns = await f.key.ns("acme", "account-1");
  if (activate) await f.activate("acme", ns);
  f.overlay.runs = [
    {
      runId: "r1",
      ns,
      generation: activate ? 1 : null,
      observedAt: T,
      streams: [{ name: "items", rows: [line], complete: false }],
    },
  ];
  return f;
}

async function read(f: Fixture, extra: Record<string, unknown>) {
  const service = await f.service();
  await f.sync(service);
  const decision = await service.resolve(ask("pdpp.acme.items", extra));
  if (decision.kind !== "local_pending") return { kind: decision.kind };
  const envelope = await body(decision);
  return {
    kind: decision.kind,
    origin: envelope.origin as string,
    ids: envelope.data.records.map((r: any) => r.id) as string[],
  };
}

const pending = {
  kind: "local_pending",
  origin: "local-pending",
  ids: ["local"],
};

describe.each([
  ["unactivated", false, "pass"],
  ["activated", true, "legacy"],
] as const)(
  "legacy body against a pending run (%s)",
  (_name, activate, kept) => {
    it("serves the pending run when it is newer than the legacy body", async () => {
      const f = await setup(activate ? 411 : 412, activate);
      expect(
        await read(f, { legacyFile: true, legacyCollectedAt: T - 1 }),
      ).toEqual(pending);
    });

    it("keeps the legacy body when it is newer", async () => {
      const f = await setup(activate ? 413 : 414, activate);
      expect(
        await read(f, { legacyFile: true, legacyCollectedAt: T + 1 }),
      ).toEqual({ kind: kept });
    });

    it("keeps the legacy body on a tie", async () => {
      const f = await setup(activate ? 415 : 416, activate);
      expect(await read(f, { legacyFile: true, legacyCollectedAt: T })).toEqual(
        {
          kind: kept,
        },
      );
    });

    it("keeps the legacy body when its time is missing", async () => {
      const f = await setup(activate ? 417 : 418, activate);
      for (const missing of [{}, { legacyCollectedAt: null }]) {
        expect(await read(f, { legacyFile: true, ...missing })).toEqual({
          kind: kept,
        });
      }
    });

    it("leaves a grantee unchanged", async () => {
      const f = await setup(activate ? 419 : 420, activate);
      expect(
        await read(f, {
          legacyFile: true,
          legacyCollectedAt: T - 1,
          isOwnerView: false,
        }),
      ).toEqual({ kind: activate ? "legacy" : "pass" });
    });
  },
);
