/**
 * A run the writer will publish can still be unreadable under the requested
 * legacy name: the projector refuses its profile. The owner is told the run
 * exists and could not be projected, on every answer that is not a view; the
 * rows stay in the raw `pdpp.<connector>.<stream>` stream.
 */

import { describe, expect, it } from "vitest";
import type { Line } from "@opendatalabs/personal-server-ts-stream-sync";
import { ask, Fixture, masterKey } from "./service-fixture.js";
import { testOwnerKey } from "./testing.js";

const T = Date.parse("2026-11-01T00:00:00Z");
const SCOPE = "strava.activities";
const CONNECTOR = "strava-browser";

async function scenario(seed: number) {
  const f = new Fixture(await testOwnerKey(masterKey(seed)));
  f.overlay.connector = CONNECTOR;
  const ns = await f.key.ns(CONNECTOR, "account-1");
  await f.activate(CONNECTOR, ns);
  // An incomplete imported base under a profile key no binding maps.
  await f.publish({
    connector: CONNECTOR,
    ns,
    stream: "activities",
    generation: 1,
    records: [{ id: "old" }],
    observedAt: T - 1000,
    profileKey: "unmapped",
    profileVersion: "1.0.0",
    complete: false,
  });
  // An accepted partial run under the same profile: the writer publishes it.
  f.overlay.runs = [
    {
      runId: "r1",
      ns,
      generation: 1,
      observedAt: T,
      streams: [
        {
          name: "activities",
          complete: false,
          primaryKey: ["id"],
          version: "1.0.0",
          profileKey: "unmapped",
          rows: [{ o: T, r: "r1", v: { id: "new" } } as Line],
        },
      ],
    },
  ];
  const service = await f.service();
  await f.sync(service);
  return { service, ns };
}

const marker = {
  runId: "r1",
  stream: "activities",
  reason: "projection_unavailable",
};

describe("projection unavailable", () => {
  it("tells the owner about the run when no stored body exists", async () => {
    const { service, ns } = await scenario(801);
    const owner = await service.resolve(ask(SCOPE));
    expect(owner).toEqual({ kind: "pass", withheld: [marker] });
    const named = await service.resolve(ask(SCOPE, { connection: ns }));
    expect(named).toMatchObject({ withheld: [marker] });
  });

  it("tells the owner about the run when a stored body answers", async () => {
    const { service } = await scenario(802);
    const owner = await service.resolve(ask(SCOPE, { legacyFile: true }));
    expect(owner).toMatchObject({ pending: { runs: 1 } });
    const grant = await service.resolve(
      ask(SCOPE, { legacyFile: true, isOwnerView: false }),
    );
    expect(grant).toEqual({ kind: owner.kind });
  });

  it("tells a named connection's owner, and never a grant", async () => {
    const { service } = await scenario(803);
    const grant = await service.resolve(ask(SCOPE, { isOwnerView: false }));
    expect(grant).not.toHaveProperty("withheld");
  });
});
