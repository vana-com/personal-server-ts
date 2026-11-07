/**
 * A legacy-named read projects with the profile key of the head the writer
 * will leave (the fold's shape), not the key of the imported base the run
 * built on.
 */

import { describe, expect, it } from "vitest";
import type { Line } from "@opendatalabs/personal-server-ts-stream-sync";
import { ask, body, Fixture, masterKey } from "./service-fixture.js";
import { testOwnerKey } from "./testing.js";

const T = Date.parse("2026-11-01T00:00:00Z");
const SCOPE = "strava.activities";
const CONNECTOR = "strava-browser";

const activity = {
  id: "90000000005",
  activity_type: "Ride",
  start_date: "2026-09-20",
  start_date_local: "2026-09-20",
  start_time: "2026-09-20T06:30:00-07:00",
  start_time_basis: "local",
  distance_m: 32150.4,
  moving_time_s: 5400,
  elapsed_time_s: 6120,
  total_elevation_gain_m: 610,
  average_heartrate: null,
  max_heartrate: null,
  calories_kcal: null,
  gear: null,
  freshness: "live",
  exported_at: null,
};

async function scenario(seed: number, replaceKey: boolean) {
  const f = new Fixture(await testOwnerKey(masterKey(seed)));
  f.overlay.connector = CONNECTOR;
  const ns = await f.key.ns(CONNECTOR, "account-1");
  await f.activate(CONNECTOR, ns);
  // The imported base: an older writer and a profile key no retained binding
  // maps.
  await f.publish({
    connector: CONNECTOR,
    ns,
    stream: "activities",
    generation: 1,
    primaryKey: replaceKey ? ["uid"] : ["id"],
    records: [replaceKey ? { uid: "old" } : { id: "old" }],
    observedAt: T - 1000,
    profileKey: "unmapped",
    profileVersion: "1.0.0",
  });
  // A newer connector with the mapped key: the writer publishes its profile.
  f.overlay.runs = [
    {
      runId: "r1",
      ns,
      generation: 1,
      observedAt: T,
      streams: [
        {
          name: "activities",
          complete: true,
          primaryKey: ["id"],
          version: "2.0.0",
          profileKey: CONNECTOR,
          rows: [{ o: T, r: "r1", v: activity } as Line],
        },
      ],
    },
  ];
  const service = await f.service();
  await f.sync(service);
  return service.resolve(ask(SCOPE));
}

describe("legacy projection key", () => {
  for (const [name, replaceKey] of [
    ["over a retained base (use_base)", false],
    ["after an empty_base fold", true],
  ] as const) {
    it(`projects with the published head's profile key ${name}`, async () => {
      const decision = await scenario(replaceKey ? 702 : 701, replaceKey);
      expect(decision.kind).toBe("view");
      const envelope = await body(decision);
      expect(envelope.data.activities.map((a: { id: string }) => a.id)).toEqual(
        replaceKey ? [activity.id] : ["old", activity.id].sort(),
      );
    });
  }
});
