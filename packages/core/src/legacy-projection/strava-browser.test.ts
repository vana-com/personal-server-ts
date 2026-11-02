import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import browser from "./declarations/strava-browser.collection-profile.json";
import provenance from "./declarations/strava-browser.provenance.json";
import {
  legacyBindingsForProfile,
  legacyScopeToPdppSelection,
  projectPdppRecordsToLegacyPayload,
} from "./index.js";

const ACTIVITIES = "strava.activities";
const DIAGNOSTICS = "strava.coverage_diagnostics";
const PROFILE = "strava-browser";
const SOURCE = "https://registry.pdpp.dev/connectors/strava-browser";

const liveActivity = {
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

describe("strava-browser 0.1.35 pin", () => {
  it("vendors the published profile bytes and provenance", () => {
    const bytes = readFileSync(
      new URL(
        "./declarations/strava-browser.collection-profile.json",
        import.meta.url,
      ),
    );
    expect(`sha256:${createHash("sha256").update(bytes).digest("hex")}`).toBe(
      provenance.outputs["collection-profile.json"],
    );
    expect(browser).toMatchObject({
      connector_key: PROFILE,
      connector_id: SOURCE,
      version: "0.1.35",
    });
    expect(provenance.source.revision).toBe(
      "a5eea369af4d23ff801d8e0b53a42f9f5939c669",
    );
    expect(
      browser.streams.map((stream) => [stream.name, stream.primary_key]),
    ).toEqual([["activities", ["id"]]]);
  });
});

describe("strava-browser legacy bindings", () => {
  it("serves strava.activities from the browser source", () => {
    expect(
      legacyScopeToPdppSelection(ACTIVITIES, { profileKey: PROFILE }),
    ).toEqual({
      ok: true,
      selection: { source: SOURCE, streams: ["activities"] },
    });
    expect(
      legacyBindingsForProfile(PROFILE).get(ACTIVITIES)?.provenance,
    ).toEqual([
      {
        kind: "oci",
        ref: "ghcr.io/pdp-connect/connector/strava-browser:0.1.35",
        digest:
          "sha256:026018b79ca78789326a6f14a88899e1f346cee04fcaba9afedc5b885f86804f",
        path: "collection-profile.json#streams[name=activities]",
      },
    ]);
  });

  // The browser method collects no diagnostics; the scope stays file-only.
  it("does not serve strava.coverage_diagnostics", () => {
    expect(
      legacyScopeToPdppSelection(DIAGNOSTICS, { profileKey: PROFILE }),
    ).toEqual({
      ok: false,
      error: {
        kind: "unsupported_profile",
        scope: DIAGNOSTICS,
        profileKey: PROFILE,
      },
    });
  });

  it("passes every native field through, as the export binding does", () => {
    const records = [{ stream: "activities", data: liveActivity }];
    const options = { fetchedStreams: ["activities"], orderByPrimaryKey: true };

    const viaBrowser = projectPdppRecordsToLegacyPayload(ACTIVITIES, records, {
      ...options,
      profileKey: PROFILE,
    });
    const viaExport = projectPdppRecordsToLegacyPayload(
      ACTIVITIES,
      records,
      options,
    );

    expect(viaBrowser).toEqual({
      ok: true,
      payload: { activities: [liveActivity] },
    });
    expect(viaBrowser).toEqual(viaExport);
  });

  it("refuses an activity without an id", () => {
    const { id: _id, ...noId } = liveActivity;
    expect(
      projectPdppRecordsToLegacyPayload(
        ACTIVITIES,
        [{ stream: "activities", data: noId }],
        { fetchedStreams: ["activities"], profileKey: PROFILE },
      ),
    ).toMatchObject({
      ok: false,
      error: { kind: "incomplete_scope", scope: ACTIVITIES },
    });
  });
});
