import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import desktopExport from "./__fixtures__/strava-desktop-export.fixture.json";
import stravaDeclaration from "./declarations/strava.collection-profile.json";
import stravaProvenance from "./declarations/strava.provenance.json";
import {
  LEGACY_SCOPE_BINDINGS,
  legacyScopeToPdppSelection,
  projectPdppRecordsToLegacyPayload,
} from "./index.js";
import type { PdppRecord } from "./types.js";

const ACTIVITIES = "strava.activities";
const DIAGNOSTICS = "strava.coverage_diagnostics";
const SOURCE = "https://registry.pdpp.dev/connectors/strava";
const MANIFEST_DIGEST =
  "sha256:b33086156d3003d0cbe48cb0de4adf48a7fde7241f28c2ea5e350cff1f17c82c";

const activity = (id: string, extra: Record<string, unknown> = {}) => ({
  id,
  activity_type: "Ride",
  start_date: "2026-08-01",
  start_time: "2026-08-01T07:15:00",
  start_time_basis: "unknown",
  distance_m: null,
  moving_time_s: 1500,
  elapsed_time_s: null,
  total_elevation_gain_m: null,
  average_heartrate: null,
  max_heartrate: null,
  calories_kcal: null,
  gear: null,
  freshness: "snapshot",
  exported_at: null,
  ...extra,
});

const diagnostic = (extra: Record<string, unknown> = {}) => ({
  id: "activities:unknown",
  stream: "activities",
  status: "partial",
  reason: "records_unreadable",
  record_count: 2,
  fields_unavailable: ["gear"],
  window_requested_from: null,
  window_requested_to: null,
  window_covered_from: "2026-08-01T07:15:00",
  window_covered_to: "2026-08-02T07:15:00",
  freshness: "snapshot",
  exported_at: null,
  ...extra,
});

const rec = (stream: string, data: Record<string, unknown>): PdppRecord => ({
  stream,
  data,
});

const project = (
  scope: string,
  records: PdppRecord[],
  options: { fetchedStreams?: string[]; orderByPrimaryKey?: boolean } = {},
) =>
  projectPdppRecordsToLegacyPayload(scope, records, {
    fetchedStreams:
      options.fetchedStreams ?? LEGACY_SCOPE_BINDINGS.get(scope)!.pdppStreams,
    ...(options.orderByPrimaryKey ? { orderByPrimaryKey: true } : {}),
  });

describe("strava 1.0.8 pin", () => {
  it("vendors the verified profile bytes and names the verified artifact", () => {
    const bytes = readFileSync(
      new URL("./declarations/strava.collection-profile.json", import.meta.url),
    );
    expect(`sha256:${createHash("sha256").update(bytes).digest("hex")}`).toBe(
      stravaProvenance.outputs["collection-profile.json"],
    );
    expect(stravaDeclaration.version).toBe("1.0.8");
    expect(stravaDeclaration.connector_id).toBe(SOURCE);
    expect(stravaProvenance.version).toBe("1.0.8");
    for (const scope of [ACTIVITIES, DIAGNOSTICS]) {
      expect(LEGACY_SCOPE_BINDINGS.get(scope)?.provenance).toEqual([
        expect.objectContaining({
          kind: "oci",
          ref: "ghcr.io/pdp-connect/connector/strava:1.0.8",
          digest: MANIFEST_DIGEST,
        }),
      ]);
    }
  });

  it("declares both streams optional mutable state keyed by id", () => {
    expect(
      stravaDeclaration.streams.map((stream) => [
        stream.name,
        stream.semantics,
        stream.required,
        stream.primary_key,
      ]),
    ).toEqual([
      ["activities", "mutable_state", false, ["id"]],
      ["coverage_diagnostics", "mutable_state", false, ["id"]],
    ]);
  });

  it("selects one stream per scope and nothing beyond the frozen scopes", () => {
    expect(legacyScopeToPdppSelection(ACTIVITIES)).toEqual({
      ok: true,
      selection: { source: SOURCE, streams: ["activities"] },
    });
    expect(legacyScopeToPdppSelection(DIAGNOSTICS)).toEqual({
      ok: true,
      selection: { source: SOURCE, streams: ["coverage_diagnostics"] },
    });
    expect(legacyScopeToPdppSelection("strava.profile")).toMatchObject({
      ok: false,
      error: { kind: "unknown_scope" },
    });
  });
});

describe("strava pass-through against the Desktop export function", () => {
  it("serves the Desktop envelope for the Rust unit-test snapshot", () => {
    const { snapshot, scopes } = desktopExport.rustUnitTest;
    expect(
      project(ACTIVITIES, [rec("activities", snapshot.activities[0]!)]),
    ).toMatchObject({
      ok: true,
      payload: scopes["strava.activities"],
    });
    // That Rust diagnostic has no id. The pinned producer always sets one,
    // so the view refuses the row instead of serving a row it cannot key.
    expect(
      project(DIAGNOSTICS, [
        rec("coverage_diagnostics", snapshot.coverage_diagnostics[0]!),
      ]),
    ).toMatchObject({
      ok: false,
      error: {
        kind: "incomplete_scope",
        reason: "coverage_diagnostics.id is unavailable",
      },
    });
  });

  it("keeps every native field, null and unknown field unchanged", () => {
    const rows = [
      activity("11", {
        start_time: "2026-08-01T07:15:00+02:00",
        start_time_basis: "utc",
        gear: "Road bike",
        average_heartrate: 141.5,
        exported_at: "2026-08-30T12:00:00.000Z",
        future_field: { nested: [1, null, "x"] },
      }),
      activity("12", { freshness: "live" }),
    ];
    const before = structuredClone(rows);

    const result = project(
      ACTIVITIES,
      rows.map((row) => rec("activities", row)),
    );

    expect(result).toMatchObject({ ok: true, payload: { activities: before } });
    expect(rows).toEqual(before);
    // No timestamp is added or rewritten.
    expect(
      result.ok &&
        (result.payload.activities as Record<string, unknown>[]).map(
          (row) => row.exported_at,
        ),
    ).toEqual(["2026-08-30T12:00:00.000Z", null]);
  });

  it("maps the two scopes independently", () => {
    const records = [
      rec("activities", activity("11")),
      rec("coverage_diagnostics", diagnostic()),
    ];

    const activities = project(ACTIVITIES, records, {
      fetchedStreams: ["activities"],
    });
    const diagnostics = project(DIAGNOSTICS, records, {
      fetchedStreams: ["coverage_diagnostics"],
    });

    expect(activities).toMatchObject({
      ok: true,
      payload: { activities: [activity("11")] },
    });
    expect(diagnostics).toMatchObject({
      ok: true,
      payload: { coverage_diagnostics: [diagnostic()] },
    });
    // Neither body carries the other stream.
    expect(activities.ok && Object.keys(activities.payload)).toEqual([
      "activities",
    ]);
    expect(diagnostics.ok && Object.keys(diagnostics.payload)).toEqual([
      "coverage_diagnostics",
    ]);
  });

  it("separates a fetched empty stream from a stream never fetched", () => {
    expect(project(ACTIVITIES, [], { fetchedStreams: ["activities"] })).toEqual(
      {
        ok: true,
        payload: { activities: [] },
        diagnostics: [
          expect.objectContaining({
            kind: "unproven",
            aspect: "collection_coverage",
          }),
        ],
      },
    );
    expect(project(DIAGNOSTICS, [], { fetchedStreams: [] })).toEqual({
      ok: false,
      error: {
        kind: "missing_stream",
        scope: DIAGNOSTICS,
        expectedStream: "coverage_diagnostics",
      },
    });
  });

  it("refuses a row without an id for either scope", () => {
    const { id: _id, ...noId } = activity("1");
    expect(project(ACTIVITIES, [rec("activities", noId)])).toMatchObject({
      ok: false,
      error: { kind: "incomplete_scope", scope: ACTIVITIES },
    });
    expect(
      project(DIAGNOSTICS, [
        rec("coverage_diagnostics", { ...diagnostic(), id: "" }),
      ]),
    ).toMatchObject({
      ok: false,
      error: { kind: "incomplete_scope", scope: DIAGNOSTICS },
    });
  });
});

describe("strava limits the projection reports instead of hiding", () => {
  it("serves a partial coverage diagnostic as written", () => {
    const partial = diagnostic({
      status: "partial",
      reason: "collection_interrupted",
      fields_unavailable: ["calories_kcal", "gear"],
    });
    const result = project(DIAGNOSTICS, [rec("coverage_diagnostics", partial)]);
    expect(result).toEqual({
      ok: true,
      payload: { coverage_diagnostics: [partial] },
    });
  });

  it("never lets activities claim coverage, with or without a diagnostic in the input", () => {
    const withDiagnostic = project(
      ACTIVITIES,
      [
        rec("activities", activity("11")),
        rec(
          "coverage_diagnostics",
          diagnostic({ status: "complete", reason: "covered_in_full" }),
        ),
      ],
      { fetchedStreams: ["activities", "coverage_diagnostics"] },
    );
    const without = project(ACTIVITIES, [rec("activities", activity("11"))]);
    for (const result of [withDiagnostic, without]) {
      expect(result.ok && result.diagnostics).toEqual([
        expect.objectContaining({
          kind: "unproven",
          scope: ACTIVITIES,
          stream: "activities",
          aspect: "collection_coverage",
        }),
      ]);
    }
  });

  it("flags record order only when there is an order to compare", () => {
    const { activities } = desktopExport.snapshotOrder;
    const rows = activities.map((row) => rec("activities", row));
    const order = (aspect: string) => (result: ReturnType<typeof project>) =>
      result.ok &&
      result.diagnostics?.some(
        (d) => d.kind === "unproven" && d.aspect === aspect,
      );

    expect(order("record_order")(project(ACTIVITIES, rows))).toBe(true);
    expect(order("record_order")(project(ACTIVITIES, rows.slice(0, 1)))).toBe(
      false,
    );
  });

  it("returns snapshot order as given, and key order when the reader asks for it", () => {
    const { activities } = desktopExport.snapshotOrder;
    const rows = activities.map((row) => rec("activities", row));
    const ids = (result: ReturnType<typeof project>) =>
      result.ok &&
      (result.payload.activities as { id: string }[]).map((row) => row.id);

    const snapshotOrder = activities.map((row) => row.id);
    expect(ids(project(ACTIVITIES, rows))).toEqual(snapshotOrder);

    const byKey = ids(project(ACTIVITIES, rows, { orderByPrimaryKey: true }));
    expect(byKey).toEqual(["100", "2000000000", "21", "3", "9"]);
    // Same rows, different order: key order does not equal the snapshot.
    expect(byKey).not.toEqual(snapshotOrder);
    expect(byKey && [...byKey].sort()).toEqual([...snapshotOrder].sort());
  });
});
