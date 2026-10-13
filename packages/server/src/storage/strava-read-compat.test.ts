import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  readCanonicalLegacyScope,
  type CanonicalConnectionSelection,
} from "@opendatalabs/personal-server-ts-core/storage/canonical-legacy-projection";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";

/**
 * Read-time compatibility for the two Strava scopes Desktop exported, read
 * through the real SQLite record store. The rows are synthetic: they are
 * shaped from the schemas and emit calls of the digest-pinned Strava 1.0.8
 * producer (sha256:b330…7c82c). Nothing here says a real account holds them.
 */

const SOURCE = "https://registry.pdpp.dev/sources/strava";
const METHOD = "strava_export";
const COLLECTED = "2026-09-10T08:30:00+02:00";
const COLLECTED_ISO = "2026-09-10T06:30:00.000Z";
const EXPORTED_AT = "2026-08-30T12:00:00.000Z";

const activity = (id: string, extra: Record<string, unknown> = {}) => ({
  id,
  activity_type: "Run",
  start_date: "2026-08-01",
  start_time: "2026-08-01T07:15:00",
  start_time_basis: "unknown",
  distance_m: 5012.5,
  moving_time_s: 1500,
  elapsed_time_s: 1620,
  total_elevation_gain_m: null,
  average_heartrate: null,
  max_heartrate: null,
  calories_kcal: null,
  gear: null,
  freshness: "snapshot",
  exported_at: EXPORTED_AT,
  ...extra,
});

const diagnostic = (extra: Record<string, unknown> = {}) => ({
  id: `activities:${EXPORTED_AT}`,
  stream: "activities",
  status: "partial",
  reason: "records_unreadable",
  record_count: 3,
  fields_unavailable: ["calories_kcal", "gear"],
  window_requested_from: null,
  window_requested_to: null,
  window_covered_from: "2026-08-01T07:15:00",
  window_covered_to: "2026-08-09T18:00:00",
  freshness: "snapshot",
  exported_at: EXPORTED_AT,
  ...extra,
});

/** What the pinned Desktop `project_export_scopes` returns for one scope. */
const desktopScope = (stream: string, snapshot: Record<string, unknown>[]) => ({
  [stream]: snapshot,
});

describe("strava legacy scopes over the real SQLite record store", () => {
  let db: InstanceType<typeof Database>;
  let store: ReturnType<typeof createSqliteRecordStore>;

  beforeEach(() => {
    db = new Database(":memory:");
    store = createSqliteRecordStore(db);
  });
  afterEach(() => store.close());

  function connect(instance: string): CanonicalConnectionSelection {
    store.registerConnection({
      instance,
      sourceId: SOURCE,
      method: METHOD,
      label: instance,
    });
    return { instance, sourceId: SOURCE, method: METHOD };
  }

  /** A full replace that names a producer time, so it leaves a receipt. */
  function replace(
    instance: string,
    stream: string,
    rows: Record<string, unknown>[],
    sourceCollectedAt: string | null = COLLECTED,
  ) {
    const result = store.replaceStream({
      instance,
      stream,
      method: METHOD,
      generation: 1,
      emittedAt: "2026-09-10T07:00:00.000Z",
      primaryKey: ["id"],
      envelopes: rows.map((data) => ({
        instance,
        stream,
        key: String(data.id),
        data,
        emitted_at: "2026-09-10T07:00:00.000Z",
      })),
      ...(sourceCollectedAt === null ? {} : { sourceCollectedAt }),
    });
    expect(result.applied).toBe(true);
  }

  const read = (
    scope: "strava.activities" | "strava.coverage_diagnostics",
    selection: CanonicalConnectionSelection,
  ) => readCanonicalLegacyScope({ store, scope, selection });

  it("serves both scopes the old export served, with every native field kept", async () => {
    const a = connect("conn_a");
    const rows = [
      activity("11", {
        average_heartrate: 141,
        gear: "Road bike",
        // Not in the pinned schema. The store and the signed ingest decide
        // what is admitted; the view must not drop what they kept.
        future_field: { nested: [1, null] },
      }),
      activity("12", { exported_at: null, freshness: "live" }),
    ];
    replace("conn_a", "activities", rows);
    replace("conn_a", "coverage_diagnostics", [diagnostic()]);

    const activities = await read("strava.activities", a);
    const diagnostics = await read("strava.coverage_diagnostics", a);

    expect(activities.ok && activities.envelope.data).toEqual(
      desktopScope("activities", rows),
    );
    expect(diagnostics.ok && diagnostics.envelope.data).toEqual(
      desktopScope("coverage_diagnostics", [diagnostic()]),
    );
    expect(activities.ok && activities.envelope.scope).toBe(
      "strava.activities",
    );
    expect(activities.ok && activities.envelope.collectedAt).toBe(
      COLLECTED_ISO,
    );
  });

  it("serves a partial coverage diagnostic as written and does not call the activities full", async () => {
    const a = connect("conn_a");
    replace("conn_a", "activities", [activity("11"), activity("12")]);
    replace("conn_a", "coverage_diagnostics", [
      diagnostic({ status: "partial", reason: "collection_interrupted" }),
    ]);

    const activities = await read("strava.activities", a);
    const diagnostics = await read("strava.coverage_diagnostics", a);

    expect(diagnostics.ok && diagnostics.envelope.data).toEqual({
      coverage_diagnostics: [
        diagnostic({ status: "partial", reason: "collection_interrupted" }),
      ],
    });
    // The activities body is rows only. It cannot say the export was read in
    // full, so the read must not claim it.
    expect(activities).toMatchObject({ ok: true, complete: false });
    expect(activities.ok && activities.diagnostics.unproven).toContainEqual(
      expect.objectContaining({
        stream: "activities",
        aspect: "collection_coverage",
      }),
    );
  });

  it("proves an empty scope only with that stream's own receipt", async () => {
    const a = connect("conn_a");
    replace("conn_a", "activities", [activity("11")]);

    // The producer returns without a diagnostic record when the import dir
    // exists and only diagnostics were requested. No row is not "empty".
    expect(await read("strava.coverage_diagnostics", a)).toMatchObject({
      ok: false,
      reason: "stream_completion_unknown",
      streams: ["coverage_diagnostics"],
    });

    replace("conn_a", "coverage_diagnostics", []);
    const empty = await read("strava.coverage_diagnostics", a);
    expect(empty).toMatchObject({ ok: true });
    expect(empty.ok && empty.envelope.data).toEqual({
      coverage_diagnostics: [],
    });

    // A row written without a source time leaves no receipt.
    const b = connect("conn_b");
    replace("conn_b", "activities", [], null);
    expect(await read("strava.activities", b)).toMatchObject({
      ok: false,
    });
  });

  it("keeps two accounts of the same source apart", async () => {
    const a = connect("conn_a");
    const b = connect("conn_b");
    replace("conn_a", "activities", [activity("11")]);
    replace("conn_b", "activities", [activity("21"), activity("22")]);

    const readA = await read("strava.activities", a);
    const readB = await read("strava.activities", b);

    expect(
      readA.ok &&
        (readA.envelope.data.activities as { id: string }[]).map((r) => r.id),
    ).toEqual(["11"]);
    expect(
      readB.ok &&
        (readB.envelope.data.activities as { id: string }[]).map((r) => r.id),
    ).toEqual(["21", "22"]);
  });

  describe("record order", () => {
    // Desktop kept the snapshot in arrival order: a full refresh appends in
    // emit order, and a re-emitted key moves to the end. The store keeps
    // (emitted_at, record_key) and the view sorts by key, so arrival order
    // is gone before the reader runs. Keys that are not sequential strings
    // make the two orders differ.
    const arrival = ["100", "9", "2000000000", "21", "3"];
    const byKey = ["100", "2000000000", "21", "3", "9"];

    it("returns the same rows in key order and says the old order is unproven", async () => {
      const a = connect("conn_a");
      replace(
        "conn_a",
        "activities",
        arrival.map((id) => activity(id)),
      );

      const result = await read("strava.activities", a);
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      const ids = (result.envelope.data.activities as { id: string }[]).map(
        (r) => r.id,
      );

      expect([...ids].sort()).toEqual([...arrival].sort());
      expect(ids).toEqual(byKey);
      expect(ids).not.toEqual(arrival);
      expect(result.complete).toBe(false);
      expect(result.diagnostics.unproven).toContainEqual(
        expect.objectContaining({
          stream: "activities",
          aspect: "record_order",
        }),
      );
    });

    it("makes no order claim for fewer than two rows", async () => {
      const a = connect("conn_a");
      replace("conn_a", "coverage_diagnostics", [diagnostic()]);
      replace("conn_a", "activities", [activity("11")]);

      const result = await read("strava.coverage_diagnostics", a);
      expect(result).toMatchObject({ ok: true, complete: true });
      expect(result.ok && result.diagnostics.unproven).toEqual([]);
    });
  });
});
