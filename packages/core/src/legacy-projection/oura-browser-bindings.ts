import { LEGACY_SCOPE_BINDINGS, partitionOuraRows } from "./bindings.js";
import type { LegacyScopeBinding, ProjectionResult } from "./types.js";

// API v2 field parity follows data-connectors PR #504 at e04efd50c.
// The checked-in OCI provenance still pins the earlier signed 0.1.2 profile.
const source = "https://registry.pdpp.dev/connectors/oura-browser";
const digest =
  "sha256:ddc901015996e4ae67030bcd9ec809aa368b1b69d94b8ed5515d1be0a886975d";

function isBrowserScore(value: unknown): boolean {
  return (
    value === null ||
    (typeof value === "number" &&
      Number.isFinite(value) &&
      value >= 0 &&
      value <= 100)
  );
}

function legacyFields(
  row: Record<string, unknown>,
  fields: ReadonlyArray<readonly [string, string]>,
): Record<string, unknown> {
  return Object.fromEntries(
    fields
      .filter(([source]) => row[source] !== undefined)
      .map(([source, target]) => [target, row[source]]),
  );
}

function legacyContributors(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

const activityFields = [
  ["active_calories", "activeCalories"],
  ["total_calories", "totalCalories"],
  ["steps", "steps"],
  ["equivalent_walking_distance", "equivalentWalkingDistance"],
  ["high_activity_time", "highActivityTime"],
  ["medium_activity_time", "mediumActivityTime"],
  ["low_activity_time", "lowActivityTime"],
  ["sedentary_time", "sedentaryTime"],
  ["resting_time", "restingTime"],
  ["inactivity_alerts", "inactivityAlerts"],
] as const;

const readinessFields = [
  ["temperature_deviation", "temperatureDeviation"],
  ["temperature_trend_deviation", "temperatureTrendDeviation"],
] as const;

const sleepPeriodFields = [
  ["type", "type"],
  ["bedtime_start", "bedtimeStart"],
  ["bedtime_end", "bedtimeEnd"],
  ["total_sleep_duration", "totalSleepDuration"],
  ["time_in_bed", "timeInBed"],
  ["awake_time", "awakeTime"],
  ["deep_sleep_duration", "deepSleepDuration"],
  ["light_sleep_duration", "lightSleepDuration"],
  ["rem_sleep_duration", "remSleepDuration"],
  ["efficiency", "efficiency"],
  ["latency", "latency"],
  ["average_heart_rate", "averageHeartRate"],
  ["average_hrv", "averageHrv"],
  ["lowest_heart_rate", "lowestHeartRate"],
  ["average_breath", "averageBreath"],
  ["restless_periods", "restlessPeriods"],
] as const;

export const OURA_BROWSER_BINDINGS: ReadonlyMap<string, LegacyScopeBinding> =
  new Map(
    ["activity", "readiness", "sleep"].map(
      (stream): [string, LegacyScopeBinding] => {
        const scope = `oura.${stream}`;
        const original = LEGACY_SCOPE_BINDINGS.get(scope);
        if (!original)
          throw new Error(`Missing retained Oura binding: ${scope}`);
        return [
          scope,
          {
            ...original,
            pdppSource: source,
            fieldsRead:
              stream === "sleep"
                ? {
                    sleep: [
                      "record_type",
                      "id",
                      "day",
                      "sleep_score",
                      "daily_sleep_id",
                      "daily_sleep_timestamp",
                      "contributors",
                      "type",
                      "bedtime_start",
                      "bedtime_end",
                      "total_sleep_duration",
                      "time_in_bed",
                      "awake_time",
                      "deep_sleep_duration",
                      "light_sleep_duration",
                      "rem_sleep_duration",
                      "efficiency",
                      "latency",
                      "average_heart_rate",
                      "average_hrv",
                      "lowest_heart_rate",
                      "average_breath",
                      "restless_periods",
                    ],
                  }
                : {
                    [stream]: [
                      ...(original.fieldsRead[stream] ?? []),
                      "timestamp",
                    ],
                  },
            lossy:
              stream === "sleep"
                ? original.lossy.filter(
                    (item) =>
                      !item.startsWith("awakeTime:") &&
                      !item.startsWith("dailyScores.timestamp:") &&
                      !item.startsWith("sleepPeriods.averageHrv:") &&
                      !item.startsWith("sleepPeriods.type:") &&
                      !item.startsWith("Legacy integer fields:"),
                  )
                : original.lossy.filter(
                    (item) =>
                      !item.startsWith("timestamp:") &&
                      !item.startsWith("Legacy integer fields:"),
                  ),
            provenance: [
              {
                kind: "oci" as const,
                ref: "ghcr.io/pdp-connect/connector/oura-browser:0.1.2",
                digest,
                path: `collection-profile.json#streams[name=${stream}]`,
              },
            ],
            project(records, options): ProjectionResult {
              if (!options.fetchedStreams.includes(stream)) {
                return {
                  ok: false,
                  error: {
                    kind: "missing_stream",
                    scope,
                    expectedStream: stream,
                  },
                };
              }
              const streamRecords = records.filter(
                (record) => record.stream === stream,
              );
              for (const { data } of streamRecords) {
                if (
                  typeof data.id !== "string" ||
                  !data.id.trim() ||
                  (stream === "sleep" &&
                    data.record_type !== "sleep_session" &&
                    data.record_type !== "daily_score")
                ) {
                  return {
                    ok: false,
                    error: {
                      kind: "incomplete_scope",
                      scope,
                      reason: `${stream} record lacks a required retained field`,
                    },
                  };
                }
              }
              // Keep valid calendar days and scores in the legacy 0–100 range,
              // then copy source numbers unchanged as the browser script does.
              if (stream !== "sleep") {
                const { rows, diagnostics } = partitionOuraRows(
                  scope,
                  stream,
                  streamRecords.map(({ data }) => data),
                  () => "score",
                  isBrowserScore,
                );
                return {
                  ok: true,
                  ...(diagnostics.length > 0 ? { diagnostics } : {}),
                  payload: {
                    days: rows.map((row) => ({
                      id: row.id,
                      day: row.day,
                      score: row.score,
                      ...legacyFields(
                        row,
                        stream === "activity"
                          ? activityFields
                          : readinessFields,
                      ),
                      ...legacyFields(row, [["timestamp", "timestamp"]]),
                      contributors: legacyContributors(row.contributors),
                    })),
                  },
                };
              }

              // A session row produces no daily score here, so only its day
              // is checked; each daily_score row must carry the legacy score.
              const { rows, diagnostics } = partitionOuraRows(
                scope,
                stream,
                streamRecords.map(({ data }) => data),
                (row) =>
                  row.record_type === "daily_score" ? "sleep_score" : undefined,
                isBrowserScore,
              );
              const sessions = rows.filter(
                (row) => row.record_type === "sleep_session",
              );
              const scores = rows.filter(
                (row) => row.record_type === "daily_score",
              );
              const sleepPeriods = sessions.map((session) => ({
                id: session.id,
                day: session.day,
                ...legacyFields(session, sleepPeriodFields),
              }));
              const dailyScores = scores.map((data) => ({
                id:
                  typeof data.daily_sleep_id === "string"
                    ? data.daily_sleep_id
                    : data.id,
                day: data.day,
                score: data.sleep_score,
                ...(data.daily_sleep_timestamp === undefined
                  ? {}
                  : { timestamp: data.daily_sleep_timestamp }),
                contributors: legacyContributors(data.contributors),
              }));
              return {
                ok: true,
                payload: { dailyScores, sleepPeriods },
                ...(diagnostics.length > 0 ? { diagnostics } : {}),
              };
            },
          },
        ];
      },
    ),
  );
