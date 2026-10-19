import {
  LEGACY_SCOPE_BINDINGS,
  OURA_SLEEP_CONTRIBUTOR_INTEGERS,
  ouraInteger,
  ouraSleepPeriod,
  withOuraContributors,
  partitionOuraRows,
} from "./bindings.js";
import type { LegacyScopeBinding, ProjectionResult } from "./types.js";

// API v2 field parity follows data-connectors PR #504 at e04efd50c.
// The checked-in OCI provenance still pins the earlier signed 0.1.2 profile.
const source = "https://registry.pdpp.dev/connectors/oura-browser";
const digest =
  "sha256:ddc901015996e4ae67030bcd9ec809aa368b1b69d94b8ed5515d1be0a886975d";

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
                      !item.startsWith("sleepPeriods.type:"),
                  )
                : original.lossy.filter(
                    (item) => !item.startsWith("timestamp:"),
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
              // Day and score rules are the base profile's: an impossible day
              // or a missing/malformed score drops and counts the row.
              if (stream !== "sleep") {
                const projected = original.project(records, options);
                if (!projected.ok) return projected;
                const days = projected.payload.days as Record<
                  string,
                  unknown
                >[];
                const sourceById = new Map(
                  streamRecords.map(({ data }) => [data.id, data]),
                );
                return {
                  ...projected,
                  payload: {
                    ...projected.payload,
                    days: days.map((day) => ({
                      ...day,
                      ...(sourceById.get(day.id)?.timestamp === undefined
                        ? {}
                        : { timestamp: sourceById.get(day.id)?.timestamp }),
                      contributors: day.contributors ?? {},
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
              );
              const sessions = rows.filter(
                (row) => row.record_type === "sleep_session",
              );
              const scores = rows.filter(
                (row) => row.record_type === "daily_score",
              );
              const sleepPeriods = sessions.map((session) => ({
                ...ouraSleepPeriod(session),
                ...(session.type === undefined ? {} : { type: session.type }),
                ...(session.bedtime_start === undefined
                  ? {}
                  : { bedtimeStart: session.bedtime_start }),
                ...(session.bedtime_end === undefined
                  ? {}
                  : { bedtimeEnd: session.bedtime_end }),
                ...(session.average_hrv === undefined
                  ? {}
                  : { averageHrv: session.average_hrv }),
                ...(typeof session.awake_time === "number" ||
                session.awake_time === null
                  ? { awakeTime: ouraInteger(session.awake_time) }
                  : {}),
              }));
              const dailyScores = scores.map((data) => ({
                id:
                  typeof data.daily_sleep_id === "string"
                    ? data.daily_sleep_id
                    : data.id,
                day: data.day,
                score: ouraInteger(data.sleep_score),
                ...(data.daily_sleep_timestamp === undefined
                  ? {}
                  : { timestamp: data.daily_sleep_timestamp }),
                ...withOuraContributors(
                  data.contributors,
                  OURA_SLEEP_CONTRIBUTOR_INTEGERS,
                ),
                ...(!data.contributors || typeof data.contributors !== "object"
                  ? { contributors: {} }
                  : {}),
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
