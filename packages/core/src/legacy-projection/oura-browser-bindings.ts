import { LEGACY_SCOPE_BINDINGS } from "./bindings.js";
import type { LegacyScopeBinding, ProjectionResult } from "./types.js";

// Map signed Oura Browser 0.1.2 records into the retained legacy scopes.
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
                : original.fieldsRead,
            lossy:
              stream === "sleep"
                ? original.lossy.filter(
                    (item) =>
                      !item.startsWith("awakeTime:") &&
                      !item.startsWith("dailyScores.timestamp:"),
                  )
                : original.lossy,
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
                  typeof data.day !== "string" ||
                  !/^\d{4}-\d{2}-\d{2}$/.test(data.day) ||
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
              if (stream !== "sleep") return original.project(records, options);

              const sessions = streamRecords.filter(
                ({ data }) => data.record_type === "sleep_session",
              );
              const scores = streamRecords.filter(
                ({ data }) => data.record_type === "daily_score",
              );
              const sessionRecords = records.filter(
                (record) =>
                  record.stream !== "sleep" ||
                  record.data.record_type === "sleep_session",
              );
              const projected = original.project(sessionRecords, options);
              if (!projected.ok) return projected;

              const sessionById = new Map(
                sessions.map(({ data }) => [data.id, data]),
              );
              const sleepPeriods = Array.isArray(projected.payload.sleepPeriods)
                ? projected.payload.sleepPeriods.map((period) => {
                    if (
                      !period ||
                      typeof period !== "object" ||
                      Array.isArray(period)
                    )
                      return period;
                    const sourceSession = sessionById.get(
                      (period as Record<string, unknown>).id,
                    );
                    if (
                      !sourceSession ||
                      !(
                        typeof sourceSession.awake_time === "number" ||
                        sourceSession.awake_time === null
                      )
                    )
                      return period;
                    return {
                      ...(period as Record<string, unknown>),
                      awakeTime: sourceSession.awake_time,
                    };
                  })
                : projected.payload.sleepPeriods;
              const dailyScores = scores.map(({ data }) => ({
                id:
                  typeof data.daily_sleep_id === "string"
                    ? data.daily_sleep_id
                    : data.id,
                day: data.day,
                ...(typeof data.sleep_score === "number" ||
                data.sleep_score === null
                  ? { score: data.sleep_score }
                  : {}),
                ...(typeof data.daily_sleep_timestamp === "string"
                  ? { timestamp: data.daily_sleep_timestamp }
                  : {}),
                ...(data.contributors && typeof data.contributors === "object"
                  ? { contributors: data.contributors }
                  : {}),
              }));
              return {
                ...projected,
                payload: { ...projected.payload, dailyScores, sleepPeriods },
              };
            },
          },
        ];
      },
    ),
  );
