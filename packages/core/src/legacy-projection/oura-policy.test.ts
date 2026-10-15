import { readFileSync } from "node:fs";
import Ajv from "ajv";
import { describe, expect, it } from "vitest";
import { compareLegacyCoverage } from "../storage/legacy-scope-coverage.js";
import { projectPdppRecordsToLegacyPayload } from "./index.js";

type IntegerCase = {
  inputPath: string[];
  outputPath: string[];
  scope: "oura.activity" | "oura.readiness" | "oura.sleep";
  stream: "activity" | "readiness" | "sleep";
  profiles: (string | undefined)[];
};

const CASES: IntegerCase[] = [
  ...[
    ["score", "score"],
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
  ].map(([input, output]) => ({
    inputPath: [input!],
    outputPath: ["days", "0", output!],
    scope: "oura.activity" as const,
    stream: "activity" as const,
    profiles: [undefined, "oura-browser"],
  })),
  ...[
    "meet_daily_targets",
    "move_every_hour",
    "recovery_time",
    "stay_active",
    "training_frequency",
    "training_volume",
  ].map((field) => ({
    inputPath: ["contributors", field],
    outputPath: ["days", "0", "contributors", field],
    scope: "oura.activity" as const,
    stream: "activity" as const,
    profiles: [undefined, "oura-browser"],
  })),
  ...[
    "score",
    "contributors.activity_balance",
    "contributors.body_temperature",
    "contributors.hrv_balance",
    "contributors.previous_day_activity",
    "contributors.previous_night",
    "contributors.recovery_index",
    "contributors.resting_heart_rate",
    "contributors.sleep_balance",
  ].map((field) => ({
    inputPath: field.split("."),
    outputPath: ["days", "0", ...field.split(".")],
    scope: "oura.readiness" as const,
    stream: "readiness" as const,
    profiles: [undefined, "oura-browser"],
  })),
  ...[
    ["sleep_score", "dailyScores", "score"],
    ["contributors.deep_sleep", "dailyScores", "contributors.deep_sleep"],
    ["contributors.efficiency", "dailyScores", "contributors.efficiency"],
    ["contributors.latency", "dailyScores", "contributors.latency"],
    ["contributors.rem_sleep", "dailyScores", "contributors.rem_sleep"],
    ["contributors.restfulness", "dailyScores", "contributors.restfulness"],
    ["contributors.timing", "dailyScores", "contributors.timing"],
    ["contributors.total_sleep", "dailyScores", "contributors.total_sleep"],
    ["total_sleep_duration", "sleepPeriods", "totalSleepDuration"],
    ["time_in_bed", "sleepPeriods", "timeInBed"],
    ["deep_sleep_duration", "sleepPeriods", "deepSleepDuration"],
    ["light_sleep_duration", "sleepPeriods", "lightSleepDuration"],
    ["rem_sleep_duration", "sleepPeriods", "remSleepDuration"],
    ["efficiency", "sleepPeriods", "efficiency"],
    ["latency", "sleepPeriods", "latency"],
    ["average_hrv", "sleepPeriods", "averageHrv"],
    ["lowest_heart_rate", "sleepPeriods", "lowestHeartRate"],
    ["restless_periods", "sleepPeriods", "restlessPeriods"],
  ].map(([input, collection, output]) => ({
    inputPath: input!.split("."),
    outputPath: [collection!, "0", ...output!.split(".")],
    scope: "oura.sleep" as const,
    stream: "sleep" as const,
    profiles: [undefined, "oura-browser"],
  })),
  {
    inputPath: ["awake_time"],
    outputPath: ["sleepPeriods", "0", "awakeTime"],
    scope: "oura.sleep",
    stream: "sleep",
    profiles: ["oura-browser"],
  },
];

function setPath(
  target: Record<string, unknown>,
  path: string[],
  value: unknown,
): void {
  let cursor = target;
  for (const segment of path.slice(0, -1)) {
    cursor[segment] ??= {};
    cursor = cursor[segment] as Record<string, unknown>;
  }
  cursor[path.at(-1)!] = value;
}

function getPath(target: Record<string, unknown>, path: string[]): unknown {
  let cursor: unknown = target;
  for (const segment of path) {
    if (cursor === null || typeof cursor !== "object") return undefined;
    cursor = (cursor as Record<string, unknown>)[segment];
  }
  return cursor;
}

function project(
  testCase: IntegerCase,
  value: number,
  profileKey?: string,
): { canonical: Record<string, unknown>; payload: Record<string, unknown> } {
  const canonical: Record<string, unknown> = {
    id: "oura-1",
    day: "2026-10-01",
    score: 80,
    sleep_score: 80,
    type: "long_sleep",
    sleep_score: 80,
    record_type:
      testCase.scope === "oura.sleep" &&
      testCase.outputPath[0] === "dailyScores"
        ? "daily_score"
        : "sleep_session",
  };
  setPath(canonical, testCase.inputPath, value);
  const frozenBefore = structuredClone(canonical);
  const result = projectPdppRecordsToLegacyPayload(
    testCase.scope,
    [{ stream: testCase.stream, data: canonical }],
    {
      fetchedStreams: [testCase.stream],
      ...(profileKey ? { profileKey } : {}),
    },
  );
  expect(result.ok).toBe(true);
  expect(canonical).toEqual(frozenBefore);
  if (!result.ok) throw new Error("Oura projection failed unexpectedly");
  return { canonical, payload: result.payload };
}

function schemaFor(scope: IntegerCase["scope"]): Record<string, unknown> {
  return JSON.parse(
    readFileSync(
      new URL(`./legacy-schemas/${scope}.json`, import.meta.url),
      "utf8",
    ),
  ) as Record<string, unknown>;
}

const ajv = new Ajv({ allErrors: true });

function expectSchemaValid(
  scope: IntegerCase["scope"],
  payload: Record<string, unknown>,
): void {
  const validate = ajv.compile(schemaFor(scope).schema!);
  expect(validate(payload), JSON.stringify(validate.errors)).toBe(true);
}

describe("Oura legacy projection policy", () => {
  it.each(CASES)("rounds integer field $scope $outputPath", (testCase) => {
    for (const profileKey of testCase.profiles) {
      const samples: [number, number][] =
        testCase.outputPath.at(-1) === "score"
          ? [
              [1.5, 2],
              [1.49, 1],
            ]
          : [
              [1.5, 2],
              [1.49, 1],
              [-1.5, -1],
            ];
      for (const [input, expected] of samples) {
        const { payload } = project(testCase, input as number, profileKey);
        const value = getPath(payload, testCase.outputPath);
        expect(value).toBe(expected);
        expectSchemaValid(testCase.scope, payload);
      }
    }
  });

  it("checks score bounds after Math.round, including negative zero", () => {
    for (const testCase of CASES.filter(
      ({ outputPath }) => outputPath.at(-1) === "score",
    )) {
      for (const profileKey of testCase.profiles) {
        const nearZero = project(testCase, -0.49, profileKey).payload;
        expect(Object.is(getPath(nearZero, testCase.outputPath), -0)).toBe(
          true,
        );
        expectSchemaValid(testCase.scope, nearZero);

        const nearMaximum = project(testCase, 100.49, profileKey).payload;
        expect(getPath(nearMaximum, testCase.outputPath)).toBe(100);
        expectSchemaValid(testCase.scope, nearMaximum);

        const aboveMaximum = project(testCase, 100.5, profileKey).payload;
        expect(getPath(aboveMaximum, testCase.outputPath)).toBeUndefined();
        expectSchemaValid(testCase.scope, aboveMaximum);
      }
    }
  });

  it.each([
    {
      scope: "oura.readiness" as const,
      stream: "readiness" as const,
      collection: "days",
      records: [
        { id: "whole", day: "2026-10-01", score: 80.0 },
        { id: "half", day: "2026-10-02", score: 79.5 },
        { id: "fraction", day: "2026-10-03", score: 80.49 },
        { id: "null", day: "2026-10-04", score: null },
      ],
      expected: [
        { id: "whole", day: "2026-10-01", score: 80 },
        { id: "half", day: "2026-10-02", score: 80 },
        { id: "fraction", day: "2026-10-03", score: 80 },
      ],
    },
    {
      scope: "oura.sleep" as const,
      stream: "sleep" as const,
      collection: "dailyScores",
      records: [
        {
          id: "whole",
          day: "2026-10-01",
          record_type: "daily_score",
          sleep_score: 80.0,
        },
        {
          id: "half",
          day: "2026-10-02",
          record_type: "daily_score",
          sleep_score: 79.5,
        },
        {
          id: "fraction",
          day: "2026-10-03",
          record_type: "daily_score",
          sleep_score: 80.49,
        },
        {
          id: "null",
          day: "2026-10-04",
          record_type: "daily_score",
          sleep_score: null,
        },
      ],
      expected: [
        { id: "whole", day: "2026-10-01", score: 80 },
        { id: "half", day: "2026-10-02", score: 80 },
        { id: "fraction", day: "2026-10-03", score: 80 },
      ],
    },
  ])(
    "serializes $scope $collection scores as integer JSON numbers",
    (testCase) => {
      for (const profileKey of [undefined, "oura-browser"]) {
        const canonicalBefore = structuredClone(testCase.records);
        const result = projectPdppRecordsToLegacyPayload(
          testCase.scope,
          testCase.records.map((data) => ({ stream: testCase.stream, data })),
          {
            fetchedStreams: [testCase.stream],
            ...(profileKey ? { profileKey } : {}),
          },
        );
        expect(testCase.records).toEqual(canonicalBefore);
        expect(result.ok).toBe(true);
        if (!result.ok) throw new Error("Oura projection failed unexpectedly");

        const entries = result.payload[testCase.collection];
        expect(entries).toEqual(testCase.expected);
        expect(JSON.stringify(entries)).toBe(JSON.stringify(testCase.expected));
        expect(
          (entries as { score: number }[]).every(({ score }) =>
            Number.isInteger(score),
          ),
        ).toBe(true);
        expectSchemaValid(testCase.scope, result.payload);
      }
    },
  );

  it("omits sleep type values outside the frozen enum and null types", () => {
    for (const profileKey of [undefined, "oura-browser"]) {
      for (const type of ["awake", null]) {
        const result = projectPdppRecordsToLegacyPayload(
          "oura.sleep",
          [
            {
              stream: "sleep",
              data: {
                id: "session-1",
                day: "2026-10-01",
                sleep_score: 80,
                type,
                record_type: "sleep_session",
              },
            },
          ],
          {
            fetchedStreams: ["sleep"],
            ...(profileKey ? { profileKey } : {}),
          },
        );
        expect(result).toMatchObject({
          ok: true,
          payload: {
            sleepPeriods: [{ id: "session-1", day: "2026-10-01" }],
          },
        });
        if (result.ok) {
          expect(result.payload.sleepPeriods).not.toHaveProperty("0.type");
          expectSchemaValid("oura.sleep", result.payload);
        }
      }
    }
  });

  it("omits a null browser daily sleep timestamp", () => {
    const result = projectPdppRecordsToLegacyPayload(
      "oura.sleep",
      [
        {
          stream: "sleep",
          data: {
            id: "score-1",
            day: "2026-10-01",
            record_type: "daily_score",
            sleep_score: 80,
            daily_sleep_timestamp: null,
          },
        },
      ],
      { fetchedStreams: ["sleep"], profileKey: "oura-browser" },
    );
    expect(result).toMatchObject({
      ok: true,
      payload: {
        dailyScores: [{ id: "score-1", day: "2026-10-01", score: 80 }],
      },
    });
    if (result.ok) {
      expect(result.payload.dailyScores).not.toHaveProperty("0.timestamp");
      expectSchemaValid("oura.sleep", result.payload);
    }
  });

  it("keeps normal integer values and known sleep types unchanged", () => {
    const result = projectPdppRecordsToLegacyPayload(
      "oura.sleep",
      [
        {
          stream: "sleep",
          data: {
            id: "session-1",
            day: "2026-10-01",
            record_type: "sleep_session",
            sleep_score: 80,
            type: "long_sleep",
            total_sleep_duration: 3600,
            average_hrv: 42,
            record_type: "sleep_session",
          },
        },
      ],
      { fetchedStreams: ["sleep"] },
    );
    expect(result).toMatchObject({
      ok: true,
      payload: {
        dailyScores: [{ score: 80 }],
        sleepPeriods: [
          {
            type: "long_sleep",
            totalSleepDuration: 3600,
            averageHrv: 42,
          },
        ],
      },
    });

    const browserResult = projectPdppRecordsToLegacyPayload(
      "oura.sleep",
      [
        {
          stream: "sleep",
          data: {
            id: "score-1",
            day: "2026-10-01",
            record_type: "daily_score",
            sleep_score: 80,
            daily_sleep_timestamp: "2026-10-01T00:00:00Z",
          },
        },
      ],
      { fetchedStreams: ["sleep"], profileKey: "oura-browser" },
    );
    expect(browserResult).toMatchObject({
      ok: true,
      payload: {
        dailyScores: [
          {
            id: "score-1",
            score: 80,
            timestamp: "2026-10-01T00:00:00Z",
          },
        ],
      },
    });
  });

  it("keeps rounded values parity-covered and permits policy omissions", () => {
    const projected = project(CASES[4]!, 12.5).payload;
    const legacy = {
      days: [
        {
          id: "oura-1",
          day: "2026-10-01",
          score: 80,
          equivalentWalkingDistance: 13,
        },
      ],
    };
    expect(
      compareLegacyCoverage(legacy, projected, {
        scope: "oura.activity",
        entityKeys: { "$.days": ["id"] },
      }).covered,
    ).toBe(true);

    const sleep = {
      dailyScores: [
        {
          id: "score-1",
          day: "2026-10-01",
          score: 80,
          timestamp: "2026-10-01T00:00:00Z",
        },
      ],
      sleepPeriods: [
        { id: "session-1", day: "2026-10-01", type: "long_sleep" },
      ],
    };
    const omitted = {
      dailyScores: [{ id: "score-1", day: "2026-10-01", score: 80 }],
      sleepPeriods: [{ id: "session-1", day: "2026-10-01" }],
    };
    const verdict = compareLegacyCoverage(sleep, omitted, {
      scope: "oura.sleep",
      entityKeys: {
        "$.dailyScores": ["id"],
        "$.sleepPeriods": ["id"],
      },
    });
    expect(verdict.covered).toBe(true);
    expect(verdict.appliedExceptions.map(({ path }) => path)).toEqual(
      expect.arrayContaining([
        "$.dailyScores[].timestamp",
        "$.sleepPeriods[].type",
      ]),
    );
  });

  it("keeps null-score row omissions covered by the parity comparator", () => {
    const cases = [
      ["oura.activity", "days"],
      ["oura.readiness", "days"],
      ["oura.sleep", "dailyScores"],
    ] as const;
    for (const [scope, collection] of cases) {
      const verdict = compareLegacyCoverage(
        {
          [collection]: [{ id: "null-score", day: "2026-10-01", score: null }],
        },
        { [collection]: [] },
        {
          scope,
          entityKeys: { [`$.${collection}`]: ["id"] },
        },
      );
      expect(verdict.covered).toBe(true);
      expect(verdict.appliedExceptions).toContainEqual(
        expect.objectContaining({ path: `$.${collection}[]` }),
      );
    }
  });
});
