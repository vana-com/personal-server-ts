import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { diffBodies } from "../legacy-projection/__fixtures__/parity/diff.js";
import {
  ingestBinaryDataContract,
  ingestDataContract,
} from "../contracts/data.js";
import type { DataStoragePort } from "../ports/index.js";
import type { WriterAttribution } from "../write/attribution.js";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";
import {
  classifyStoredBody,
  legacyScopesProjectedFrom,
  supersedeLegacyVersions,
  withLegacyProjection,
  type LegacyProjectionIssue,
} from "./legacy-projection.js";

const conversation = {
  id: "conv-1",
  title: "Trip plan",
  create_time: "2026-09-01T10:00:00Z",
  update_time: "2026-09-01T10:05:00Z",
  current_node: "m2",
  message_count_on_current_branch: 2,
};
const messages = [
  {
    id: "m2",
    conversation_id: "conv-1",
    parent_id: "m1",
    role: "assistant",
    content: "Take the train.",
    content_type: "text",
    model_slug: "gpt-5",
    create_time: "2026-09-01T10:02:00Z",
    on_current_branch: true,
  },
  {
    id: "m1",
    conversation_id: "conv-1",
    parent_id: null,
    role: "user",
    content: "How do I get to Lyon?",
    content_type: "text",
    model_slug: null,
    create_time: "2026-09-01T10:01:00Z",
    on_current_branch: true,
  },
];

async function store(
  storage: DataStoragePort,
  scope: string,
  collectedAt: string,
  body: Record<string, unknown>,
  attribution?: WriterAttribution,
) {
  const result = await ingestDataContract({
    storage,
    scopeParam: scope,
    body,
    collectedAt,
    status: "stored",
    attribution,
  });
  if (!result.ok) throw new Error(JSON.stringify(result.body));
}

describe("classifyStoredBody", () => {
  it.each([
    ["chatgpt.conversations", { records: [] }, "pdpp-projected"],
    ["claude.projects", { records: [{ id: "p" }] }, "pdpp-projected"],
    ["chatgpt.messages", { records: [] }, "pdpp-unprojected"],
    ["oura.sleep", { records: [] }, "pdpp-projected"],
    ["github.repositories", { records: [] }, "pdpp-unprojected"],
    ["chatgpt.conversations", { conversations: [], total: 0 }, "legacy"],
    ["chatgpt.conversations", { records: [], total: 0 }, "legacy"],
    ["chatgpt.conversations", { records: {} }, "legacy"],
    ["chatgpt.conversations", [], "legacy"],
    [
      "chatgpt.conversations",
      { exportSummary: {}, timestamp: "t", version: "1", platform: "web" },
      "legacy",
    ],
    [
      "chatgpt.conversations",
      { records: [], $writtenBy: { builder: "0x1" } },
      "pdpp-projected",
    ],
    [
      "chatgpt.conversations",
      { records: [{ stream: "conversations", data: { id: "c" } }] },
      "pdpp-unprojected",
    ],
  ])("%s %j is %s", (scope, data, form) => {
    expect(classifyStoredBody(scope, data)).toBe(form);
  });
});

describe("legacyScopesProjectedFrom", () => {
  it.each([
    ["chatgpt.messages", ["chatgpt.conversations"]],
    ["chatgpt.conversations", []],
    ["claude.account_profile", ["claude.conversations", "claude.projects"]],
    ["claude.project_documents", ["claude.projects"]],
    ["oura.sleep", []],
    ["notes", []],
  ])("%s → %j", (scope, expected) => {
    expect(legacyScopesProjectedFrom(scope).sort()).toEqual(expected);
  });
});

describe("withLegacyProjection", () => {
  it("emits the legacy empty contributors object when an Oura API row omits it", async () => {
    const raw = createMemoryDataStorage();
    const at = "2026-10-01T00:00:00Z";
    await store(raw, "oura.activity", at, {
      records: [
        {
          id: "a",
          day: "2026-09-01",
          score: 80,
        },
      ],
    });
    await store(raw, "oura.sleep", at, {
      records: [
        {
          id: "s",
          day: "2026-09-01",
          record_type: "daily_score",
          sleep_score: 82,
        },
      ],
    });
    const served = withLegacyProjection(raw);
    expect((await served.readEnvelope("oura.activity", at)).data).toEqual({
      days: [{ id: "a", day: "2026-09-01", score: 80, contributors: {} }],
    });
    expect((await served.readEnvelope("oura.sleep", at)).data).toEqual({
      dailyScores: [
        { id: "s", day: "2026-09-01", score: 82, contributors: {} },
      ],
      sleepPeriods: [],
    });
  });

  it("projects the data-connectors API v2 replay fixture through the served port", async () => {
    const fixture = JSON.parse(
      readFileSync(
        new URL("./__fixtures__/oura-api-v2-replay.json", import.meta.url),
        "utf8",
      ),
    ) as Record<string, Record<string, unknown>[]>;
    const raw = createMemoryDataStorage();
    const at = "2026-10-01T00:00:00Z";
    await store(raw, "oura.readiness", at, {
      records: fixture.daily_readiness,
    });
    await store(raw, "oura.activity", at, { records: fixture.daily_activity });
    await store(raw, "oura.sleep", at, {
      records: [
        ...fixture.sleep.map((session) => ({
          ...session,
          record_type: "sleep_session",
        })),
        ...fixture.daily_sleep.map((score) => ({
          record_type: "daily_score",
          id: score.id,
          day: score.day,
          daily_sleep_id: score.id,
          sleep_score: score.score,
          daily_sleep_timestamp: score.timestamp,
          contributors: score.contributors,
        })),
      ],
    });
    const served = withLegacyProjection(raw);
    expect(
      (await served.readEnvelope("oura.readiness", at)).data,
    ).toMatchObject({
      days: [
        {
          id: fixture.daily_readiness[0].id,
          timestamp: "2026-09-23T08:15:00+00:00",
          temperatureDeviation: 0.2,
          temperatureTrendDeviation: 0.1,
        },
      ],
    });
    expect((await served.readEnvelope("oura.activity", at)).data).toMatchObject(
      {
        days: [
          {
            id: fixture.daily_activity[0].id,
            timestamp: "2026-09-23T08:15:00+00:00",
            activeCalories: 250,
            equivalentWalkingDistance: 3800,
          },
        ],
      },
    );
    expect((await served.readEnvelope("oura.sleep", at)).data).toEqual({
      dailyScores: [
        {
          id: fixture.daily_sleep[0].id,
          day: "2026-09-23",
          score: 88,
          timestamp: "2026-09-23T08:15:00+00:00",
          contributors: { efficiency: 91 },
        },
      ],
      sleepPeriods: [
        {
          id: fixture.sleep[0].id,
          day: "2026-09-23",
          type: "long_sleep",
          bedtimeStart: "2026-09-22T22:00:00+00:00",
          bedtimeEnd: "2026-09-23T06:00:00+00:00",
          totalSleepDuration: 28000,
          timeInBed: 29000,
          deepSleepDuration: 7200,
          lightSleepDuration: 12300,
          remSleepDuration: 8500,
          awakeTime: 1200,
          efficiency: 96,
          latency: 500,
          averageHeartRate: 58,
          averageHrv: 42,
          lowestHeartRate: 51,
          averageBreath: 14,
          restlessPeriods: 3,
        },
      ],
    });
  });

  it("serves every Oura API v2 field in the legacy shapes without changing stored records", async () => {
    const raw = createMemoryDataStorage();
    const at = "2026-10-01T00:00:00Z";
    const readiness = {
      id: "readiness-1",
      day: "2026-09-01",
      score: 85,
      timestamp: "2026-09-01T07:00:00Z",
      temperature_deviation: 0.2,
      temperature_trend_deviation: -0.1,
      contributors: { hrv_balance: 81 },
    };
    const activity = {
      id: "activity-1",
      day: "2026-09-01",
      score: 82,
      timestamp: "2026-09-01T23:59:00Z",
      active_calories: 420,
      total_calories: 2100,
      steps: 8500,
      equivalent_walking_distance: 6200,
      high_activity_time: 900,
      medium_activity_time: 1800,
      low_activity_time: 2700,
      sedentary_time: 3600,
      resting_time: 1800,
      inactivity_alerts: 1,
      contributors: { stay_active: 79 },
    };
    const score = {
      record_type: "daily_score",
      id: "score-1",
      daily_sleep_id: "score-1",
      day: "2026-09-01",
      sleep_score: 83,
      daily_sleep_timestamp: "2026-09-01T07:15:00Z",
      contributors: { deep_sleep: 75 },
    };
    const period = {
      record_type: "sleep_session",
      id: "period-1",
      day: "2026-09-01",
      type: "new_sleep_type",
      bedtime_start: "2026-08-31T23:00:00Z",
      bedtime_end: "2026-09-01T07:00:00Z",
      total_sleep_duration: 26000,
      time_in_bed: 28800,
      deep_sleep_duration: 5000,
      light_sleep_duration: 12000,
      rem_sleep_duration: 9000,
      awake_time: 1200,
      efficiency: 90,
      latency: 600,
      average_heart_rate: 52.5,
      average_hrv: 45.75,
      lowest_heart_rate: 42,
      average_breath: 14.2,
      restless_periods: 2,
    };
    await store(raw, "oura.readiness", at, { records: [readiness] });
    await store(raw, "oura.activity", at, { records: [activity] });
    await store(raw, "oura.sleep", at, { records: [score, period] });
    const served = withLegacyProjection(raw);

    expect((await served.readEnvelope("oura.readiness", at)).data).toEqual({
      days: [
        {
          id: "readiness-1",
          day: "2026-09-01",
          score: 85,
          timestamp: "2026-09-01T07:00:00Z",
          temperatureDeviation: 0.2,
          temperatureTrendDeviation: -0.1,
          contributors: { hrv_balance: 81 },
        },
      ],
    });
    expect((await served.readEnvelope("oura.activity", at)).data).toEqual({
      days: [
        {
          id: "activity-1",
          day: "2026-09-01",
          score: 82,
          timestamp: "2026-09-01T23:59:00Z",
          activeCalories: 420,
          totalCalories: 2100,
          steps: 8500,
          equivalentWalkingDistance: 6200,
          highActivityTime: 900,
          mediumActivityTime: 1800,
          lowActivityTime: 2700,
          sedentaryTime: 3600,
          restingTime: 1800,
          inactivityAlerts: 1,
          contributors: { stay_active: 79 },
        },
      ],
    });
    expect((await served.readEnvelope("oura.sleep", at)).data).toEqual({
      dailyScores: [
        {
          id: "score-1",
          day: "2026-09-01",
          score: 83,
          timestamp: "2026-09-01T07:15:00Z",
          contributors: { deep_sleep: 75 },
        },
      ],
      sleepPeriods: [
        {
          id: "period-1",
          day: "2026-09-01",
          type: "new_sleep_type",
          bedtimeStart: "2026-08-31T23:00:00Z",
          bedtimeEnd: "2026-09-01T07:00:00Z",
          totalSleepDuration: 26000,
          timeInBed: 28800,
          deepSleepDuration: 5000,
          lightSleepDuration: 12000,
          remSleepDuration: 9000,
          awakeTime: 1200,
          efficiency: 90,
          latency: 600,
          averageHeartRate: 52.5,
          averageHrv: 45.75,
          lowestHeartRate: 42,
          averageBreath: 14.2,
          restlessPeriods: 2,
        },
      ],
    });
    expect((await raw.readEnvelope("oura.sleep", at)).data).toEqual({
      records: [score, period],
    });
    expect((await served.readStoredEnvelope!("oura.sleep", at)).data).toEqual({
      records: [score, period],
    });
    const nextAt = "2026-10-02T00:00:00Z";
    await store(raw, "oura.readiness", nextAt, {
      records: [{ ...readiness, score: 91 }],
    });
    expect(
      (await served.readEnvelope("oura.readiness", nextAt)).data,
    ).toMatchObject({
      days: [{ score: 91 }],
    });
    expect(
      (await served.readEnvelope("oura.readiness", at)).data,
    ).toMatchObject({
      days: [{ score: 85 }],
    });
  });

  it.each([
    ["2026-10-01T00:00:00Z", "2026-10-01T00:00:00.500Z"],
    ["2026-10-01T00:00:00.500Z", "2026-10-01T00:00:00Z"],
  ])(
    "uses the newest input instant for mixed formats (%s, %s)",
    async (own, sibling) => {
      const raw = createMemoryDataStorage();
      await store(raw, "chatgpt.conversations", own, {
        records: [conversation],
      });
      await store(raw, "chatgpt.messages", sibling, { records: messages });
      const envelope = await withLegacyProjection(raw).readEnvelope(
        "chatgpt.conversations",
        own,
      );
      expect(envelope.data).toMatchObject({
        conversations: [{ fetched_at: "2026-10-01T00:00:00.500Z" }],
      });
    },
  );

  it("serves chatgpt.conversations projected from the stored conversations and messages streams", async () => {
    const raw = createMemoryDataStorage();
    await store(raw, "chatgpt.messages", "2026-10-01T00:00:02.000Z", {
      records: messages,
    });
    await store(raw, "chatgpt.conversations", "2026-10-01T00:00:01.000Z", {
      records: [conversation],
    });
    const served = withLegacyProjection(raw);

    const envelope = await served.readEnvelope(
      "chatgpt.conversations",
      "2026-10-01T00:00:01.000Z",
    );

    expect(envelope.scope).toBe("chatgpt.conversations");
    expect(envelope.collectedAt).toBe("2026-10-01T00:00:01.000Z");
    expect(envelope.data).toEqual({
      conversations: [
        {
          id: "conv-1",
          title: "Trip plan",
          create_time: "2026-09-01T10:00:00Z",
          update_time: "2026-09-01T10:05:00Z",
          message_count: 2,
          messages: [
            {
              id: "m1",
              role: "user",
              content: "How do I get to Lyon?",
              content_type: "text",
              create_time: "2026-09-01T10:01:00Z",
              model: null,
            },
            {
              id: "m2",
              role: "assistant",
              content: "Take the train.",
              content_type: "text",
              create_time: "2026-09-01T10:02:00Z",
              model: "gpt-5",
            },
          ],
          // The newest input version, not the wall clock.
          fetched_at: "2026-10-01T00:00:02.000Z",
        },
      ],
      total: 1,
    });
  });

  it("leaves the raw port's stored body untouched", async () => {
    const raw = createMemoryDataStorage();
    await store(raw, "chatgpt.conversations", "2026-10-01T00:00:01.000Z", {
      records: [{ ...conversation, message_count_on_current_branch: 0 }],
    });
    const before = JSON.stringify(
      await raw.readEnvelope(
        "chatgpt.conversations",
        "2026-10-01T00:00:01.000Z",
      ),
    );
    const served = withLegacyProjection(raw);
    await served.readEnvelope(
      "chatgpt.conversations",
      "2026-10-01T00:00:01.000Z",
    );

    expect(
      JSON.stringify(
        await raw.readEnvelope(
          "chatgpt.conversations",
          "2026-10-01T00:00:01.000Z",
        ),
      ),
    ).toBe(before);
    expect(
      (
        await served.readStoredEnvelope!(
          "chatgpt.conversations",
          "2026-10-01T00:00:01.000Z",
        )
      ).data,
    ).toEqual({
      records: [{ ...conversation, message_count_on_current_branch: 0 }],
    });
  });

  it.each([
    ["a legacy body", "chatgpt.conversations", { conversations: [], total: 0 }],
    ["an unbound records stream", "chatgpt.messages", { records: messages }],
    ["records of an unprojected source", "oura.sleep", { records: [{}] }],
    ["an unrelated scope", "notes.entries", { text: "hello" }],
  ])("passes %s through unchanged", async (_label, scope, body) => {
    const raw = createMemoryDataStorage();
    await store(raw, scope, "2026-10-01T00:00:01.000Z", body);
    const served = withLegacyProjection(raw);

    expect(
      await served.readEnvelope(scope, "2026-10-01T00:00:01.000Z"),
    ).toEqual(await raw.readEnvelope(scope, "2026-10-01T00:00:01.000Z"));
  });

  it("serves the other conversations when one stored conversation is malformed", async () => {
    const raw = createMemoryDataStorage();
    const issues: LegacyProjectionIssue[] = [];
    await store(raw, "chatgpt.messages", "2026-10-01T00:00:01.000Z", {
      records: messages,
    });
    await store(raw, "chatgpt.conversations", "2026-10-01T00:00:01.000Z", {
      records: [
        conversation,
        { id: "conv-2", title: "Broken", current_node: "x" },
      ],
    });
    const served = withLegacyProjection(raw, {
      onIssue: (issue) => issues.push(issue),
    });

    const { data } = await served.readEnvelope(
      "chatgpt.conversations",
      "2026-10-01T00:00:01.000Z",
    );

    expect(data).toMatchObject({
      conversations: [{ id: "conv-1", message_count: 2 }],
      total: 1,
    });
    expect(issues).toEqual([
      {
        kind: "projection_diagnostics",
        scope: "chatgpt.conversations",
        collectedAt: "2026-10-01T00:00:01.000Z",
        diagnostics: [
          {
            kind: "records_dropped",
            scope: "chatgpt.conversations",
            stream: "conversations",
            count: 1,
            reasons: ["Conversation lacks a current-branch message count"],
          },
        ],
      },
    ]);
  });

  it("projects conversations with empty threads when no messages stream is stored", async () => {
    const raw = createMemoryDataStorage();
    await store(raw, "chatgpt.conversations", "2026-10-01T00:00:01.000Z", {
      records: [conversation],
    });
    const served = withLegacyProjection(raw);

    const { data } = await served.readEnvelope(
      "chatgpt.conversations",
      "2026-10-01T00:00:01.000Z",
    );

    expect(data).toMatchObject({
      conversations: [{ id: "conv-1", message_count: 0, messages: [] }],
      total: 1,
    });
  });

  it("serves the stored body and reports the error when projection fails", async () => {
    const raw = createMemoryDataStorage();
    const onIssue = vi.fn();
    // A claude scope with no account_profile stream cannot be projected.
    await store(raw, "claude.projects", "2026-10-01T00:00:01.000Z", {
      records: [{ id: "p1", name: "Research" }],
    });
    const served = withLegacyProjection(raw, { onIssue });

    const envelope = await served.readEnvelope(
      "claude.projects",
      "2026-10-01T00:00:01.000Z",
    );

    expect(envelope.data).toEqual({
      records: [{ id: "p1", name: "Research" }],
    });
    expect(onIssue).toHaveBeenCalledWith(
      expect.objectContaining({
        kind: "projection_failed",
        scope: "claude.projects",
        error: expect.objectContaining({ kind: "missing_stream" }),
      }),
    );
  });

  it("projects the same stored data to the same bytes on every read", async () => {
    const raw = createMemoryDataStorage();
    await store(raw, "chatgpt.messages", "2026-10-01T00:00:02.000Z", {
      records: messages,
    });
    await store(raw, "chatgpt.conversations", "2026-10-01T00:00:01.000Z", {
      records: [conversation],
    });
    const first = JSON.stringify(
      await withLegacyProjection(raw).readEnvelope(
        "chatgpt.conversations",
        "2026-10-01T00:00:01.000Z",
      ),
    );
    await new Promise((resolve) => setTimeout(resolve, 5));
    const second = JSON.stringify(
      await withLegacyProjection(raw).readEnvelope(
        "chatgpt.conversations",
        "2026-10-01T00:00:01.000Z",
      ),
    );

    expect(second).toBe(first);
  });

  it("re-projects when a sibling stream gets a new version", async () => {
    const raw = createMemoryDataStorage();
    await store(raw, "chatgpt.conversations", "2026-10-01T00:00:01.000Z", {
      records: [conversation],
    });
    const served = withLegacyProjection(raw);
    const before = await served.readEnvelope(
      "chatgpt.conversations",
      "2026-10-01T00:00:01.000Z",
    );
    await store(raw, "chatgpt.messages", "2026-10-01T00:00:03.000Z", {
      records: messages,
    });
    const after = await served.readEnvelope(
      "chatgpt.conversations",
      "2026-10-01T00:00:01.000Z",
    );

    expect(before.data).toMatchObject({
      conversations: [{ message_count: 0 }],
    });
    expect(after.data).toMatchObject({
      conversations: [{ message_count: 2 }],
    });
  });

  it("serves the new content after a version is deleted and written again at the same collectedAt", async () => {
    const raw = createMemoryDataStorage();
    const at = "2026-10-01T00:00:01.000Z";
    await store(raw, "chatgpt.conversations", at, {
      records: [{ ...conversation, message_count_on_current_branch: 0 }],
    });
    const served = withLegacyProjection(raw);
    await served.readEnvelope("chatgpt.conversations", at);
    await raw.deleteVersion("chatgpt.conversations", at);
    await store(raw, "chatgpt.conversations", at, {
      records: [
        {
          ...conversation,
          title: "Replaced",
          message_count_on_current_branch: 0,
        },
      ],
    });

    const { data } = await served.readEnvelope("chatgpt.conversations", at);

    expect(data).toMatchObject({ conversations: [{ title: "Replaced" }] });
  });

  it("serves chatgpt.conversations newest update first, not in id order", async () => {
    const raw = createMemoryDataStorage();
    const older = {
      ...conversation,
      id: "conv-a",
      update_time: "2026-09-01T10:05:00Z",
      current_node: null,
      message_count_on_current_branch: 0,
    };
    const newer = {
      ...older,
      id: "conv-b",
      update_time: "2026-09-02T10:05:00Z",
    };
    await store(raw, "chatgpt.messages", "2026-10-01T00:00:00.000Z", {
      records: [],
    });
    await store(raw, "chatgpt.conversations", "2026-10-01T00:00:01.000Z", {
      records: [older, newer],
    });

    const { data } = await withLegacyProjection(raw).readEnvelope(
      "chatgpt.conversations",
      "2026-10-01T00:00:01.000Z",
    );

    expect(
      (data as { conversations: { id: string }[] }).conversations.map(
        (c) => c.id,
      ),
    ).toEqual(["conv-b", "conv-a"]);
  });

  it("parses each legacy version once to classify it, even when reads alternate between scopes", async () => {
    const raw = createMemoryDataStorage();
    await store(raw, "chatgpt.conversations", "2026-10-01T00:00:01.000Z", {
      conversations: [],
      total: 0,
    });
    await store(raw, "chatgpt.memories", "2026-10-01T00:00:01.000Z", {
      memories: [],
      total: 0,
    });
    // Raw bytes, as a file-backed port returns them without parsing.
    raw.readEnvelopeBytes = async () => new Uint8Array();
    const readEnvelope = vi.spyOn(raw, "readEnvelope");
    const served = withLegacyProjection(raw);

    for (let round = 0; round < 3; round += 1) {
      for (const scope of ["chatgpt.conversations", "chatgpt.memories"]) {
        await served.readEnvelopeBytes!(scope, "2026-10-01T00:00:01.000Z");
      }
    }

    expect(readEnvelope.mock.calls.map(([scope]) => scope).sort()).toEqual([
      "chatgpt.conversations",
      "chatgpt.memories",
    ]);
  });

  it("reads a legacy envelope once when it serves it", async () => {
    const raw = createMemoryDataStorage();
    await store(raw, "chatgpt.conversations", "2026-10-01T00:00:01.000Z", {
      conversations: [],
      total: 0,
    });
    const readEnvelope = vi.spyOn(raw, "readEnvelope");

    await withLegacyProjection(raw).readEnvelope(
      "chatgpt.conversations",
      "2026-10-01T00:00:01.000Z",
    );

    expect(readEnvelope).toHaveBeenCalledOnce();
  });

  it("serves a body of tagged {stream, data} rows as stored", async () => {
    const raw = createMemoryDataStorage();
    await store(raw, "chatgpt.messages", "2026-10-01T00:00:00.000Z", {
      records: messages,
    });
    const body = {
      records: [{ stream: "conversations", data: conversation }],
    };
    await store(raw, "chatgpt.conversations", "2026-10-01T00:00:01.000Z", body);

    const { data } = await withLegacyProjection(raw).readEnvelope(
      "chatgpt.conversations",
      "2026-10-01T00:00:01.000Z",
    );

    expect(data).toEqual(body);
  });

  it.each([
    ["after", "2026-10-01T00:00:02.000Z", "2026-10-02T00:00:02.000Z"],
    ["before", "2026-10-01T00:00:00.000Z", "2026-10-02T00:00:00.000Z"],
  ])(
    "joins a historical version with the messages its run wrote %s it",
    async (_order, run1Messages, run2Messages) => {
      const raw = createMemoryDataStorage();
      await store(raw, "chatgpt.messages", run1Messages, { records: messages });
      await store(raw, "chatgpt.conversations", "2026-10-01T00:00:01.000Z", {
        records: [conversation],
      });
      await store(raw, "chatgpt.messages", run2Messages, {
        records: [messages[1]],
      });
      await store(raw, "chatgpt.conversations", "2026-10-02T00:00:01.000Z", {
        records: [
          {
            ...conversation,
            current_node: "m1",
            message_count_on_current_branch: 1,
          },
        ],
      });
      const served = withLegacyProjection(raw);
      const thread = async (collectedAt: string) =>
        (
          (await served.readEnvelope("chatgpt.conversations", collectedAt))
            .data as { conversations: { messages: { id: string }[] }[] }
        ).conversations[0].messages.map((m) => m.id);

      expect(await thread("2026-10-01T00:00:01.000Z")).toEqual(["m1", "m2"]);
      expect(await thread("2026-10-02T00:00:01.000Z")).toEqual(["m1"]);
    },
  );

  it("is idempotent", () => {
    const served = withLegacyProjection(createMemoryDataStorage());
    expect(withLegacyProjection(served)).toBe(served);
  });

  it("forwards writes and listings to the raw port", async () => {
    const raw = createMemoryDataStorage();
    const served = withLegacyProjection(raw);
    await store(served, "chatgpt.conversations", "2026-10-01T00:00:01.000Z", {
      records: [],
    });

    expect(raw.entries.map((entry) => entry.scope)).toEqual([
      "chatgpt.conversations",
    ]);
    expect(served.listScopes({}).total).toBe(1);
    expect(served.kind).toBe("custom");
  });
});

describe("withLegacyProjection parity goldens", () => {
  // Same clock the legacy connector ran under (see the goldens' provenance),
  // so the projection time equals legacy's stamped fetched_at.
  const COLLECTED_AT = "2026-10-01T00:00:00.000Z";

  it.each([
    "chatgpt.conversations",
    "chatgpt.memories",
    "claude.conversations",
    "claude.projects",
  ])(
    "serves %s from its stored PDPP streams as the legacy connector's body, except the reviewed differences",
    async (scope) => {
      const golden = JSON.parse(
        readFileSync(
          new URL(
            `../legacy-projection/__fixtures__/parity/${scope}.json`,
            import.meta.url,
          ),
          "utf8",
        ),
      ) as {
        streams: Record<string, Record<string, unknown>[]>;
        legacyBody: Record<string, unknown>;
        reviewedDifferences: { path: string }[];
      };
      const source = scope.split(".")[0];
      const raw = createMemoryDataStorage();
      for (const [stream, rows] of Object.entries(golden.streams)) {
        await store(raw, `${source}.${stream}`, COLLECTED_AT, {
          records: rows,
        });
      }

      const { data } = await withLegacyProjection(raw).readEnvelope(
        scope,
        COLLECTED_AT,
      );

      expect(
        diffBodies(golden.legacyBody, data).map(({ path }) => path),
      ).toEqual(golden.reviewedDifferences.map(({ path }) => path));
    },
  );
});

describe("supersedeLegacyVersions", () => {
  it("never supersedes stored Oura legacy versions, even for matching item counts", async () => {
    const raw = createMemoryDataStorage();
    const oldAt = "2026-09-01T00:00:00Z";
    const newAt = "2026-10-01T00:00:00Z";
    await store(raw, "oura.sleep", oldAt, {
      dailyScores: [{ id: "score-1", day: "2026-09-01", score: 80 }],
      sleepPeriods: [{ id: "period-1", day: "2026-09-01" }],
    });
    await store(raw, "oura.sleep", newAt, {
      records: [
        {
          record_type: "daily_score",
          id: "score-1",
          day: "2026-09-01",
          sleep_score: 80,
        },
      ],
    });
    expect(
      await supersedeLegacyVersions(
        withLegacyProjection(raw),
        "oura.sleep",
        newAt,
      ),
    ).toEqual({ superseded: [], refused: "Oura projection is read-time only" });
    expect((await raw.readEnvelope("oura.sleep", oldAt)).data).toMatchObject({
      dailyScores: [{ id: "score-1" }],
    });
  });

  it("deletes only older legacy-form versions of the scope", async () => {
    const raw = createMemoryDataStorage();
    const legacy = { conversations: [], total: 0 };
    await store(raw, "chatgpt.messages", "2026-09-30T00:00:00.000Z", {
      records: messages,
    });
    await store(
      raw,
      "chatgpt.conversations",
      "2026-09-01T00:00:00.000Z",
      legacy,
    );
    await store(raw, "chatgpt.conversations", "2026-09-02T00:00:00.000Z", {
      records: [],
    });
    await store(
      raw,
      "chatgpt.conversations",
      "2026-09-03T00:00:00.000Z",
      legacy,
    );
    await store(raw, "chatgpt.conversations", "2026-10-01T00:00:00.000Z", {
      records: [conversation],
    });
    // Written later (another device): not superseded by an older write.
    await store(
      raw,
      "chatgpt.conversations",
      "2026-10-02T00:00:00.000Z",
      legacy,
    );
    await store(raw, "chatgpt.memories", "2026-09-01T00:00:00.000Z", {
      memories: [],
      total: 0,
    });

    const { superseded } = await supersedeLegacyVersions(
      withLegacyProjection(raw),
      "chatgpt.conversations",
      "2026-10-01T00:00:00.000Z",
    );

    expect(superseded.sort()).toEqual([
      "2026-09-01T00:00:00.000Z",
      "2026-09-03T00:00:00.000Z",
    ]);
    expect(
      raw.entries.map((entry) => `${entry.scope} ${entry.collectedAt}`).sort(),
    ).toEqual([
      "chatgpt.conversations 2026-09-02T00:00:00.000Z",
      "chatgpt.conversations 2026-10-01T00:00:00.000Z",
      "chatgpt.conversations 2026-10-02T00:00:00.000Z",
      "chatgpt.memories 2026-09-01T00:00:00.000Z",
      "chatgpt.messages 2026-09-30T00:00:00.000Z",
    ]);
  });

  it.each([
    ["an unprojected records stream", "chatgpt.messages", { records: [] }],
    ["a legacy body", "chatgpt.conversations", { conversations: [], total: 0 }],
  ])("deletes nothing after %s", async (_label, scope, body) => {
    const raw = createMemoryDataStorage();
    await store(raw, scope, "2026-09-01T00:00:00.000Z", {
      conversations: [],
      total: 0,
    });
    await store(raw, scope, "2026-10-01T00:00:00.000Z", body);

    expect(
      (await supersedeLegacyVersions(raw, scope, "2026-10-01T00:00:00.000Z"))
        .superseded,
    ).toEqual([]);
    expect(raw.entries).toHaveLength(2);
  });

  it("deletes nothing when the new version cannot be projected", async () => {
    const raw = createMemoryDataStorage();
    await store(raw, "claude.projects", "2026-09-01T00:00:00.000Z", {
      projects: [],
      total: 0,
    });
    // No claude.account_profile stream is stored, so projection fails.
    await store(raw, "claude.projects", "2026-10-01T00:00:00.000Z", {
      records: [{ id: "p1", name: "Research" }],
    });

    expect(
      await supersedeLegacyVersions(
        withLegacyProjection(raw),
        "claude.projects",
        "2026-10-01T00:00:00.000Z",
      ),
    ).toEqual({
      superseded: [],
      refused: "the new version cannot be projected",
    });
    expect(raw.entries).toHaveLength(2);
  });

  it.each([
    ["claude.conversations", "messages", "conversation_id"],
    ["claude.projects", "project_documents", "project_id"],
  ])(
    "keeps the legacy %s when the projection holds fewer nested items",
    async (scope, nestedStream, _parentKey) => {
      const golden = JSON.parse(
        readFileSync(
          new URL(
            `../legacy-projection/__fixtures__/parity/${scope}.json`,
            import.meta.url,
          ),
          "utf8",
        ),
      ) as {
        streams: Record<string, Record<string, unknown>[]>;
        legacyBody: Record<string, unknown>;
      };
      const raw = createMemoryDataStorage();
      await store(raw, scope, "2026-09-01T00:00:00.000Z", golden.legacyBody);
      for (const [stream, rows] of Object.entries(golden.streams)) {
        const kept =
          stream === nestedStream
            ? rows.slice(0, rows.length - 1)
            : rows.map((row) => {
                // No source count to check the nested rows against.
                const { message_count: _count, ...rest } = row;
                return rest;
              });
        await store(raw, `claude.${stream}`, "2026-10-01T00:00:00.000Z", {
          records: kept,
        });
      }

      const result = await supersedeLegacyVersions(
        withLegacyProjection(raw),
        scope,
        "2026-10-01T00:00:00.000Z",
      );

      expect(result.superseded).toEqual([]);
      expect(result.refused).toMatch(/nested/);
      expect(raw.entries.filter((entry) => entry.scope === scope)).toHaveLength(
        2,
      );
    },
  );

  it("supersedes a complete Claude projection", async () => {
    const golden = JSON.parse(
      readFileSync(
        new URL(
          "../legacy-projection/__fixtures__/parity/claude.projects.json",
          import.meta.url,
        ),
        "utf8",
      ),
    ) as {
      streams: Record<string, Record<string, unknown>[]>;
      legacyBody: Record<string, unknown>;
    };
    const raw = createMemoryDataStorage();
    await store(
      raw,
      "claude.projects",
      "2026-09-01T00:00:00.000Z",
      golden.legacyBody,
    );
    for (const [stream, rows] of Object.entries(golden.streams)) {
      await store(raw, `claude.${stream}`, "2026-10-01T00:00:00.000Z", {
        records: rows,
      });
    }

    expect(
      (
        await supersedeLegacyVersions(
          withLegacyProjection(raw),
          "claude.projects",
          "2026-10-01T00:00:00.000Z",
        )
      ).superseded,
    ).toEqual(["2026-09-01T00:00:00.000Z"]);
  });

  it("compares versions by instant, keeping a later version that sorts earlier as a string", async () => {
    const raw = createMemoryDataStorage();
    await store(raw, "chatgpt.messages", "2026-10-01T00:00:00.000Z", {
      records: [],
    });
    await store(raw, "chatgpt.conversations", "2026-10-01T12:00:00.500Z", {
      conversations: [],
      total: 0,
    });
    await store(raw, "chatgpt.conversations", "2026-10-01T12:00:00Z", {
      records: [],
    });

    expect(
      await supersedeLegacyVersions(
        withLegacyProjection(raw),
        "chatgpt.conversations",
        "2026-10-01T12:00:00Z",
      ),
    ).toEqual({ superseded: [] });
    expect(raw.entries).toHaveLength(3);
  });

  it("keeps an older binary upload under the scope", async () => {
    const raw = createMemoryDataStorage();
    await store(raw, "chatgpt.messages", "2026-09-30T00:00:00.000Z", {
      records: [],
    });
    const binary = await ingestBinaryDataContract({
      storage: raw,
      scopeParam: "chatgpt.conversations",
      bytes: new TextEncoder().encode("%PDF-1.4"),
      mimeType: "application/pdf",
      collectedAt: "2026-09-01T00:00:00.000Z",
      status: "stored",
    });
    expect(binary.ok).toBe(true);
    await store(raw, "chatgpt.conversations", "2026-10-01T00:00:00.000Z", {
      records: [],
    });

    expect(
      await supersedeLegacyVersions(
        withLegacyProjection(raw),
        "chatgpt.conversations",
        "2026-10-01T00:00:00.000Z",
      ),
    ).toEqual({ superseded: [] });
    expect(raw.entries).toHaveLength(3);
  });

  async function legacyWithThread(raw: DataStoragePort) {
    await store(raw, "chatgpt.conversations", "2026-09-01T00:00:00.000Z", {
      conversations: [
        {
          id: "conv-1",
          title: "Trip plan",
          message_count: 2,
          messages: [{ id: "m1" }, { id: "m2" }],
        },
      ],
      total: 1,
    });
  }

  it("deletes nothing when the messages stream is missing", async () => {
    const raw = createMemoryDataStorage();
    await legacyWithThread(raw);
    await store(raw, "chatgpt.conversations", "2026-10-01T00:00:00.000Z", {
      records: [conversation],
    });

    expect(
      await supersedeLegacyVersions(
        withLegacyProjection(raw),
        "chatgpt.conversations",
        "2026-10-01T00:00:00.000Z",
      ),
    ).toEqual({
      superseded: [],
      refused: "the projection is partial (stream_missing)",
    });
    expect(raw.entries).toHaveLength(2);
  });

  it("deletes nothing when the projection drops a row", async () => {
    const raw = createMemoryDataStorage();
    await legacyWithThread(raw);
    await store(raw, "chatgpt.messages", "2026-09-30T00:00:00.000Z", {
      records: messages,
    });
    const { message_count_on_current_branch: _count, ...countless } =
      conversation;
    await store(raw, "chatgpt.conversations", "2026-10-01T00:00:00.000Z", {
      records: [countless],
    });

    expect(
      await supersedeLegacyVersions(
        withLegacyProjection(raw),
        "chatgpt.conversations",
        "2026-10-01T00:00:00.000Z",
      ),
    ).toEqual({
      superseded: [],
      refused: "the projection is partial (records_dropped)",
    });
    expect(raw.entries).toHaveLength(3);
  });

  it("deletes nothing when the projection holds fewer items than the newest legacy version", async () => {
    const raw = createMemoryDataStorage();
    await legacyWithThread(raw);
    await store(raw, "chatgpt.messages", "2026-09-30T00:00:00.000Z", {
      records: [],
    });
    await store(raw, "chatgpt.conversations", "2026-10-01T00:00:00.000Z", {
      records: [],
    });

    expect(
      await supersedeLegacyVersions(
        withLegacyProjection(raw),
        "chatgpt.conversations",
        "2026-10-01T00:00:00.000Z",
      ),
    ).toEqual({
      superseded: [],
      refused:
        "the projection has 0 conversations; the newest legacy version has 1",
    });
    expect(raw.entries).toHaveLength(3);
  });

  it("deletes nothing when the projection lacks a conversation the newest legacy version holds", async () => {
    const raw = createMemoryDataStorage();
    await legacyWithThread(raw);
    await store(raw, "chatgpt.messages", "2026-09-30T00:00:00.000Z", {
      records: [],
    });
    // A windowed run: as many conversations as legacy, but other ones.
    await store(raw, "chatgpt.conversations", "2026-10-01T00:00:00.000Z", {
      records: [
        {
          ...conversation,
          id: "conv-2",
          current_node: null,
          message_count_on_current_branch: 0,
        },
      ],
    });

    expect(
      await supersedeLegacyVersions(
        withLegacyProjection(raw),
        "chatgpt.conversations",
        "2026-10-01T00:00:00.000Z",
      ),
    ).toEqual({
      superseded: [],
      refused:
        "the projection lacks 1 of the conversations in the newest legacy version",
    });
    expect(raw.entries).toHaveLength(3);
  });

  const builderWrite: WriterAttribution = {
    builder: "0x00000000000000000000000000000000000000b1",
    grantId: "grant-1",
    signature: "payload.sig",
    bodyHash: "hash",
    writtenAt: "2026-09-01T00:00:00.000Z",
  };

  it.each([
    [
      "a legacy body a builder wrote",
      { conversations: [], total: 0 },
      builderWrite,
    ],
    ["a body without the legacy collection", { records: [], extra: 1 }],
    ["a body whose collection is not an array", { conversations: {} }],
  ])("keeps %s", async (_label, body, attribution?: WriterAttribution) => {
    const raw = createMemoryDataStorage();
    await store(raw, "chatgpt.messages", "2026-09-30T00:00:00.000Z", {
      records: [],
    });
    await store(
      raw,
      "chatgpt.conversations",
      "2026-09-01T00:00:00.000Z",
      body,
      attribution,
    );
    await store(raw, "chatgpt.conversations", "2026-10-01T00:00:00.000Z", {
      records: [],
    });

    expect(
      await supersedeLegacyVersions(
        withLegacyProjection(raw),
        "chatgpt.conversations",
        "2026-10-01T00:00:00.000Z",
      ),
    ).toEqual({ superseded: [] });
    expect(raw.entries).toHaveLength(3);
  });

  it("deletes nothing on a raw port, which cannot show the projection", async () => {
    const raw = createMemoryDataStorage();
    await store(raw, "chatgpt.messages", "2026-09-30T00:00:00.000Z", {
      records: [],
    });
    await store(raw, "chatgpt.conversations", "2026-09-01T00:00:00.000Z", {
      conversations: [],
      total: 0,
    });
    await store(raw, "chatgpt.conversations", "2026-10-01T00:00:00.000Z", {
      records: [],
    });

    expect(
      (
        await supersedeLegacyVersions(
          raw,
          "chatgpt.conversations",
          "2026-10-01T00:00:00.000Z",
        )
      ).superseded,
    ).toEqual([]);
    expect(raw.entries).toHaveLength(3);
  });
});

describe("withLegacyProjection and the first-seen sidecar", () => {
  const SCOPE = "chatgpt.conversations";
  const T1 = "2026-09-01T00:00:00.000Z";
  const T2 = "2026-10-01T00:00:00.000Z";

  it("passes the sidecar methods through to the raw port", async () => {
    const raw = createMemoryDataStorage();
    const served = withLegacyProjection(raw);

    await served.writeFirstSeenLedger!(SCOPE, { marker: 1 });
    expect(await raw.readFirstSeenLedger!(SCOPE)).toEqual({ marker: 1 });
    expect(await served.readFirstSeenLedger!(SCOPE)).toEqual({ marker: 1 });
    await served.deleteFirstSeenLedger!(SCOPE);
    expect(await raw.readFirstSeenLedger!(SCOPE)).toBeNull();
  });

  it("keys a scope moving from the legacy form to the stored rows form identically", async () => {
    const raw = createMemoryDataStorage();
    await store(raw, SCOPE, T1, { conversations: [conversation], total: 1 });
    await store(raw, SCOPE, T2, {
      records: [conversation, { ...conversation, id: "conv-2" }],
    });

    const ledger = (await raw.readFirstSeenLedger!(SCOPE)) as {
      baseline: string;
      records: Record<string, [string, string]>;
    };
    expect(ledger.baseline).toBe(T1);
    // conv-1 is the same record in both forms; only conv-2 is new.
    expect(ledger.records["conversations:i:conv-1"]).toEqual([T1, T2]);
    expect(ledger.records["conversations:i:conv-2"]).toEqual([T2, T2]);
  });

  it("never serves ledger content through the served port", async () => {
    const raw = createMemoryDataStorage();
    await store(raw, SCOPE, T1, { records: [conversation] });
    const served = withLegacyProjection(raw);

    const envelope = await served.readEnvelope(SCOPE, T1);
    const stored = await served.readStoredEnvelope!(SCOPE, T1);
    for (const view of [envelope, stored]) {
      expect(JSON.stringify(view)).not.toContain("baseline");
      expect(JSON.stringify(view)).not.toContain("conversations:i:");
    }
  });
});
