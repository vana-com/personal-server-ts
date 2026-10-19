import Ajv from "ajv";
import { describe, expect, it } from "vitest";
import ouraActivitySchema from "./legacy-schemas/oura.activity.json";
import ouraReadinessSchema from "./legacy-schemas/oura.readiness.json";
import ouraSleepSchema from "./legacy-schemas/oura.sleep.json";
import { projectPdppRecordsToLegacyPayload } from "./index.js";

const ajv = new Ajv({ strict: false, allErrors: true });

const BAD_DAY = "Oura day is missing or not a YYYY-MM-DD date";

const ouraCases = [
  {
    scope: "oura.activity",
    stream: "activity",
    listKey: "days",
    schema: ouraActivitySchema,
    row: (id: string, day: unknown, score: number | null = 80) => ({
      id,
      day,
      score,
      steps: 10,
    }),
  },
  {
    scope: "oura.readiness",
    stream: "readiness",
    listKey: "days",
    schema: ouraReadinessSchema,
    row: (id: string, day: unknown, score: number | null = 80) => ({
      id,
      day,
      score,
    }),
  },
  {
    scope: "oura.sleep",
    stream: "sleep",
    listKey: "dailyScores",
    schema: ouraSleepSchema,
    row: (id: string, day: unknown, score: number | null = 80) => ({
      id,
      day,
      sleep_score: score,
      type: "long_sleep",
    }),
  },
] as const;

describe.each(ouraCases)("$scope row validity", (c) => {
  const project = (rows: Record<string, unknown>[]) =>
    projectPdppRecordsToLegacyPayload(
      c.scope,
      rows.map((data) => ({ stream: c.stream, data })),
      { fetchedStreams: [c.stream] },
    );

  it.each([
    ["null", null],
    ["missing", undefined],
    ["empty", ""],
    ["a timestamp", "2026-08-01T00:00:00Z"],
    ["an impossible date", "2026-02-30"],
    ["a number", 20260801],
  ])("never emits a day that is %s", (_name, bad) => {
    const result = project([c.row("bad", bad)]);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.payload[c.listKey]).toEqual([]);
    expect(result.diagnostics).toEqual([
      {
        kind: "records_dropped",
        scope: c.scope,
        stream: c.stream,
        count: 1,
        reasons: [BAD_DAY],
      },
    ]);
  });

  it("keeps null scores, drops invalid days, and validates", () => {
    const result = project([
      c.row("good1", "2026-08-01", null),
      c.row("bad", null),
      c.row("good2", "2026-08-02", 77),
    ]);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const list = result.payload[c.listKey] as { id: string; score?: unknown }[];
    expect(list.map((r) => r.id)).toEqual(["good1", "good2"]);
    expect(list[0]?.score).toBeNull();
    expect(list[1]?.score).toBe(77);
    expect(result.diagnostics).toEqual([
      expect.objectContaining({
        kind: "records_dropped",
        count: 1,
        reasons: [BAD_DAY],
      }),
    ]);
    for (const entry of list as { day?: unknown }[]) {
      expect(entry.day).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    }
    const validate = ajv.compile(c.schema.schema as Record<string, unknown>);
    expect(validate(result.payload), JSON.stringify(validate.errors)).toBe(
      true,
    );
  });

  it("reports no diagnostic when every row is valid", () => {
    const result = project([c.row("g", "2026-08-01")]);
    expect(result.ok && result.diagnostics).toBeFalsy();
  });
});

describe("oura.sleep drops a bad-day row from sleepPeriods as well", () => {
  it("keeps the two lists aligned", () => {
    const result = projectPdppRecordsToLegacyPayload(
      "oura.sleep",
      [
        {
          stream: "sleep",
          data: { id: "s1", day: "2026-08-01", sleep_score: 70 },
        },
        { stream: "sleep", data: { id: "s2", day: null, sleep_score: 70 } },
      ],
      { fetchedStreams: ["sleep"] },
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(
      (result.payload.sleepPeriods as { id: string }[]).map((p) => p.id),
    ).toEqual(["s1"]);
    expect(
      (result.payload.dailyScores as { id: string }[]).map((p) => p.id),
    ).toEqual(["s1"]);
  });
});

describe("spotify.savedTracks skipped rows", () => {
  const track = (id: string, extra: Record<string, unknown> = {}) => ({
    id,
    name: `Song ${id}`,
    artist_names: ["A"],
    album_name: "Album",
    duration_ms: 1,
    added_at: "2026-01-02T03:04:05Z",
    uri: `spotify:track:${id}`,
    explicit: false,
    ...extra,
  });
  const project = (rows: Record<string, unknown>[]) =>
    projectPdppRecordsToLegacyPayload(
      "spotify.savedTracks",
      rows.map((data) => ({ stream: "saved_tracks", data })),
      { fetchedStreams: ["saved_tracks"] },
    );

  it("counts rows without a name or with malformed artist_names, keeping added_at on peers", () => {
    const result = project([
      track("ok"),
      track("noname", { name: null }),
      track("noartists", { artist_names: null }),
      track("badartist", { artist_names: ["A", 3] }),
    ]);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.payload.savedTracks).toEqual([
      expect.objectContaining({
        name: "Song ok",
        added_at: "2026-01-02T03:04:05Z",
      }),
    ]);
    expect(result.payload.total).toBe(1);
    expect(result.diagnostics).toEqual([
      expect.objectContaining({
        kind: "records_dropped",
        scope: "spotify.savedTracks",
        stream: "saved_tracks",
        count: 3,
        reasons: [
          "Saved track lacks a name",
          "Saved track lacks a valid artist list",
        ],
      }),
    ]);
  });
});

describe("heb.orders unknown item count", () => {
  const order = (extra: Record<string, unknown>) => ({
    stream: "orders",
    data: { id: "o1", order_date: "2026-09-15", ...extra },
  });
  const line = {
    stream: "order_items",
    data: {
      id: "l1",
      order_id: "o1",
      name: "Milk",
      product_id: "p1",
      quantity: 1,
    },
  };
  const project = (records: { stream: string; data: unknown }[]) =>
    projectPdppRecordsToLegacyPayload("heb.orders", records as never, {
      fetchedStreams: ["orders", "order_items"],
    });

  it.each([
    ["null", null],
    ["absent", undefined],
    ["negative", -1],
    ["fractional", 1.5],
  ])("rejects an order with no usable line and a %s count", (_n, count) => {
    expect(
      project([order(count === undefined ? {} : { item_count: count })]),
    ).toMatchObject({
      ok: false,
      error: { kind: "incomplete_scope", scope: "heb.orders" },
    });
  });

  it("rejects a positive count with no usable line", () => {
    expect(project([order({ item_count: 2 })])).toMatchObject({
      ok: false,
      error: { kind: "incomplete_scope" },
    });
  });

  it("accepts a known zero count as an empty order", () => {
    const result = project([order({ item_count: 0 })]);
    expect(result.ok && result.payload.orders).toEqual([
      expect.objectContaining({ orderId: "o1", items: [] }),
    ]);
  });

  it("still delivers an order whose count is unknown when a usable line exists", () => {
    const result = project([order({ item_count: null }), line]);
    expect(result.ok && result.payload.totalItems).toBe(1);
  });

  it("still serves a fetched stream with zero orders as empty", () => {
    const result = project([]);
    expect(result.ok && result.payload).toMatchObject({ orders: [] });
  });
});

describe("wholefoods.orders unknown item count", () => {
  const project = (data: Record<string, unknown>) =>
    projectPdppRecordsToLegacyPayload(
      "wholefoods.orders",
      [{ stream: "orders", data: { id: "o1", ...data } }],
      { fetchedStreams: ["orders", "order_items"] },
    );
  it("rejects an unknown count and accepts a known zero", () => {
    expect(project({ item_count: null })).toMatchObject({
      ok: false,
      error: { kind: "incomplete_scope" },
    });
    expect(project({ item_count: 0 }).ok).toBe(true);
  });
});
