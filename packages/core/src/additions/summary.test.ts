import { describe, expect, it } from "vitest";
import type { ScopeFirstSeenLedger } from "./first-added.js";
import {
  InvalidTimezoneError,
  bucketAdditionsByLocalDay,
  readAdditionsSummary,
  projectPortableAdditionsByLocalDay,
  readAdditionsSummaryJson,
  summarizeAdditions,
  validateTimezone,
  type AdditionsSummary,
  type AdditionsSummaryInput,
} from "./summary.js";

/** A fixed instant in UTC; the default test clock. */
const NOW = "2026-10-09T12:00:00.000Z";
const BASELINE = "2026-09-01T00:00:00.000Z";

function ledger(
  scope: string,
  records: Record<string, [string, string]>,
  overrides: Partial<ScopeFirstSeenLedger> = {},
): ScopeFirstSeenLedger {
  return {
    version: 5,
    scope,
    baseline: BASELINE,
    current: NOW,
    through: NOW,
    latest: { collectedAt: NOW, total: Object.keys(records).length },
    records,
    ...overrides,
  };
}

function summarize(
  ledgers: AdditionsSummaryInput["ledgers"],
  overrides: Partial<AdditionsSummaryInput> = {},
): Promise<AdditionsSummary> {
  return summarizeAdditions({
    ledgers,
    timezone: "UTC",
    days: 7,
    now: new Date(NOW),
    ...overrides,
  });
}

function addedOn(summary: AdditionsSummary, date: string): number | undefined {
  return summary.days.find((day) => day.date === date)?.added;
}

describe("summarizeAdditions", () => {
  it("counts records first added today and yesterday into the right days", async () => {
    const summary = await summarize([
      ledger("notes.entries", {
        "items:i:a": ["2026-10-09T01:00:00.000Z", NOW],
        "items:i:b": ["2026-10-08T23:00:00.000Z", NOW],
        // Outside the 7-day window: counts toward no day.
        "items:i:c": ["2026-10-01T10:00:00.000Z", NOW],
      }),
    ]);

    expect(summary.total).toBe(3);
    expect(summary.days).toHaveLength(7);
    expect(summary.days.at(-1)).toEqual({ date: "2026-10-09", added: 1 });
    expect(addedOn(summary, "2026-10-08")).toBe(1);
    expect(addedOn(summary, "2026-10-01")).toBeUndefined();
  });

  it("assigns an instant to its local calendar day in the requested timezone", async () => {
    const records = {
      "items:i:a": ["2026-10-09T03:30:00.000Z", NOW] as [string, string],
    };

    const toronto = await summarize([ledger("notes.entries", records)], {
      timezone: "America/Toronto",
    });
    expect(addedOn(toronto, "2026-10-08")).toBe(1);
    expect(addedOn(toronto, "2026-10-09")).toBe(0);

    const utc = await summarize([ledger("notes.entries", records)]);
    expect(addedOn(utc, "2026-10-09")).toBe(1);
    expect(addedOn(utc, "2026-10-08")).toBe(0);
  });

  it("lists consecutive local days across a DST change with no duplicates or gaps", async () => {
    // 2026-11-01 is the fall-back DST change in America/Toronto.
    const summary = await summarize([], {
      timezone: "America/Toronto",
      now: new Date("2026-11-01T06:30:00.000Z"),
    });

    expect(summary.days.map((day) => day.date)).toEqual([
      "2026-10-26",
      "2026-10-27",
      "2026-10-28",
      "2026-10-29",
      "2026-10-30",
      "2026-10-31",
      "2026-11-01",
    ]);
  });

  const WINDOW_BASELINE = "2026-09-20T00:00:00.000Z";
  const baselineRecords = (): Record<string, [string, string]> => ({
    // First seen at the baseline.
    "items:i:old": [WINDOW_BASELINE, NOW],
    // Added today but no longer in the newest version.
    "items:i:gone": ["2026-10-09T02:00:00.000Z", "2026-10-09T03:00:00.000Z"],
    "items:i:new": ["2026-10-09T01:00:00.000Z", NOW],
  });
  const BASELINE_DAY = "2026-09-20";

  it("counts permanent arrivals even when records are absent from the newest snapshot", async () => {
    const summary = await summarize(
      [
        ledger("notes.entries", baselineRecords(), {
          latest: { collectedAt: NOW, total: 2 },
          baseline: WINDOW_BASELINE,
        }),
      ],
      { days: 31 },
    );
    expect(summary.total).toBe(2);
    expect(summary.partial).toBe(false);
    expect(summary.scopes[0]!.partial).toBe(false);
    expect(addedOn(summary, BASELINE_DAY)).toBe(1);
    expect(addedOn(summary, "2026-10-09")).toBe(2);
  });

  it("does not count a partial scope's baseline records, and flags it", async () => {
    const summary = await summarize(
      [
        ledger("notes.entries", baselineRecords(), {
          latest: { collectedAt: NOW, total: 2 },
          baseline: WINDOW_BASELINE,
          partial: true,
        }),
      ],
      { days: 31 },
    );
    expect(addedOn(summary, BASELINE_DAY)).toBe(0);
    expect(addedOn(summary, "2026-10-09")).toBe(2);
    expect(summary.partial).toBe(true);
    expect(summary.scopes[0]).toMatchObject({
      trackedSince: WINDOW_BASELINE,
      partial: true,
    });
  });

  it("adds two scopes' records to the same day, one of them on its baseline", async () => {
    const day = "2026-10-09T01:00:00.000Z";
    const summary = await summarize([
      ledger(
        "a.fresh",
        { "items:i:1": [day, NOW], "items:i:2": [day, NOW] },
        { baseline: day },
      ),
      ledger("b.old", { "items:i:x": [day, NOW] }),
    ]);
    expect(addedOn(summary, "2026-10-09")).toBe(3);
    expect(summary.partial).toBe(false);
  });

  it("reports latest.total per scope, including records without ids", async () => {
    const summary = await summarize([
      ledger("b.scope", {}, { latest: { collectedAt: NOW, total: 5 } }),
      ledger("a.scope", {}, { latest: { collectedAt: NOW, total: 0 } }),
    ]);
    expect(summary.total).toBe(5);
    expect(summary.scopes.map((s) => [s.scope, s.total])).toEqual([
      ["a.scope", 0],
      ["b.scope", 5],
    ]);
  });

  it("reports the earliest baseline as trackedSince, null with no scopes", async () => {
    const summary = await summarize([
      ledger("aaa.scope", {}, { baseline: "2026-10-01T00:00:00.000Z" }),
      ledger("bbb.scope", {}, { baseline: "2026-09-20T00:00:00.000Z" }),
    ]);
    expect(summary.trackedSince).toBe("2026-09-20T00:00:00.000Z");
    expect(summary.scopes.map((s) => s.trackedSince)).toEqual([
      "2026-10-01T00:00:00.000Z",
      "2026-09-20T00:00:00.000Z",
    ]);
    expect((await summarize([])).trackedSince).toBeNull();
  });

  it("compares baselines as instants, not strings", async () => {
    const summary = await summarize([
      ledger("a.scope", {}, { baseline: "2026-09-01T00:00:00.500Z" }),
      ledger("b.scope", {}, { baseline: "2026-09-01T00:00:00Z" }),
    ]);
    expect(summary.trackedSince).toBe("2026-09-01T00:00:00Z");
  });

  it("treats a scope with no baseline or a skipped ledger as total-only", async () => {
    const summary = await summarize([
      ledger(
        "a.binary",
        {},
        {
          baseline: null,
          current: null,
          latest: { collectedAt: NOW, total: 1 },
        },
      ),
      ledger(
        "b.huge",
        {},
        {
          skipped: "too_large",
          latest: { collectedAt: NOW, total: 300_000 },
        },
      ),
      ledger("c.normal", { "items:i:x": ["2026-10-09T01:00:00.000Z", NOW] }),
    ]);
    expect(summary.total).toBe(300_002);
    expect(summary.scopes).toEqual([
      {
        daily: [],
        scope: "a.binary",
        total: 1,
        trackedSince: null,
        partial: false,
        buckets: [],
      },
      {
        daily: [],
        scope: "b.huge",
        total: 300_000,
        trackedSince: null,
        partial: false,
        buckets: [],
      },
      {
        daily: [],
        scope: "c.normal",
        total: 1,
        trackedSince: BASELINE,
        partial: false,
        buckets: [{ start: "2026-10-09T01:00:00.000Z", added: 1 }],
      },
    ]);
    expect(summary.trackedSince).toBe(BASELINE);
    expect(summary.days.at(-1)).toEqual({ date: "2026-10-09", added: 1 });
    const none = await summarize([ledger("a.binary", {}, { baseline: null })]);
    expect(none.trackedSince).toBeNull();
  });

  it("summarizes lazily, one ledger at a time", async () => {
    let live = 0;
    let peak = 0;
    async function* source() {
      for (const name of ["a.one", "b.two", "c.three"]) {
        live += 1;
        peak = Math.max(peak, live);
        yield ledger(name, { "items:i:x": ["2026-10-09T01:00:00.000Z", NOW] });
        live -= 1;
      }
    }
    const summary = await summarize(source());
    expect(summary.scopes).toHaveLength(3);
    expect(peak).toBe(1);
  });

  it.each([
    [
      "Asia/Kolkata",
      "2026-10-08T18:15:00.000Z",
      "2026-10-08T18:30:00.000Z",
      "2026-10-09",
    ],
    [
      "Asia/Kathmandu",
      "2026-10-08T18:00:00.000Z",
      "2026-10-08T18:15:00.000Z",
      "2026-10-09",
    ],
    [
      "America/New_York",
      "2026-11-01T05:30:00.000Z",
      "2026-11-01T06:30:00.000Z",
      "2026-11-01",
    ],
  ])(
    "rebuckets UTC intervals into %s calendar days",
    (timezone, first, second, today) => {
      const rows = bucketAdditionsByLocalDay(
        [
          { start: first, added: 2 },
          { start: second, added: 3 },
        ],
        timezone,
        2,
        new Date(second),
      );
      expect(rows.at(-1)).toEqual({
        date: today,
        added: timezone === "America/New_York" ? 5 : 3,
      });
      expect(rows[0]!.added).toBe(timezone === "America/New_York" ? 0 : 2);
    },
  );

  it("stores quarter-hour UTC buckets and excludes only the literal reserved prefix", async () => {
    const at = "2026-10-09T01:14:59.999Z";
    const summary = await summarize(
      [
        ledger("vana.system.additions", { a: [at, NOW] }),
        ledger("vanaXsystem.scope", { b: [at, NOW] }),
        ledger("notes.entries", { c: ["2026-10-09T01:15:00.000Z", NOW] }),
      ],
      { through: { "notes.entries": "3" } },
    );
    expect(summary.buckets).toEqual([
      { start: "2026-10-09T01:00:00.000Z", added: 1 },
      { start: "2026-10-09T01:15:00.000Z", added: 1 },
    ]);
    expect(summary.total).toBe(2);
    expect(
      summary.scopes.map(({ scope, buckets }) => ({ scope, buckets })),
    ).toEqual([
      {
        scope: "notes.entries",
        buckets: [{ start: "2026-10-09T01:15:00.000Z", added: 1 }],
      },
      {
        scope: "vanaXsystem.scope",
        buckets: [{ start: "2026-10-09T01:00:00.000Z", added: 1 }],
      },
    ]);
    expect(summary.through).toEqual({ "notes.entries": "3" });
  });

  it("keeps coordination coverage separate from unknown historical dates", async () => {
    const historical = ledger("notes.entries", baselineRecords(), {
      partial: true,
    });
    expect((await summarize([historical])).coverage).toBe("complete");
    for (const coverage of [
      "complete",
      "behind",
      "partial",
      "unavailable",
    ] as const) {
      const summary = await summarize([historical], { coverage });
      expect(summary.coverage).toBe(coverage);
      expect(summary.partial).toBe(true);
    }
    const incomplete = ledger("notes.entries", {}, { incomplete: true });
    expect((await summarize([incomplete])).coverage).toBe("partial");
    expect(
      (await summarize([incomplete], { coverage: "complete" })).coverage,
    ).toBe("partial");
  });

  it("reads only versioned valid summaries from an untrusted transport", async () => {
    const summary = await summarize([
      ledger("notes.entries", { a: [NOW, NOW] }),
    ]);
    expect(readAdditionsSummary(summary)).toEqual(summary);
    for (const invalid of [
      { ...summary, version: 0 },
      { ...summary, total: -1 },
      { ...summary, coverage: "ready" },
      { ...summary, through: { "notes.entries": "not-a-version" } },
      {
        ...summary,
        buckets: [{ start: "2026-10-09T12:01:00.000Z", added: 1 }],
      },
      { ...summary, buckets: [{ start: NOW, added: -1 }] },
    ])
      expect(readAdditionsSummary(invalid)).toBeNull();
  });

  it("compacts old UTC counts without losing exact requested local days", async () => {
    const records: Record<string, [string, string]> = {
      old: ["2026-09-15T23:50:00.000Z", NOW],
      edge: ["2026-09-29T00:00:00.000Z", NOW],
      recent: ["2026-10-08T23:50:00.000Z", NOW],
    };
    const summary = await summarize([ledger("notes.entries", records)], {
      timezone: "Asia/Kathmandu",
      days: 31,
    });
    expect(summary.daily).toEqual([{ date: "2026-09-15", added: 1 }]);
    expect(summary.buckets).toHaveLength(2);
    expect(summary.fineSince).toBe("2026-09-29T00:00:00.000Z");
    expect(addedOn(summary, "2026-10-09")).toBe(1);
    expect(addedOn(summary, "2026-09-29")).toBe(1);
    // Older local days are reconstructed from exact ledger timestamps.
    expect(addedOn(summary, "2026-09-16")).toBe(1);
    expect(
      projectPortableAdditionsByLocalDay(
        summary,
        "Asia/Kathmandu",
        31,
        new Date(NOW),
      ),
    ).toEqual({ coverage: "partial", days: null });
    expect(
      projectPortableAdditionsByLocalDay(summary, "UTC", 31, new Date(NOW))
        .days,
    ).toContainEqual({ date: "2026-09-15", added: 1 });
    expect(readAdditionsSummaryJson(JSON.stringify(summary))).toEqual(summary);
    expect(
      readAdditionsSummaryJson(" ".repeat(8 * 1024 * 1024 + 1)),
    ).toBeNull();
    expect(readAdditionsSummary(summary)).toEqual(summary);
  });

  it("normalizes accepted offset timestamps for portable UTC projection", async () => {
    const summary = await summarize([]);
    summary.buckets = [{ start: "2026-10-09T00:00:00+05:45", added: 2 }];
    const parsed = readAdditionsSummary(summary);
    expect(parsed).not.toBeNull();
    if (!parsed) throw new Error("Valid transport rejected");
    const projection = projectPortableAdditionsByLocalDay(
      parsed,
      "UTC",
      2,
      new Date(NOW),
    );
    expect(projection.days).toEqual([
      { date: "2026-10-08", added: 2 },
      { date: "2026-10-09", added: 0 },
    ]);
  });

  it.each([
    "Pacific/Kiritimati",
    "Etc/GMT+12",
    "America/New_York",
    "Australia/Lord_Howe",
    "Asia/Kolkata",
    "Asia/Kathmandu",
    "Pacific/Chatham",
  ])("keeps seven local days in the fine window for %s", async (timezone) => {
    const now = new Date("2026-11-02T00:01:00Z");
    const summary = await summarize(
      [
        ledger("notes.entries", {
          a: ["2026-10-26T23:59:59Z", NOW],
          b: ["2026-11-01T05:59:59Z", NOW],
          c: ["2026-11-01T06:00:00Z", NOW],
        }),
      ],
      { now, timezone },
    );
    expect(
      projectPortableAdditionsByLocalDay(summary, timezone, 7, now),
    ).toEqual({ coverage: "complete", days: summary.days });
  });

  it("throws InvalidTimezoneError for an unknown timezone", async () => {
    await expect(summarize([], { timezone: "Not/AZone" })).rejects.toThrow(
      InvalidTimezoneError,
      bucketAdditionsByLocalDay,
      readAdditionsSummary,
      projectPortableAdditionsByLocalDay,
      readAdditionsSummaryJson,
    );
    expect(() => validateTimezone("Not/AZone")).toThrow(InvalidTimezoneError);
    expect(() => validateTimezone("America/Toronto")).not.toThrow();
  });
});
