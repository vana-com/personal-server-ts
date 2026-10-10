import { describe, expect, it } from "vitest";
import type { ScopeFirstSeenLedger } from "./first-added.js";
import {
  InvalidTimezoneError,
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
    version: 2,
    scope,
    baseline: BASELINE,
    current: NOW,
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

  it("never counts pre-tracking records, absent records or other scopes' days", async () => {
    const summary = await summarize([
      ledger(
        "notes.entries",
        {
          // First seen at the baseline: predates tracking.
          "items:i:old": [BASELINE, NOW],
          // Added today but no longer in the newest version.
          "items:i:gone": [
            "2026-10-09T02:00:00.000Z",
            "2026-10-09T03:00:00.000Z",
          ],
          "items:i:new": ["2026-10-09T01:00:00.000Z", NOW],
        },
        { latest: { collectedAt: NOW, total: 2 } },
      ),
    ]);

    expect(summary.total).toBe(2);
    expect(summary.days.at(-1)).toEqual({ date: "2026-10-09", added: 1 });
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
          skipped: "too_many_keys",
          latest: { collectedAt: NOW, total: 300_000 },
        },
      ),
      ledger("c.normal", { "items:i:x": ["2026-10-09T01:00:00.000Z", NOW] }),
    ]);
    expect(summary.total).toBe(300_002);
    expect(summary.scopes).toEqual([
      { scope: "a.binary", total: 1, trackedSince: null },
      { scope: "b.huge", total: 300_000, trackedSince: null },
      { scope: "c.normal", total: 1, trackedSince: BASELINE },
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

  it("throws InvalidTimezoneError for an unknown timezone", async () => {
    await expect(summarize([], { timezone: "Not/AZone" })).rejects.toThrow(
      InvalidTimezoneError,
    );
    expect(() => validateTimezone("Not/AZone")).toThrow(InvalidTimezoneError);
    expect(() => validateTimezone("America/Toronto")).not.toThrow();
  });
});
