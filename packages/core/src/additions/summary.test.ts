import { describe, expect, it } from "vitest";
import type { FirstAddedLedger } from "./first-added.js";
import {
  InvalidTimezoneError,
  summarizeAdditions,
  type AdditionsSummary,
  type AdditionsSummaryInput,
  type ScopeAdditionsInput,
} from "./summary.js";

/** A fixed instant in UTC; the default test clock. */
const NOW = "2026-10-09T12:00:00.000Z";

function ledger(
  trackedSince: string,
  records: Record<string, string | null>,
): FirstAddedLedger {
  return { version: 1, trackedSince, records };
}

function withLedger(
  data: Record<string, unknown>,
  firstAdded: FirstAddedLedger,
): Record<string, unknown> {
  return { ...data, $firstAdded: firstAdded };
}

function scope(
  scopeName: string,
  data: Record<string, unknown>,
  recentData?: Record<string, unknown>[],
): ScopeAdditionsInput {
  return { scope: scopeName, latestData: data, recentData };
}

function summarize(
  scopes: ScopeAdditionsInput[],
  overrides: Partial<AdditionsSummaryInput> = {},
): Promise<AdditionsSummary> {
  return summarizeAdditions({
    scopes,
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
  it("counts records first added today, yesterday and 8 days ago into the right days", async () => {
    const data = withLedger(
      { items: [{ id: "a" }, { id: "b" }, { id: "c" }] },
      ledger(NOW, {
        "items:i:a": "2026-10-09T01:00:00.000Z",
        "items:i:b": "2026-10-08T23:00:00.000Z",
        "items:i:c": "2026-10-01T10:00:00.000Z",
      }),
    );

    const summary = await summarize([scope("notes.entries", data)]);

    expect(summary.total).toBe(3);
    expect(summary.days).toHaveLength(7);
    expect(summary.days.at(-1)).toEqual({ date: "2026-10-09", added: 1 });
    expect(addedOn(summary, "2026-10-08")).toBe(1);
    // 2026-10-01 is outside the 7-day window, so it counts toward no day.
    expect(addedOn(summary, "2026-10-01")).toBeUndefined();
  });

  it("assigns a timestamp to its local calendar day in the requested timezone", async () => {
    const data = withLedger(
      { items: [{ id: "a" }] },
      ledger(NOW, { "items:i:a": "2026-10-09T03:30:00.000Z" }),
    );

    const toronto = await summarize([scope("notes.entries", data)], {
      timezone: "America/Toronto",
    });
    expect(addedOn(toronto, "2026-10-08")).toBe(1);
    expect(addedOn(toronto, "2026-10-09")).toBe(0);

    const utc = await summarize([scope("notes.entries", data)], {
      timezone: "UTC",
    });
    expect(addedOn(utc, "2026-10-09")).toBe(1);
    expect(addedOn(utc, "2026-10-08")).toBe(0);
  });

  it("lists consecutive local days across a DST change with no duplicates or gaps", async () => {
    // 2026-11-01 is the fall-back DST change in America/Toronto; this clock is
    // 30 minutes after the 02:00 EDT -> 01:00 EST transition.
    const summary = await summarizeAdditions({
      scopes: [],
      timezone: "America/Toronto",
      days: 7,
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

  it("counts records with no first-added date toward total but no day", async () => {
    const data = withLedger(
      { items: [{ id: "a" }, { id: "b" }, { id: "c" }] },
      ledger(NOW, {
        "items:i:a": null,
        // "items:i:b" is absent from the ledger entirely.
        "items:i:c": "2026-10-09T01:00:00.000Z",
      }),
    );

    const summary = await summarize([scope("notes.entries", data)]);

    expect(summary.total).toBe(3);
    expect(summary.days.at(-1)).toEqual({ date: "2026-10-09", added: 1 });
  });

  it("ignores ledger entries for records no longer present", async () => {
    const data = withLedger(
      { items: [{ id: "a" }] },
      ledger(NOW, {
        "items:i:a": "2026-10-09T01:00:00.000Z",
        "items:i:gone": "2026-10-09T02:00:00.000Z",
      }),
    );

    const summary = await summarize([scope("notes.entries", data)]);

    expect(summary.total).toBe(1);
    expect(summary.days.at(-1)).toEqual({ date: "2026-10-09", added: 1 });
  });

  it("merges recent ledgers, preferring the earliest date and any null", async () => {
    const latest = withLedger(
      { items: [{ id: "a" }, { id: "b" }] },
      ledger(NOW, {
        "items:i:a": "2026-10-09T01:00:00.000Z",
        "items:i:b": "2026-10-09T01:00:00.000Z",
      }),
    );
    const recent = withLedger(
      { items: [{ id: "a" }, { id: "b" }] },
      ledger("2026-10-05T00:00:00.000Z", {
        "items:i:a": "2026-10-08T01:00:00.000Z",
        "items:i:b": null,
      }),
    );

    const summary = await summarize([scope("notes.entries", latest, [recent])]);

    expect(summary.total).toBe(2);
    // `a` takes the earlier date from the recent ledger; `b` was null there.
    expect(addedOn(summary, "2026-10-08")).toBe(1);
    expect(addedOn(summary, "2026-10-09")).toBe(0);
  });

  it("lists a ledgerless scope and skips binary scopes", async () => {
    const noLedger = { items: [{ id: "a" }, { id: "b" }] };
    const binary = { $binary: { mimeType: "application/pdf" } };

    const summary = await summarize([
      scope("notes.entries", noLedger),
      scope("documents.pdf", binary),
    ]);

    expect(summary.total).toBe(2);
    expect(summary.trackedSince).toBeNull();
    expect(summary.scopes).toEqual([
      { scope: "notes.entries", total: 2, trackedSince: null },
    ]);
    // The input objects are left untouched.
    expect(noLedger).toEqual({ items: [{ id: "a" }, { id: "b" }] });
  });

  it("reports the earliest trackedSince across scopes and null when none has a ledger", async () => {
    const older = withLedger(
      { items: [{ id: "a" }] },
      ledger("2026-09-20T00:00:00.000Z", {}),
    );
    const newer = withLedger(
      { items: [{ id: "b" }] },
      ledger("2026-10-01T00:00:00.000Z", {}),
    );

    const summary = await summarize([
      scope("aaa.scope", newer),
      scope("bbb.scope", older),
    ]);
    expect(summary.trackedSince).toBe("2026-09-20T00:00:00.000Z");

    const none = await summarize([
      scope("notes.entries", { items: [{ id: "a" }] }),
    ]);
    expect(none.trackedSince).toBeNull();
  });

  it("throws InvalidTimezoneError for an unknown timezone", async () => {
    await expect(
      summarize([scope("notes.entries", { items: [] })], {
        timezone: "Not/AZone",
      }),
    ).rejects.toBeInstanceOf(InvalidTimezoneError);
  });

  it("follows record rules for ruled and empty-rule scopes", async () => {
    const notes = withLedger(
      { notes: [{ recordName: "n1" }, { recordName: "n2" }] },
      ledger(NOW, {
        "notes:i:n1": "2026-10-09T01:00:00.000Z",
        "notes:i:n2": null,
      }),
    );
    const profile = withLedger(
      { displayName: "test" },
      ledger("2026-09-01T00:00:00.000Z", {}),
    );

    const summary = await summarize([
      scope("icloud_notes.notes", notes),
      scope("github.profile", profile),
    ]);

    expect(summary.total).toBe(2);
    expect(summary.scopes).toEqual([
      {
        scope: "github.profile",
        total: 0,
        trackedSince: "2026-09-01T00:00:00.000Z",
      },
      { scope: "icloud_notes.notes", total: 2, trackedSince: NOW },
    ]);
    expect(summary.days.at(-1)).toEqual({ date: "2026-10-09", added: 1 });
  });
});
