/**
 * Additions summary: how many records each scope's newest version holds and
 * how many of those records were first seen on each of the last N local
 * calendar days. Pure: it reads only the ledgers it is handed, never a store,
 * and never mutates them. A scope's records first seen at its `trackedSince`
 * count on that date unless the scope is `partial`.
 */

import {
  listAddedTimestamps,
  type ScopeFirstSeenLedger,
} from "./first-added.js";

export interface AdditionsSummaryInput {
  /**
   * One first-seen ledger per visible scope. Consumed one at a time, so a
   * lazy source keeps only one ledger in memory.
   */
  ledgers: Iterable<ScopeFirstSeenLedger> | AsyncIterable<ScopeFirstSeenLedger>;
  /** IANA timezone, e.g. "America/Toronto". */
  timezone: string;
  /** Number of local calendar days to report, ending with the day containing `now`. 1..31. */
  days: number;
  now: Date;
}

export interface AdditionsSummary {
  timezone: string;
  /** Records in each scope's newest version (tracked or not), summed. */
  total: number;
  /** Oldest first, exactly `days` entries, the last one is the local day containing `now`. */
  days: { date: string; added: number }[]; // date is "YYYY-MM-DD" in `timezone`
  /** Earliest scope baseline, or null when no scope has a trackable version yet. */
  trackedSince: string | null;
  /** Some scope's baseline was clamped (see the scope entries' `partial`). */
  partial: boolean;
  scopes: {
    scope: string;
    total: number;
    /**
     * The scope's baseline: records first seen then predate tracking. Null
     * when no version of the scope is trackable yet (binary only, over the
     * record cap, or no record has an id): the scope is total-only.
     */
    trackedSince: string | null;
    /**
     * The scope's baseline is not known to be its first version (older
     * versions were not folded or no longer exist), so records first seen at
     * `trackedSince` have an unknown date and are not counted as added.
     */
    partial: boolean;
  }[];
}

export class InvalidTimezoneError extends Error {}

function createFormatter(timezone: string): Intl.DateTimeFormat {
  try {
    return new Intl.DateTimeFormat("en-CA", {
      timeZone: timezone,
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
    });
  } catch {
    throw new InvalidTimezoneError(`Unknown timezone: ${timezone}`);
  }
}

/**
 * The local "YYYY-MM-DD" of an instant, built from `formatToParts` rather
 * than the joined en-CA string so the ordering is guaranteed.
 */
function localDate(formatter: Intl.DateTimeFormat, instant: Date): string {
  let year = "";
  let month = "";
  let day = "";
  for (const part of formatter.formatToParts(instant)) {
    if (part.type === "year") year = part.value;
    else if (part.type === "month") month = part.value;
    else if (part.type === "day") day = part.value;
  }
  return `${year}-${month}-${day}`;
}

function pad2(value: number): string {
  return String(value).padStart(2, "0");
}

/**
 * `days` local dates, oldest first, ending with the local day of `now`.
 * Previous dates use calendar arithmetic on the Y-M-D parts (via UTC), so a
 * daylight-saving change cannot skip or repeat a day.
 */
function buildDayRows(
  formatter: Intl.DateTimeFormat,
  now: Date,
  days: number,
): AdditionsSummary["days"] {
  const [year, month, day] = localDate(formatter, now).split("-").map(Number);
  const rows: AdditionsSummary["days"] = [];
  for (let offset = days - 1; offset >= 0; offset -= 1) {
    const date = new Date(Date.UTC(year, month - 1, day - offset));
    rows.push({
      date: `${date.getUTCFullYear()}-${pad2(
        date.getUTCMonth() + 1,
      )}-${pad2(date.getUTCDate())}`,
      added: 0,
    });
  }
  return rows;
}

/** Throws InvalidTimezoneError unless `timezone` is a known IANA zone. */
export function validateTimezone(timezone: string): void {
  createFormatter(timezone);
}

export async function summarizeAdditions(
  input: AdditionsSummaryInput,
): Promise<AdditionsSummary> {
  const { timezone, days, now } = input;
  const formatter = createFormatter(timezone);
  const dayRows = buildDayRows(formatter, now, days);
  const dayIndex = new Map(dayRows.map((row, index) => [row.date, index]));

  const scopes: AdditionsSummary["scopes"] = [];
  let total = 0;
  let trackedSince: string | null = null;
  let trackedSinceAt = Infinity;
  let anyPartial = false;

  for await (const ledger of input.ledgers) {
    for (const firstSeen of listAddedTimestamps(ledger)) {
      const date = localDate(formatter, new Date(Date.parse(firstSeen)));
      const index = dayIndex.get(date);
      if (index !== undefined) dayRows[index].added += 1;
    }

    total += ledger.latest.total;
    // A skipped scope keeps no per-record keys: it is total-only.
    const scopeTrackedSince = ledger.skipped ? null : ledger.baseline;
    if (scopeTrackedSince !== null) {
      const baselineAt = Date.parse(scopeTrackedSince);
      if (baselineAt < trackedSinceAt) {
        trackedSinceAt = baselineAt;
        trackedSince = scopeTrackedSince;
      }
    }
    const partial = ledger.partial === true;
    anyPartial ||= partial;
    scopes.push({
      scope: ledger.scope,
      total: ledger.latest.total,
      trackedSince: scopeTrackedSince,
      partial,
    });
  }

  scopes.sort((a, b) => a.scope.localeCompare(b.scope));

  return {
    timezone,
    total,
    days: dayRows,
    trackedSince,
    partial: anyPartial,
    scopes,
  };
}
