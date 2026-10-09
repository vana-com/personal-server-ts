/**
 * Additions summary: how many records a scope's latest snapshots hold and how
 * many of those records were first added on each of the last N local calendar
 * days. Pure: it reads only the data objects it is handed, never a store, and
 * never mutates them.
 */

import {
  extractRecordKeys,
  readFirstAddedLedger,
  type FirstAddedLedger,
} from "./first-added.js";

export interface ScopeAdditionsInput {
  scope: string;
  /** `data` of the scope's latest stored snapshot. */
  latestData: Record<string, unknown>;
  /** `data` of other recent snapshots of the same scope (any order); may be empty. */
  recentData?: readonly Record<string, unknown>[];
}

export interface AdditionsSummaryInput {
  scopes: readonly ScopeAdditionsInput[];
  /** IANA timezone, e.g. "America/Toronto". */
  timezone: string;
  /** Number of local calendar days to report, ending with the day containing `now`. 1..31. */
  days: number;
  now: Date;
}

export interface AdditionsSummary {
  timezone: string;
  /** Records present in the latest snapshots, by the same rules the ledger uses. */
  total: number;
  /** Oldest first, exactly `days` entries, the last one is the local day containing `now`. */
  days: { date: string; added: number }[]; // date is "YYYY-MM-DD" in `timezone`
  /** Earliest `trackedSince` among scopes that have a ledger, or null when none has one. */
  trackedSince: string | null;
  scopes: {
    scope: string;
    total: number;
    /** null when the scope's latest snapshot has no ledger yet (not re-imported since tracking began). */
    trackedSince: string | null;
  }[];
}

export class InvalidTimezoneError extends Error {}

/** The merged first-added value of one present record across a scope's ledgers. */
interface FirstAddedCandidate {
  /** Any ledger marked the record as existing before tracking began. */
  preTracking: boolean;
  /** Earliest parseable timestamp seen so far; Infinity when none parsed. */
  earliestAt: number;
}

function hasOwn(data: object, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(data, key);
}

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

/**
 * Fold one ledger's value for `key` into the candidate. A null (pre-tracking)
 * wins outright; otherwise the earliest parseable timestamp wins, and values
 * that do not parse are ignored.
 */
function considerLedger(
  ledger: FirstAddedLedger | null,
  key: string,
  candidate: FirstAddedCandidate,
): void {
  if (!ledger || !hasOwn(ledger.records, key)) return;
  const value = ledger.records[key];
  if (value === null) {
    candidate.preTracking = true;
    return;
  }
  if (typeof value !== "string") return;
  const at = Date.parse(value);
  if (Number.isNaN(at)) return;
  if (at < candidate.earliestAt) candidate.earliestAt = at;
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

  for (const scopeInput of input.scopes) {
    const keys = await extractRecordKeys(
      scopeInput.scope,
      scopeInput.latestData,
    );
    if (keys === null) continue;

    const ledger = readFirstAddedLedger(scopeInput.latestData);
    const recentLedgers = (scopeInput.recentData ?? []).map((data) =>
      readFirstAddedLedger(data),
    );

    for (const key of keys) {
      const candidate: FirstAddedCandidate = {
        preTracking: false,
        earliestAt: Infinity,
      };
      considerLedger(ledger, key, candidate);
      for (const recentLedger of recentLedgers) {
        considerLedger(recentLedger, key, candidate);
      }
      if (candidate.preTracking || candidate.earliestAt === Infinity) continue;
      const date = localDate(formatter, new Date(candidate.earliestAt));
      const index = dayIndex.get(date);
      if (index !== undefined) dayRows[index].added += 1;
    }

    total += keys.length;
    const scopeTrackedSince = ledger?.trackedSince ?? null;
    if (scopeTrackedSince !== null) {
      const at = Date.parse(scopeTrackedSince);
      if (!Number.isNaN(at) && at < trackedSinceAt) {
        trackedSinceAt = at;
        trackedSince = scopeTrackedSince;
      }
    }
    scopes.push({
      scope: scopeInput.scope,
      total: keys.length,
      trackedSince: scopeTrackedSince,
    });
  }

  scopes.sort((a, b) => a.scope.localeCompare(b.scope));

  return { timezone, total, days: dayRows, trackedSince, scopes };
}
