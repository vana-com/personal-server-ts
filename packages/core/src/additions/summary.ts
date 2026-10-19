/**
 * Additions summary: how many records each scope's newest version holds and
 * how many records arrived on each of the last N local
 * calendar days. Pure: it reads only the ledgers it is handed, never a store,
 * and never mutates them. A scope's records first seen at its `trackedSince`
 * count on that date unless the scope is `partial`.
 */

import { z } from "zod";
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
  /** Current coordination coverage, independent from unknown historical baseline dates. */
  coverage?: AdditionsCoverage;
  /** Stable per-scope source version markers, supplied by the coordinator. */
  through?: Record<string, string>;
  /** Inventory fingerprints corresponding to these folded counts. */
  inventory?: Record<string, string>;
}

export type AdditionsCoverage =
  "complete" | "behind" | "partial" | "unavailable";
export interface AdditionsBucket {
  /** Inclusive UTC start of a 15-minute interval, ISO 8601. */
  start: string;
  added: number;
}
export const ADDITIONS_BUCKET_MS = 15 * 60 * 1000;
const UTC_DAY_MS = 24 * 60 * 60 * 1000;
// Ten complete UTC days plus today cover a seven-local-day chart even at
// UTC-12/UTC+14 and across DST changes. Exact ledgers retain older timestamps.
export const ADDITIONS_FINE_DAYS = 10;
export interface AdditionsDailyCount {
  date: string;
  added: number;
}

export interface AdditionsSummary {
  version: 1;
  coverage: AdditionsCoverage;
  through: Record<string, string>;
  /** Absent on older producers; cannot certify portable freshness after a reorg. */
  inventory?: Record<string, string>;
  /** UTC midnight cutoff. Older daily counts cannot prove exact local days. */
  fineSince: string;
  daily: AdditionsDailyCount[];
  /** Recent arrivals in UTC quarter-hours. */
  buckets: AdditionsBucket[];
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
    daily: AdditionsDailyCount[];
    /** Recent scope arrivals. */
    buckets: AdditionsBucket[];
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

const countSchema = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const instantSchema = z.string().datetime({ offset: true });
const daySchema = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}$/)
  .refine((value) => {
    const date = new Date(`${value}T00:00:00.000Z`);
    return (
      Number.isFinite(date.getTime()) &&
      date.toISOString().slice(0, 10) === value
    );
  });

const bucketsSchema = z.array(
  z.object({
    start: instantSchema.refine(
      (value) => Date.parse(value) % ADDITIONS_BUCKET_MS === 0,
    ),
    added: countSchema,
  }),
);

/** Browser-safe transport contract for the version-1 owner summary. */
export const AdditionsSummarySchema = z.object({
  version: z.literal(1),
  coverage: z.enum(["complete", "behind", "partial", "unavailable"]),
  through: z.record(z.string(), z.string().regex(/^(0|[1-9]\d*)$/)),
  inventory: z
    .record(z.string(), z.string().regex(/^0x[0-9a-f]{64}$/))
    .optional(),
  fineSince: instantSchema,
  daily: z.array(z.object({ date: daySchema, added: countSchema })),
  buckets: bucketsSchema,
  timezone: z.string().refine((value) => {
    try {
      validateTimezone(value);
      return true;
    } catch {
      return false;
    }
  }),
  total: countSchema,
  days: z
    .array(z.object({ date: daySchema, added: countSchema }))
    .min(1)
    .max(31),
  trackedSince: instantSchema.nullable(),
  partial: z.boolean(),
  scopes: z.array(
    z.object({
      scope: z
        .string()
        .min(1)
        .refine((scope) => !scope.startsWith("vana.system.")),
      total: countSchema,
      buckets: bucketsSchema,
      daily: z.array(z.object({ date: daySchema, added: countSchema })),
      trackedSince: instantSchema.nullable(),
      partial: z.boolean(),
    }),
  ),
});

/** Null for unsupported or malformed transport payloads. */
export function readAdditionsSummary(value: unknown): AdditionsSummary | null {
  try {
    const result = AdditionsSummarySchema.safeParse(value);
    return result.success ? result.data : null;
  } catch {
    return null;
  }
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

/** Rebucket UTC arrivals into local calendar days, including DST and fractional-hour zones. */
export function bucketAdditionsByLocalDay(
  buckets: readonly AdditionsBucket[],
  timezone: string,
  days: number,
  now: Date,
): AdditionsSummary["days"] {
  const formatter = createFormatter(timezone);
  const rows = buildDayRows(formatter, now, days);
  const byDate = new Map(rows.map((row) => [row.date, row]));
  for (const bucket of buckets) {
    const row = byDate.get(localDate(formatter, new Date(bucket.start)));
    if (row) row.added += bucket.added;
  }
  return rows;
}

/** Sort the recent UTC intervals. */
function sortedBuckets(counts: ReadonlyMap<number, number>): AdditionsBucket[] {
  return [...counts]
    .sort(([a], [b]) => a - b)
    .map(([start, added]) => ({ start: new Date(start).toISOString(), added }));
}

export async function summarizeAdditions(
  input: AdditionsSummaryInput,
): Promise<AdditionsSummary> {
  const { timezone, days, now } = input;
  validateTimezone(timezone);
  const fineSinceAt =
    Math.floor(now.getTime() / UTC_DAY_MS) * UTC_DAY_MS -
    ADDITIONS_FINE_DAYS * UTC_DAY_MS;
  const bucketCounts = new Map<number, number>();
  const dailyCounts = new Map<number, number>();
  const exactDays = buildDayRows(createFormatter(timezone), now, days);
  const byDate = new Map(exactDays.map((row) => [row.date, row]));
  const formatter = createFormatter(timezone);
  const sortedDays = (
    counts: ReadonlyMap<number, number>,
  ): AdditionsDailyCount[] =>
    [...counts]
      .sort(([a], [b]) => a - b)
      .map(([at, added]) => ({
        date: new Date(at).toISOString().slice(0, 10),
        added,
      }));
  let incomplete = false;

  const scopes: AdditionsSummary["scopes"] = [];
  let total = 0;
  let trackedSince: string | null = null;
  let trackedSinceAt = Infinity;
  let anyPartial = false;

  for await (const ledger of input.ledgers) {
    if (ledger.scope.startsWith("vana.system.")) continue;
    incomplete ||= Boolean(
      ledger.skipped || ledger.incomplete || ledger.truncated || ledger.retry,
    );
    const scopeBucketCounts = new Map<number, number>();
    const scopeDailyCounts = new Map<number, number>();
    for (const firstSeen of listAddedTimestamps(ledger)) {
      const start =
        Math.floor(Date.parse(firstSeen) / ADDITIONS_BUCKET_MS) *
        ADDITIONS_BUCKET_MS;
      const row = byDate.get(localDate(formatter, new Date(firstSeen)));
      if (row) row.added++;
      if (start >= fineSinceAt) {
        bucketCounts.set(start, (bucketCounts.get(start) ?? 0) + 1);
        scopeBucketCounts.set(start, (scopeBucketCounts.get(start) ?? 0) + 1);
      } else {
        const day = Math.floor(start / UTC_DAY_MS) * UTC_DAY_MS;
        dailyCounts.set(day, (dailyCounts.get(day) ?? 0) + 1);
        scopeDailyCounts.set(day, (scopeDailyCounts.get(day) ?? 0) + 1);
      }
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
    // Only a tracked scope can be partial: with no baseline there is nothing
    // whose date could be unknown.
    const partial = scopeTrackedSince !== null && ledger.partial === true;
    anyPartial ||= partial;
    scopes.push({
      scope: ledger.scope,
      total: ledger.latest.total,
      buckets: sortedBuckets(scopeBucketCounts),
      daily: sortedDays(scopeDailyCounts),
      trackedSince: scopeTrackedSince,
      partial,
    });
  }

  scopes.sort((a, b) => a.scope.localeCompare(b.scope));

  const buckets = sortedBuckets(bucketCounts);
  return {
    version: 1,
    coverage:
      incomplete && (!input.coverage || input.coverage === "complete")
        ? "partial"
        : (input.coverage ?? "complete"),
    through: { ...input.through },
    ...(input.inventory ? { inventory: { ...input.inventory } } : {}),
    buckets,
    fineSince: new Date(fineSinceAt).toISOString(),
    daily: sortedDays(dailyCounts),
    timezone,
    total,
    days: exactDays,
    trackedSince,
    partial: anyPartial,
    scopes,
  };
}

export const ADDITIONS_SUMMARY_MAX_BYTES = 8 * 1024 * 1024;

/** Parse a portable document only within its browser transport size limit. */
export function readAdditionsSummaryJson(
  json: string,
): AdditionsSummary | null {
  if (
    json.length > ADDITIONS_SUMMARY_MAX_BYTES ||
    new TextEncoder().encode(json).byteLength > ADDITIONS_SUMMARY_MAX_BYTES
  )
    return null;
  try {
    return readAdditionsSummary(JSON.parse(json));
  } catch {
    return null;
  }
}

/** Old UTC days cannot be split into exact local days without the owner ledger. */
export function projectPortableAdditionsByLocalDay(
  summary: AdditionsSummary,
  timezone: string,
  days: number,
  now: Date,
): { coverage: AdditionsCoverage; days: AdditionsSummary["days"] | null } {
  const formatter = createFormatter(timezone);
  const rows = buildDayRows(formatter, now, days);
  if (timezone === "UTC") {
    const byDate = new Map(rows.map((row) => [row.date, row]));
    for (const count of summary.daily) {
      const row = byDate.get(count.date);
      if (row) row.added += count.added;
    }
    for (const bucket of summary.buckets) {
      const row = byDate.get(new Date(bucket.start).toISOString().slice(0, 10));
      if (row) row.added += bucket.added;
    }
    return { coverage: summary.coverage, days: rows };
  }
  // Reject the cutoff's local day too, since it may begin before UTC midnight.
  if (
    rows.some(
      (row) => row.date <= localDate(formatter, new Date(summary.fineSince)),
    )
  )
    return { coverage: "partial", days: null };
  return {
    coverage: summary.coverage,
    days: bucketAdditionsByLocalDay(summary.buckets, timezone, days, now),
  };
}
