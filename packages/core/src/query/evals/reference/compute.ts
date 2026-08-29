/**
 * The independent reference path.
 *
 * Everything here re-reads the **serialized** corpus through a `FixtureSource`
 * and recomputes from scratch. It deliberately shares no state with the
 * generator: if the fixture and its expectation both came from one in-memory
 * accumulator, the eval would only prove that the generator's arithmetic agrees
 * with itself, which is not a test of anything.
 *
 * These are also the reference implementations of the implicit rules from
 * design §12 — the nap rule and the `current_node` walk — so the trap numbers
 * are computed the way a correct parser would compute them, not the way the
 * generator happened to emit them.
 */

import type { FixtureSource } from "../fixtures/sink.js";
import { PEOPLE } from "../fixtures/text.js";
import {
  Q14_JPY_PER_USD,
  Q14_TRIP_END_DAY,
  Q14_TRIP_START_DAY,
  Q8_CONFLICT_MARKER,
  Q5_RESTAURANT,
} from "../fixtures/planted.js";
import { CORPUS_DAYS, DAY_MS, dayIso, dayStartMs } from "../fixtures/time.js";

async function readJson<T>(source: FixtureSource, file: string): Promise<T> {
  return JSON.parse(await source.read(file)) as T;
}

/* ------------------------------------------------------------------ */
/* Trap 1 — Oura naps (design §18.2)                                   */
/* ------------------------------------------------------------------ */

export interface SleepTrap {
  /** Main sleep only, excluding `rest`/`deleted` and null durations — correct. */
  correctHours: number;
  /** Main sleep plus naps — the design §18.2 naive reading. */
  naiveHours: number;
  /** Percentage error of the naps-included figure, signed. */
  errorPct: number;
  /**
   * Every row whose type is not `late_nap` — the filter that looks like it
   * excludes naps and in fact also sweeps in `rest` and `deleted` periods.
   * A nastier trap than the nap rule, because it reads as more careful.
   */
  excludingNapsOnlyHours: number;
  excludingNapsOnlyErrorPct: number;
  /** Main sleep with null durations coerced to zero. */
  nullAsZeroHours: number;
  /** Nights with a usable main-sleep record. */
  nights: number;
  /** Rows the naps-included average divides by. */
  naiveRows: number;
  /** Rows dropped because their type is `rest` or `deleted`. */
  excludedRows: number;
  /** Main-sleep rows whose `total_sleep_duration` is null. */
  nullDurationRows: number;
  /** Calendar days in the window, for the "N of M nights" denominator. */
  windowDays: number;
}

interface SleepRow {
  day: string;
  type: string;
  total_sleep_duration: number | null;
  average_heart_rate: number;
  bedtime_start: string;
}

/** Rows whose type disqualifies them from every calculation. */
const EXCLUDED_TYPES = new Set(["rest", "deleted"]);

function meanHours(rows: SleepRow[], nullAsZero = false): number {
  const usable = nullAsZero
    ? rows
    : rows.filter((r) => r.total_sleep_duration !== null);
  if (usable.length === 0) return 0;
  const total = usable.reduce((a, r) => a + (r.total_sleep_duration ?? 0), 0);
  return total / usable.length / 3600;
}

/**
 * @param windowDays trailing calendar days to average over, or `null` for the
 * whole corpus. The whole-corpus figure is the stable regression number; the
 * 31-day figure is what Q1 actually asks for and is noisier by construction.
 */
export async function sleepTrap(
  source: FixtureSource,
  windowDays: number | null = null,
): Promise<SleepTrap> {
  const rows = await readJson<SleepRow[]>(source, "oura_sleep.json");

  let scoped = rows;
  let days = CORPUS_DAYS;
  if (windowDays !== null) {
    const lastDay = rows.reduce((a, r) => (r.day > a ? r.day : a), "");
    const cutoffMs =
      Date.parse(`${lastDay}T00:00:00.000Z`) - (windowDays - 1) * DAY_MS;
    const cutoff = new Date(cutoffMs).toISOString().slice(0, 10);
    scoped = rows.filter((r) => r.day >= cutoff);
    days = windowDays;
  }

  const main = scoped.filter((r) => r.type === "long_sleep");
  // Valid periods: main sleep and naps, with rest/deleted dropped.
  const valid = scoped.filter((r) => !EXCLUDED_TYPES.has(r.type));
  // The plausible-looking filter that misses rest/deleted entirely.
  const notNaps = scoped.filter((r) => r.type !== "late_nap");

  const correctHours = meanHours(main);
  const naiveHours = meanHours(valid);
  const excludingNapsOnlyHours = meanHours(notNaps);

  return {
    correctHours,
    naiveHours,
    errorPct: correctHours === 0 ? 0 : (naiveHours / correctHours - 1) * 100,
    excludingNapsOnlyHours,
    excludingNapsOnlyErrorPct:
      correctHours === 0
        ? 0
        : (excludingNapsOnlyHours / correctHours - 1) * 100,
    nullAsZeroHours: meanHours(main, true),
    nights: main.filter((r) => r.total_sleep_duration !== null).length,
    naiveRows: valid.length,
    excludedRows: scoped.length - valid.length,
    nullDurationRows: main.filter((r) => r.total_sleep_duration === null)
      .length,
    windowDays: days,
  };
}

/**
 * How many sleep rows have a `day` that disagrees with the UTC date of their
 * `bedtime_start`. Any implementation that re-derives the date from the
 * localized timestamp gets these wrong.
 */
export async function localDateDrift(source: FixtureSource): Promise<{
  rows: number;
  mismatched: number;
}> {
  const rows = await readJson<SleepRow[]>(source, "oura_sleep.json");
  let mismatched = 0;
  for (const row of rows) {
    const derived = new Date(row.bedtime_start).toISOString().slice(0, 10);
    if (derived !== row.day) mismatched++;
  }
  return { rows: rows.length, mismatched };
}

/* ------------------------------------------------------------------ */
/* Trap 2 — ChatGPT sibling branches (design §18.2)                    */
/* ------------------------------------------------------------------ */

export interface BranchTrap {
  conversations: number;
  /** Messages on the path from `current_node` back to the root. */
  correctMessages: number;
  /** Every node in `mapping` with a message, including abandoned branches. */
  naiveMessages: number;
  /** Percentage of phantom messages the naive flatten invents. */
  phantomPct: number;
}

interface ChatConversation {
  current_node: string;
  mapping: Record<
    string,
    { id: string; parent: string | null; message: unknown | null }
  >;
}

export async function branchTrap(source: FixtureSource): Promise<BranchTrap> {
  const conversations = await readJson<ChatConversation[]>(
    source,
    "conversations.json",
  );

  let correct = 0;
  let naive = 0;
  for (const conv of conversations) {
    for (const node of Object.values(conv.mapping)) {
      if (node.message) naive++;
    }
    // Design §12.3: the only correct reconstruction walks current_node back
    // through parent and reverses. Anything else double-counts regenerations.
    let cursor: string | null = conv.current_node;
    const seen = new Set<string>();
    while (cursor && cursor !== "root" && !seen.has(cursor)) {
      seen.add(cursor);
      const node: ChatConversation["mapping"][string] | undefined =
        conv.mapping[cursor];
      if (!node) break;
      if (node.message) correct++;
      cursor = node.parent;
    }
  }

  return {
    conversations: conversations.length,
    correctMessages: correct,
    naiveMessages: naive,
    phantomPct: correct === 0 ? 0 : (naive / correct - 1) * 100,
  };
}

/* ------------------------------------------------------------------ */
/* Literal scans — needle uniqueness and absence proofs                */
/* ------------------------------------------------------------------ */

export interface LiteralScan {
  occurrences: number;
  files: string[];
  bytesScanned: number;
}

/** Counts a literal across every file in the corpus. */
export async function scanLiteral(
  source: FixtureSource,
  needle: string,
): Promise<LiteralScan> {
  const files = await source.list();
  let occurrences = 0;
  let bytesScanned = 0;
  const hits: string[] = [];
  for (const file of files) {
    const text = await source.read(file);
    bytesScanned += text.length;
    let count = 0;
    let i = text.indexOf(needle);
    while (i !== -1) {
      count++;
      i = text.indexOf(needle, i + needle.length);
    }
    if (count > 0) {
      hits.push(file);
      occurrences += count;
    }
  }
  return { occurrences, files: hits, bytesScanned };
}

/* ------------------------------------------------------------------ */
/* Q5 — the needle                                                     */
/* ------------------------------------------------------------------ */

export interface NeedleReference {
  answer: string;
  occurrences: number;
  speakerAlias: string;
  date: string;
  /** How far from the end of the corpus, in days — recency truncation's blind spot. */
  daysBeforeEnd: number;
}

interface SlackRow {
  ts: string;
  user: string;
  channel: string;
  text: string;
}

export async function needleReference(
  source: FixtureSource,
): Promise<NeedleReference> {
  const rows = await readJson<SlackRow[]>(source, "slack_messages.json");
  const hit = rows.find((r) => r.text.includes(Q5_RESTAURANT));
  if (!hit) throw new Error("Q5 needle is missing from the generated corpus");

  const scan = await scanLiteral(source, Q5_RESTAURANT);
  const tsMs = Number(hit.ts) * 1000;
  const endMs = dayStartMs(CORPUS_DAYS);
  return {
    answer: Q5_RESTAURANT,
    occurrences: scan.occurrences,
    speakerAlias: hit.user,
    date: new Date(tsMs).toISOString().slice(0, 10),
    daysBeforeEnd: Math.round((endMs - tsMs) / DAY_MS),
  };
}

/* ------------------------------------------------------------------ */
/* Q6 — distinct people                                                */
/* ------------------------------------------------------------------ */

export interface IdentityReference {
  /** Distinct humans after alias resolution — the answer. */
  distinctPeople: number;
  /** Distinct raw strings — what counting rows gives instead. */
  distinctAliases: number;
  rowsScanned: number;
}

interface EmailRow {
  from: string;
  to: string;
  date: string;
}
interface CalendarRow {
  attendees: string[];
  start: string;
}

/** Alias → person id, built from the identity graph rather than string munging. */
function aliasIndex(): Map<string, string> {
  const index = new Map<string, string>();
  for (const person of PEOPLE) {
    for (const alias of person.aliases) index.set(alias, person.id);
  }
  return index;
}

export async function identityReference(
  source: FixtureSource,
  windowDays = 31,
): Promise<IdentityReference> {
  const index = aliasIndex();
  const people = new Set<string>();
  const aliases = new Set<string>();
  let rows = 0;

  const cutoffMs = dayStartMs(CORPUS_DAYS - windowDays);
  const note = (alias: string): void => {
    aliases.add(alias);
    const id = index.get(alias);
    if (id) people.add(id);
  };

  for (const row of await readJson<SlackRow[]>(source, "slack_messages.json")) {
    if (Number(row.ts) * 1000 < cutoffMs) continue;
    rows++;
    note(row.user);
  }
  for (const row of await readJson<EmailRow[]>(source, "email.json")) {
    if (Date.parse(row.date) < cutoffMs) continue;
    rows++;
    note(row.from);
    note(row.to);
  }
  for (const row of await readJson<CalendarRow[]>(source, "calendar.json")) {
    if (Date.parse(row.start) < cutoffMs) continue;
    rows++;
    for (const attendee of row.attendees) note(attendee);
  }

  return {
    distinctPeople: people.size,
    distinctAliases: aliases.size,
    rowsScanned: rows,
  };
}

/* ------------------------------------------------------------------ */
/* Q7 — recurring expenses                                             */
/* ------------------------------------------------------------------ */

export interface RecurringReference {
  recurringMerchants: string[];
  crept: { merchant: string; from: number; to: number }[];
  transactions: number;
}

interface BankRow {
  date: string;
  merchant: string;
  amount: number;
  currency: string;
}

export async function recurringReference(
  source: FixtureSource,
): Promise<RecurringReference> {
  const rows = await readJson<BankRow[]>(source, "bank_transactions.json");
  const byMerchant = new Map<string, BankRow[]>();
  for (const row of rows) {
    const list = byMerchant.get(row.merchant) ?? [];
    list.push(row);
    byMerchant.set(row.merchant, list);
  }

  const recurring: string[] = [];
  const crept: RecurringReference["crept"] = [];
  const months = Math.ceil(CORPUS_DAYS / 30);

  for (const [merchant, list] of byMerchant) {
    // Recurring = roughly one charge per month across most of the window.
    if (list.length < months * 0.8) continue;
    recurring.push(merchant);
    const sorted = [...list].sort((a, b) => a.date.localeCompare(b.date));
    const first = Math.abs(sorted[0]!.amount);
    const last = Math.abs(sorted[sorted.length - 1]!.amount);
    if (last > first * 1.05) crept.push({ merchant, from: first, to: last });
  }

  recurring.sort();
  crept.sort((a, b) => a.merchant.localeCompare(b.merchant));
  return { recurringMerchants: recurring, crept, transactions: rows.length };
}

/* ------------------------------------------------------------------ */
/* Q8 — absence with unreadables                                       */
/* ------------------------------------------------------------------ */

export interface AbsenceReference {
  documents: number;
  readable: number;
  unreadable: number;
  /** Occurrences of the marker a genuinely conflicting agreement would carry. */
  conflictMarkerOccurrences: number;
  /** Documents a keyword scan flags but which are not binding. */
  nearMisses: number;
}

interface DocumentRow {
  id: string;
  text_extracted: string | null;
  extraction_error: string | null;
}

export async function absenceReference(
  source: FixtureSource,
): Promise<AbsenceReference> {
  const rows = await readJson<DocumentRow[]>(source, "documents.json");
  const unreadable = rows.filter((r) => r.text_extracted === null).length;
  const scan = await scanLiteral(source, Q8_CONFLICT_MARKER);
  const nearMisses = rows.filter(
    (r) =>
      r.text_extracted !== null &&
      /exclusivit|non-compete/i.test(r.text_extracted) &&
      r.id !== "doc-contract-under-test",
  ).length;

  return {
    documents: rows.length,
    readable: rows.length - unreadable,
    unreadable,
    conflictMarkerOccurrences: scan.occurrences,
    nearMisses,
  };
}

/* ------------------------------------------------------------------ */
/* Q11 — anomaly against a personal baseline                           */
/* ------------------------------------------------------------------ */

export interface AnomalyReference {
  /**
   * Resting heart rate over the last week: `oura_heartrate` rows whose
   * `source` is `rest` or `sleep`. **This is the graded value**, and it is
   * reachable only through that filter — see the two contaminated figures
   * below, both of which are an order of magnitude outside the tolerance.
   */
  lastWeekBpm: number;
  /** The same filtered series over the rest of the history. */
  baselineBpm: number;
  deltaBpm: number;
  baselineStdDev: number;
  /** Standard deviations from baseline — "unusual" needs a stated threshold. */
  zScore: number;
  /** Samples behind each figure. Thin by construction; the answer must say so. */
  lastWeekSamples: number;
  baselineSamples: number;
  /**
   * The same two figures computed without filtering on `source`. Workout and
   * session samples sit ~45bpm higher, so an unfiltered reading is inflated
   * far past the anomaly it is supposed to detect.
   */
  unfilteredLastWeekBpm: number;
  unfilteredBaselineBpm: number;
  /**
   * The other route to a number that looks like an answer:
   * `oura_sleep.average_heart_rate`, which is the mean heart rate *during
   * sleep* and not a resting series at all. It used to be what this case
   * graded, which is why the case passed without ever reading `oura.heartrate`
   * (implementation plan §6).
   */
  sleepRowLastWeekBpm: number;
  sleepRowBaselineBpm: number;
}

interface HeartRateRow {
  bpm: number;
  source: string;
  timestamp: string;
}

/** `source` values that represent a genuine resting measurement. */
const RESTING_HR_SOURCES = new Set(["rest", "sleep"]);

const mean = (xs: readonly number[]): number =>
  xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : 0;

/**
 * Q11's resting-heart-rate figures, from the `heartrate` collection.
 *
 * The window is cut on the sample's **own timestamp date**, because that is
 * the only date a `heartrate` row carries — there is no `day` field here, so
 * the sleep-day convention that governs `oura_sleep` does not apply and cannot
 * be borrowed. The generator emits each night's samples starting two hours
 * before midnight, so a night's block is timestamped on the evening before it,
 * exactly as a real export does.
 */
export async function anomalyReference(
  source: FixtureSource,
  windowDays = 7,
): Promise<AnomalyReference> {
  const cutoff = dayIso(CORPUS_DAYS - windowDays);

  const hr = await readJson<HeartRateRow[]>(source, "oura_heartrate.json");
  const recent = hr.filter((r) => r.timestamp.slice(0, 10) >= cutoff);
  const older = hr.filter((r) => r.timestamp.slice(0, 10) < cutoff);
  const resting = (rows: HeartRateRow[]): number[] =>
    rows.filter((r) => RESTING_HR_SOURCES.has(r.source)).map((r) => r.bpm);

  const recentResting = resting(recent);
  const baselineResting = resting(older);
  const lastWeekBpm = mean(recentResting);
  const baselineBpm = mean(baselineResting);
  const variance = baselineResting.length
    ? baselineResting.reduce((a, b) => a + (b - baselineBpm) ** 2, 0) /
      baselineResting.length
    : 0;
  const sd = Math.sqrt(variance);

  // The route this case used to grade, kept as a measured figure rather than
  // dropped: it is the near-miss a model lands on when it answers a resting-HR
  // question from the sleep collection, and the notes quote it.
  const sleep = await readJson<SleepRow[]>(source, "oura_sleep.json");
  const main = sleep.filter((r) => r.type === "long_sleep");
  const sleepRowLastWeekBpm = mean(
    main.filter((r) => r.day >= cutoff).map((r) => r.average_heart_rate),
  );
  const sleepRowBaselineBpm = mean(
    main.filter((r) => r.day < cutoff).map((r) => r.average_heart_rate),
  );

  return {
    lastWeekBpm,
    baselineBpm,
    deltaBpm: lastWeekBpm - baselineBpm,
    baselineStdDev: sd,
    zScore: sd === 0 ? 0 : (lastWeekBpm - baselineBpm) / sd,
    lastWeekSamples: recentResting.length,
    baselineSamples: baselineResting.length,
    unfilteredLastWeekBpm: mean(recent.map((r) => r.bpm)),
    unfilteredBaselineBpm: mean(older.map((r) => r.bpm)),
    sleepRowLastWeekBpm,
    sleepRowBaselineBpm,
  };
}

/* ------------------------------------------------------------------ */
/* Q14 — aggregation over an implicitly-defined set                    */
/* ------------------------------------------------------------------ */

export interface TripReference {
  startDay: string;
  endDay: string;
  /** Total in USD including the pre-paid flight charged outside the window. */
  totalUsd: number;
  /** What a naive "transactions between the dates" filter returns instead. */
  inWindowOnlyUsd: number;
  flightUsd: number;
  jpyTransactions: number;
}

export async function tripReference(
  source: FixtureSource,
): Promise<TripReference> {
  const rows = await readJson<BankRow[]>(source, "bank_transactions.json");
  const start = dayIso(Q14_TRIP_START_DAY);
  const end = dayIso(Q14_TRIP_END_DAY);

  /*
   * Rates come from the corpus, exactly as a script would read them.
   *
   * `fx_rates.json` is emitted for every profile so Q14 stops requiring a
   * model to guess a constant only the grader knows. On `small`/`full`/`lite`
   * the series is flat at `Q14_JPY_PER_USD`, so this computes the identical
   * total it always did; on `dogfood` it drifts by date, which is what design
   * §3 Q14 means by "FX applied at transaction date". The fallback keeps the
   * function working against a corpus generated before the scope existed.
   */
  const files = await source.list();
  const rateByDate = new Map<string, number>();
  if (files.includes("fx_rates.json")) {
    for (const r of await readJson<{ date: string; jpy_per_usd: number }[]>(
      source,
      "fx_rates.json",
    )) {
      rateByDate.set(r.date, r.jpy_per_usd);
    }
  }
  const rateOn = (date: string): number =>
    rateByDate.get(date) ?? Q14_JPY_PER_USD;

  let inWindow = 0;
  let jpyCount = 0;
  for (const row of rows) {
    if (row.date < start || row.date > end) continue;
    const usd =
      row.currency === "JPY"
        ? Math.abs(row.amount) / rateOn(row.date)
        : Math.abs(row.amount);
    if (row.currency === "JPY") jpyCount++;
    inWindow += usd;
  }

  const flight = rows
    .filter((r) => r.merchant === "DELTA AIR 006")
    .reduce((a, r) => a + Math.abs(r.amount), 0);

  return {
    startDay: start,
    endDay: end,
    totalUsd: inWindow + flight,
    inWindowOnlyUsd: inWindow,
    flightUsd: flight,
    jpyTransactions: jpyCount,
  };
}

/* ------------------------------------------------------------------ */
/* Q18 — conditional aggregation across two sources                    */
/* ------------------------------------------------------------------ */

export interface ConditionalReference {
  /** Days with a run over the threshold that also have a daily-activity row. */
  matchedDays: number;
  /** Run days with no matching activity row — honest n, not silently dropped. */
  unmatchedDays: number;
  meanCaloriesOnRunDays: number;
  meanCaloriesOtherDays: number;
  /** Workout rows before deduplicating manual/autodetected pairs. */
  workoutRows: number;
  /** Distinct sessions after dedup. */
  dedupedSessions: number;
  /**
   * What the filter returns if `distance` is read as kilometres rather than
   * metres: every workout qualifies, and the conditional aggregate collapses
   * into an unconditional one.
   */
  runDaysIfDistanceReadAsKm: number;
}

interface ActivityRow {
  day: string;
  total_calories: number;
}

interface WorkoutRow {
  day: string;
  distance: number;
  source: string;
}

export async function conditionalReference(
  source: FixtureSource,
  thresholdMetres = 10_000,
): Promise<ConditionalReference> {
  const activity = await readJson<ActivityRow[]>(source, "oura_activity.json");
  const workouts = await readJson<WorkoutRow[]>(source, "oura_workout.json");

  // `workout.source` is both `manual` and `autodetected`, so one session can
  // appear twice. Dedup by day before the join or every figure double-counts.
  const byDay = new Map<string, WorkoutRow>();
  for (const w of workouts) {
    const existing = byDay.get(w.day);
    if (!existing || w.source === "autodetected") byDay.set(w.day, w);
  }

  const runDays = new Set(
    [...byDay.values()]
      .filter((w) => w.distance > thresholdMetres)
      .map((w) => w.day),
  );
  const activityByDay = new Map(activity.map((a) => [a.day, a]));

  const matched: ActivityRow[] = [];
  let unmatched = 0;
  for (const day of runDays) {
    const row = activityByDay.get(day);
    if (row) matched.push(row);
    else unmatched++;
  }
  const others = activity.filter((a) => !runDays.has(a.day));

  const mean = (xs: ActivityRow[]): number =>
    xs.length ? xs.reduce((a, b) => a + b.total_calories, 0) / xs.length : 0;

  return {
    matchedDays: matched.length,
    unmatchedDays: unmatched,
    meanCaloriesOnRunDays: mean(matched),
    meanCaloriesOtherDays: mean(others),
    workoutRows: workouts.length,
    dedupedSessions: byDay.size,
    runDaysIfDistanceReadAsKm: new Set(
      [...byDay.values()].filter((w) => w.distance > 10).map((w) => w.day),
    ).size,
  };
}

/* ------------------------------------------------------------------ */
/* Time-axis audit — the regression guard for the compression artifact */
/* ------------------------------------------------------------------ */

export interface TimeAxisSpan {
  scope: string;
  file: string;
  first: string;
  last: string;
  spanDays: number;
  records: number;
}

/** Extracts the timestamp span of every time-bearing source, for the audit test. */
export async function timeAxisAudit(
  source: FixtureSource,
): Promise<TimeAxisSpan[]> {
  const specs: { scope: string; file: string; at: (row: never) => number }[] = [
    {
      scope: "oura.sleep",
      file: "oura_sleep.json",
      at: (r: never) => Date.parse(`${(r as { day: string }).day}T00:00:00Z`),
    },
    {
      scope: "oura.heartrate",
      file: "oura_heartrate.json",
      at: (r: never) => Date.parse((r as { timestamp: string }).timestamp),
    },
    {
      scope: "chatgpt.conversations",
      file: "conversations.json",
      at: (r: never) => (r as { create_time: number }).create_time * 1000,
    },
    {
      scope: "slack.messages",
      file: "slack_messages.json",
      at: (r: never) => Number((r as { ts: string }).ts) * 1000,
    },
    {
      scope: "email.messages",
      file: "email.json",
      at: (r: never) => Date.parse((r as { date: string }).date),
    },
    {
      scope: "bank.transactions",
      file: "bank_transactions.json",
      at: (r: never) => Date.parse(`${(r as { date: string }).date}T00:00:00Z`),
    },
    {
      scope: "calendar.events",
      file: "calendar.json",
      at: (r: never) => Date.parse((r as { start: string }).start),
    },
    {
      scope: "browser.history",
      file: "browser_history.json",
      at: (r: never) => Date.parse((r as { visit_time: string }).visit_time),
    },
    {
      scope: "notes.entries",
      file: "notes.json",
      at: (r: never) => Date.parse((r as { created: string }).created),
    },
  ];

  const out: TimeAxisSpan[] = [];
  const available = new Set(await source.list());
  for (const spec of specs) {
    if (!available.has(spec.file)) continue;
    const rows = await readJson<never[]>(source, spec.file);
    if (rows.length === 0) continue;
    let min = Infinity;
    let max = -Infinity;
    for (const row of rows) {
      const t = spec.at(row);
      if (t < min) min = t;
      if (t > max) max = t;
    }
    out.push({
      scope: spec.scope,
      file: spec.file,
      first: new Date(min).toISOString().slice(0, 10),
      last: new Date(max).toISOString().slice(0, 10),
      spanDays: Math.round((max - min) / DAY_MS),
      records: rows.length,
    });
  }
  return out;
}

/** Spotify lives across several files, so its span is computed separately. */
export async function spotifySpan(
  source: FixtureSource,
): Promise<TimeAxisSpan> {
  const files = (await source.list()).filter((f) =>
    f.startsWith("Streaming_History_Audio_"),
  );
  let min = Infinity;
  let max = -Infinity;
  let records = 0;
  for (const file of files) {
    for (const row of await readJson<{ ts: string }[]>(source, file)) {
      const t = Date.parse(row.ts);
      records++;
      if (t < min) min = t;
      if (t > max) max = t;
    }
  }
  return {
    scope: "spotify.streaming",
    file: files.join(","),
    first: new Date(min).toISOString().slice(0, 10),
    last: new Date(max).toISOString().slice(0, 10),
    spanDays: Math.round((max - min) / DAY_MS),
    records,
  };
}
