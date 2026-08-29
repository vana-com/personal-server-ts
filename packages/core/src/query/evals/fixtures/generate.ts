/**
 * The seeded, deterministic fixture generator.
 *
 * Replaces `docs/query-layer-fixtures/gen.js` + `gen2.js`. Same corpus shape,
 * three differences that matter:
 *
 *  1. **Seeded.** `Math.random()` appears nowhere; one seed reproduces the
 *     corpus byte for byte, so an expected value stays valid.
 *  2. **Real time axes.** Every source spreads across the same 1100-day window
 *     with burstiness, weekday bias and a diurnal curve. The old generator used
 *     a fixed delta per source, which compressed conversations into ~10 days
 *     and made Q9/Q10 vacuous.
 *  3. **Planted facts.** Q5's needle, Q8's absence-with-unreadables, Q11's
 *     anomaly and Q14's trip are constructed rather than hoped for.
 *
 * Node-free by construction: everything writes through `FixtureSink`.
 */

import { createRng, deriveSeed, type Rng } from "./prng.js";
import {
  writeJsonArray,
  type FixtureSink,
  type FixtureSource,
} from "./sink.js";
import {
  CORPUS_DAYS,
  DAY_MS,
  DIURNAL,
  apportion,
  dayIso,
  dayStartMs,
  dayWeights,
  iso,
  spreadTimestamps,
} from "./time.js";
import { PEOPLE, paragraph, sentence, FILLER_WORDS } from "./text.js";
import {
  FOCUS_LOUD_TOPIC,
  FOCUS_REAL_TOPIC,
  FOCUS_WEEK_DAYS,
  INTENTIONS,
  MORNING_CLAIMS,
  MORNING_COMMIT_PEAK_HOUR,
  MORNING_COMMIT_SHARE,
  SARAH_JOHNSON_FACTS,
  SARAH_NGUYEN_FACTS,
  TOPIC_ARCS,
  arcLineForDay,
  proseParagraph,
  proseSentence,
} from "./prose.js";
import type { FixtureProfile } from "./profiles.js";
import { DEFAULT_SEED, PROFILES, type FixtureProfileName } from "./profiles.js";
import {
  CHATGPT_DICT_PART_CHANCE,
  CHATGPT_NULL_CREATE_TIME_CHANCE,
  CHATGPT_NULL_PARTS_CHANCE,
  HOME_UTC_OFFSET,
  OURA_DELETED_CHANCE,
  OURA_HR_SOURCES,
  OURA_HR_WORKOUT_BPM_OFFSET,
  OURA_NULL_DURATION_CHANCE,
  OURA_REST_CHANCE,
  OURA_WORKOUT_DUPLICATE_CHANCE,
  SPOTIFY_ACCOUNT_DATA_DAYS,
  SPOTIFY_ACCOUNT_DATA_FILE,
  TRIP_UTC_OFFSET,
  type OuraSleepType,
  Q11_ANOMALY_BPM_OFFSET,
  Q11_ANOMALY_DAYS,
  Q18_DISTANCE_THRESHOLD_M,
  Q14_FLIGHT_AMOUNT_USD,
  Q14_FLIGHT_CHARGE_LEAD_DAYS,
  Q14_FLIGHT_MERCHANT,
  Q14_TRIP_END_DAY,
  Q14_TRIP_START_DAY,
  Q14_JPY_PER_USD,
  FX_BASE_CURRENCY,
  FX_DRIFT_AMPLITUDE,
  FX_DRIFT_PERIOD_DAYS,
  Q5_CHANNEL,
  Q5_DAY_INDEX,
  Q5_DECOYS,
  Q5_SPEAKER_ALIAS,
  Q8_CONTRACT_ID,
  Q8_NEAR_MISSES,
  Q8_UNREADABLE_COUNT,
  Q8_UNREADABLE_REASON,
  q5NeedleText,
} from "./planted.js";

/** Scope names, as a consumer's grant would express them. */
export const SCOPES = {
  fx: "fx.rates",
  nutrition: "nutrition.log",
  commits: "git.commits",
  ouraSleep: "oura.sleep",
  ouraDailySleep: "oura.daily_sleep",
  ouraWorkout: "oura.workout",
  ouraHeartRate: "oura.heartrate",
  ouraActivity: "oura.activity",
  ouraReadiness: "oura.readiness",
  spotify: "spotify.streaming",
  chatgpt: "chatgpt.conversations",
  slack: "slack.messages",
  email: "email.messages",
  bank: "bank.transactions",
  calendar: "calendar.events",
  browser: "browser.history",
  notes: "notes.entries",
  documents: "documents.files",
} as const;

/** Which files back each scope. Populated by the generator; used by the reference path. */
export interface CorpusManifest {
  seed: number;
  profile: FixtureProfileName;
  scopes: { scope: string; files: string[]; records: number }[];
}

/* ------------------------------------------------------------------ */
/* Semantic injection (dogfood only)                                    */
/* ------------------------------------------------------------------ */

/**
 * How often a text record carries an arc line rather than background prose.
 *
 * Deliberately low. An arc that shows up in a quarter of all notes is not a
 * topic a model has to *find*, it is a topic it trips over — which would make
 * Q9 and Q10 easy for the wrong reason. At 4% the arcs are a few dozen records
 * inside thousands, which is the needle-ish density the questions assume.
 */
const ARC_LINE_CHANCE = 0.04;
/** Stated intentions and morning claims are rarer still — a handful each. */
const INTENTION_CHANCE = 0.012;
const MORNING_CLAIM_CHANCE = 0.006;
const PERSON_FACT_CHANCE = 0.014;

/**
 * The semantic content for one record on one day, or undefined for background.
 *
 * Centralised so every text source draws from the same pool in the same way —
 * the arcs have to appear in notes *and* chat *and* slack for Q9's "order by
 * time across sources" to mean anything, and a per-source copy of this logic
 * would drift.
 */
function semanticLine(rng: Rng, dayIndex: number): string | undefined {
  if (rng.chance(ARC_LINE_CHANCE)) {
    const arc = rng.pick(TOPIC_ARCS);
    const line = arcLineForDay(rng, arc, dayIndex);
    if (line) return line;
  }
  if (rng.chance(INTENTION_CHANCE)) {
    return rng.pick(rng.pick(INTENTIONS).stated);
  }
  if (rng.chance(MORNING_CLAIM_CHANCE)) {
    return rng.pick(MORNING_CLAIMS);
  }
  if (rng.chance(PERSON_FACT_CHANCE)) {
    const facts = rng.chance(0.75) ? SARAH_JOHNSON_FACTS : SARAH_NGUYEN_FACTS;
    return rng.pick(facts).text;
  }
  return undefined;
}

/** Is this day inside the final week — the window Q2 asks about? */
function inFocusWeek(dayIndex: number): boolean {
  return dayIndex >= CORPUS_DAYS - FOCUS_WEEK_DAYS;
}

/** Sleep: main period 4.5–8.5h, naps 0.4–1.4h. */
const MAIN_SLEEP_MIN_H = 4.5;
const MAIN_SLEEP_MAX_H = 8.5;
const NAP_MIN_H = 0.4;
const NAP_MAX_H = 1.4;
/** Design §12.1: a day can hold multiple sleep periods. This is Q1's whole trap. */
const NAP_CHANCE = 0.12;
/** Nights genuinely missing from the export, so Q1's denominator is real. */
const SLEEP_MISSING_CHANCE = 0.06;

const MERCHANTS = [
  "SQ *BLUE BOTTLE 9821",
  "AMZN Mktp US*2H9",
  "UBER *TRIP",
  "WHOLEFDS #104",
  "SHELL OIL 4471",
  "TRADER JOES #221",
];

/** Fixed-cadence subscriptions — Q7's "recurring", with two that creep upward. */
const SUBSCRIPTIONS = [
  { merchant: "NETFLIX.COM", amount: 15.49, creepTo: 22.99 },
  { merchant: "SPOTIFY P0A2", amount: 9.99, creepTo: 11.99 },
  { merchant: "RENT ACH", amount: 2400, creepTo: 2400 },
  { merchant: "ICLOUD STORAGE", amount: 2.99, creepTo: 2.99 },
];

const JP_MERCHANTS = [
  "JR EAST TOKYO",
  "LAWSON OSAKA",
  "FAMILYMART KYOTO",
  "HOTEL GRANVIA",
];

const SLACK_CHANNELS = ["#eng", "#general", "#design", "#random", "#alerts"];

export interface GenerateOptions {
  seed?: number;
  profile?: FixtureProfileName;
}

/**
 * Generates the whole corpus into `sink` and returns a manifest.
 *
 * The manifest is bookkeeping for the *runner* (which scopes exist, which files
 * back them). It is deliberately not a source of expected values — those come
 * from the reference path re-reading the bytes.
 */
export async function generateCorpus(
  sink: FixtureSink,
  options: GenerateOptions = {},
): Promise<CorpusManifest> {
  const seed = options.seed ?? DEFAULT_SEED;
  const profile = PROFILES[options.profile ?? "small"];
  const rng = (stream: string): Rng => createRng(deriveSeed(seed, stream));

  const scopes: CorpusManifest["scopes"] = [];
  const record = (scope: string, files: string[], records: number): void => {
    scopes.push({ scope, files, records });
  };

  const sleepNights = await writeSleep(sink, rng("oura.sleep"), profile);
  record(SCOPES.ouraSleep, ["oura_sleep.json"], sleepNights);

  record(
    SCOPES.ouraDailySleep,
    ["oura_daily_sleep.json"],
    await writeDailySleep(sink, rng("oura.dailysleep"), profile),
  );
  // Collected while workouts are written so the nutrition log can raise intake
  // on heavy training days. Empty for profiles that emit no nutrition log.
  const highMileageDays = new Set<string>();
  record(
    SCOPES.ouraWorkout,
    ["oura_workout.json"],
    await writeWorkouts(sink, rng("oura.workout"), profile, highMileageDays),
  );
  record(
    SCOPES.ouraHeartRate,
    ["oura_heartrate.json"],
    await writeHeartRate(sink, rng("oura.heartrate"), profile),
  );
  record(
    SCOPES.ouraActivity,
    ["oura_activity.json"],
    await writeActivity(sink, rng("oura.activity"), profile),
  );
  record(
    SCOPES.ouraReadiness,
    ["oura_readiness.json"],
    await writeReadiness(sink, rng("oura.readiness"), profile),
  );

  const spotify = await writeSpotify(sink, rng("spotify"), profile);
  record(SCOPES.spotify, spotify.files, spotify.records);

  record(
    SCOPES.chatgpt,
    ["conversations.json"],
    await writeConversations(sink, rng("chatgpt"), profile),
  );
  record(
    SCOPES.slack,
    ["slack_messages.json"],
    await writeSlack(sink, rng("slack"), profile),
  );
  record(
    SCOPES.email,
    ["email.json"],
    await writeEmail(sink, rng("email"), profile),
  );
  record(
    SCOPES.bank,
    ["bank_transactions.json"],
    await writeBank(sink, rng("bank"), profile),
  );
  record(
    SCOPES.calendar,
    ["calendar.json"],
    await writeCalendar(sink, rng("calendar"), profile),
  );
  record(
    SCOPES.browser,
    ["browser_history.json"],
    await writeBrowser(sink, rng("browser"), profile),
  );
  record(
    SCOPES.notes,
    ["notes.json"],
    await writeNotes(sink, rng("notes"), profile),
  );
  record(
    SCOPES.documents,
    ["documents.json"],
    await writeDocuments(sink, rng("documents"), profile),
  );

  // Emitted for EVERY profile: without a rate the script can read, Q14 asks a
  // model to guess a constant that exists only in the grader. A new scope adds
  // no draw to any existing stream, so no committed number moves.
  record(SCOPES.fx, ["fx_rates.json"], await writeFxRates(sink, profile));

  // New scopes rather than changes to existing ones, so no committed trap
  // number moves. Only the dogfood profile emits them.
  if (profile.extraSources) {
    record(
      SCOPES.nutrition,
      ["nutrition_log.json"],
      await writeNutrition(sink, rng("nutrition"), profile, highMileageDays),
    );
    record(
      SCOPES.commits,
      ["git_commits.json"],
      await writeCommits(sink, rng("commits"), profile),
    );
  }

  return { seed, profile: profile.name, scopes };
}

/* ------------------------------------------------------------------ */
/* Oura                                                                */
/* ------------------------------------------------------------------ */

export interface SleepRecord {
  id: string;
  day: string;
  type: OuraSleepType;
  bedtime_start: string;
  bedtime_end: string;
  total_sleep_duration: number | null;
  deep_sleep_duration: number | null;
  rem_sleep_duration: number | null;
  time_in_bed: number;
  average_hrv: number;
  average_heart_rate: number;
  efficiency: number;
  latency: number;
}

/** Local-offset ISO string: Oura emits these, not UTC. */
function localIso(ms: number, offset: string): string {
  const sign = offset.startsWith("-") ? -1 : 1;
  const [h, m] = offset.slice(1).split(":").map(Number);
  const shifted = ms + sign * ((h! * 60 + m!) * 60_000);
  return new Date(shifted).toISOString().slice(0, 23) + offset;
}

function offsetForDay(dayIndex: number): string {
  return dayIndex >= Q14_TRIP_START_DAY && dayIndex <= Q14_TRIP_END_DAY
    ? TRIP_UTC_OFFSET
    : HOME_UTC_OFFSET;
}

/**
 * A UTC instant that `localIso` will render at the given **local** wall-clock
 * hour.
 *
 * `localIso` shifts a UTC instant by the offset before formatting, so naming a
 * local hour means pre-compensating for it. Getting this backwards is not a
 * cosmetic bug: Q16 asks whether the user is a morning person, and an
 * uncompensated 06:00 renders as 22:00 the previous evening under `-08:00` —
 * which would make the corpus assert the exact opposite of what it intends and
 * grade a correct answer wrong.
 */
function atLocalHour(
  dayIndex: number,
  hour: number,
  minute: number,
  offset: string,
): number {
  const sign = offset.startsWith("-") ? -1 : 1;
  const [h, m] = offset.slice(1).split(":").map(Number);
  const offsetMs = sign * ((h! * 60 + m!) * 60_000);
  return dayStartMs(dayIndex) + (hour * 60 + minute) * 60_000 - offsetMs;
}

function* sleepRecords(
  rng: Rng,
  profile: FixtureProfile,
): Generator<SleepRecord> {
  const anomalyStart = profile.sleepDays - Q11_ANOMALY_DAYS;
  for (let d = 0; d < profile.sleepDays; d++) {
    if (rng.chance(SLEEP_MISSING_CHANCE)) continue;

    const offset = offsetForDay(d);
    const emit = (
      type: OuraSleepType,
      hours: number,
      startMs: number,
      index: number,
    ): SleepRecord => {
      const duration = Math.round(hours * 3600);
      // `total_sleep_duration` is nullable in the API. Treating null as zero is
      // its own silent-wrongness path, distinct from the nap rule.
      const nulled = rng.chance(OURA_NULL_DURATION_CHANCE);
      const anomalous = d >= anomalyStart;
      return {
        id: `s${d}_${index}`,
        day: dayIso(d),
        type,
        // Localized, with an offset. `day` is authoritative — re-deriving the
        // date from this string shifts it whenever the offset is positive.
        bedtime_start: localIso(startMs, offset),
        bedtime_end: localIso(startMs + duration * 1000, offset),
        total_sleep_duration: nulled ? null : duration,
        deep_sleep_duration: nulled ? null : Math.round(duration * 0.18),
        rem_sleep_duration: nulled ? null : Math.round(duration * 0.22),
        // Not the same thing as total sleep, and the profile has to say so.
        time_in_bed: duration + rng.int(2400),
        average_hrv: 30 + rng.int(50),
        average_heart_rate:
          48 + rng.int(18) + (anomalous ? Q11_ANOMALY_BPM_OFFSET : 0),
        efficiency: 70 + rng.int(28),
        latency: 300 + rng.int(1500),
      };
    };

    const base = dayStartMs(d);
    let index = 0;

    // Main sleep, starting the previous evening.
    yield emit(
      "long_sleep",
      rng.range(MAIN_SLEEP_MIN_H, MAIN_SLEEP_MAX_H),
      base - 2 * 3_600_000,
      index++,
    );

    if (rng.chance(NAP_CHANCE)) {
      yield emit(
        "late_nap",
        rng.range(NAP_MIN_H, NAP_MAX_H),
        base + 14 * 3_600_000,
        index++,
      );
    }
    // `rest` — falsely detected and rejected by the user. Must never be counted.
    if (rng.chance(OURA_REST_CHANCE)) {
      yield emit("rest", rng.range(0.2, 0.8), base + 11 * 3_600_000, index++);
    }
    // `deleted` — user-deleted. Must never be counted either.
    if (rng.chance(OURA_DELETED_CHANCE)) {
      yield emit(
        "deleted",
        rng.range(1.0, 3.0),
        base + 16 * 3_600_000,
        index++,
      );
    }
  }
}

async function writeSleep(
  sink: FixtureSink,
  rng: Rng,
  profile: FixtureProfile,
): Promise<number> {
  return writeJsonArray(sink, "oura_sleep.json", sleepRecords(rng, profile));
}

/**
 * `daily_sleep` carries a score and contributors and **no duration field at
 * all**. Emitting it matters precisely because it is where an agent looks for
 * sleep duration and does not find it.
 */
async function writeDailySleep(
  sink: FixtureSink,
  rng: Rng,
  profile: FixtureProfile,
): Promise<number> {
  function* rows(): Generator<Record<string, unknown>> {
    for (let d = 0; d < profile.sleepDays; d++) {
      yield {
        id: `ds${d}`,
        day: dayIso(d),
        score: 40 + rng.int(60),
        timestamp: localIso(dayStartMs(d), offsetForDay(d)),
        contributors: {
          deep_sleep: 40 + rng.int(60),
          efficiency: 40 + rng.int(60),
          latency: 40 + rng.int(60),
          rem_sleep: 40 + rng.int(60),
          restfulness: 40 + rng.int(60),
          timing: 40 + rng.int(60),
          total_sleep: 40 + rng.int(60),
        },
      };
    }
  }
  return writeJsonArray(sink, "oura_daily_sleep.json", rows());
}

async function writeHeartRate(
  sink: FixtureSink,
  rng: Rng,
  profile: FixtureProfile,
): Promise<number> {
  // Oura samples heart rate at ~5-minute cadence, overwhelmingly during sleep —
  // not uniformly around the clock the way the old generator emitted it.
  const perDay = apportion(
    profile.heartRateSamples,
    dayWeights(rng, profile.sleepDays, {
      deadDayChance: SLEEP_MISSING_CHANCE,
      drift: 0.04,
    }),
  );
  const anomalyStart = profile.sleepDays - Q11_ANOMALY_DAYS;
  function* samples(): Generator<{
    bpm: number;
    source: string;
    timestamp: string;
  }> {
    for (let d = 0; d < profile.sleepDays; d++) {
      const n = perDay[d]!;
      const nightStart = dayStartMs(d) - 2 * 3_600_000;
      const offset = d >= anomalyStart ? Q11_ANOMALY_BPM_OFFSET : 0;
      for (let i = 0; i < n; i++) {
        // A resting baseline that does not filter on `source` is contaminated
        // by workout samples, which sit ~45bpm higher.
        const source = rng.pick(OURA_HR_SOURCES);
        const workoutLift =
          source === "workout" || source === "session"
            ? OURA_HR_WORKOUT_BPM_OFFSET
            : 0;
        yield {
          bpm: 45 + rng.int(22) + offset + workoutLift,
          source,
          timestamp: iso(nightStart + i * 300_000),
        };
      }
    }
  }
  return writeJsonArray(sink, "oura_heartrate.json", samples());
}

/**
 * Workouts. `distance` is in **metres**, and the same session can appear twice
 * — once `autodetected`, once `manual` — so Q18's join has to dedup first.
 */
async function writeWorkouts(
  sink: FixtureSink,
  rng: Rng,
  profile: FixtureProfile,
  /**
   * Days whose (deduped) run cleared the Q18 threshold, collected as they are
   * written. The nutrition log reads this so intake can rise on heavy training
   * days — without it Q18's answer is indistinguishable from noise, since the
   * two means land within 20 kcal of each other.
   *
   * An out-param rather than a changed return type: it adds no rng draw and no
   * emitted field, so `small`/`full`/`lite` stay byte-identical.
   */
  highMileageDays?: Set<string>,
): Promise<number> {
  function* rows(): Generator<Record<string, unknown>> {
    for (let d = 0; d < profile.sleepDays; d++) {
      if (!rng.chance(0.28)) continue;
      const startMs = dayStartMs(d) + 7 * 3_600_000 + rng.int(6 * 3_600_000);
      const distanceM = Math.round(rng.range(4_000, 18_000));
      const durationS = Math.round(distanceM / rng.range(2.4, 3.4));
      const base = {
        day: dayIso(d),
        activity: "running",
        distance: distanceM,
        calories: Math.round(distanceM * rng.range(0.055, 0.075)),
        start_datetime: localIso(startMs, offsetForDay(d)),
        end_datetime: localIso(startMs + durationS * 1000, offsetForDay(d)),
      };
      // The autodetected row is the one the dedup rule keeps, so it is the one
      // that decides whether the day qualifies.
      if (highMileageDays && distanceM > Q18_DISTANCE_THRESHOLD_M) {
        highMileageDays.add(base.day);
      }
      yield { id: `w${d}_auto`, ...base, source: "autodetected" };
      if (rng.chance(OURA_WORKOUT_DUPLICATE_CHANCE)) {
        // Same session, logged by hand as well. Distance differs slightly.
        yield {
          id: `w${d}_manual`,
          ...base,
          distance: distanceM + rng.int(200) - 100,
          source: "manual",
        };
      }
    }
  }
  return writeJsonArray(sink, "oura_workout.json", rows());
}

async function writeActivity(
  sink: FixtureSink,
  rng: Rng,
  profile: FixtureProfile,
): Promise<number> {
  function* rows(): Generator<Record<string, unknown>> {
    for (let d = 0; d < profile.sleepDays; d++) {
      // Days the ring was not worn. Q18 needs a sparse right-hand side so that
      // "honest handling of days where one side is missing" is a real test and
      // not a property the fixture hands over for free.
      if (rng.chance(0.08)) continue;
      // Distance lives on `workout`, in metres — not here. Q18's filter has to
      // join to that scope rather than read a convenient field off this one.
      yield {
        day: dayIso(d),
        steps: 2000 + rng.int(14000),
        active_calories: 200 + rng.int(900),
        total_calories: 1800 + rng.int(1200),
      };
    }
  }
  return writeJsonArray(sink, "oura_activity.json", rows());
}

async function writeReadiness(
  sink: FixtureSink,
  rng: Rng,
  profile: FixtureProfile,
): Promise<number> {
  function* rows(): Generator<Record<string, unknown>> {
    for (let d = 0; d < profile.sleepDays; d++) {
      yield {
        day: dayIso(d),
        score: 40 + rng.int(60),
        temperature_deviation: Number(rng.range(-1, 1).toFixed(2)),
      };
    }
  }
  return writeJsonArray(sink, "oura_readiness.json", rows());
}

/* ------------------------------------------------------------------ */
/* Spotify                                                             */
/* ------------------------------------------------------------------ */

async function writeSpotify(
  sink: FixtureSink,
  rng: Rng,
  profile: FixtureProfile,
): Promise<{ files: string[]; records: number }> {
  const artists = Array.from({ length: 1800 }, (_, i) => `Artist ${i}`);
  const tracks = Array.from({ length: 22000 }, (_, i) => `Track ${i}`);
  const total = profile.spotifyFiles * profile.spotifyRowsPerFile;

  // One chronological pass, chunked into files the way a real export splits.
  const timestamps = [
    ...spreadTimestamps(rng, total, DIURNAL.leisure!, {
      weekendBias: 1.25,
      deadDayChance: 0.02,
      burstChance: 0.015,
    }),
  ];

  const files: string[] = [];
  let records = 0;
  for (let f = 0; f < profile.spotifyFiles; f++) {
    const slice = timestamps.slice(
      f * profile.spotifyRowsPerFile,
      (f + 1) * profile.spotifyRowsPerFile,
    );
    const year = slice.length ? new Date(slice[0]!).getUTCFullYear() : 2023;
    const name = `Streaming_History_Audio_${year}_${f}.json`;
    files.push(name);
    records += await writeJsonArray(
      sink,
      name,
      spotifyRows(rng, slice, artists, tracks),
    );
  }

  // The *account data* package's streaming history: same idea, different
  // schema, and only the last year. An agent that picks this file answers a
  // multi-year question with twelve months and has no way to notice.
  const cutoff = dayStartMs(CORPUS_DAYS - SPOTIFY_ACCOUNT_DATA_DAYS);
  const recent = timestamps.filter((ts) => ts >= cutoff);
  files.push(SPOTIFY_ACCOUNT_DATA_FILE);
  records += await writeJsonArray(
    sink,
    SPOTIFY_ACCOUNT_DATA_FILE,
    recent.map((ts) => ({
      endTime: iso(ts).slice(0, 16).replace("T", " "),
      artistName: rng.pick(artists),
      trackName: rng.pick(tracks),
      msPlayed: rng.int(300_000),
    })),
  );

  return { files, records };
}

function* spotifyRows(
  rng: Rng,
  timestamps: number[],
  artists: string[],
  tracks: string[],
): Generator<Record<string, unknown>> {
  let previous: number | null = null;
  for (const ts of timestamps) {
    // Three content clusters share one schema with no type flag: audio,
    // podcast and video. Design §12.2 describes only two. They are told apart
    // by which field cluster is non-null, and nothing else.
    const roll = rng.next();
    const kind = roll < 0.08 ? "podcast" : roll < 0.11 ? "video" : "audio";
    // ~2.6% of rows overlap a neighbour's timestamp and need dedup.
    const stamp: number =
      previous !== null && rng.chance(0.026) ? previous : ts;
    previous = stamp;
    const reasonEnd = rng.pick([
      "trackdone",
      "fwdbtn",
      "backbtn",
      "endplay",
      "unknown",
    ]);
    yield {
      ts: iso(stamp),
      platform: "osx",
      ms_played: rng.int(300_000),
      conn_country: "US",
      master_metadata_track_name: kind === "audio" ? rng.pick(tracks) : null,
      master_metadata_album_artist_name:
        kind === "audio" ? rng.pick(artists) : null,
      master_metadata_album_album_name:
        kind === "audio" ? `Album ${rng.int(9000)}` : null,
      spotify_track_uri:
        kind === "audio"
          ? `spotify:track:${(rng.int(0x7fffffff) >>> 0).toString(36).padStart(9, "0")}`
          : null,
      episode_name: kind === "podcast" ? `Episode ${rng.int(500)}` : null,
      episode_show_name: kind === "podcast" ? `Show ${rng.int(60)}` : null,
      spotify_episode_uri:
        kind === "podcast"
          ? `spotify:episode:${(rng.int(0x7fffffff) >>> 0).toString(36).padStart(9, "0")}`
          : null,
      audiobook_title: null,
      episode_show_uri: null,
      // Video rows: a fourth field cluster again sharing the same schema.
      spotify_video_uri:
        kind === "video"
          ? `spotify:video:${(rng.int(0x7fffffff) >>> 0).toString(36).padStart(9, "0")}`
          : null,
      reason_start: rng.pick(["trackdone", "clickrow", "fwdbtn", "playbtn"]),
      reason_end: reasonEnd,
      // Design §12.2: `skipped` alone is unreliable — deliberately inconsistent
      // with reason_end so a parser that trusts it gets a different answer.
      shuffle: rng.chance(0.5),
      skipped: rng.chance(0.3),
      offline: false,
      offline_timestamp: null,
      incognito_mode: false,
      // NOTE: `ip_addr`, `user_agent` and `username` are real fields in this
      // export and are deliberately NOT emitted. They are PII, and nothing in
      // the graded set tests PII handling — a fixture should not manufacture
      // sensitive data it has no case for.
    };
  }
}

/* ------------------------------------------------------------------ */
/* ChatGPT                                                             */
/* ------------------------------------------------------------------ */

interface ChatNode {
  id: string;
  message: {
    id: string;
    author: { role: string };
    /** Nullable in real exports. Coerced to epoch it becomes the earliest record. */
    create_time: number | null;
    content: {
      content_type: string;
      /** Nullable, and entries are `str | dict` — `parts.join("")` corrupts counts. */
      parts: (string | Record<string, unknown>)[] | null;
    };
    metadata: Record<string, unknown>;
  } | null;
  parent: string | null;
  children: string[];
}

type ChatContent = {
  content_type: string;
  parts: (string | Record<string, unknown>)[] | null;
};

/** One message's content, exercising the nullable/dict shapes real exports carry. */
function chatContent(
  rng: Rng,
  sentences: number,
  /** Dogfood only: a semantic line to lead with, if one was drawn for this day. */
  lead?: string,
  semantic = false,
): ChatContent {
  const text = (): string =>
    semantic
      ? [lead, proseParagraph(rng, sentences)].filter(Boolean).join(" ")
      : paragraph(rng, sentences);

  if (rng.chance(CHATGPT_NULL_PARTS_CHANCE)) {
    return { content_type: "text", parts: null };
  }
  if (rng.chance(CHATGPT_DICT_PART_CHANCE)) {
    // An image or tool part: a dict, not a string. Joining it yields
    // "[object Object]" and silently corrupts any character count.
    return {
      content_type: "multimodal_text",
      parts: [
        {
          content_type: "image_asset_pointer",
          asset_pointer: `file-service://${rng.int(1e9)}`,
        },
        text(),
      ],
    };
  }
  return { content_type: "text", parts: [text()] };
}

/** Design §12.3: edits/regenerations are sibling children, not overwrites. */
const SIBLING_CHANCE = 0.15;

async function writeConversations(
  sink: FixtureSink,
  rng: Rng,
  profile: FixtureProfile,
): Promise<number> {
  const starts = [
    ...spreadTimestamps(rng, profile.conversations, DIURNAL.evening!, {
      weekendBias: 1.1,
      deadDayChance: 0.03,
      burstChance: 0.02,
      burstStrength: 3,
    }),
  ];

  function* conversations(): Generator<Record<string, unknown>> {
    for (let c = 0; c < starts.length; c++) {
      const startMs = starts[c]!;
      const mapping: Record<string, ChatNode> = {
        root: { id: "root", message: null, parent: null, children: [] },
      };
      const turns = 4 + rng.int(16);
      let last = "root";
      // Messages inside a conversation are minutes apart, not conversations apart.
      let cursor = startMs;

      const convDay = Math.floor((startMs - dayStartMs(0)) / DAY_MS);
      for (let t = 0; t < turns; t++) {
        cursor += rng.between(120_000, 480_000);
        const id = `n${c}_${t}`;
        const role = t % 2 ? "assistant" : "user";
        // Only the user's own turns carry the arcs — an assistant reply is not
        // evidence of what the user thinks, and Q9/Q16 turn on the user's words.
        const lead =
          profile.semanticProse && role === "user"
            ? semanticLine(rng, convDay)
            : undefined;
        mapping[id] = {
          id,
          message: {
            id,
            author: { role },
            // Nullable in real exports. An implementation that coerces null to
            // 0 dates this message to 1970 and hands Q9 a wrong "first" answer.
            create_time: rng.chance(CHATGPT_NULL_CREATE_TIME_CHANCE)
              ? null
              : cursor / 1000,
            content: chatContent(
              rng,
              role === "user" ? 1 : 3,
              lead,
              profile.semanticProse,
            ),
            metadata: {},
          },
          parent: last,
          children: [],
        };
        mapping[last]!.children.push(id);

        if (rng.chance(SIBLING_CHANCE)) {
          // An abandoned regeneration: a child of the same parent, off the path
          // from current_node. Counting mapping.values() double-counts it.
          const sib = `n${c}_${t}_r`;
          mapping[sib] = {
            id: sib,
            message: {
              id: sib,
              author: { role },
              create_time: (cursor + 1000) / 1000,
              // Abandoned branches deliberately carry no arc line. If they did,
              // a naive `mapping.values()` flatten could surface an "earliest
              // mention" the user never actually sent, and Q9's ground truth
              // would depend on which reconstruction the reader used.
              content: chatContent(rng, 2, undefined, profile.semanticProse),
              metadata: {},
            },
            parent: last,
            children: [],
          };
          mapping[last]!.children.push(sib);
        }
        last = id;
      }

      yield {
        title: `${rng.pick(FILLER_WORDS)} ${rng.pick(FILLER_WORDS)}`,
        create_time: startMs / 1000,
        update_time: cursor / 1000,
        mapping,
        current_node: last,
      };
    }
  }

  return writeJsonArray(sink, "conversations.json", conversations());
}

/* ------------------------------------------------------------------ */
/* Slack — carries the Q5 needle                                       */
/* ------------------------------------------------------------------ */

async function writeSlack(
  sink: FixtureSink,
  rng: Rng,
  profile: FixtureProfile,
): Promise<number> {
  const aliases = PEOPLE.flatMap((p) => p.aliases);
  const timestamps = [
    ...spreadTimestamps(rng, profile.slackMessages, DIURNAL.work!, {
      weekendBias: 0.15,
      deadDayChance: 0.04,
      burstChance: 0.02,
    }),
  ];

  const planted = new Map<
    number,
    { user: string; channel: string; text: string }
  >();
  const plantAt = (
    dayIndex: number,
    entry: { user: string; channel: string; text: string },
  ): void => {
    // Attach to the first message on that day, so the needle inherits a
    // realistic timestamp rather than an obviously synthetic one.
    const idx = timestamps.findIndex((ts) => ts >= dayStartMs(dayIndex));
    if (idx >= 0) planted.set(idx, entry);
  };
  plantAt(Q5_DAY_INDEX, {
    user: Q5_SPEAKER_ALIAS,
    channel: Q5_CHANNEL,
    text: q5NeedleText(),
  });
  for (const decoy of Q5_DECOYS) {
    plantAt(decoy.dayIndex, {
      user: decoy.alias,
      channel: decoy.channel,
      text: decoy.text,
    });
  }

  function* messages(): Generator<Record<string, unknown>> {
    for (let i = 0; i < timestamps.length; i++) {
      const override = planted.get(i);
      if (override) {
        yield {
          ts: (timestamps[i]! / 1000).toFixed(6),
          user: override.user,
          channel: override.channel,
          text: override.text,
        };
        continue;
      }
      if (!profile.semanticProse) {
        yield {
          ts: (timestamps[i]! / 1000).toFixed(6),
          user: rng.pick(aliases),
          channel: rng.pick(SLACK_CHANNELS),
          text: sentence(rng),
        };
        continue;
      }

      const ts = timestamps[i]!;
      const dayIndex = Math.floor((ts - dayStartMs(0)) / DAY_MS);
      // Q2's trap: in the final week Slack is dominated by a high-volume,
      // low-substance thread that is *not* what the week was about. A
      // volume-weighted answer picks this; the defensible answer does not.
      const focus = inFocusWeek(dayIndex);
      const loud = focus && rng.chance(0.72);
      // A little real-topic chatter survives in Slack, so the trap is "22
      // messages about the office move against 3 about the cutover" rather
      // than a total absence. A zero would make the ratio infinite and let a
      // case pass by noticing the real topic is missing from Slack entirely,
      // which is not the discrimination Q2 is asking for.
      const realChatter = focus && !loud && rng.chance(0.35);
      const text = loud
        ? rng.pick(FOCUS_LOUD_TOPIC.lines)
        : realChatter
          ? rng.pick(FOCUS_REAL_TOPIC.lines)
          : (semanticLine(rng, dayIndex) ?? proseSentence(rng));
      yield {
        ts: (ts / 1000).toFixed(6),
        user: rng.pick(aliases),
        channel: loud ? "#office-move" : rng.pick(SLACK_CHANNELS),
        text,
      };
    }
  }

  return writeJsonArray(sink, "slack_messages.json", messages());
}

/* ------------------------------------------------------------------ */
/* Email, bank, calendar, browser, notes                               */
/* ------------------------------------------------------------------ */

async function writeEmail(
  sink: FixtureSink,
  rng: Rng,
  profile: FixtureProfile,
): Promise<number> {
  const aliases = PEOPLE.flatMap((p) => p.aliases);
  const timestamps = [
    ...spreadTimestamps(rng, profile.emails, DIURNAL.work!, {
      weekendBias: 0.25,
      deadDayChance: 0.02,
    }),
  ];
  /** Open threads a later message can reply into. Dogfood only. */
  const threads: { id: string; subject: string }[] = [];

  function* rows(): Generator<Record<string, unknown>> {
    for (let i = 0; i < timestamps.length; i++) {
      const ts = timestamps[i]!;
      if (!profile.semanticProse) {
        yield {
          id: `m${i}`,
          date: iso(ts),
          from: rng.pick(aliases),
          to: rng.pick(aliases),
          subject: sentence(rng).slice(0, 60),
          body: paragraph(rng, 3 + rng.int(6)),
        };
        continue;
      }

      const dayIndex = Math.floor((ts - dayStartMs(0)) / DAY_MS);
      const carried = semanticLine(rng, dayIndex);
      const body = [carried, proseParagraph(rng, 3 + rng.int(5))]
        .filter(Boolean)
        .join(" ");

      /*
       * Threading and multiple recipients.
       *
       * Without these, email is a pile of unrelated one-to-one messages:
       * no `thread_id`, no `In-Reply-To`, subjects that never repeat, and a
       * single `to`. Any conversation-shaped question is then unanswerable,
       * and so is anything about group mail or Cc. Roughly a third of
       * messages continue an existing thread, which is the shape a real
       * mailbox has.
       */
      const reply = threads.length > 0 && rng.chance(0.34);
      const thread = reply
        ? rng.pick(threads)
        : (() => {
            const t = {
              id: `t${i}`,
              subject: (carried ?? proseSentence(rng)).slice(0, 60),
            };
            // Bounded so late messages do not reply into the whole history.
            threads.push(t);
            if (threads.length > 40) threads.shift();
            return t;
          })();

      const to = [rng.pick(aliases)];
      if (rng.chance(0.22)) to.push(rng.pick(aliases));
      const cc = rng.chance(0.18) ? [rng.pick(aliases)] : [];

      yield {
        id: `m${i}`,
        date: iso(ts),
        from: rng.pick(aliases),
        // Arrays, not strings: group mail and Cc are ordinary, and a
        // recipient-counting question cannot be asked of a single string.
        to,
        cc,
        thread_id: thread.id,
        in_reply_to: reply ? `${thread.id}-prev` : null,
        subject: reply ? `Re: ${thread.subject}` : thread.subject,
        body,
      };
    }
  }
  return writeJsonArray(sink, "email.json", rows());
}

async function writeBank(
  sink: FixtureSink,
  rng: Rng,
  profile: FixtureProfile,
): Promise<number> {
  const months = Math.ceil(CORPUS_DAYS / 30);
  const rows: Record<string, unknown>[] = [];

  // Recurring subscriptions on a fixed monthly cadence, two of which creep up.
  for (const sub of SUBSCRIPTIONS) {
    for (let m = 0; m < months; m++) {
      const day = Math.min(m * 30 + 3, CORPUS_DAYS - 1);
      const progress = m / Math.max(1, months - 1);
      const amount =
        sub.amount + (sub.creepTo - sub.amount) * (progress > 0.5 ? 1 : 0);
      rows.push({
        date: dayIso(day),
        merchant: sub.merchant,
        amount: -Number(amount.toFixed(2)),
        currency: "USD",
        account: "chk_9021",
      });
    }
  }

  // The Japan trip: a pre-paid flight charged well before departure, then JPY
  // spend inside the window. Q14 has to find both.
  rows.push({
    date: dayIso(Q14_TRIP_START_DAY - Q14_FLIGHT_CHARGE_LEAD_DAYS),
    merchant: Q14_FLIGHT_MERCHANT,
    amount: -Q14_FLIGHT_AMOUNT_USD,
    currency: "USD",
    account: "chk_9021",
  });
  for (let d = Q14_TRIP_START_DAY; d <= Q14_TRIP_END_DAY; d++) {
    const perDay = rng.between(2, 5);
    for (let i = 0; i < perDay; i++) {
      rows.push({
        date: dayIso(d),
        merchant: rng.pick(JP_MERCHANTS),
        amount: -Number(rng.range(500, 22000).toFixed(0)),
        currency: "JPY",
        account: "chk_9021",
      });
    }
  }

  // Ordinary spend across the window.
  const remaining = Math.max(0, profile.bankTransactions - rows.length);
  for (const ts of spreadTimestamps(rng, remaining, DIURNAL.leisure!, {
    weekendBias: 1.15,
  })) {
    rows.push({
      date: iso(ts).slice(0, 10),
      merchant: rng.pick(MERCHANTS),
      amount: -Number(rng.range(3, 220).toFixed(2)),
      currency: "USD",
      account: "chk_9021",
    });
  }

  rows.sort((a, b) => String(a.date).localeCompare(String(b.date)));
  return writeJsonArray(sink, "bank_transactions.json", rows);
}

async function writeCalendar(
  sink: FixtureSink,
  rng: Rng,
  profile: FixtureProfile,
): Promise<number> {
  const aliases = PEOPLE.flatMap((p) => p.aliases);
  const timestamps = [
    ...spreadTimestamps(rng, profile.calendarEvents, DIURNAL.work!, {
      weekendBias: 0.1,
      deadDayChance: 0.05,
    }),
  ];
  function* rows(): Generator<Record<string, unknown>> {
    for (const ts of timestamps) {
      const dayIndex = Math.floor((ts - dayStartMs(0)) / DAY_MS);
      const inTrip =
        dayIndex >= Q14_TRIP_START_DAY && dayIndex <= Q14_TRIP_END_DAY;
      let title: string;
      if (inTrip) {
        // The trip is nameable from the calendar, which is how Q14's date range
        // is resolvable at all.
        title = "Japan trip — out of office";
      } else if (!profile.semanticProse) {
        title = sentence(rng).slice(0, 40);
      } else if (inFocusWeek(dayIndex) && rng.chance(0.6)) {
        // Q2's defensible evidence: the focus week's calendar hours go to the
        // real topic even though Slack volume says otherwise.
        title = `${FOCUS_REAL_TOPIC.label} — working session`;
      } else if (rng.chance(0.03)) {
        // Q15's follow-through: only the kept intentions get calendar evidence.
        const kept = INTENTIONS.filter((i) => i.followedThrough);
        title = `${rng.pick(kept).anchor} — booked`;
      } else {
        title = proseSentence(rng).slice(0, 50);
      }
      /*
       * Duration and group size vary only on dogfood.
       *
       * Every event being exactly one hour with exactly two attendees makes
       * "most of your calendar hours" degenerate — hours and event counts
       * become the same number — and group-size questions unanswerable. The
       * focus week's working sessions are deliberately long, which is what
       * gives Q2 a defensible hours-based answer against Slack volume.
       */
      const durationMin = !profile.semanticProse
        ? 60
        : inFocusWeek(dayIndex) && title.includes(FOCUS_REAL_TOPIC.label)
          ? rng.pick([90, 120, 180])
          : rng.pick([15, 30, 30, 45, 60, 60, 90]);
      const attendeeCount = !profile.semanticProse
        ? 2
        : rng.chance(0.18)
          ? rng.between(3, 7)
          : rng.between(1, 2);
      const attendees: string[] = [];
      for (let a = 0; a < attendeeCount; a++) attendees.push(rng.pick(aliases));

      yield {
        start: iso(ts),
        end: iso(ts + durationMin * 60_000),
        duration_minutes: durationMin,
        title,
        attendees,
        status: rng.pick(["accepted", "declined", "tentative"]),
      };
    }
  }
  return writeJsonArray(sink, "calendar.json", rows());
}

async function writeBrowser(
  sink: FixtureSink,
  rng: Rng,
  profile: FixtureProfile,
): Promise<number> {
  const timestamps = [
    ...spreadTimestamps(rng, profile.browserVisits, DIURNAL.evening!, {
      deadDayChance: 0.02,
      burstChance: 0.02,
    }),
  ];
  function* rows(): Generator<Record<string, unknown>> {
    for (const ts of timestamps) {
      yield {
        url: `https://site${rng.int(4000)}.com/${rng.pick(FILLER_WORDS)}`,
        title: sentence(rng).slice(0, 50),
        visit_time: iso(ts),
      };
    }
  }
  return writeJsonArray(sink, "browser_history.json", rows());
}

async function writeNotes(
  sink: FixtureSink,
  rng: Rng,
  profile: FixtureProfile,
): Promise<number> {
  const timestamps = [
    ...spreadTimestamps(rng, profile.notes, DIURNAL.evening!, {
      weekendBias: 1.4,
      burstChance: 0.02,
    }),
  ];
  function* rows(): Generator<Record<string, unknown>> {
    for (let i = 0; i < timestamps.length; i++) {
      const ts = timestamps[i]!;
      if (!profile.semanticProse) {
        yield {
          id: `note${i}`,
          created: iso(ts),
          title: sentence(rng).slice(0, 40),
          body: paragraph(rng, 6 + rng.int(14)),
        };
        continue;
      }

      const dayIndex = Math.floor((ts - dayStartMs(0)) / DAY_MS);
      const carried = semanticLine(rng, dayIndex);
      // The focus week's real topic lives in notes and calendar, not in the
      // Slack volume — that asymmetry is the whole of Q2.
      const focus =
        inFocusWeek(dayIndex) && rng.chance(0.55)
          ? rng.pick(FOCUS_REAL_TOPIC.lines)
          : undefined;
      const lead = focus ?? carried;
      const body = [
        lead,
        proseParagraph(rng, 4 + rng.int(8)),
        // A second arc line sometimes lands later in the same note, so the
        // topic is not always the first thing on the page.
        rng.chance(0.15) ? semanticLine(rng, dayIndex) : undefined,
      ]
        .filter(Boolean)
        .join(" ");

      yield {
        id: `note${i}`,
        created: iso(ts),
        title: (lead ?? proseSentence(rng)).slice(0, 60),
        body,
      };
    }
  }
  return writeJsonArray(sink, "notes.json", rows());
}

/* ------------------------------------------------------------------ */
/* FX rates — what makes Q14 answerable rather than clairvoyant         */
/* ------------------------------------------------------------------ */

/**
 * The JPY/USD rate for a given day.
 *
 * Flat outside the dogfood profile so the committed Q14 total does not move;
 * a slow sinusoidal drift inside it, which is what "FX at transaction date"
 * means. Deterministic in both cases — no rng draw, so this cannot perturb
 * any stream.
 */
export function jpyPerUsdOnDay(dayIndex: number, drift: boolean): number {
  if (!drift) return Q14_JPY_PER_USD;
  const phase = (2 * Math.PI * dayIndex) / FX_DRIFT_PERIOD_DAYS;
  const rate = Q14_JPY_PER_USD * (1 + FX_DRIFT_AMPLITUDE * Math.sin(phase));
  // Four decimals: enough precision that a per-date sum is exactly
  // reproducible, and the shape a real rate feed publishes.
  return Number(rate.toFixed(4));
}

/**
 * A rate table the script can actually read.
 *
 * One row per day of the corpus window, so a script can join on transaction
 * date rather than guessing a constant.
 */
async function writeFxRates(
  sink: FixtureSink,
  profile: FixtureProfile,
): Promise<number> {
  function* rows(): Generator<Record<string, unknown>> {
    for (let d = 0; d < CORPUS_DAYS; d++) {
      yield {
        date: dayIso(d),
        base: FX_BASE_CURRENCY,
        quote: "JPY",
        // "How many JPY one USD buys" — named explicitly, because inverting a
        // rate is the classic silent error and the field name is the only
        // thing standing between a correct answer and one 22,000x wrong.
        jpy_per_usd: jpyPerUsdOnDay(d, profile.driftingFxRates),
      };
    }
  }
  return writeJsonArray(sink, "fx_rates.json", rows());
}

/* ------------------------------------------------------------------ */
/* Nutrition — the intake source Q18 actually asks about                */
/* ------------------------------------------------------------------ */

/**
 * Q18 asks how many calories the user *eats* on high-mileage days. The corpus
 * had no intake source, so the case stood on `oura_activity.total_calories` —
 * an expenditure figure — as a proxy. That is a different question with a
 * similar-sounding name, and on a run day the two move in opposite directions.
 *
 * Logging is partial on purpose (design §3 Q18: "a sparse left side"), and the
 * gaps are not random: they cluster on weekends, the way real logging lapses.
 * The honest answer has to state its `n`, because `n` is not the number of days
 * in the window.
 */
async function writeNutrition(
  sink: FixtureSink,
  rng: Rng,
  profile: FixtureProfile,
  highMileageDays: ReadonlySet<string>,
): Promise<number> {
  function* rows(): Generator<Record<string, unknown>> {
    for (let d = 0; d < profile.sleepDays; d++) {
      const dow = new Date(dayStartMs(d)).getUTCDay();
      const weekend = dow === 0 || dow === 6;
      // Weekend logging is materially worse than weekday logging.
      const logged = rng.chance(
        weekend ? profile.nutritionCoverage * 0.55 : profile.nutritionCoverage,
      );
      if (!logged) continue;

      const day = dayIso(d);
      // Intake rises on heavy training days. Without this the run-day and
      // other-day means land within 20 kcal of each other and Q18's answer is
      // indistinguishable from noise — the case would grade a model on a
      // difference that is not there. 14% is a realistic post-long-run bump,
      // large enough to be detectable and small enough that a careless
      // aggregate still gets it wrong.
      const bump = highMileageDays.has(day) ? 1.14 : 1;
      const meals = rng.between(2, 4);
      let total = 0;
      const entries: Record<string, unknown>[] = [];
      for (let m = 0; m < meals; m++) {
        const kcal = Math.round(rng.range(280, 900) * bump);
        total += kcal;
        entries.push({
          meal: ["breakfast", "lunch", "dinner", "snack"][m] ?? "snack",
          kcal,
          protein_g: Math.round(kcal * rng.range(0.04, 0.09)),
        });
      }
      yield {
        day,
        entries,
        total_kcal: total,
        // Partial days happen: the user logged breakfast and gave up. Flagged
        // so a careful answer can exclude them rather than averaging them in.
        complete: meals >= 3,
      };
    }
  }
  return writeJsonArray(sink, "nutrition_log.json", rows());
}

/* ------------------------------------------------------------------ */
/* Commits — the measured half of Q16                                   */
/* ------------------------------------------------------------------ */

/**
 * Q16 ("am I a morning person?") is graded on noticing that stated and measured
 * evidence disagree. `prose.ts` supplies the stated half — the user says, more
 * than once, that they are not a morning person. This is the rebuttal: a commit
 * stream clustered hard in the early morning.
 *
 * The disagreement is the point. A system that reads only text says no; one that
 * only aggregates says yes; the design asks for both, reported as a conflict.
 */
async function writeCommits(
  sink: FixtureSink,
  rng: Rng,
  profile: FixtureProfile,
): Promise<number> {
  const perDay = Math.max(1, Math.round(profile.commits / profile.sleepDays));
  function* rows(): Generator<Record<string, unknown>> {
    let n = 0;
    for (let d = 0; d < profile.sleepDays && n < profile.commits; d++) {
      const dow = new Date(dayStartMs(d)).getUTCDay();
      if (dow === 0 || dow === 6 ? rng.chance(0.75) : false) continue;
      const count = rng.between(0, perDay * 2);
      for (let i = 0; i < count && n < profile.commits; i++, n++) {
        // Most commits land in the early-morning cluster; the rest are spread
        // across the working day so the distribution is skewed, not degenerate.
        const hour = rng.chance(MORNING_COMMIT_SHARE)
          ? MORNING_COMMIT_PEAK_HOUR + rng.int(2)
          : 11 + rng.int(10);
        const offset = offsetForDay(d);
        const ts = atLocalHour(d, hour, rng.int(60), offset);
        yield {
          sha: `${(n + 0x1000000).toString(16)}${rng.int(1e6).toString(16)}`,
          authored_at: localIso(ts, offset),
          repo: rng.pick(["personal-server", "data-gateway", "notes"]),
          message: inFocusWeek(d)
            ? `${FOCUS_REAL_TOPIC.anchor}: ${proseSentence(rng).toLowerCase()}`
            : proseSentence(rng).toLowerCase(),
          additions: rng.int(400),
          deletions: rng.int(200),
        };
      }
    }
  }
  return writeJsonArray(sink, "git_commits.json", rows());
}

/* ------------------------------------------------------------------ */
/* Documents — the Q8 absence case                                     */
/* ------------------------------------------------------------------ */

async function writeDocuments(
  sink: FixtureSink,
  rng: Rng,
  profile: FixtureProfile,
): Promise<number> {
  const rows: Record<string, unknown>[] = [];

  rows.push({
    id: Q8_CONTRACT_ID,
    title: "Services Agreement (executed)",
    content_type: "application/pdf",
    created: dayIso(1000),
    text_extracted:
      "Services Agreement. Section 7: Exclusivity. Supplier shall not provide comparable services to any competitor within the territory for the term.",
    extraction_error: null,
  });

  for (const near of Q8_NEAR_MISSES) {
    rows.push({
      id: near.id,
      title: near.title,
      content_type: "application/pdf",
      created: dayIso(rng.int(CORPUS_DAYS)),
      text_extracted: near.body,
      extraction_error: null,
    });
  }

  const unreadableTarget = Q8_UNREADABLE_COUNT;
  const readableTarget = profile.documents - unreadableTarget - rows.length;

  for (let i = 0; i < readableTarget; i++) {
    rows.push({
      id: `doc-readable-${i}`,
      title: sentence(rng).slice(0, 50),
      content_type: "application/pdf",
      created: dayIso(rng.int(CORPUS_DAYS)),
      text_extracted: paragraph(rng, 4 + rng.int(8)),
      extraction_error: null,
    });
  }

  // The records that make a bare "no" dishonest: real documents whose text was
  // never extracted. Any answer to Q8 has to account for them explicitly.
  for (let i = 0; i < unreadableTarget; i++) {
    rows.push({
      id: `doc-scanned-${i}`,
      title: `Scanned document ${i}`,
      content_type: "application/pdf",
      created: dayIso(rng.int(CORPUS_DAYS)),
      text_extracted: null,
      extraction_error: Q8_UNREADABLE_REASON,
    });
  }

  return writeJsonArray(sink, "documents.json", rows);
}

/** Convenience for tests and the runner: generate into memory and hand back a source. */
export async function generateInto(
  sink: FixtureSink & FixtureSource,
  options: GenerateOptions = {},
): Promise<{ manifest: CorpusManifest; source: FixtureSource }> {
  const manifest = await generateCorpus(sink, options);
  return { manifest, source: sink };
}
