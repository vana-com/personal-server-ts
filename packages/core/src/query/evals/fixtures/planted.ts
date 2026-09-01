/**
 * Deliberately planted facts. Everything else in the corpus is filler; these are
 * the records the graded set actually turns on.
 *
 * Two of the eighteen questions are unanswerable unless the corpus is
 * *constructed* to answer them, because they test honesty rather than
 * computation: Q5 asks for a single fact that exists exactly once, and Q8 asks
 * for a negative that is only trustworthy if coverage is stated.
 */

/* ------------------------------------------------------------------ */
/* Q5 — the needle                                                     */
/* ------------------------------------------------------------------ */

/**
 * The answer to Q5. A token that appears exactly once in the entire corpus and
 * cannot be produced by the filler generator (it is not in `FILLER_WORDS`, and
 * the filler emits single lowercase words only).
 *
 * The eval asserts occurrence count == 1 across every generated file, so a
 * regression that leaks this string into filler fails loudly rather than
 * quietly making the question easy.
 */
export const Q5_RESTAURANT = "Baan Saothong";

/**
 * The needle is spoken by `sarahj`, not by "Sarah Johnson". The question says
 * "Sarah". Matching on the display name misses it; matching on "Sarah" alone
 * also hits Sarah Nguyen, who recommends something else. Entity resolution is
 * the actual work.
 */
export const Q5_SPEAKER_ALIAS = "sarahj";
export const Q5_SPEAKER_PERSON_ID = "sarah-johnson";

/**
 * Day index within the corpus window. Deep in the past (~8% in, ≈2023-03-30) so
 * that any recency truncation — the failure mode design §3 Q5 names — misses it.
 */
export const Q5_DAY_INDEX = 88;

export const Q5_CHANNEL = "#dm-sarahj";

export function q5NeedleText(): string {
  return `finally went to that thai place i mentioned — ${Q5_RESTAURANT} on the corner by the station. get the boat noodles. you will thank me later.`;
}

/**
 * Decoys. Both are Thai-restaurant recommendations that are *not* the answer:
 * one from the other Sarah, one from a different person entirely. A system that
 * resolves "Sarah" to the wrong human, or that skips resolution and takes the
 * first Thai hit, returns one of these.
 */
export interface Q5Decoy {
  alias: string;
  dayIndex: number;
  channel: string;
  text: string;
}

export const Q5_DECOYS: readonly Q5Decoy[] = [
  {
    alias: "snguyen",
    dayIndex: 640,
    channel: "#dm-snguyen",
    text: "if you want thai near the office, Golden Orchid Kitchen is the reliable one. nothing special but never bad.",
  },
  {
    alias: "mortiz",
    dayIndex: 902,
    channel: "#random",
    text: "thai place recommendation for the team dinner: Silver Elephant Noodle House. they can do a big table.",
  },
];

/* ------------------------------------------------------------------ */
/* Q8 — the absence case                                               */
/* ------------------------------------------------------------------ */

/**
 * Q8 ("have I ever agreed to anything that conflicts with this contract?") is
 * graded on the *shape* of the answer, not a value. A bare "no" is wrong even
 * when it is true, because the corpus contains documents that cannot be read.
 * The correct answer is "no conflicting agreement across N readable records; M
 * documents could not be text-extracted".
 *
 * These counts mirror the illustrative figures in design §3 Q8 so the graded
 * answer reads the way the design describes it.
 */
export const Q8_DOCUMENT_COUNT = 340;
export const Q8_UNREADABLE_COUNT = 22;
export const Q8_READABLE_COUNT = Q8_DOCUMENT_COUNT - Q8_UNREADABLE_COUNT;

/**
 * The contract under test carries an exclusivity clause. A conflicting
 * agreement would be a second exclusivity or non-compete commitment that the
 * user actually signed.
 */
export const Q8_CONTRACT_ID = "doc-contract-under-test";

/**
 * The marker a genuinely conflicting agreement would carry. It appears **zero**
 * times in the corpus; the eval asserts that, so the honest answer stays
 * "none found".
 */
export const Q8_CONFLICT_MARKER = "Exclusive Supplier Undertaking";

/**
 * Near-misses, so that a keyword scan alone produces false positives and the
 * answer has to reason about whether each is actually binding. All are
 * unexecuted, expired, or explicitly declined.
 */
export const Q8_NEAR_MISSES: readonly {
  id: string;
  title: string;
  body: string;
}[] = [
  {
    id: "doc-draft-exclusivity",
    title: "DRAFT — Reseller Agreement (unexecuted)",
    body: "This draft contains an exclusivity clause covering the same territory. Marked DRAFT, never signed, no counterparty signature block completed. Superseded and abandoned.",
  },
  {
    id: "doc-declined-noncompete",
    title: "Offer letter — declined",
    body: "Includes a non-compete covenant. The offer was declined by email on the same day; no agreement was formed.",
  },
  {
    id: "doc-expired-nda",
    title: "Mutual NDA (expired)",
    body: "Confidentiality only, no exclusivity. Term expired two years before the contract under test was executed.",
  },
];

/** How many documents are deliberately unparseable, and why. */
export const Q8_UNREADABLE_REASON = "scanned image, no text layer";

/* ------------------------------------------------------------------ */
/* Q11 — the anomaly                                                   */
/* ------------------------------------------------------------------ */

/**
 * Q11 ("was my resting heart rate unusual last week?") needs a baseline *and* a
 * genuine excursion, otherwise the honest answer is "no" and the case cannot
 * distinguish a working implementation from one that always says no.
 *
 * A 12 bpm elevation is placed in the final week. It has to clear the corpus's
 * own nightly spread (uniform over 18 bpm, so sd ≈ 5.2) at a sample size of
 * roughly six nights — a smaller offset is within sampling noise and would make
 * the case pass or fail on the seed rather than on the answer. 12 bpm is still
 * a realistic excursion: illness or overtraining looks like this.
 *
 * Invisible to anything that does not compute a personal baseline over the full
 * history, which is the point of the case.
 */
export const Q11_ANOMALY_DAYS = 7;
export const Q11_ANOMALY_BPM_OFFSET = 12;

/* ------------------------------------------------------------------ */
/* Verified source rules (Oura API v2 1.37, Spotify, ChatGPT export)   */
/* ------------------------------------------------------------------ */

/**
 * Oura's `sleep.type` enum has five values, not the two design §12.1 implies.
 *
 * `deleted` (user-deleted) and `rest` (falsely detected, user-rejected) must be
 * excluded from **every** calculation, naps included. This is a nastier trap
 * than the nap rule, because the correct-looking filter `type === "long_sleep"`
 * dodges it by accident while the equally natural `type !== "late_nap"` walks
 * straight into it.
 */
export const OURA_SLEEP_TYPES = [
  "long_sleep",
  "late_nap",
  "sleep",
  "rest",
  "deleted",
] as const;
export type OuraSleepType = (typeof OURA_SLEEP_TYPES)[number];

/** Types that count toward any sleep figure. */
export const OURA_VALID_SLEEP_TYPES: readonly OuraSleepType[] = [
  "long_sleep",
  "late_nap",
  "sleep",
];
/** Types that must be dropped before anything is computed. */
export const OURA_EXCLUDED_SLEEP_TYPES: readonly OuraSleepType[] = [
  "rest",
  "deleted",
];

export const OURA_REST_CHANCE = 0.05;
export const OURA_DELETED_CHANCE = 0.04;
/** `total_sleep_duration` is nullable; treating null as zero drags the mean down. */
export const OURA_NULL_DURATION_CHANCE = 0.015;

/**
 * `heartrate.source` enum. A resting baseline computed without filtering to
 * `rest`/`sleep` is contaminated by workout samples, which is Q11's trap.
 */
export const OURA_HR_SOURCES = [
  "awake",
  "workout",
  "rest",
  "sleep",
  "live",
  "session",
] as const;
export const OURA_HR_WORKOUT_BPM_OFFSET = 45;

/**
 * `workout.distance` is in **metres**, so Q18's "more than 10km" is `> 10000`.
 * Reading it as kilometres makes every run qualify.
 */
export const Q18_DISTANCE_THRESHOLD_M = 10_000;
/**
 * `workout.source` includes both `manual` and `autodetected`, so one session can
 * appear twice. Dedup before joining or the conditional aggregate double-counts.
 */
export const OURA_WORKOUT_DUPLICATE_CHANCE = 0.12;

/**
 * `bedtime_start`/`bedtime_end` are localized strings carrying a UTC offset, and
 * Oura's sleep day rolls at 18:00 local. Re-deriving the date with
 * `new Date(x).toISOString().slice(0, 10)` shifts it whenever the offset is
 * positive — so the `day` field is authoritative and must never be recomputed.
 *
 * The user is in `-08:00` normally and `+09:00` during the Japan trip, which is
 * also the timezone change design §3 Q1 warns about.
 */
export const HOME_UTC_OFFSET = "-08:00";
export const TRIP_UTC_OFFSET = "+09:00";

/**
 * ChatGPT: `content.parts` is nullable and its entries are `str | dict`, so
 * `parts.join("")` corrupts character counts on non-text parts. And
 * `message.create_time` is nullable — coerced to epoch it becomes the earliest
 * record in the corpus and silently destroys Q9's answer.
 */
export const CHATGPT_NULL_CREATE_TIME_CHANCE = 0.03;
export const CHATGPT_NULL_PARTS_CHANCE = 0.02;
export const CHATGPT_DICT_PART_CHANCE = 0.04;

/**
 * Spotify ships two different packages whose streaming-history files look alike
 * and are not: the *account data* package covers the past year only with
 * `endTime`/`msPlayed`/`trackName`, while the *extended* package is lifetime
 * with `ts`/`ms_played`/`master_metadata_*`. An agent handed the account-data
 * file answers a ten-year question with twelve months of data.
 */
export const SPOTIFY_ACCOUNT_DATA_FILE = "StreamingHistory_music_0.json";
export const SPOTIFY_ACCOUNT_DATA_DAYS = 365;

/* ------------------------------------------------------------------ */
/* Q14 — the implicitly-defined set                                    */
/* ------------------------------------------------------------------ */

/**
 * Q14 ("how much did I spend on my Japan trip?") is an entity-resolution
 * question wearing an arithmetic question's clothes: the sum is trivial once
 * "the Japan trip" is resolved to a date range, and the range is stated
 * nowhere. It is inferable from the flight booking and the calendar block.
 *
 * The pre-paid flight is charged well before departure, so a naive
 * "transactions between the dates" filter misses it — the failure design §3
 * Q14 calls out.
 */
export const Q14_TRIP_START_DAY = 780;
export const Q14_TRIP_END_DAY = 794;
/** Days before departure that the flight is charged. */
export const Q14_FLIGHT_CHARGE_LEAD_DAYS = 61;
export const Q14_FLIGHT_MERCHANT = "DELTA AIR 006";
export const Q14_FLIGHT_AMOUNT_USD = 1418.6;
/** Fixed rate so the expected total is exact rather than rate-source dependent. */
export const Q14_JPY_PER_USD = 149.5;

/**
 * The rate has to be *in the corpus*, not only in the grader.
 *
 * Until this existed the corpus contained no exchange rate anywhere — no field,
 * no table, no source — and the sandbox has zero network egress by design. So
 * `Q14_JPY_PER_USD` was known only to the reference path, and against a ±1
 * tolerance on ~7,727 only that exact constant passed: 149.0 or 150.0 missed by
 * ~$12, 155.0 by ~$130. A model could apply the FX rule correctly, state its
 * assumption honestly, and still fail. That made Q14 a test of clairvoyance
 * rather than of reasoning, and it was producing a false negative in a measured
 * result.
 *
 * `fx.rates` is a new scope, so emitting it adds no draw to any existing
 * stream and no committed trap number moves.
 *
 * Two shapes, deliberately:
 *
 *  - **Flat** on `small`/`full`/`lite`: every date carries `Q14_JPY_PER_USD`,
 *    so Q14 becomes answerable while its committed total (7727.24) is
 *    unchanged to the last decimal.
 *  - **Per-date** on `dogfood`: rates drift the way real ones do, which is what
 *    design §3 Q14 actually asks for ("FX applied at transaction date"). A
 *    single flat rate is easier to grade; a drifting one is the honest version,
 *    and it is only safe to introduce where no number is yet committed.
 */
export const FX_BASE_CURRENCY = "USD";
/** Peak-to-trough drift of the dogfood rate, as a fraction of the base rate. */
export const FX_DRIFT_AMPLITUDE = 0.06;
/** Days per full drift cycle — slow enough to look like an FX series. */
export const FX_DRIFT_PERIOD_DAYS = 220;
