/**
 * Corpus sizes.
 *
 * `full` reproduces the design §18 corpus (~222MB, ~10 sources) that the
 * measured timings and trap numbers came from. `small` is the same corpus
 * *shape* at ~1/50 scale: identical nap rate, identical sibling-regeneration
 * rate, the same planted needle, the same unreadable documents. Every graded
 * case is expressible against `small`, so the default eval run is seconds and
 * megabytes rather than minutes and 222MB.
 *
 * `lite` is the PS-Lite profile (plan §4.2): smaller again, and generated
 * entirely in memory because the browser runtime has no filesystem.
 */

export type FixtureProfileName = "small" | "full" | "lite";

export interface FixtureProfile {
  name: FixtureProfileName;
  /** Days of Oura sleep/activity/readiness coverage. */
  sleepDays: number;
  heartRateSamples: number;
  spotifyFiles: number;
  spotifyRowsPerFile: number;
  conversations: number;
  slackMessages: number;
  emails: number;
  bankTransactions: number;
  calendarEvents: number;
  browserVisits: number;
  notes: number;
  /** Q8's document scope is fixed across profiles — the counts are the assertion. */
  documents: number;
}

const DOCUMENTS = 340;

export const PROFILES: Record<FixtureProfileName, FixtureProfile> = {
  full: {
    name: "full",
    sleepDays: 1100,
    heartRateSamples: 110_000,
    spotifyFiles: 6,
    spotifyRowsPerFile: 38_000,
    conversations: 10_400,
    slackMessages: 90_000,
    emails: 14_000,
    bankTransactions: 9_000,
    calendarEvents: 6_000,
    browserVisits: 120_000,
    notes: 12_000,
    documents: DOCUMENTS,
  },
  small: {
    name: "small",
    sleepDays: 1100,
    heartRateSamples: 4_000,
    spotifyFiles: 2,
    spotifyRowsPerFile: 2_500,
    conversations: 400,
    slackMessages: 3_000,
    emails: 700,
    bankTransactions: 900,
    calendarEvents: 400,
    browserVisits: 3_000,
    notes: 400,
    documents: DOCUMENTS,
  },
  lite: {
    name: "lite",
    sleepDays: 1100,
    heartRateSamples: 1_000,
    spotifyFiles: 1,
    spotifyRowsPerFile: 800,
    conversations: 120,
    slackMessages: 800,
    emails: 200,
    bankTransactions: 300,
    calendarEvents: 150,
    browserVisits: 800,
    notes: 120,
    documents: DOCUMENTS,
  },
};

/**
 * `sleepDays` stays at 1100 in every profile on purpose. Q9/Q10/Q11 test
 * behaviour over a multi-year axis; shrinking the *window* rather than the
 * *density* would reintroduce exactly the artifact this generator exists to
 * fix. Small profiles are thinner, not shorter.
 */
export const DEFAULT_SEED = 20260828;
