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

export type FixtureProfileName =
  "small" | "full" | "lite" | "dogfood" | "dogfood-xl";

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

  /**
   * Emit reasoning-grade prose: topic arcs, the stated/measured conflict,
   * intentions, person facts, and a weighted focus week (`prose.ts`).
   *
   * **Off for `small`/`full`/`lite`, and that is load-bearing.** Those profiles
   * carry the committed trap numbers — the Oura nap error, the ChatGPT phantom
   * rate, Q14's total, Q18's conditional mean — and every one of them is an
   * expectation somewhere. Emitting extra rows into a shared source would draw
   * from that source's stream and shift the numbers downstream, so the flag
   * gates every additional draw. With it off the generator's output is byte
   * identical to before this existed.
   */
  semanticProse: boolean;
  /**
   * Emit a nutrition log (`nutrition.log`) and a commit stream (`git.commits`).
   *
   * Q18 asks about calories on high-mileage days and the corpus had no intake
   * source at all, so `total_calories` — an expenditure figure — was standing in
   * for intake. Q16 asks whether the user is a morning person and there was no
   * behavioural signal to weigh a stated claim against. Both are new scopes
   * rather than changes to existing ones, so no committed number moves.
   */
  extraSources: boolean;
  /** Days of nutrition coverage, as a fraction of `sleepDays`. Partial by design. */
  nutritionCoverage: number;
  commits: number;
  /**
   * Emit a per-date JPY/USD series rather than one flat rate.
   *
   * `fx.rates` is emitted for every profile — without a readable rate in the
   * corpus, Q14 is a test of clairvoyance, since the sandbox has no network and
   * the constant lived only in the grader. But only `dogfood` lets the rate
   * *drift*: design §3 Q14 asks for "FX applied at transaction date", and a
   * moving rate is the honest version of that. The older profiles keep a flat
   * series so their committed Q14 total stays exact to the last decimal.
   */
  driftingFxRates: boolean;
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
    semanticProse: false,
    extraSources: false,
    nutritionCoverage: 0,
    commits: 0,
    driftingFxRates: false,
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
    semanticProse: false,
    extraSources: false,
    nutritionCoverage: 0,
    commits: 0,
    driftingFxRates: false,
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
    semanticProse: false,
    extraSources: false,
    nutritionCoverage: 0,
    commits: 0,
    driftingFxRates: false,
  },

  /**
   * The semantic-exercise profile. Denser prose than `small`, nowhere near
   * `full`'s scale — this exists to test whether a model can *reason* over the
   * corpus, not whether it can scan a large one.
   *
   * Volumes are chosen so the arcs are findable but sparse: an arc line lands in
   * a few percent of notes and messages, which is roughly how often a person
   * actually writes about the thing that is bothering them.
   */
  dogfood: {
    name: "dogfood",
    sleepDays: 1100,
    heartRateSamples: 8_000,
    spotifyFiles: 2,
    spotifyRowsPerFile: 4_000,
    conversations: 1_400,
    slackMessages: 9_000,
    emails: 2_600,
    bankTransactions: 1_800,
    calendarEvents: 1_200,
    browserVisits: 6_000,
    notes: 2_200,
    documents: DOCUMENTS,
    semanticProse: true,
    extraSources: true,
    nutritionCoverage: 0.72,
    commits: 4_200,
    driftingFxRates: true,
  },

  /**
   * `dogfood` semantics at `full` volume — the scale profile (design §19.16).
   *
   * Every measurement in §19 was taken at 20.2MB, and §19.15's central finding
   * (the model reimplements search in-script rather than calling the tool) was
   * explicitly flagged as a property of corpus size: the in-script
   * substitute's cost is linear in records and the tool's is not. Testing that
   * crossover needs a corpus that is large *and* still semantically graded.
   * `full` is large but sets `semanticProse: false` / `extraSources: false`,
   * so Q2, Q9, Q10, Q13, Q15, Q16, Q17 and Q18's nutrition join are
   * structurally vacuous on it. This profile is the missing cell: `full`'s
   * record counts with `dogfood`'s flags.
   *
   * **It adds a profile rather than changing one.** `small`/`full`/`lite`
   * carry the committed trap numbers and `dogfood` carries every §19 result;
   * a new key draws from its own `Rng` and shifts nothing downstream.
   *
   * `documents` stays at `DOCUMENTS` and `sleepDays` at 1100 for the reasons
   * given above — Q8's counts are the assertion, and the multi-year axis is
   * what Q9/Q10/Q11 are about. This profile is denser, not longer or wider.
   *
   * `commits` is scaled by the notes ratio (12000/2200 ≈ 5.45) rather than
   * copied from `dogfood`, so the commit stream stays proportionate to the
   * prose it sits beside instead of becoming a rounding error against it.
   */
  "dogfood-xl": {
    name: "dogfood-xl",
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
    semanticProse: true,
    extraSources: true,
    nutritionCoverage: 0.72,
    commits: 23_000,
    driftingFxRates: true,
  },
};

/**
 * `sleepDays` stays at 1100 in every profile on purpose. Q9/Q10/Q11 test
 * behaviour over a multi-year axis; shrinking the *window* rather than the
 * *density* would reintroduce exactly the artifact this generator exists to
 * fix. Small profiles are thinner, not shorter.
 */
export const DEFAULT_SEED = 20260828;
