/**
 * Defensible readings of an ambiguous question, and the rule that grades
 * against them.
 *
 * Design §19.9: when the model was made to declare which set it had chosen, it
 * complied 12/12 and in every failing run its number was *exactly* consistent
 * with the set it declared. Q1's "last month" has five defensible readings
 * spanning 0.26h against a ±0.05 tolerance, so strict grading cannot tell a
 * wrong answer from a different reading. This module implements the rule the
 * user chose: **a defensible resolution plus a number consistent with it is a
 * pass.**
 *
 * Three properties keep that from being a rubber stamp:
 *
 * 1. **Readings are enumerated from the corpus, before any model output is
 *    read.** A reading is a property of the data and the English, not a
 *    description of what some run happened to say. `scripts/enum-readings.ts`
 *    computes them; the values here are those figures.
 * 2. **The number is checked against the reading the model named**, not
 *    against the union of all readings. Declaring "December" and returning the
 *    trailing-31 figure fails. This is what stops a vague declaration plus any
 *    number from passing.
 * 3. **A question with one honest reading gets none of this.** Ambiguity is
 *    declared per question and deliberately sparingly; over-declaring it is
 *    the way this rule would quietly become meaningless.
 */

/** One defensible way to read an ambiguous question. */
export interface DefensibleReading {
  /** Stable id, e.g. `trailing31`. */
  id: string;
  /** Human label used in reports. */
  label: string;
  /** The value this reading yields, computed from the corpus. */
  value: number;
  /** Tolerance for this reading; normally the case's own. */
  tolerance: number;
  /** n for this reading, where the case reports a denominator. */
  denominator?: number;
  /** Why this reading is defensible. Prose, for the report. */
  why: string;
  /** True for the reading the strict eval encodes. */
  isEvalReading?: boolean;
  /**
   * Signals that classify a declared resolution as this reading.
   *
   * Concept-first: they name the *idea* (a calendar month, a trailing window)
   * rather than any phrasing observed in a transcript. `all` must every match;
   * `none` must not match.
   */
  signals: { all?: RegExp[]; none?: RegExp[] };
}

/** How a run fared under the resolution-aware rule. */
export type ResolutionOutcome =
  /** Declared a known reading and computed it correctly. */
  | { kind: "pass"; reading: DefensibleReading }
  /** No `resolution` was declared at all. */
  | { kind: "undeclared" }
  /** Declared something that is not a defensible reading of this question. */
  | { kind: "unrecognised"; resolution: string }
  /** Declared reading A and returned reading B's number, or neither's. */
  | {
      kind: "inconsistent";
      reading: DefensibleReading;
      value: number;
      expected: number;
    };

/**
 * Classify a declared resolution into one of the enumerated readings.
 *
 * Returns `undefined` when nothing matches — which is a real failure, not a
 * fallback to the eval's reading.
 */
export function classifyResolution(
  resolution: string,
  readings: readonly DefensibleReading[],
): DefensibleReading | undefined {
  /*
   * Parenthetical asides are dropped before matching.
   *
   * The prompt now asks the model, when a phrase has several defensible
   * readings, to "name the alternative and its number". It complies — and it
   * puts the alternative in parentheses: "…over the 108 logged days (with 74
   * complete days…)". Matching the whole string then classifies the run by the
   * reading it explicitly set aside, and penalises exactly the helpful
   * behaviour the prompt asked for. The primary declaration is the one outside
   * the brackets.
   */
  const text = resolution.toLowerCase().replace(/\([^)]*\)/g, " ");
  return readings.find(
    (r) =>
      (r.signals.all ?? []).every((re) => re.test(text)) &&
      !(r.signals.none ?? []).some((re) => re.test(text)),
  );
}

/**
 * Grade one run under the resolution-aware rule.
 *
 * `value` is the number the run returned; `resolution` is what it declared.
 */
export function gradeAgainstReadings(
  readings: readonly DefensibleReading[],
  resolution: string | undefined,
  value: number | undefined,
): ResolutionOutcome {
  if (!resolution || resolution.trim() === "") return { kind: "undeclared" };
  const reading = classifyResolution(resolution, readings);
  if (!reading) return { kind: "unrecognised", resolution };
  if (typeof value !== "number") {
    return {
      kind: "inconsistent",
      reading,
      value: Number.NaN,
      expected: reading.value,
    };
  }
  // The anti-cheat: the number must match the reading that was NAMED.
  if (Math.abs(value - reading.value) > reading.tolerance) {
    return { kind: "inconsistent", reading, value, expected: reading.value };
  }
  return { kind: "pass", reading };
}

/* ------------------------------------------------------------------ */
/* The enumerated readings, per ambiguous question                     */
/* ------------------------------------------------------------------ */

const CALENDAR_MONTH =
  /calendar month|full month|full calendar|december|november/;
const TRAILING = /trailing|rolling|last \d+ days|past \d+ days|preceding/;

/**
 * Q1 — "How much did I sleep on average over the last month?"
 *
 * Genuinely ambiguous: English "the last month" admits a trailing window and a
 * calendar month, and the trailing window admits several lengths. Values from
 * `scripts/enum-readings.ts` over the `dogfood` corpus at the committed seed.
 */
export const Q1_READINGS: readonly DefensibleReading[] = [
  {
    id: "calendarDec",
    label: "calendar December 2025",
    value: 6.6817,
    tolerance: 0.05,
    denominator: 27,
    why: '"Last month" as the last complete calendar month — the reading a person means when they say it on 4 January.',
    signals: { all: [CALENDAR_MONTH], none: [/november/] },
  },
  {
    id: "calendarNov",
    label: "calendar November 2025",
    value: 6.8354,
    tolerance: 0.05,
    denominator: 30,
    why: "The last month for which a full month of data exists, if December is treated as incomplete.",
    signals: { all: [/november/] },
  },
  {
    id: "trailing31",
    label: "trailing 31 days",
    value: 6.5775,
    tolerance: 0.05,
    denominator: 28,
    why: "A trailing month measured to the last day of data. What the strict eval encodes.",
    isEvalReading: true,
    signals: { all: [TRAILING, /31/] },
  },
  {
    id: "trailing30",
    label: "trailing 30 days",
    value: 6.619,
    tolerance: 0.05,
    denominator: 27,
    why: "A trailing month taken as 30 days.",
    signals: { all: [TRAILING, /30/] },
  },
  {
    id: "trailing28",
    label: "trailing 28 days",
    value: 6.5769,
    tolerance: 0.05,
    denominator: 25,
    why: "A trailing four weeks — the reading that keeps whole weeks intact.",
    signals: { all: [TRAILING, /28|four weeks/] },
  },
];

/**
 * Q14 — "How much did I spend on my Japan trip?"
 *
 * Ambiguous in exactly one place, which design §3 names: whether a flight
 * bought two months earlier is part of "the trip". It is *not* ambiguous about
 * currency — a yen-only total silently drops in-window dollar spend, which is
 * an incomplete set rather than a different reading of the question, so it is
 * deliberately absent here and grades as a failure.
 */
/** "…plus the flight", "…including airfare" — the flight is inside the set. */
const FLIGHT_IN =
  /(includ\w*|plus|add\w*|together with|along with|and the)[^.]{0,40}(flight|airfare|delta)|(flight|airfare|delta)[^.]{0,40}(included|added|counted)/;
/** "…excluding the flight" — the flight is named only to rule it out. */
const FLIGHT_OUT =
  /(exclud\w*|without|not includ\w*|omitt\w*|separate from|apart from|other than|excepting)[^.]{0,40}(flight|airfare|delta)/;

export const Q14_READINGS: readonly DefensibleReading[] = [
  {
    id: "inWindowPlusFlight",
    label: "in-window spend plus the pre-booked flight",
    value: 9146.9,
    tolerance: 1,
    why: "The trip includes getting there, so a flight bought earlier counts. What the strict eval encodes.",
    isEvalReading: true,
    signals: { all: [FLIGHT_IN], none: [FLIGHT_OUT] },
  },
  {
    id: "inWindowAllCcy",
    label: "in-window spend, all currencies",
    value: 7728.3,
    tolerance: 1,
    why: 'Spend during the days in Japan, all currencies converted. Defensible if "on the trip" means "while away".',
    signals: {
      all: [/window|during|while|between|trip dates|in japan/],
      none: [FLIGHT_IN],
    },
  },
];

/**
 * Q18 — "How many calories do I typically eat on days I run more than 10km?"
 *
 * Ambiguous in the denominator: every qualifying day that has a log, or only
 * the days whose log is marked complete. Both are honest answers to "typically
 * eat"; the second trades n for data quality.
 *
 * The activity-tracker expenditure figure is *not* a reading of this question —
 * it answers what was burned, not what was eaten — so it is absent and grades
 * as a failure.
 */
export const Q18_READINGS: readonly DefensibleReading[] = [
  {
    id: "completeLogged",
    label: "complete logs only",
    value: 2387.66,
    tolerance: 5,
    denominator: 74,
    why: "Restricting to days whose log is marked complete — fewer days, cleaner intake.",
    signals: { all: [/complete/] },
  },
  {
    id: "allLogged",
    label: "all logged run days",
    value: 2054.7,
    tolerance: 5,
    denominator: 108,
    why: "Every qualifying run day that has any nutrition log. What the strict eval encodes.",
    isEvalReading: true,
    signals: {
      all: [/logg|nutrition|food|intake|recorded/],
      none: [/complete/],
    },
  },
];

/**
 * Questions treated as ambiguous, and nothing else.
 *
 * Deliberately short. Notably absent:
 *
 * - **Q6** ("distinct people last month"). Two runs excluded one person as
 *   "yourself", but the corpus models no owner identity — all six are
 *   counterparties — so nominating one as self is an unforced inference about
 *   the data, not a reading of the question. Grades strictly.
 * - **Q11** ("last week"). Every observed run resolved the same window; there
 *   is no spread to accommodate.
 * - **Q8** (document count). One honest answer.
 */
export const AMBIGUOUS_READINGS: Readonly<
  Record<string, readonly DefensibleReading[]>
> = {
  Q1: Q1_READINGS,
  Q14: Q14_READINGS,
  Q18: Q18_READINGS,
};
