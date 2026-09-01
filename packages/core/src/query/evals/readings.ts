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
 * 4. **A reading's value belongs to one corpus.** These figures were computed
 *    over `dogfood` at `DEFAULT_SEED`; on any other corpus they describe
 *    nothing. `readingsFor` returns them only for that pair, so a run on
 *    another profile grades strictly rather than against numbers that do not
 *    apply to it.
 */

import { DEFAULT_SEED } from "./fixtures/profiles.js";

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
/**
 * Constructions that mark a clause as an *aside* rather than the declaration.
 *
 * Concept-first, like the signals themselves: these name the relation one
 * reading bears to another — a subset, a wider set, an alternative, a
 * comparison — rather than any phrasing lifted from a transcript. The prompt
 * asks the model to name the alternative it did not use; it obliges in
 * whatever words it likes, but the alternative is always introduced *as* an
 * alternative, and that is what this matches.
 */
const ASIDE =
  /\b(alternativ\w*|subset|superset|refin\w*|narrower|wider|broader|stricter|looser|for comparison|by comparison|set aside|also report\w*|separately report\w*|additionally|secondar\w*|cross-check\w*)\b/;

/** Clause boundaries, for locating an aside inside a longer declaration. */
const CLAUSE_BOUNDARY = /[;:,]|\s+and\s+|\s+while\s+|\s+whereas\s+/g;

/**
 * Drop the clauses that introduce an alternative reading, keep the rest.
 *
 * Parentheses were the first form this took, and are still the commonest, but
 * the model also sets an alternative aside in a plain coordinate clause:
 * "…computing intake across all 108 logged days **and reporting the 74
 * complete logged days as a refined subset**." Matching the whole string
 * classifies that run by the reading it explicitly declined, which is the same
 * defect the parenthetical rule was written to fix.
 *
 * Deliberately conservative: clauses are split only to *locate* an aside, and
 * when none is found the original text is returned byte-for-byte. A
 * declaration that names one reading and nothing else is therefore matched
 * exactly as it was before this existed — including the multi-word signals
 * (`FLIGHT_IN`) that span a clause boundary and would not survive a rejoin.
 */
function stripAsides(text: string): string {
  const clauses: { start: number; end: number }[] = [];
  let start = 0;
  CLAUSE_BOUNDARY.lastIndex = 0;
  for (let m = CLAUSE_BOUNDARY.exec(text); m; m = CLAUSE_BOUNDARY.exec(text)) {
    clauses.push({ start, end: m.index });
    start = m.index + m[0].length;
  }
  clauses.push({ start, end: text.length });

  const kept = clauses.filter((c) => !ASIDE.test(text.slice(c.start, c.end)));
  // Nothing set aside, or *everything* was: in both cases the declaration is
  // the whole string. An aside is only an aside next to a primary clause.
  if (kept.length === clauses.length || kept.length === 0) return text;
  return kept.map((c) => text.slice(c.start, c.end)).join(" ");
}

export function classifyResolution(
  resolution: string,
  readings: readonly DefensibleReading[],
): DefensibleReading | undefined {
  /*
   * Asides are dropped before matching.
   *
   * The prompt now asks the model, when a phrase has several defensible
   * readings, to "name the alternative and its number". It complies — and it
   * puts the alternative in parentheses: "…over the 108 logged days (with 74
   * complete days…)", or in a trailing clause. Matching the whole string then
   * classifies the run by the reading it explicitly set aside, and penalises
   * exactly the helpful behaviour the prompt asked for. The primary
   * declaration is what is left once the alternatives are removed.
   */
  const text = stripAsides(resolution.toLowerCase().replace(/\([^)]*\)/g, " "));
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
/**
 * A window measured backwards from the end of the data.
 *
 * The `\d+ … days` arm carries an optional adjective, because the qualifier a
 * run reaches for is not fixed: "the last 30 **calendar** days" is the same
 * window as "the last 30 days", and the earlier pattern's hard adjacency
 * classified it as `unrecognised` — a run whose window and value were
 * byte-identical to two others that classified fine.
 */
const TRAILING =
  /trailing|rolling|preceding|\b(?:last|past|previous|final)\s+\d+[\s-]*(?:[a-z]+\s+)?days?\b/;

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
 *   `scripts/enum-readings.ts` also settles the *window* axis, which is the
 *   same phrase Q1 turns on: the count is 6 for every trailing window from a
 *   week up (5 only at four days), so no reading of "last month" moves it. The
 *   `denominator` — rows scanned — does move (256 / 260 / 274 over trailing
 *   28 / 30 / 31), and that is recorded rather than acted on, because crediting
 *   it would mean declaring Q6 ambiguous on grounds §19.10 already refused.
 * - **Q11** ("last week"). The corpus ends on **Sunday 2026-01-04**, so the two
 *   readings that would otherwise diverge — the trailing seven days, and the
 *   Monday-to-Sunday week that just ended — are the *same seven days*, and
 *   yield the same 69.4286bpm. There is nothing for a reading to disambiguate.
 *   (The week before that averages 54.4286bpm, but "last week" asked on a
 *   Sunday does not mean the week before the one that just ended.)
 * - **Q8** (document count). One honest answer.
 *
 * And one question that is **genuinely ambiguous and still absent**, which is a
 * different case from the three above and is recorded here rather than acted
 * on:
 *
 * - **Q7** ("what are my recurring monthly expenses, and which ones have crept
 *   up?"). Two readings, both defensible, and `scripts/enum-readings.ts`
 *   separates them cleanly over 1,800 transactions across 37 months:
 *
 *   | merchant             |   n | distinct amounts | max/min | gaps of 26–35d |
 *   | -------------------- | --- | ---------------- | ------- | -------------- |
 *   | RENT ACH             |  37 |                1 |    1.00 |           100% |
 *   | ICLOUD STORAGE       |  37 |                1 |    1.00 |           100% |
 *   | NETFLIX.COM          |  37 |                2 |    1.48 |           100% |
 *   | SPOTIFY P0A2         |  37 |                2 |    1.20 |           100% |
 *   | TRADER JOES #221     | 279 |              276 |   44.90 |             0% |
 *   | AMZN Mktp US\*2H9    | 273 |              270 |   71.16 |             0% |
 *   | UBER \*TRIP          | 272 |              270 |   47.61 |             1% |
 *   | SHELL OIL 4471       | 259 |              256 |   56.49 |             0% |
 *   | WHOLEFDS #104        | 258 |              258 |   51.11 |             0% |
 *   | SQ \*BLUE BOTTLE 982 | 256 |              255 |   73.10 |             0% |
 *
 *   The eval encodes the second reading via `reference/compute.ts`'s
 *   `list.length >= months * 0.8`, which is a **count** threshold rather than a
 *   cadence test: 273 clears 29.6 easily. It is defensible as "the things I
 *   spend on every month" — all ten do appear in every month. The competing
 *   reading is the one the question's own second clause presupposes: **only a
 *   fixed price can creep up.** The four subscriptions hold one or two amounts
 *   across three years and are charged at a monthly interval 100% of the time;
 *   the six retail merchants are charged roughly seven times a month at a
 *   different amount almost every time, so they have no price to creep and no
 *   monthly cadence to speak of. All three sweep runs declared that reading up
 *   front and got all four merchants and both price transitions right.
 *
 *   **It is not declared here because the machinery is numeric-only.** A
 *   `DefensibleReading` is a number plus a tolerance, and `gradeAgainstReadings`
 *   compares `|value - reading.value|`; `readingsFor` is consulted only from
 *   the `numeric` branch of the runner. Q7 is a `set` case, so listing it would
 *   be inert at best and, worse, would report Q7 as graded generously when
 *   nothing about its grading had changed. **Q7 therefore stays failing**, and
 *   that is the finding: the corpus asks a question with two readings and
 *   scores only one of them.
 */
export const AMBIGUOUS_READINGS: Readonly<
  Record<string, readonly DefensibleReading[]>
> = {
  Q1: Q1_READINGS,
  Q14: Q14_READINGS,
  Q18: Q18_READINGS,
};

/**
 * The corpus these values were enumerated over.
 *
 * A reading is a window plus the number that window yields, and the number is
 * a fact about one corpus. Applied to a different profile or seed the labels
 * would still match and every value would be wrong, which is the worst of both
 * rules: a generous grade against arithmetic that describes another dataset.
 */
export const READINGS_CORPUS = {
  profile: "dogfood",
  seed: DEFAULT_SEED,
} as const;

/**
 * The readings for a question, or `undefined` if it has none *here*.
 *
 * `undefined` covers two different situations on purpose, because the caller
 * treats them the same way — grade strictly: the question has one honest
 * reading, or this run is not on the corpus the readings describe.
 */
export function readingsFor(
  id: string,
  profile: string,
  seed: number,
): readonly DefensibleReading[] | undefined {
  if (profile !== READINGS_CORPUS.profile || seed !== READINGS_CORPUS.seed) {
    return undefined;
  }
  return AMBIGUOUS_READINGS[id];
}
