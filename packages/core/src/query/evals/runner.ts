/**
 * The eval runner: cases in, graded report out, against any answerer.
 *
 * Grading deliberately refuses to guess. A `judged` case with no judge is
 * `skipped`, not `pass` — a harness that scores unjudgeable cases as passes is
 * worse than one that scores nothing, because it reports a number that looks
 * like progress.
 *
 * **Two rules, both recorded** (design §19.10). A numeric case is graded twice:
 *
 * - *strict* — the number must match the single reading the eval encodes;
 * - *resolution-aware* — the run must declare a `resolution`, that resolution
 *   must classify to a reading enumerated from the corpus before any model
 *   output was read, and the number must match **that** reading.
 *
 * The reported `outcome` is the resolution-aware one for a question with
 * enumerated readings, strict for everything else — but `strictPass` is always
 * carried, because the rule moves results *both ways* (§19.10 demoted two
 * strict passes) and a headline that could not be attributed would hide that.
 */

import { readingsFor, gradeAgainstReadings } from "./readings.js";
import type { DefensibleReading, ResolutionOutcome } from "./readings.js";
import type {
  EvalAnswerer,
  EvalCaseResult,
  EvalClassRollup,
  EvalQueryAnswer,
  EvalReport,
  QueryEvalCase,
  QueryEvalClass,
} from "./types.js";

export interface JudgeVerdict {
  pass: boolean;
  reason: string;
}

/** Supplied only when a model is available; absent means judged cases skip. */
export interface EvalJudge {
  judge(
    rubric: string,
    testCase: QueryEvalCase,
    answer: EvalQueryAnswer,
  ): Promise<JudgeVerdict>;
}

export interface RunOptions {
  answerer: EvalAnswerer;
  cases: QueryEvalCase[];
  seed: number;
  profile: string;
  judge?: EvalJudge;
  /** Run only these ids. */
  only?: string[];
}

/**
 * Pulls the first number out of an answer's prose.
 *
 * Retained for answerers that cannot set `value` (the reference answerer), but
 * **no longer used to grade a model answer** — see `gradeNumeric`. It scraped
 * `29` out of "December 29" on a run that had computed 69.43 correctly, which
 * is worse than returning nothing: it manufactures a precise-looking wrong
 * number and files a correct run as a numeric failure.
 */
export function extractNumber(text: string): number | undefined {
  const match = text.replace(/,/g, "").match(/-?\d+(\.\d+)?/);
  return match ? Number(match[0]) : undefined;
}

/** Both verdicts on one numeric case, with the reasons behind each. */
interface NumericGrades {
  actual?: number;
  strictOk: boolean;
  strictReasons: string[];
  /** `null` when this question has no enumerated readings on this corpus. */
  resolutionAware: {
    ok: boolean;
    outcome: ResolutionOutcome;
    reasons: string[];
  } | null;
}

/**
 * The missing-`value` reason, shared by both rules.
 *
 * Only an explicitly-declared `value` is graded. Scraping prose produced a
 * date ("December 29" -> 29) on a run whose text carried the right figure, so
 * a missing `value` is reported as ungradeable rather than graded against
 * whatever number happened to appear first. The prompt requires the field;
 * failing to supply it is a contract problem, not a wrong answer.
 */
const NO_VALUE_REASON =
  "ungradeable: the answer set no `value`, and grading numeric cases by " +
  "scraping prose reads dates and window sizes as results";

function gradeNumericStrict(
  testCase: QueryEvalCase & { expect: { kind: "numeric" } },
  answer: EvalQueryAnswer,
  reasons: string[],
): boolean {
  const { value, tolerance, denominator } = testCase.expect;
  const actual = answer.value;
  if (actual === undefined) {
    reasons.push(NO_VALUE_REASON);
    return false;
  }
  const delta = Math.abs(actual - value);
  let ok = true;
  if (delta > tolerance) {
    reasons.push(
      `expected ${value} ±${tolerance}, got ${actual} (off by ${delta.toFixed(4)})`,
    );
    ok = false;
  }
  if (
    denominator !== undefined &&
    !answer.answer.includes(String(denominator))
  ) {
    // Design §4.3: a stated denominator is part of correctness, not decoration.
    reasons.push(`answer does not state the denominator (${denominator})`);
    ok = false;
  }
  return ok;
}

/**
 * The resolution-aware rule, including its own denominator check.
 *
 * **The denominator is checked against the reading the run named**, not against
 * the eval's (design §19.11). `gemini-3.1-pro-preview` returned 6.62 on Q1 —
 * trailing-30, inside the ±0.05 tolerance — and stated n=27, the honest
 * denominator for the set it chose; the strict assertion demands 28, the
 * denominator of a set it did not use, so it failed for stating its own
 * arithmetic truthfully. Under this rule the reading fixes both numbers, and a
 * run that names a set must report *that* set's n.
 */
function gradeNumericByResolution(
  testCase: QueryEvalCase & { expect: { kind: "numeric" } },
  answer: EvalQueryAnswer,
  readings: readonly DefensibleReading[],
  reasons: string[],
): { ok: boolean; outcome: ResolutionOutcome } {
  const outcome = gradeAgainstReadings(
    readings,
    answer.resolution,
    answer.value,
  );
  switch (outcome.kind) {
    case "undeclared":
      // Never a fallback to the eval's reading: a number nobody attributed to a
      // set is exactly what this rule exists to stop crediting.
      reasons.push(
        answer.value === undefined
          ? NO_VALUE_REASON
          : "no `resolution` declared — the number cannot be attributed to a set",
      );
      return { ok: false, outcome };
    case "unrecognised":
      reasons.push(
        `declared a resolution that matches no enumerated reading: "${outcome.resolution}"`,
      );
      return { ok: false, outcome };
    case "inconsistent":
      reasons.push(
        Number.isNaN(outcome.value)
          ? NO_VALUE_REASON
          : `declared "${outcome.reading.label}" (${outcome.expected} ±${outcome.reading.tolerance}) but returned ${outcome.value}`,
      );
      return { ok: false, outcome };
    case "pass":
      break;
  }

  const { reading } = outcome;
  if (testCase.expect.denominator === undefined) return { ok: true, outcome };
  if (reading.denominator === undefined) {
    // A gap in the readings table, not a fault of the run — but it is reported
    // loudly rather than skipped, because a denominator the eval requires and
    // the rule cannot check is a hole in the rule. `runner.test.ts` asserts
    // this never happens.
    reasons.push(
      `reading "${reading.label}" declares no denominator, but the case requires one`,
    );
    return { ok: false, outcome };
  }
  if (!answer.answer.includes(String(reading.denominator))) {
    reasons.push(
      `answer does not state the denominator for "${reading.label}" (${reading.denominator})`,
    );
    return { ok: false, outcome };
  }
  return { ok: true, outcome };
}

function gradeNumeric(
  testCase: QueryEvalCase & { expect: { kind: "numeric" } },
  answer: EvalQueryAnswer,
  readings: readonly DefensibleReading[] | undefined,
): NumericGrades {
  const strictReasons: string[] = [];
  const strictOk = gradeNumericStrict(testCase, answer, strictReasons);
  if (!readings) {
    return {
      actual: answer.value,
      strictOk,
      strictReasons,
      resolutionAware: null,
    };
  }
  const reasons: string[] = [];
  const { ok, outcome } = gradeNumericByResolution(
    testCase,
    answer,
    readings,
    reasons,
  );
  return {
    actual: answer.value,
    strictOk,
    strictReasons,
    resolutionAware: { ok, outcome, reasons },
  };
}

/* ------------------------------------------------------------------ */
/* Set grading: naming an entity vs including its data                 */
/* ------------------------------------------------------------------ */

/**
 * Language that marks a mention as *ruled out* rather than asserted.
 *
 * Concept-first, like `readings.ts`'s signals: these name the *act* of holding
 * two things apart — attributing something elsewhere, setting it aside, saying
 * it is not the thing asked about — not any phrasing observed in a transcript.
 *
 * **Announcing an ambiguity is deliberately NOT in this set**, and that
 * distinction is the whole rule. "There are two different people named Sarah",
 * "another Sarah", "two distinct individuals" report that more than one entity
 * answers to the query term. Reporting that is not resolving it: an answer can
 * say "there are two" and then assert both as co-equal answers, which is the
 * opposite of ruling one out. These forms were in this set and produced a false
 * positive on the sweep's Q5 run 0 — an answer that named the decoy as one of
 * two answers was exonerated with the reason "appears only where the answer
 * rules it out", which was not true of it. Ruling out is directional and is
 * performed *on* a term; a headcount is neither.
 *
 * `distinct` is admitted only in its directional form `distinct from`, for the
 * same reason: "two distinct people" is a count, "distinct from Sarah Nguyen"
 * is an exclusion.
 */
const RULES_OUT =
  /\b(disambiguat\w*|distinguish\w*|differentiat\w*|not to be confused|distinct from|exclud\w*|excepting|separate from|apart from|other than|rather than|as opposed to|unlike|not the same|unrelated to|does not refer|do not refer)\b/i;

/**
 * A markdown list marker: `1.`, `2)`, `-`, `*`, `+`, `•`.
 *
 * The ordinal is capped at two digits so a year ending a sentence is not one.
 * "…in a direct message on March 30, 2023. 2. **Sarah Nguyen**…" splits into
 * three blocks under an unbounded `\d+`, the middle one being the bare string
 * `2023.`, which is not a list item — and that ends the run of items a lead-in
 * governs one block early, silently.
 */
const LIST_MARKER = /^\s*(?:\d{1,2}[.)]|[-*+•])\s/;
const BLOCK_BOUNDARY = /\n+|\s+(?=(?:\d{1,2}[.)]|[-*+•])\s)/g;
const SENTENCE_BOUNDARY = /(?<=[.!?])\s+/g;

interface Span {
  start: number;
  end: number;
}

/** Split `text` on `boundary`, carrying absolute offsets. */
function split(text: string, boundary: RegExp, from = 0): Span[] {
  const out: Span[] = [];
  let start = 0;
  boundary.lastIndex = 0;
  for (let m = boundary.exec(text); m; m = boundary.exec(text)) {
    out.push({ start: from + start, end: from + m.index });
    start = m.index + m[0].length;
  }
  out.push({ start: from + start, end: from + text.length });
  return out;
}

/**
 * The regions of an answer in which naming an excluded term is disambiguation
 * rather than assertion.
 *
 * Two shapes, and both require {@link RULES_OUT} language — an announcement
 * that the query term is ambiguous buys nothing on its own:
 *
 * 1. **A clause that rules the term out.** "Distinct from Sarah Nguyen
 *    (`sarah.nguyen@partner.io`, `snguyen`), who is an external partner
 *    contact." The exclusion is local to the sentence.
 * 2. **A lead-in that rules terms out and governs a list.** "Excluded from this
 *    summary:" followed by one item per excluded entity. The exclusion is
 *    stated once and each item inherits it.
 *
 * Shape 2 used to accept an *ambiguity* lead-in — "There are two different
 * people named Sarah…:" over a list giving one answer per person — on the
 * reasoning that "the enumeration under it *is* the resolution". It is not.
 * Such a list asserts every item, including the decoy, as an answer; naming the
 * ambiguity above it does not rule any of them out. That reading exonerated the
 * sweep's Q5 run 0 while an answer with the same content failed for saying "two
 * people" instead of "two different people", which is a grader artifact, not a
 * difference in the answers. Requiring `RULES_OUT` in the lead-in removes it
 * without removing the shape: a lead-in that genuinely sets its items aside
 * still governs them.
 *
 * The inherited scope is deliberately bounded at the first thing that is not a
 * list item. Q17's answers open with "…distinguishing her from Sarah Nguyen:"
 * and then a `###` heading, which would otherwise hand a single marker in the
 * first sentence a licence over the whole document.
 */
function exclusionContexts(text: string): Span[] {
  const out: Span[] = [];
  const blocks = split(text, BLOCK_BOUNDARY);

  for (const [i, block] of blocks.entries()) {
    const body = text.slice(block.start, block.end);

    for (const sentence of split(body, SENTENCE_BOUNDARY, block.start)) {
      if (RULES_OUT.test(text.slice(sentence.start, sentence.end))) {
        out.push(sentence);
      }
    }

    if (!RULES_OUT.test(body) || !/:\s*$/.test(body)) continue;
    for (const next of blocks.slice(i + 1)) {
      const following = text.slice(next.start, next.end);
      if (following.trim() === "") continue;
      if (!LIST_MARKER.test(following)) break;
      out.push(next);
    }
  }
  return out;
}

/**
 * Grade a `set` case: required mentions present, excluded ones not asserted.
 *
 * **Containment alone cannot tell naming an entity from including its data**,
 * and it punished Q17, which resolved the alias sets and was failed for the
 * sentence saying *whom it had excluded*. Implementation plan §6 left this
 * open; the user has now decided it: **surfacing the ambiguity explicitly is
 * acceptable, silently mixing the two people's data is not.**
 *
 * So an excluded term is a violation when it is asserted, and not when every
 * occurrence sits inside an {@link exclusionContexts} region.
 *
 * "Surfacing the ambiguity" means saying which entity the answer is *not*
 * about. It does not mean declining to choose. Q5's sweep answers report both
 * Sarahs' restaurants as co-equal answers to "what was the name of that Thai
 * restaurant"; the decoy is asserted, never set aside, so it is a violation —
 * see {@link RULES_OUT}. Whether presenting both is the better *product*
 * behaviour is plan §6's remaining open item and a human's call; what is fixed
 * here is only that the grader must not answer it by accident, differently for
 * two answers that say the same thing.
 *
 * The gate that keeps this from being a rubber stamp: **exoneration is
 * available only to an answer that already carries every required mention.**
 * An answer that mixes the two people is one that is missing the subject's
 * facts and carrying the decoy's, and it gets no generosity at all — its
 * excluded mentions are counted exactly as before. That is what still fails
 * the sweep's Q17 run 1, which missed five required anchors *and* carried both
 * of the other Sarah's handles, while passing runs 0 and 2, which missed
 * nothing and named her only to set her aside.
 */
function gradeSet(
  testCase: QueryEvalCase & { expect: { kind: "set" } },
  answer: EvalQueryAnswer,
  reasons: string[],
): boolean {
  const haystack = answer.answer.toLowerCase();
  let ok = true;

  const missing = testCase.expect.contains.filter(
    (needle) => !haystack.includes(needle.toLowerCase()),
  );
  for (const needle of missing) {
    reasons.push(`missing required mention: ${needle}`);
    ok = false;
  }

  const banned = testCase.expect.excludes ?? [];
  if (banned.length === 0) return ok;

  const contexts =
    missing.length === 0 ? exclusionContexts(answer.answer) : /* gated */ [];

  for (const term of banned) {
    const needle = term.toLowerCase();
    let asserted = false;
    let seen = false;
    for (
      let at = haystack.indexOf(needle);
      at >= 0;
      at = haystack.indexOf(needle, at + 1)
    ) {
      seen = true;
      if (!contexts.some((s) => at >= s.start && at < s.end)) asserted = true;
    }
    if (asserted) {
      reasons.push(`contains excluded mention: ${term}`);
      ok = false;
    } else if (seen) {
      // Recorded on a passing row, the way the strict reasons are: a reader
      // auditing this rule needs to see every place it was generous, not only
      // the places it refused.
      reasons.push(
        `[disambiguated] excluded mention "${term}" appears only where the answer rules it out`,
      );
    }
  }
  return ok;
}

/**
 * Language naming records the scan could not read.
 *
 * Concept-first, like {@link RULES_OUT}: the *fact* that text was not obtained
 * from a record, however the model words it. Two forms, because English offers
 * two and the model uses both:
 *
 * 1. **A word that already means it** — `unreadable`, `corrupt`, `no text
 *    layer`. Self-contained.
 * 2. **A reading verb under a negation** — "could not be read", "unable to
 *    parse", "were not searched". Written as a negation followed by a verb
 *    within a short span rather than as fixed phrases, because the two are not
 *    adjacent in practice: the reference answerer says "could not be
 *    **text-**extracted", which every adjacency spelling of this misses.
 * 3. **The same thing with the words the other way round** — "extraction
 *    failed". Kept to `fail` and kept tight, because the general reverse order
 *    is not safe: "were read with no errors" is a negation near a reading verb
 *    and means the opposite.
 */
const UNREADABLE_CUE =
  /\b(?:unreadable|not readable|unparse\w*|undecodable|unextractable|corrupt\w*|(?:no|without a?n?) text layer)\b|\b(?:not|n't|never|no|fail\w*|unable|omitted)\b[^.]{0,20}?\b(?:read|readable|pars\w*|extract\w*|open\w*|decod\w*|search\w*|index\w*)\b|\b(?:extract\w*|pars\w*|read|decod\w*|ocr|index\w*)\b[^.]{0,10}?\bfail\w*/i;

/**
 * How far apart the count and the cue may sit and still be one assertion.
 *
 * Same sentence is the primary bound; this bounds the sentence, so a long
 * sentence that mentions the number for one reason and unreadable records for
 * another does not read as a claim about both. "22 documents in the archive
 * could not be read" is ~30 characters end to end, so there is real headroom.
 */
const UNREADABLE_PROXIMITY_CHARS = 60;

/**
 * Does the answer *assert* `count` about the records it could not read?
 *
 * This was `answer.includes(String(count))`, which a date, an id or a record
 * count satisfies — the integrity rule (prompt doc §1) is that an incomplete
 * scan says so *in the prose*, and a bare digit says nothing. Q8 passed 3/3
 * under it while only one run's retained text visibly stated the figure.
 *
 * The rule: the count and an {@link UNREADABLE_CUE} must occur in the same
 * sentence, within {@link UNREADABLE_PROXIMITY_CHARS} of each other, in either
 * order — so "22 documents could not be read", "22 unreadable", "22 files
 * failed extraction" and "of these, 22 had no text layer" all count, and
 * "…on December 22" does not. Word-bounded so `1,022` is not a match.
 */
function statesUnreadableCount(text: string, count: number): boolean {
  const number = new RegExp(`\\b${count}\\b`, "g");
  for (const sentence of split(text, SENTENCE_BOUNDARY)) {
    const body = text.slice(sentence.start, sentence.end);
    number.lastIndex = 0;
    for (let m = number.exec(body); m; m = number.exec(body)) {
      // Widen from the digits by the proximity bound on both sides, then ask
      // whether a cue falls inside that window. Clamped to the sentence so the
      // window can never reach across into a neighbouring claim.
      const from = Math.max(0, m.index - UNREADABLE_PROXIMITY_CHARS);
      const to = Math.min(
        body.length,
        m.index + m[0].length + UNREADABLE_PROXIMITY_CHARS,
      );
      if (UNREADABLE_CUE.test(body.slice(from, to))) return true;
    }
  }
  return false;
}

function gradeAbsence(
  testCase: QueryEvalCase,
  answer: EvalQueryAnswer,
  reasons: string[],
): boolean {
  let ok = true;
  const expected = testCase.expectedCoverage;

  if (
    expected?.recordsScanned !== undefined &&
    answer.coverage.recordsScanned < expected.recordsScanned
  ) {
    reasons.push(
      `scanned ${answer.coverage.recordsScanned} records, expected at least ${expected.recordsScanned}`,
    );
    ok = false;
  }
  if (expected?.unreadable !== undefined) {
    if (answer.coverage.unreadable !== expected.unreadable) {
      reasons.push(
        `coverage.unreadable is ${answer.coverage.unreadable ?? "unset"}, expected ${expected.unreadable}`,
      );
      ok = false;
    }
    // The integrity rule (prompt doc §1): an incomplete scan must say so in the
    // answer text, not only in metadata.
    if (!statesUnreadableCount(answer.answer, expected.unreadable)) {
      reasons.push(
        `answer text does not mention the ${expected.unreadable} unreadable records`,
      );
      ok = false;
    }
  }
  /*
   * There is deliberately no "claimed a total scan while unreadable records
   * exist" check to go with these, because the two are independent.
   *
   * An unreadable record was *reached*, not skipped: the runtime recognised
   * its marker as it streamed past, which is how it got counted at all. A run
   * can stream every granted scope end to end and still have found records it
   * could not read, and on Q8 every correct run is exactly that — 318 readable
   * and 22 unreadable, the 22 stated in prose and in `coverage.unreadable`.
   * A check pairing the two failed those runs for doing the task properly.
   *
   * The integrity property — a bounded scan must say so in the answer text,
   * not only in metadata — is carried whole by the two checks above: the count
   * must match the corpus, and it must appear in the prose.
   */
  return ok;
}

async function runCase(
  testCase: QueryEvalCase,
  options: RunOptions,
): Promise<EvalCaseResult> {
  const started = Date.now();
  /*
   * Three reason buckets, because two rules are being reported at once.
   * `shared` holds everything neither rule forgives — citations, coverage, and
   * the non-numeric expectations. The rule-specific buckets are merged into
   * the result labelled, so a reader can see both verdicts on the failing row
   * rather than only the one that produced `outcome`.
   */
  const shared: string[] = [];
  let answer: EvalQueryAnswer;

  try {
    answer = await options.answerer.answer({
      question: testCase.question,
      grantedScopes: testCase.scopes,
    });
  } catch (error) {
    return {
      id: testCase.id,
      class: testCase.class,
      outcome: "fail",
      reasons: [`answerer threw: ${(error as Error).message}`],
      durationMs: Date.now() - started,
      cost: { toolCalls: 0, inputTokens: 0, outputTokens: 0 },
      gradedBy: "strict",
      strictPass: false,
      resolutionOutcome: null,
    };
  }

  let sharedOk = true;
  let numeric: NumericGrades | undefined;
  /** Set only where a model actually returned the verdict. */
  let modelGraded = false;

  switch (testCase.expect.kind) {
    case "numeric": {
      numeric = gradeNumeric(
        testCase as QueryEvalCase & { expect: { kind: "numeric" } },
        answer,
        readingsFor(testCase.id, options.profile, options.seed),
      );
      break;
    }
    case "set":
      sharedOk = gradeSet(
        testCase as QueryEvalCase & { expect: { kind: "set" } },
        answer,
        shared,
      );
      break;
    case "absence":
      sharedOk = gradeAbsence(testCase, answer, shared);
      break;
    case "judged": {
      if (!options.judge) {
        return {
          id: testCase.id,
          class: testCase.class,
          outcome: "skipped",
          reasons: ["judged case, no judge supplied"],
          durationMs: Date.now() - started,
          cost: answer.cost,
          resolutionOutcome: null,
        };
      }
      const verdict = await options.judge.judge(
        testCase.expect.rubric,
        testCase,
        answer,
      );
      // Marked here, where the verdict is actually made. Reconstructing it
      // downstream from `expect.kind === "judged"` cannot tell a row a model
      // decided from one that skipped for want of a judge.
      modelGraded = true;
      sharedOk = verdict.pass;
      if (!verdict.pass) shared.push(verdict.reason);
      break;
    }
  }

  if (testCase.mustCite && answer.citations.length === 0) {
    shared.push("no citations");
    sharedOk = false;
  }
  if (testCase.mustReportCoverage) {
    // The host's own caveat is no longer graded here. It used to be, keyed off
    // `coverage.complete`, but that flag demanded every granted scope be read
    // end to end — never true of a real question — so the check only ever
    // asserted that the host had appended a caveat it appended unconditionally.
    // `agent/loop.ts`'s `honestAnswerText` is the thing that owes that text now,
    // and `loop.test.ts` pins it directly, including the fail-closed case.
    if (answer.coverage.scopesScanned.length === 0) {
      shared.push("coverage reports no scopes scanned");
      sharedOk = false;
    }
  }

  const resolutionAware = numeric?.resolutionAware ?? null;
  const strictPass = sharedOk && (numeric?.strictOk ?? true);
  const resolutionPass = resolutionAware
    ? sharedOk && resolutionAware.ok
    : strictPass;
  const gradedBy = resolutionAware ? "resolution-aware" : "strict";

  /*
   * Both rules' reasons, labelled, whenever both ran. The headline rule's come
   * first; the strict ones stay visible even on a run the generous rule passed,
   * because "passed only because the eval's reading was not the one it chose"
   * is the finding, not noise to be filtered out.
   */
  const reasons = [...shared];
  if (resolutionAware) {
    for (const r of resolutionAware.reasons) {
      reasons.push(`[resolution-aware] ${r}`);
    }
    for (const r of numeric?.strictReasons ?? []) reasons.push(`[strict] ${r}`);
  } else {
    reasons.push(...(numeric?.strictReasons ?? []));
  }

  const matched =
    resolutionAware?.outcome.kind === "pass"
      ? resolutionAware.outcome.reading
      : resolutionAware?.outcome.kind === "inconsistent"
        ? resolutionAware.outcome.reading
        : undefined;

  return {
    id: testCase.id,
    class: testCase.class,
    outcome: resolutionPass ? "pass" : "fail",
    reasons,
    durationMs: Date.now() - started,
    cost: answer.cost,
    actual: numeric?.actual,
    ...(answer.resolution !== undefined
      ? { resolution: answer.resolution }
      : {}),
    ...(modelGraded ? { modelGraded: true } : {}),
    gradedBy,
    strictPass,
    resolutionOutcome: resolutionAware?.outcome ?? null,
    ...(matched ? { readingId: matched.id, readingLabel: matched.label } : {}),
  };
}

export async function runEval(options: RunOptions): Promise<EvalReport> {
  const selected = options.only
    ? options.cases.filter((c) => options.only!.includes(c.id))
    : options.cases;

  const results: EvalCaseResult[] = [];
  for (const testCase of selected) {
    results.push(await runCase(testCase, options));
  }

  const classes = [...new Set(results.map((r) => r.class))] as QueryEvalClass[];
  const rollups: EvalClassRollup[] = classes.map((cls) => {
    const inClass = results.filter((r) => r.class === cls);
    return {
      class: cls,
      pass: inClass.filter((r) => r.outcome === "pass").length,
      fail: inClass.filter((r) => r.outcome === "fail").length,
      skipped: inClass.filter((r) => r.outcome === "skipped").length,
      strictPass: inClass.filter((r) => r.strictPass === true).length,
    };
  });

  return {
    answerer: options.answerer.name,
    seed: options.seed,
    profile: options.profile,
    results,
    rollups,
    // Recorded from the results rather than from `AMBIGUOUS_READINGS`, so it
    // reflects the questions this run actually graded generously — which is
    // empty on a corpus the readings were not enumerated over.
    resolutionAware: results
      .filter((r) => r.gradedBy === "resolution-aware")
      .map((r) => r.id),
    totals: {
      pass: results.filter((r) => r.outcome === "pass").length,
      fail: results.filter((r) => r.outcome === "fail").length,
      skipped: results.filter((r) => r.outcome === "skipped").length,
      strictPass: results.filter((r) => r.strictPass === true).length,
      wallClockMs: results.reduce((a, r) => a + r.durationMs, 0),
      inputTokens: results.reduce((a, r) => a + r.cost.inputTokens, 0),
      outputTokens: results.reduce((a, r) => a + r.cost.outputTokens, 0),
      usd: results.reduce((a, r) => a + (r.cost.usd ?? 0), 0),
    },
  };
}

/** Human-readable report, for `npm run eval`. */
export function formatReport(report: EvalReport): string {
  const lines: string[] = [];
  const mark = { pass: "PASS", fail: "FAIL", skipped: "SKIP" } as const;
  const aware = new Set(report.resolutionAware);

  lines.push(
    `query-layer eval — answerer=${report.answerer} profile=${report.profile} seed=${report.seed}`,
    "",
  );
  for (const result of report.results) {
    // Both verdicts on the row where they disagree. A single mark would let a
    // demotion (strict pass, resolution-aware fail) read as a plain failure.
    const strict =
      result.strictPass === undefined || !aware.has(result.id)
        ? ""
        : `  strict:${result.strictPass ? "PASS" : "FAIL"}`;
    const reading = result.readingLabel ? `  «${result.readingLabel}»` : "";
    // A model's opinion and a computed comparison must never render alike.
    const judged = result.modelGraded ? "  [model-graded]" : "";
    lines.push(
      `  ${mark[result.outcome]}  ${result.id.padEnd(4)} ${result.class.padEnd(14)} ${String(result.durationMs).padStart(6)}ms${strict}${reading}${judged}`,
    );
    for (const reason of result.reasons) lines.push(`          ${reason}`);
  }

  lines.push("", "  by class:");
  for (const rollup of report.rollups) {
    lines.push(
      `    ${rollup.class.padEnd(14)} pass ${rollup.pass}  fail ${rollup.fail}  skip ${rollup.skipped}  (strict pass ${rollup.strictPass})`,
    );
  }

  const { totals } = report;
  const graded = totals.pass + totals.fail;
  /*
   * Both scoreboards, and which rule produced the headline.
   *
   * §19.10's rule moves results in both directions, so a bare total is not
   * interpretable without saying which questions it was applied to. When no
   * question was graded generously — a corpus the readings were not enumerated
   * over — that is stated too, rather than left to be assumed either way.
   */
  const headline = aware.size
    ? `resolution-aware on ${[...aware].join(", ")}; strict elsewhere`
    : "strict throughout — no enumerated readings apply to this corpus";
  lines.push(
    "",
    `  totals: pass ${totals.pass}  fail ${totals.fail}  skip ${totals.skipped}   [${headline}]`,
    `  strict scoreboard: pass ${totals.strictPass}  fail ${graded - totals.strictPass}  skip ${totals.skipped}`,
    `  wall clock: ${totals.wallClockMs}ms   tokens: ${totals.inputTokens} in / ${totals.outputTokens} out   cost: $${totals.usd.toFixed(4)}`,
  );
  return lines.join("\n");
}
