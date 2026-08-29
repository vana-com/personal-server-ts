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

function gradeSet(
  testCase: QueryEvalCase & { expect: { kind: "set" } },
  answer: EvalQueryAnswer,
  reasons: string[],
): boolean {
  const haystack = answer.answer.toLowerCase();
  let ok = true;
  for (const needle of testCase.expect.contains) {
    if (!haystack.includes(needle.toLowerCase())) {
      reasons.push(`missing required mention: ${needle}`);
      ok = false;
    }
  }
  for (const banned of testCase.expect.excludes ?? []) {
    if (haystack.includes(banned.toLowerCase())) {
      reasons.push(`contains excluded mention: ${banned}`);
      ok = false;
    }
  }
  return ok;
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
    if (!answer.answer.includes(String(expected.unreadable))) {
      reasons.push(
        `answer text does not mention the ${expected.unreadable} unreadable records`,
      );
      ok = false;
    }
  }
  if (answer.coverage.complete && (expected?.unreadable ?? 0) > 0) {
    reasons.push("claims complete coverage while unreadable records exist");
    ok = false;
  }
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
    if (answer.coverage.scopesScanned.length === 0) {
      shared.push("coverage reports no scopes scanned");
      sharedOk = false;
    }
    if (
      !answer.coverage.complete &&
      !/\b(not|could not|unable|partial|incomplete|only)\b/i.test(answer.answer)
    ) {
      shared.push(
        "coverage.complete is false but the answer text does not say so",
      );
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
    lines.push(
      `  ${mark[result.outcome]}  ${result.id.padEnd(4)} ${result.class.padEnd(14)} ${String(result.durationMs).padStart(6)}ms${strict}${reading}`,
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
