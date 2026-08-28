/**
 * The eval runner: cases in, graded report out, against any answerer.
 *
 * Grading deliberately refuses to guess. A `judged` case with no judge is
 * `skipped`, not `pass` — a harness that scores unjudgeable cases as passes is
 * worse than one that scores nothing, because it reports a number that looks
 * like progress.
 */

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

/** Pulls the first number out of an answer's prose, for answerers that do not set `value`. */
export function extractNumber(text: string): number | undefined {
  const match = text.replace(/,/g, "").match(/-?\d+(\.\d+)?/);
  return match ? Number(match[0]) : undefined;
}

function gradeNumeric(
  testCase: QueryEvalCase & { expect: { kind: "numeric" } },
  answer: EvalQueryAnswer,
  reasons: string[],
): { ok: boolean; actual?: number } {
  const { value, tolerance, denominator } = testCase.expect;
  const actual = answer.value ?? extractNumber(answer.answer);
  if (actual === undefined) {
    reasons.push("no numeric value in answer");
    return { ok: false };
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
  return { ok, actual };
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
  const reasons: string[] = [];
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
    };
  }

  let ok = true;
  let actual: number | undefined;
  let outcome: EvalCaseResult["outcome"] = "pass";

  switch (testCase.expect.kind) {
    case "numeric": {
      const graded = gradeNumeric(
        testCase as QueryEvalCase & { expect: { kind: "numeric" } },
        answer,
        reasons,
      );
      ok = graded.ok;
      actual = graded.actual;
      break;
    }
    case "set":
      ok = gradeSet(
        testCase as QueryEvalCase & { expect: { kind: "set" } },
        answer,
        reasons,
      );
      break;
    case "absence":
      ok = gradeAbsence(testCase, answer, reasons);
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
        };
      }
      const verdict = await options.judge.judge(
        testCase.expect.rubric,
        testCase,
        answer,
      );
      ok = verdict.pass;
      if (!verdict.pass) reasons.push(verdict.reason);
      break;
    }
  }

  if (testCase.mustCite && answer.citations.length === 0) {
    reasons.push("no citations");
    ok = false;
  }
  if (testCase.mustReportCoverage) {
    if (answer.coverage.scopesScanned.length === 0) {
      reasons.push("coverage reports no scopes scanned");
      ok = false;
    }
    if (
      !answer.coverage.complete &&
      !/\b(not|could not|unable|partial|incomplete|only)\b/i.test(answer.answer)
    ) {
      reasons.push(
        "coverage.complete is false but the answer text does not say so",
      );
      ok = false;
    }
  }

  outcome = ok ? "pass" : "fail";
  return {
    id: testCase.id,
    class: testCase.class,
    outcome,
    reasons,
    durationMs: Date.now() - started,
    cost: answer.cost,
    actual,
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
    };
  });

  return {
    answerer: options.answerer.name,
    seed: options.seed,
    profile: options.profile,
    results,
    rollups,
    totals: {
      pass: results.filter((r) => r.outcome === "pass").length,
      fail: results.filter((r) => r.outcome === "fail").length,
      skipped: results.filter((r) => r.outcome === "skipped").length,
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

  lines.push(
    `query-layer eval — answerer=${report.answerer} profile=${report.profile} seed=${report.seed}`,
    "",
  );
  for (const result of report.results) {
    lines.push(
      `  ${mark[result.outcome]}  ${result.id.padEnd(4)} ${result.class.padEnd(14)} ${String(result.durationMs).padStart(6)}ms`,
    );
    for (const reason of result.reasons) lines.push(`          ${reason}`);
  }

  lines.push("", "  by class:");
  for (const rollup of report.rollups) {
    lines.push(
      `    ${rollup.class.padEnd(14)} pass ${rollup.pass}  fail ${rollup.fail}  skip ${rollup.skipped}`,
    );
  }

  const { totals } = report;
  lines.push(
    "",
    `  totals: pass ${totals.pass}  fail ${totals.fail}  skip ${totals.skipped}`,
    `  wall clock: ${totals.wallClockMs}ms   tokens: ${totals.inputTokens} in / ${totals.outputTokens} out   cost: $${totals.usd.toFixed(4)}`,
  );
  return lines.join("\n");
}
