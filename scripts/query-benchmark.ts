/**
 * Full-corpus benchmark: run every graded question once and record what it
 * cost, what it scanned, and whether it was right.
 *
 * This is the per-question companion to `query-eval.ts` (pass/fail) and
 * `query-determinism.ts` (variance across repeats). It exists because neither
 * of those reports the axis the design actually argues about: design §18.3
 * predicts that scans are free and semantic judgement dominates spend, and
 * nothing in the harness measured that per question.
 *
 *   npx tsx scripts/query-benchmark.ts --profile dogfood --live --judge
 *   npx tsx scripts/query-benchmark.ts --profile dogfood --only Q1,Q14
 *   npx tsx scripts/query-benchmark.ts --profile dogfood --live --repeat 3
 *
 * `--repeat N` is the default posture for any live claim. At temperature 0 the
 * model still produced 60 distinct scripts in 60 runs (design §15.3), so one
 * live run is a SAMPLE, not a verification. A single-run pass on Q18 was
 * reported as fixed and then measured at 1-in-4 on re-run; a question that is
 * neither 0/N nor N/N is the most informative row in the table, and a single
 * run cannot show it.
 *
 * Judged cases are graded by a model against the ground-truth anchors the
 * corpus plants, and every such row is labelled `model-graded` in the output.
 * A judge's opinion is not a measurement and the report must never let the two
 * blur together.
 */

import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  DEFAULT_SEED,
  PROFILES,
  buildCases,
  createReferenceAnswerer,
  generateInto,
  runEval,
  type EvalJudge,
  type FixtureProfileName,
  type QueryEvalCase,
} from "@opendatalabs/personal-server-ts-core/query/evals";
import type { QueryAnswer } from "../packages/core/src/query/agent/index.js";
import type { InferenceProvider } from "../packages/core/src/derivatives/inference.js";

import { FsFixtureSink } from "./query-eval-fs-sink.js";
import { buildAgentAnswerer, buildLiveProvider } from "./query-eval-harness.js";

function arg(name: string, fallback?: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i === -1 ? fallback : process.argv[i + 1];
}
const flag = (name: string) => process.argv.includes(`--${name}`);

/** One row of the benchmark table. */
interface Row {
  id: string;
  /** 0-based repeat index; rows with the same id differ only by this. */
  run: number;
  klass: string;
  kind: string;
  outcome: string;
  modelGraded: boolean;
  ms: number;
  inTok: number;
  outTok: number;
  toolCalls: number;
  records: number;
  bytes: number;
  scopes: number;
  complete: boolean;
  stoppedBecause?: string;
  method?: string;
  value?: number;
  expected?: number;
  reasons: string[];
  answerHead: string;
  scriptChars?: number;
  script?: string;
  unreadable?: number;
  unprofiled: number;
}

/**
 * A model judge, scoped as tightly as the rubric allows.
 *
 * It is handed the rubric, the planted ground truth, and the answer — and told
 * to fail anything it cannot verify against those anchors. The failure mode to
 * design against is a judge that rewards fluent prose, so the prompt makes the
 * anchors the only evidence that counts.
 */
function buildJudge(provider: InferenceProvider, model?: string): EvalJudge {
  return {
    async judge(rubric: string, testCase: QueryEvalCase, answer) {
      const facts = testCase.referenceFacts
        ? JSON.stringify(testCase.referenceFacts, null, 2)
        : "(none recorded)";
      const reply = await provider.chat({
        model: model ?? provider.defaultModel,
        maxTokens: 1024,
        messages: [
          {
            role: "system",
            content:
              "You grade one answer against one rubric. Reply with a single " +
              'JSON object: {"pass": boolean, "reason": "<= 200 chars"}. ' +
              "Nothing else.\n\n" +
              "Grade ONLY against the rubric and the ground-truth facts. " +
              "Fluent, confident, well-structured prose is not evidence. If a " +
              "claim in the rubric cannot be checked against the facts given, " +
              "fail it and say which claim. An answer that omits a required " +
              "element fails even if everything it does say is true.",
          },
          {
            role: "user",
            content:
              `QUESTION: ${testCase.question}\n\n` +
              `RUBRIC (all of it must hold):\n${rubric}\n\n` +
              `GROUND TRUTH (computed from the corpus, authoritative):\n${facts}\n\n` +
              `COVERAGE REPORTED BY HOST: complete=${answer.coverage.complete}, ` +
              `method=${answer.coverage.method ?? "n/a"}, ` +
              `records=${answer.coverage.recordsScanned}\n\n` +
              `ANSWER UNDER TEST:\n${answer.answer}`,
          },
        ],
      });
      const text = reply.content ?? "";
      const match = text.match(/\{[\s\S]*\}/);
      if (!match) {
        return {
          pass: false,
          reason: `judge returned no JSON: ${text.slice(0, 120)}`,
        };
      }
      try {
        const parsed = JSON.parse(match[0]) as {
          pass?: unknown;
          reason?: unknown;
        };
        return {
          pass: parsed.pass === true,
          reason:
            typeof parsed.reason === "string"
              ? parsed.reason
              : "(no reason given)",
        };
      } catch {
        return {
          pass: false,
          reason: `judge JSON unparseable: ${match[0].slice(0, 120)}`,
        };
      }
    },
  };
}

async function main(): Promise<void> {
  const profile = (arg("profile", "dogfood") ??
    "dogfood") as FixtureProfileName;
  if (!(profile in PROFILES)) {
    throw new Error(`unknown profile "${profile}"`);
  }
  const seed = Number(arg("seed", String(DEFAULT_SEED)));
  const live = flag("live");
  const dir = await mkdtemp(join(tmpdir(), "query-bench-"));
  const sink = new FsFixtureSink(dir);
  await sink.init();

  const genStart = Date.now();
  const { manifest, source } = await generateInto(sink, { profile, seed });
  const files = new Set(manifest.scopes.flatMap((s) => s.files)).size;
  process.stderr.write(
    `corpus: ${profile} seed=${seed} — ${files} files / ${manifest.scopes.length} scopes in ${Date.now() - genStart}ms\n`,
  );

  const provider = live ? buildLiveProvider() : undefined;
  // A FRESH answerer per question, deliberately. The sandbox tool host
  // accumulates coverage across a request and never resets, which is correct
  // for a single question spanning several turns and catastrophic for a
  // benchmark: reusing one answerer makes `recordsScanned` monotonically
  // increasing, so Q18 inherits everything Q1..Q17 touched. The first run of
  // this script did exactly that and reported 723,794 records for Q18.
  const freshAnswerer = async () =>
    live
      ? await buildAgentAnswerer(dir, manifest, provider)
      : createReferenceAnswerer(source);
  const answerer = await freshAnswerer();
  const judge =
    flag("judge") && provider
      ? buildJudge(provider, process.env.INFERENCE_MODEL)
      : undefined;

  const onlyArg = arg("only");
  const only = onlyArg
    ? onlyArg.split(",").map((s) => s.trim().toUpperCase())
    : undefined;

  const cases = await buildCases(source);
  const rows: Row[] = [];
  const answers = new Map<string, QueryAnswer>();

  // Wrap the answerer so per-question telemetry is captured even when grading
  // throws it away. runEval reports pass/fail; the benchmark needs the rest.
  const capturing = {
    name: answerer.name,
    async answer(request: Parameters<typeof answerer.answer>[0]) {
      const per = await freshAnswerer();
      const out = await per.answer(request);
      answers.set(request.question, out as QueryAnswer);
      return out;
    },
  };

  const repeat = Math.max(1, Number(arg("repeat", "1")));
  const started = Date.now();

  // One `runEval` per repeat, not one repeat inside `runEval`: each pass must
  // see a fresh answerer AND a fresh grading pass, so a repeat cannot inherit
  // state from the one before it. The per-question `freshAnswerer()` above
  // already guards coverage accumulation within a pass.
  const reports = [];
  for (let run = 0; run < repeat; run++) {
    if (repeat > 1) {
      process.stderr.write(`\n--- repeat ${run + 1}/${repeat} ---\n`);
    }
    const report = await runEval({
      cases,
      answerer: capturing,
      seed,
      profile,
      only,
      judge,
    });
    reports.push(report);

    for (const result of report.results) {
      const testCase = cases.find((c) => c.id === result.id);
      const answer = testCase ? answers.get(testCase.question) : undefined;
      // `bytesScanned` and `unreadable` are declared on `QueryCoverage` as of
      // the per-scope attribution fix, so this no longer needs a cast.
      const cov = answer?.coverage;
      rows.push({
        id: result.id,
        run,
        klass: result.class,
        kind: testCase?.expect.kind ?? "?",
        outcome: result.outcome,
        modelGraded: testCase?.expect.kind === "judged" && judge !== undefined,
        ms: result.durationMs,
        inTok: result.cost.inputTokens,
        outTok: result.cost.outputTokens,
        toolCalls: result.cost.toolCalls,
        records: cov?.recordsScanned ?? 0,
        bytes: cov?.bytesScanned ?? 0,
        scopes: cov?.scopesScanned.length ?? 0,
        complete: cov?.complete ?? false,
        stoppedBecause: cov?.stoppedBecause,
        method: cov?.method,
        value: answer?.value,
        expected:
          testCase?.expect.kind === "numeric"
            ? testCase.expect.value
            : undefined,
        reasons: result.reasons,
        answerHead: (answer?.answer ?? "").replace(/\s+/g, " ").slice(0, 400),
        scriptChars: answer?.script?.length,
        script: answer?.script,
        unreadable: cov?.unreadable,
        unprofiled: cov?.unprofiledScopes?.length ?? 0,
      });
    }
    answers.clear();
  }
  const wall = Date.now() - started;

  const totals = {
    pass: reports.reduce((n, r) => n + r.totals.pass, 0),
    fail: reports.reduce((n, r) => n + r.totals.fail, 0),
    skipped: reports.reduce((n, r) => n + r.totals.skipped, 0),
    inputTokens: reports.reduce((n, r) => n + r.totals.inputTokens, 0),
    outputTokens: reports.reduce((n, r) => n + r.totals.outputTokens, 0),
  };

  const out = {
    profile,
    seed,
    live,
    repeat,
    judged: judge !== undefined,
    model: process.env.INFERENCE_MODEL ?? null,
    wallClockMs: wall,
    totals,
    rows,
  };
  const path =
    arg("out") ?? join(tmpdir(), `query-bench-${profile}-${Date.now()}.json`);
  await writeFile(path, JSON.stringify(out, null, 2));

  const median = (xs: number[]): number => {
    if (xs.length === 0) return 0;
    const v = [...xs].sort((a, b) => a - b);
    const mid = v.length >> 1;
    return v.length % 2 ? v[mid] : Math.round((v[mid - 1] + v[mid]) / 2);
  };

  // Aggregate by question. The headline number is pass-count-out-of-N, never a
  // single verdict: a row that is neither 0/N nor N/N is the one a single-run
  // benchmark would have misreported, so it gets called out explicitly.
  const ids = [...new Set(rows.map((r) => r.id))];
  const agg = ids.map((id) => {
    const rs = rows.filter((r) => r.id === id);
    const passes = rs.filter((r) => r.outcome === "pass").length;
    const skips = rs.filter((r) => r.outcome === "skip").length;
    const graded = rs.length - skips;
    const modes = [
      ...new Set(
        rs
          .filter((r) => r.outcome === "fail")
          .map((r) => r.stoppedBecause ?? r.reasons[0] ?? "wrong-answer")
          .map((m) => m.slice(0, 40)),
      ),
    ];
    const values = [
      ...new Set(rs.map((r) => r.value).filter((v) => v != null)),
    ];
    return {
      id,
      klass: rs[0].klass,
      kind: rs[0].kind,
      modelGraded: rs[0].modelGraded,
      passes,
      graded,
      skips,
      flaky: passes > 0 && passes < graded,
      ms: median(rs.map((r) => r.ms)),
      inTok: median(rs.map((r) => r.inTok)),
      outTok: median(rs.map((r) => r.outTok)),
      calls: median(rs.map((r) => r.toolCalls)),
      records: median(rs.map((r) => r.records)),
      bytes: median(rs.map((r) => r.bytes)),
      anyComplete: rs.some((r) => r.complete),
      modes,
      values,
    };
  });

  process.stdout.write(
    `\n${"id".padEnd(4)} ${"class".padEnd(13)} ${"kind".padEnd(8)} ${"pass".padEnd(6)} ` +
      `${"ms".padStart(7)} ${"in".padStart(8)} ${"out".padStart(6)} ${"calls".padStart(5)} ` +
      `${"records".padStart(8)} ${"cmpl".padStart(4)}  failure mode\n`,
  );
  for (const a of agg) {
    const score =
      a.graded === 0 ? `-/${a.skips}skip` : `${a.passes}/${a.graded}`;
    process.stdout.write(
      `${a.id.padEnd(4)} ${a.klass.padEnd(13)} ${a.kind.padEnd(8)} ${score.padEnd(6)} ` +
        `${String(a.ms).padStart(7)} ${String(a.inTok).padStart(8)} ${String(a.outTok).padStart(6)} ` +
        `${String(a.calls).padStart(5)} ${String(a.records).padStart(8)} ` +
        `${(a.anyComplete ? "yes" : "no").padStart(4)}  ${a.modes.join("; ")}` +
        `${a.flaky ? "   << FLAKY" : ""}${a.modelGraded ? "  [model-graded]" : ""}\n`,
    );
  }

  const flaky = agg.filter((a) => a.flaky);
  const solid = agg.filter((a) => a.graded > 0 && a.passes === a.graded);
  process.stdout.write(
    `\nrepeats: ${repeat}   questions: ${ids.length}\n` +
      `always-pass: ${solid.length} (${solid.map((a) => a.id).join(", ") || "none"})\n` +
      `FLAKY:       ${flaky.length} (${flaky.map((a) => `${a.id} ${a.passes}/${a.graded}`).join(", ") || "none"})\n` +
      `run-totals: pass ${totals.pass}  fail ${totals.fail}  skip ${totals.skipped}\n` +
      `tokens: ${totals.inputTokens} in / ${totals.outputTokens} out   wall ${(wall / 1000).toFixed(1)}s\n` +
      `coverage.complete ever true: ${agg.some((a) => a.anyComplete) ? "YES" : "NO"}\n` +
      `raw: ${path}\n`,
  );

  await rm(dir, { recursive: true, force: true });
}

main().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});
