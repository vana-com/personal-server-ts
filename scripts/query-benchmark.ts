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

  const started = Date.now();
  const report = await runEval({
    cases,
    answerer: capturing,
    seed,
    profile,
    only,
    judge,
  });
  const wall = Date.now() - started;

  for (const result of report.results) {
    const testCase = cases.find((c) => c.id === result.id);
    const answer = testCase ? answers.get(testCase.question) : undefined;
    // `bytesScanned` is produced by the tool layer and travels on the runtime
    // object, but `QueryCoverage` does not declare it — so no typed consumer
    // can read it without this cast. Reported as a defect, not papered over.
    const cov = answer?.coverage as
      | (NonNullable<typeof answer>["coverage"] & { bytesScanned?: number })
      | undefined;
    rows.push({
      id: result.id,
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
        testCase?.expect.kind === "numeric" ? testCase.expect.value : undefined,
      reasons: result.reasons,
      answerHead: (answer?.answer ?? "").replace(/\s+/g, " ").slice(0, 400),
      scriptChars: answer?.script?.length,
      script: answer?.script,
      unprofiled: cov?.unprofiledScopes?.length ?? 0,
    });
  }

  const out = {
    profile,
    seed,
    live,
    judged: judge !== undefined,
    model: process.env.INFERENCE_MODEL ?? null,
    wallClockMs: wall,
    totals: report.totals,
    rows,
  };
  const path =
    arg("out") ?? join(tmpdir(), `query-bench-${profile}-${Date.now()}.json`);
  await writeFile(path, JSON.stringify(out, null, 2));

  // Table
  const h = [
    "id",
    "class",
    "kind",
    "outcome",
    "ms",
    "in",
    "out",
    "calls",
    "records",
    "bytes",
    "scopes",
    "cmpl",
    "stopped",
  ];
  process.stdout.write(
    `\n${h[0].padEnd(4)} ${h[1].padEnd(13)} ${h[2].padEnd(8)} ${h[3].padEnd(7)} ${h[4].padStart(7)} ${h[5].padStart(7)} ${h[6].padStart(6)} ${h[7].padStart(5)} ${h[8].padStart(8)} ${h[9].padStart(9)} ${h[10].padStart(6)} ${h[11].padStart(4)} ${h[12]}\n`,
  );
  for (const r of rows) {
    process.stdout.write(
      `${r.id.padEnd(4)} ${r.klass.padEnd(13)} ${r.kind.padEnd(8)} ${r.outcome.padEnd(7)} ` +
        `${String(r.ms).padStart(7)} ${String(r.inTok).padStart(7)} ${String(r.outTok).padStart(6)} ` +
        `${String(r.toolCalls).padStart(5)} ${String(r.records).padStart(8)} ${String(r.bytes).padStart(9)} ` +
        `${String(r.scopes).padStart(6)} ${(r.complete ? "yes" : "no").padStart(4)} ${r.stoppedBecause ?? ""}` +
        `${r.modelGraded ? "  [model-graded]" : ""}\n`,
    );
  }

  const t = report.totals;
  process.stdout.write(
    `\ntotals: pass ${t.pass}  fail ${t.fail}  skip ${t.skipped}\n` +
      `tokens: ${t.inputTokens} in / ${t.outputTokens} out   wall ${(wall / 1000).toFixed(1)}s\n` +
      `raw: ${path}\n`,
  );

  await rm(dir, { recursive: true, force: true });
}

main().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});
