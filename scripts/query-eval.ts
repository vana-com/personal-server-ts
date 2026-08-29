/**
 * Query-layer eval runner (implementation plan phase 1).
 *
 * Generates the seeded fixture corpus and grades the question set against a
 * pluggable answerer. The eval harness itself lives in `packages/core` and is
 * browser-safe; this script supplies the Node filesystem sink it cannot.
 *
 *   npm run eval                        # small profile, reference answerer
 *   npm run eval -- --profile full      # the ~277MB corpus
 *   npm run eval -- --answerer null     # prove the harness fails honestly
 *   npm run eval -- --keep out/corpus   # keep the corpus for inspection
 *   scripts/live-gemini.sh --judge      # also grade the judged cases
 *
 * Phase 2 determinism lives in `query-determinism.ts`, sharing this script's
 * wiring via `query-eval-harness.ts`.
 *
 * WITHOUT `--judge` the eight `{ kind: "judged" }` cases report `skipped`, and
 * that is the correct behaviour rather than a gap: the runner refuses to guess,
 * because a harness that scores unjudgeable cases as passes reports a number
 * that looks like progress. `--judge` supplies a model grader (the same live
 * provider that answered, unless an operator splits them) which grades against
 * the corpus's planted ground-truth anchors. Every row it decides is labelled
 * `model-graded` in the output. A judge's opinion is not a measurement and the
 * report must never let the two blur together.
 */

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  DEFAULT_SEED,
  PROFILES,
  buildCases,
  buildJudge,
  createNullAnswerer,
  createReferenceAnswerer,
  formatReport,
  generateInto,
  runEval,
  type EvalReport,
  type FixtureProfileName,
} from "@opendatalabs/personal-server-ts-core/query/evals";

import { FsFixtureSink } from "./query-eval-fs-sink.js";
import { buildAgentAnswerer, buildLiveProvider } from "./query-eval-harness.js";

function arg(name: string, fallback?: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i === -1 ? fallback : process.argv[i + 1];
}
const flag = (name: string): boolean => process.argv.includes(`--${name}`);

/**
 * Name the judge, and say plainly what its verdicts are worth.
 *
 * The per-row `[model-graded]` label is no longer applied here: it is a field
 * on `EvalCaseResult`, set in `runner.ts` where the verdict is actually made
 * and rendered by `formatReport`. This used to be line surgery over that
 * output, which could only infer which rows a model decided from the case
 * list. What remains is the part the report genuinely cannot know — which
 * model was asked — plus the standing caveat, which belongs next to the
 * scoreboard rather than buried in a row.
 */
function judgeFooter(report: EvalReport, judgeModel: string): string {
  const graded = report.results.filter((r) => r.modelGraded).map((r) => r.id);
  return (
    `\n\n  model-graded: ${graded.length} row(s) decided by ${judgeModel}` +
    `${graded.length > 0 ? ` — ${graded.join(", ")}` : ""}\n` +
    "  A model's verdict is not a measurement. Rows above without this label\n" +
    "  were graded against computed expected values."
  );
}

async function main(): Promise<void> {
  const profile = (arg("profile", "small") ?? "small") as FixtureProfileName;
  if (!(profile in PROFILES)) {
    throw new Error(
      `unknown profile "${profile}" — expected one of ${Object.keys(PROFILES).join(", ")}`,
    );
  }
  const seed = Number(arg("seed", String(DEFAULT_SEED)));
  const keep = arg("keep");
  const dir = keep ?? (await mkdtemp(join(tmpdir(), "query-eval-")));

  const sink = new FsFixtureSink(dir);
  await sink.init();

  const startedAt = Date.now();
  process.stderr.write(
    `generating "${profile}" corpus (seed ${seed}) into ${dir}\n`,
  );
  const { manifest, source } = await generateInto(sink, { profile, seed });
  const fileCount = new Set(manifest.scopes.flatMap((s) => s.files)).size;
  process.stderr.write(
    `generated ${fileCount} files / ${manifest.scopes.length} scopes in ${Date.now() - startedAt}ms\n\n`,
  );

  const which = arg("answerer", "reference") ?? "reference";

  // One provider, shared by the answerer and the judge. Two `buildLiveProvider()`
  // calls would be two configurations that can silently diverge, and a judge
  // grading against a different endpoint than the one that answered is a
  // measurement of two systems reported as one.
  const wantsJudge = flag("judge");
  const liveProvider =
    which === "live" || wantsJudge ? buildLiveProvider() : undefined;

  const answerer =
    which === "null"
      ? createNullAnswerer()
      : which === "agent"
        ? await buildAgentAnswerer(dir, manifest)
        : which === "live"
          ? await buildAgentAnswerer(dir, manifest, liveProvider)
          : createReferenceAnswerer(source);

  // `--judge` with a non-live answerer is deliberately allowed: grading the
  // reference answerer's known-good output is the control that says whether the
  // judge can recognise a correct answer at all.
  const judgeModel = process.env.INFERENCE_MODEL;
  const judge =
    wantsJudge && liveProvider
      ? buildJudge(liveProvider, judgeModel)
      : undefined;

  const onlyArg = arg("only");
  const only = onlyArg
    ? onlyArg.split(",").map((id) => id.trim().toUpperCase())
    : undefined;

  // --show-answers: a failing numeric case is usually either a real
  // miscalculation or the grader pulling the wrong number out of prose.
  // Telling those apart requires seeing the answer.
  const show = process.argv.includes("--show-answers");
  const graded = show
    ? {
        name: answerer.name,
        async answer(request: Parameters<typeof answerer.answer>[0]) {
          const out = await answerer.answer(request);
          process.stderr.write(
            `\n--- ANSWER (${request.question.slice(0, 60)}...) ---\n` +
              `value: ${JSON.stringify(out.value)}\n` +
              `answer: ${out.answer}\n` +
              `coverage: ${JSON.stringify(out.coverage)}\n` +
              `citations: ${JSON.stringify(out.citations)}\n---\n\n`,
          );
          return out;
        },
      }
    : answerer;

  const cases = await buildCases(source);
  const report = await runEval({
    cases,
    answerer: graded,
    seed,
    profile,
    only,
    judge,
  });

  const rendered = formatReport(report);
  process.stdout.write(
    rendered +
      (judge
        ? judgeFooter(report, judgeModel ?? liveProvider!.defaultModel)
        : "") +
      "\n",
  );

  if (!keep) await rm(dir, { recursive: true, force: true });
  process.exitCode = report.totals.fail > 0 ? 1 : 0;
}

main().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});
