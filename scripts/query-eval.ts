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
  type QueryEvalCase,
} from "@opendatalabs/personal-server-ts-core/query/evals";

import { FsFixtureSink } from "./query-eval-fs-sink.js";
import { buildAgentAnswerer, buildLiveProvider } from "./query-eval-harness.js";

function arg(name: string, fallback?: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i === -1 ? fallback : process.argv[i + 1];
}
const flag = (name: string): boolean => process.argv.includes(`--${name}`);

/**
 * Mark every row a model decided, and say so again in a footer.
 *
 * This is line surgery over `formatReport`'s output rather than a field on the
 * result, which is not where it belongs: the durable fix is `modelGraded` on
 * `EvalCaseResult` and a `[model-graded]` suffix inside `formatReport` itself,
 * both of which live in `runner.ts` / `types.ts`. Until that lands, the label
 * is applied here, because the alternative — a table where a model's opinion
 * and a computed comparison render identically — is the specific confusion this
 * whole harness is built to prevent. `formatReport` emits one line per result
 * as `  MARK  id ...`, so the id column is an exact anchor.
 */
function labelModelGraded(
  text: string,
  report: EvalReport,
  cases: QueryEvalCase[],
  judgeModel: string,
): string {
  const judgedIds = new Set(
    cases.filter((c) => c.expect.kind === "judged").map((c) => c.id),
  );
  const graded = report.results
    .filter((r) => judgedIds.has(r.id) && r.outcome !== "skipped")
    .map((r) => r.id);
  const gradedSet = new Set(graded);

  const labelled = text
    .split("\n")
    .map((line) => {
      const match = line.match(/^ {2}(?:PASS|FAIL|SKIP) {2}(\S+)/);
      return match && gradedSet.has(match[1])
        ? `${line}  [model-graded]`
        : line;
    })
    .join("\n");

  return (
    labelled +
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
    (judge
      ? labelModelGraded(
          rendered,
          report,
          cases,
          judgeModel ?? liveProvider!.defaultModel,
        )
      : rendered) + "\n",
  );

  if (!keep) await rm(dir, { recursive: true, force: true });
  process.exitCode = report.totals.fail > 0 ? 1 : 0;
}

main().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});
