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
 *
 * Phase 2 determinism lives in `query-determinism.ts`, sharing this script's
 * wiring via `query-eval-harness.ts`.
 */

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  DEFAULT_SEED,
  PROFILES,
  buildCases,
  createNullAnswerer,
  createReferenceAnswerer,
  formatReport,
  generateInto,
  runEval,
  type FixtureProfileName,
} from "@opendatalabs/personal-server-ts-core/query/evals";

import { FsFixtureSink } from "./query-eval-fs-sink.js";
import { buildAgentAnswerer, buildLiveProvider } from "./query-eval-harness.js";

function arg(name: string, fallback?: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i === -1 ? fallback : process.argv[i + 1];
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
  const answerer =
    which === "null"
      ? createNullAnswerer()
      : which === "agent"
        ? await buildAgentAnswerer(dir, manifest)
        : which === "live"
          ? await buildAgentAnswerer(dir, manifest, buildLiveProvider())
          : createReferenceAnswerer(source);

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

  const report = await runEval({
    cases: await buildCases(source),
    answerer: graded,
    seed,
    profile,
    only,
  });

  process.stdout.write(formatReport(report) + "\n");

  if (!keep) await rm(dir, { recursive: true, force: true });
  process.exitCode = report.totals.fail > 0 ? 1 : 0;
}

main().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});
