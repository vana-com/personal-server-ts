/**
 * The set-resolution experiment.
 *
 * Measured cause of most remaining benchmark failures: the arithmetic is right
 * and the *set* is wrong. Q1 averaged the last full calendar month where the
 * eval means a trailing 31 days; Q14 resolved the trip window correctly then
 * omitted the pre-trip flight; Q18 computed two defensible denominators and
 * headlined the wrong one.
 *
 * This runs the affected cases N times and records, per run, the number AND
 * the set the answer says it aggregated over. The diagnostic nobody has had is
 * **how often the resolution was right while the number was wrong** — that is
 * what separates a reporting problem from a reasoning problem.
 *
 *   npx tsx scripts/query-set-resolution.ts --repeat 3 --only Q1,Q6,Q14,Q18
 *   npx tsx scripts/query-set-resolution.ts --repeat 3 --live --only Q1
 *
 * Live runs cost money; `--live` is required to spend any.
 */

import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  DEFAULT_SEED,
  buildCases,
  generateInto,
  runEval,
  type FixtureProfileName,
  type QueryEvalCase,
} from "../packages/core/src/query/evals/index.js";

import { FsFixtureSink } from "./query-eval-fs-sink.js";
import { buildAgentAnswerer, buildLiveProvider } from "./query-eval-harness.js";

function arg(name: string, fallback?: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i === -1 ? fallback : process.argv[i + 1];
}

interface Observation {
  run: number;
  outcome: string;
  value?: number;
  resolution?: string;
  reasons: string[];
  ms: number;
  inputTokens: number;
  outputTokens: number;
}

async function main(): Promise<void> {
  const profile = (arg("profile", "dogfood") ??
    "dogfood") as FixtureProfileName;
  const seed = Number(arg("seed", String(DEFAULT_SEED)));
  const repeat = Number(arg("repeat", "3"));
  const live = process.argv.includes("--live");
  const label = arg("label", live ? "live" : "offline") ?? "live";
  const onlyArg = arg("only", "Q1,Q6,Q14,Q18");
  const only = (onlyArg ?? "")
    .split(",")
    .map((s) => s.trim().toUpperCase())
    .filter(Boolean);

  if (live && profile === "full") {
    throw new Error("refusing to run the full profile live");
  }
  if (live && repeat > 5) {
    throw new Error("refusing more than 5 live runs per case without review");
  }

  const dir = await mkdtemp(join(tmpdir(), "query-setres-"));
  const sink = new FsFixtureSink(dir);
  await sink.init();
  const { manifest, source } = await generateInto(sink, { profile, seed });
  process.stderr.write(
    `corpus: ${profile} (${manifest.scopes.length} scopes), seed ${seed}\n` +
      `mode: ${live ? "LIVE" : "offline"}  repeat: ${repeat}  cases: ${only.join(",")}\n\n`,
  );

  const allCases = await buildCases(source);
  const selected = allCases.filter((c: QueryEvalCase) => only.includes(c.id));

  const results: Record<string, Observation[]> = {};

  for (const testCase of selected) {
    const obs: Observation[] = [];
    for (let run = 0; run < repeat; run += 1) {
      // A fresh answerer per run: the tool host accumulates coverage across a
      // request and never resets, so reuse would make coverage look
      // monotonically increasing rather than per-run.
      const answerer = await buildAgentAnswerer(
        dir,
        manifest,
        live ? buildLiveProvider() : undefined,
      );
      const started = Date.now();
      const report = await runEval({
        cases: [testCase],
        answerer,
        seed,
        profile,
      });
      const r = report.results[0];
      obs.push({
        run,
        outcome: r?.outcome ?? "unknown",
        value: r?.actual,
        resolution: r?.resolution,
        reasons: r?.reasons ?? [],
        ms: Date.now() - started,
        inputTokens: r?.cost.inputTokens ?? 0,
        outputTokens: r?.cost.outputTokens ?? 0,
      });
      process.stderr.write(
        `  ${testCase.id} run ${run}: ${r?.outcome}` +
          ` value=${r?.actual ?? "-"}` +
          ` ` +
          `\n    resolution: ${r?.resolution ?? "(none declared)"}\n`,
      );
    }
    results[testCase.id] = obs;
  }

  // Report
  const lines: string[] = ["", `=== set-resolution experiment (${label}) ===`];
  let declared = 0;
  let total = 0;
  for (const testCase of selected) {
    const obs = results[testCase.id] ?? [];
    const pass = obs.filter((o) => o.outcome === "pass").length;
    const withRes = obs.filter((o) => o.resolution).length;
    declared += withRes;
    total += obs.length;
    const expected =
      testCase.expect.kind === "numeric" ? testCase.expect.value : undefined;
    lines.push(
      `\n${testCase.id} (${testCase.class})  pass ${pass}/${obs.length}` +
        (expected !== undefined ? `  expected ${expected}` : ""),
    );
    lines.push(`  resolution declared: ${withRes}/${obs.length}`);
    for (const o of obs) {
      lines.push(
        `  run ${o.run}: ${o.outcome.padEnd(4)} value=${o.value ?? "-"}` +
          ` ${o.ms}ms in=${o.inputTokens} out=${o.outputTokens}`,
      );
      if (o.resolution) lines.push(`    set: ${o.resolution}`);
      for (const reason of o.reasons) lines.push(`    ! ${reason}`);
    }
  }
  lines.push(
    `\nresolution declared overall: ${declared}/${total}`,
    "\nThe diagnostic to read: for runs where the VALUE was wrong, does the",
    "stated set explain the number? A stated set that matches the number means",
    "the model reasoned consistently over a different reading (a definition",
    "problem). A stated set that does NOT match its own number means the",
    "computation drifted from the declared set (a reasoning problem).",
  );
  const text = lines.join("\n");
  process.stdout.write(text + "\n");

  const out = arg("out");
  if (out) {
    await writeFile(
      out,
      JSON.stringify({ label, profile, seed, results }, null, 2),
    );
    process.stderr.write(`\nraw -> ${out}\n`);
  }
  await rm(dir, { recursive: true, force: true });
}

main().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});
