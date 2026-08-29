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
 * Every row is written to disk the moment it completes — appended to
 * `<out>.jsonl` and folded into `<out>` — so a sweep killed at 50 minutes
 * yields a partial dataset rather than nothing, which is what happened to the
 * first `gemini-3.1-pro-preview` N=3 run. Re-running the same command resumes:
 * rows already in the JSONL are skipped, not re-asked. `--fresh` ignores what
 * is there and starts over, which is what you want if the corpus or the model
 * changed under the same `--out` path.
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

import {
  appendFile,
  mkdtemp,
  readFile,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  DEFAULT_SEED,
  PROFILES,
  buildCases,
  buildJudge,
  createReferenceAnswerer,
  generateInto,
  runEval,
  type FixtureProfileName,
} from "@opendatalabs/personal-server-ts-core/query/evals";
import type { QueryAnswer } from "../packages/core/src/query/agent/index.js";

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
  /**
   * The set the model declared before computing, when it declared one.
   *
   * Carried so `query-regrade.ts` can grade a resolution it was *given*
   * rather than one inferred from prose. Design §19.10: inferring a
   * declaration misclassified 2 of 9 runs, which is why the 54-run benchmark
   * that predates the field cannot be regraded at all.
   */
  resolution?: string;
  reasons: string[];
  answerHead: string;
  scriptChars?: number;
  script?: string;
  unreadable?: number;
  unprofiled: number;
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
  //
  // `buildAgentAnswerer` now builds the host per request as well — it has to,
  // since the grant is per request — so this is belt and braces rather than
  // the only thing standing between the table and that bug.
  const freshAnswerer = async () =>
    live
      ? await buildAgentAnswerer(dir, manifest, provider)
      : createReferenceAnswerer(source);
  const answerer = await freshAnswerer();
  // The shared judge from `evals/judge.ts`, not a local copy. This script's
  // fork was where the judge began, and it drifted: it never carried
  // `testCase.notes` — the written-down trap — into the prompt, it threw on a
  // relay hiccup instead of recording `judge-error:` and losing the whole
  // sweep with it, and it coerced a non-boolean `pass` rather than failing the
  // contract. One judge, or the benchmark and the eval grade differently from
  // the same corpus on the same day.
  const judge =
    flag("judge") && provider
      ? buildJudge(provider, process.env.INFERENCE_MODEL)
      : undefined;

  const onlyArg = arg("only");
  const only = onlyArg
    ? onlyArg.split(",").map((s) => s.trim().toUpperCase())
    : undefined;

  const cases = await buildCases(source);
  const answers = new Map<string, QueryAnswer>();

  const repeat = Math.max(1, Number(arg("repeat", "1")));

  /*
   * Where the run persists itself, decided BEFORE the first question runs.
   *
   * A ~50-minute `gemini-3.1-pro-preview` N=3 sweep was killed at the wire and
   * produced nothing at all, because the only write happened after the last
   * row. Two files now, written as each row lands:
   *
   *  - `<out>.jsonl`, one row per line, appended and never rewritten. It is
   *    the durable record: an append cannot corrupt what is already on disk,
   *    so a kill mid-write costs at most the row in flight.
   *  - `<out>`, the same envelope this script always wrote, rewritten via a
   *    temp file and a rename after every row. `query-regrade.ts` reads
   *    `{ rows: [...] }` and now finds it whether or not the sweep finished;
   *    the rename is atomic, so a reader never sees half an envelope.
   *
   * Rewriting the whole envelope per row is O(n²) in bytes. At 54 rows of a
   * few KB it is noise against a 50-minute live sweep, and it buys a partial
   * dump that needs no reassembly.
   */
  const outPath =
    arg("out") ?? join(tmpdir(), `query-bench-${profile}-${Date.now()}.json`);
  const jsonlPath = outPath.replace(/\.json$/, "") + ".jsonl";
  const tmpPath = `${outPath}.tmp`;

  /*
   * Resume from whatever the killed sweep managed to write.
   *
   * Keyed on `id#run`, because a repeat is only meaningful as a whole: a row
   * that completed is not re-asked, and a row that was in flight when the
   * process died was never appended, so it is re-asked. `--fresh` opts out
   * for the case where the corpus or the model changed under the same path —
   * resuming across either would silently mix two experiments into one table.
   */
  const rows: Row[] = [];
  const done = new Set<string>();
  const key = (id: string, run: number) => `${id}#${run}`;
  if (!flag("fresh")) {
    let existing = "";
    try {
      existing = await readFile(jsonlPath, "utf8");
    } catch {
      existing = "";
    }
    let torn = existing !== "" && !existing.endsWith("\n");
    for (const line of existing.split("\n")) {
      if (!line.trim()) continue;
      try {
        const row = JSON.parse(line) as Row;
        if (done.has(key(row.id, row.run))) continue;
        done.add(key(row.id, row.run));
        rows.push(row);
      } catch {
        // A torn final line is the expected shape of a kill. Drop it and
        // re-ask that row rather than carrying a half-parsed one forward.
        torn = true;
      }
    }
    if (torn) {
      // Rewrite from what parsed, because appending onto a half-written line
      // would glue the next row to it and lose that one too — the kill would
      // then cost two rows instead of one.
      await writeFile(
        jsonlPath,
        rows.map((r) => JSON.stringify(r)).join("\n") +
          (rows.length ? "\n" : ""),
      );
      process.stderr.write(`repaired a torn tail in ${jsonlPath}\n`);
    }
    if (rows.length > 0) {
      process.stderr.write(
        `resuming: ${rows.length} row(s) already in ${jsonlPath}\n`,
      );
    }
  }

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

  /*
   * Totals are derived from `rows`, not summed out of the per-pass reports.
   *
   * A resumed sweep has rows it never graded in this process, so a report-based
   * total would silently under-count everything the resume recovered. Rows are
   * the only thing both halves of a resumed run have in common.
   */
  const envelope = () => ({
    profile,
    seed,
    live,
    repeat,
    judged: judge !== undefined,
    model: process.env.INFERENCE_MODEL ?? null,
    wallClockMs: Date.now() - started,
    totals: {
      pass: rows.filter((r) => r.outcome === "pass").length,
      fail: rows.filter((r) => r.outcome === "fail").length,
      skipped: rows.filter((r) => r.outcome === "skipped").length,
      inputTokens: rows.reduce((n, r) => n + r.inTok, 0),
      outputTokens: rows.reduce((n, r) => n + r.outTok, 0),
    },
    rows,
  });

  const persist = async (row: Row): Promise<void> => {
    await appendFile(jsonlPath, JSON.stringify(row) + "\n");
    await writeFile(tmpPath, JSON.stringify(envelope(), null, 2));
    await rename(tmpPath, outPath);
  };

  // One `runEval` per QUESTION per repeat, not one call spanning a whole pass.
  // Each question still sees a fresh answerer and a fresh grading pass — the
  // invariant that stops a repeat inheriting state — and the row lands on disk
  // before the next question starts, which is what makes a killed sweep yield
  // a partial dataset rather than nothing.
  const selected = only ? cases.filter((c) => only.includes(c.id)) : cases;
  for (let run = 0; run < repeat; run++) {
    if (repeat > 1) {
      process.stderr.write(`\n--- repeat ${run + 1}/${repeat} ---\n`);
    }
    for (const testCase of selected) {
      if (done.has(key(testCase.id, run))) {
        process.stderr.write(`  ${testCase.id} run ${run}: already recorded\n`);
        continue;
      }
      const report = await runEval({
        cases,
        answerer: capturing,
        seed,
        profile,
        only: [testCase.id],
        judge,
      });
      const result = report.results[0];
      if (!result) continue;
      const answer = answers.get(testCase.question);
      // `bytesScanned` and `unreadable` are declared on `QueryCoverage` as of
      // the per-scope attribution fix, so this no longer needs a cast.
      const cov = answer?.coverage;
      const row: Row = {
        id: result.id,
        run,
        klass: result.class,
        kind: testCase.expect.kind,
        outcome: result.outcome,
        modelGraded: testCase.expect.kind === "judged" && judge !== undefined,
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
          testCase.expect.kind === "numeric"
            ? testCase.expect.value
            : undefined,
        resolution: result.resolution,
        reasons: result.reasons,
        answerHead: (answer?.answer ?? "").replace(/\s+/g, " ").slice(0, 400),
        scriptChars: answer?.script?.length,
        script: answer?.script,
        unreadable: cov?.unreadable,
        unprofiled: cov?.unprofiledScopes?.length ?? 0,
      };
      rows.push(row);
      done.add(key(result.id, run));
      answers.clear();
      await persist(row);
    }
  }
  const wall = Date.now() - started;

  // A final write even when every row was resumed and nothing ran, so `--out`
  // always exists and always carries the whole table.
  await writeFile(tmpPath, JSON.stringify(envelope(), null, 2));
  await rename(tmpPath, outPath);
  const totals = envelope().totals;
  const path = outPath;

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
    // `"skipped"`, not `"skip"` — the runner's own spelling. Matching the
    // wrong string counted a judged case with no judge as a graded zero, so a
    // question nobody scored reported as 0/3 rather than as unscored.
    const skips = rs.filter((r) => r.outcome === "skipped").length;
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
      `raw: ${path}\n` +
      `rows: ${jsonlPath} (appended per row; re-run the same command to resume)\n`,
  );

  await rm(dir, { recursive: true, force: true });
}

main().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});
