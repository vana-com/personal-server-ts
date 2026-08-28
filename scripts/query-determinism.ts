/**
 * Phase 2 — determinism measurement (design §15.3 / §17.3, plan phase 2).
 *
 * Design §17.3, stated plainly: "A replayed script is deterministic; a
 * regenerated one is not, and nobody has measured the variance." This
 * measures it, and it is the single result that gates how much we
 * materialize.
 *
 *   npx tsx scripts/query-determinism.ts --repeat 10               # offline control
 *   npx tsx scripts/query-determinism.ts --repeat 10 --live        # live
 *   npx tsx scripts/query-determinism.ts --repeat 10 --live --only Q1,Q11
 *
 * Live runs cost real money. Default is offline.
 */

import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  DEFAULT_SEED,
  PROFILES,
  buildCases,
  generateInto,
  type FixtureProfileName,
  type QueryEvalCase,
} from "@opendatalabs/personal-server-ts-core/query/evals";

import { FsFixtureSink } from "./query-eval-fs-sink.js";
import { buildAgentAnswerer, buildLiveProvider } from "./query-eval-harness.js";

function arg(name: string, fallback?: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i === -1 ? fallback : process.argv[i + 1];
}

interface RunObservation {
  run: number;
  value?: number;
  script?: string;
  recordsScanned: number;
  scopesScanned: string[];
  complete: boolean;
  stoppedBecause?: string;
  inputTokens: number;
  outputTokens: number;
  durationMs: number;
  /** Set when the run failed for a reason that is not disagreement. */
  crash?: string;
}

/**
 * Strip what does not change meaning, so "the script differs" means the
 * logic differs rather than the formatting.
 *
 * Comments and whitespace go. String literals are deliberately preserved: a
 * changed scope name or a changed field name is a real difference, not
 * cosmetic.
 */
export function normalizeScript(src: string): string {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/(^|[^:])\/\/[^\n]*/g, "$1 ")
    .replace(/\s+/g, " ")
    .trim();
}

const sha = (t: string): string =>
  createHash("sha256").update(t).digest("hex").slice(0, 8);

function median(xs: number[]): number {
  const s = [...xs].sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m]! : (s[m - 1]! + s[m]!) / 2;
}

function stddev(xs: number[]): number {
  if (xs.length < 2) return 0;
  const mean = xs.reduce((a, b) => a + b, 0) / xs.length;
  return Math.sqrt(
    xs.reduce((a, b) => a + (b - mean) ** 2, 0) / (xs.length - 1),
  );
}

function report(
  caseId: string,
  expected: { value: number; tolerance: number } | undefined,
  obs: RunObservation[],
): string {
  const out: string[] = [];
  const crashes = obs.filter((o) => o.crash);
  const good = obs.filter((o) => !o.crash);
  out.push(
    `\n  ${caseId}  ${obs.length} runs, ${crashes.length} non-variance failures`,
  );

  if (crashes.length) {
    // A crash is not variance. Reported separately so it cannot corrupt the
    // numbers below.
    const byReason = new Map<string, number>();
    for (const c of crashes)
      byReason.set(c.crash!, (byReason.get(c.crash!) ?? 0) + 1);
    for (const [reason, n] of byReason)
      out.push(`    EXCLUDED         ${n}x ${reason}`);
  }
  if (!good.length) {
    out.push("    no successful runs — nothing to measure");
    return out.join("\n");
  }

  const values = good.filter((o) => o.value !== undefined).map((o) => o.value!);
  if (values.length) {
    // Two different questions, and they come apart when a model rounds
    // inconsistently: "did every run return the same bits?" (reproducibility)
    // versus "did every run agree on the answer?" (correctness).
    const exact = new Map<number, number>();
    for (const v of values) exact.set(v, (exact.get(v) ?? 0) + 1);
    out.push(
      `    exact-identical  ${Math.max(...exact.values())}/${values.length}` +
        `   ${exact.size} distinct: ${[...exact.keys()].join(", ")}`,
    );
    if (expected) {
      const within = values.filter(
        (v) => Math.abs(v - expected.value) <= expected.tolerance,
      ).length;
      out.push(
        `    within-tolerance ${within}/${values.length}` +
          `   expected ${expected.value} +/- ${expected.tolerance}`,
      );
      const devs = values.map((v) => Math.abs(v - expected.value));
      out.push(
        `    error            min ${Math.min(...devs).toFixed(6)}  max ${Math.max(...devs).toFixed(6)}`,
      );
    }
    out.push(
      `    spread           min ${Math.min(...values)}  max ${Math.max(...values)}` +
        `  median ${median(values)}  sd ${stddev(values).toFixed(6)}`,
    );
  } else {
    out.push("    value            none of the runs returned a numeric value");
  }

  const scripts = good.filter((o) => o.script).map((o) => o.script!);
  if (scripts.length) {
    const raw = new Set(scripts.map(sha));
    const norm = new Set(scripts.map((x) => sha(normalizeScript(x))));
    out.push(
      `    script distinct  raw ${raw.size}/${scripts.length}` +
        `   normalized ${norm.size}/${scripts.length}`,
    );
    out.push(`    script variants  ${[...norm].join(" ")}`);
  } else {
    out.push("    script           none captured (no run block executed)");
  }

  // Coverage stability is a variance result too, and it bears directly on
  // Q8-class trustworthiness: a model that scans 5 scopes one run and 8 the
  // next has not given the same guarantee twice.
  const recs = new Set(good.map((o) => o.recordsScanned));
  const scopeSets = new Set(
    good.map((o) => [...o.scopesScanned].sort().join(",")),
  );
  out.push(
    `    coverage records ${recs.size} distinct ${JSON.stringify([...recs])}`,
  );
  out.push(
    `    coverage scopes  ${scopeSets.size} distinct set(s)` +
      `   complete ${good.filter((o) => o.complete).length}/${good.length}`,
  );

  const tin = good.reduce((a, o) => a + o.inputTokens, 0);
  const tout = good.reduce((a, o) => a + o.outputTokens, 0);
  const ms = good.reduce((a, o) => a + o.durationMs, 0);
  out.push(
    `    cost             ${tin} in / ${tout} out` +
      `   ${Math.round(ms / good.length)}ms avg`,
  );
  return out.join("\n");
}

async function main(): Promise<void> {
  const profile = (arg("profile", "small") ?? "small") as FixtureProfileName;
  if (!(profile in PROFILES)) throw new Error(`unknown profile "${profile}"`);
  const seed = Number(arg("seed", String(DEFAULT_SEED)));
  const repeat = Number(arg("repeat", "10"));
  const live = process.argv.includes("--live");
  const onlyArg = arg("only");
  const only = onlyArg
    ? onlyArg.split(",").map((s) => s.trim().toUpperCase())
    : undefined;
  const rawOut = arg("raw-out");

  if (live && profile === "full") {
    throw new Error("refusing to run the full profile live");
  }
  if (repeat > 10 && live) {
    throw new Error("refusing more than 10 live runs per case without review");
  }

  const dir = await mkdtemp(join(tmpdir(), "query-determinism-"));
  const sink = new FsFixtureSink(dir);
  await sink.init();
  const { manifest, source } = await generateInto(sink, { profile, seed });

  const cases: QueryEvalCase[] = await buildCases(source);
  const selected = cases.filter(
    (c) =>
      (only ? only.includes(c.id) : c.class === "aggregation") &&
      !c.requiresJudge,
  );
  if (!selected.length) throw new Error("no cases selected");

  process.stdout.write(
    `determinism — ${selected.map((c) => c.id).join(", ")} ` +
      `x ${repeat} runs, ${live ? "LIVE" : "offline scripted"}, seed ${seed}\n`,
  );

  const provider = live ? buildLiveProvider() : undefined;
  const started = Date.now();
  const sections: string[] = [];
  const raw: unknown[] = [];

  for (const testCase of selected) {
    const obs: RunObservation[] = [];
    for (let i = 0; i < repeat; i++) {
      // A FRESH answerer per run, deliberately. The sandbox tool host
      // accumulates coverage across every run in a request and never resets,
      // so reusing one would make coverage look monotonically increasing
      // instead of variable — the opposite of what is being measured.
      const answerer = await buildAgentAnswerer(dir, manifest, provider);
      const t0 = Date.now();
      try {
        const a = await answerer.answer({
          question: testCase.question,
          grantedScopes: testCase.scopes,
        });
        const stopped = a.coverage.stoppedBecause;
        obs.push({
          run: i,
          ...(a.value !== undefined ? { value: a.value } : {}),
          ...(a.script !== undefined ? { script: a.script } : {}),
          recordsScanned: a.coverage.recordsScanned,
          scopesScanned: a.coverage.scopesScanned,
          complete: a.coverage.complete,
          ...(stopped ? { stoppedBecause: stopped } : {}),
          inputTokens: a.cost.inputTokens,
          outputTokens: a.cost.outputTokens,
          durationMs: Date.now() - t0,
          // A contract violation or a budget kill is a failure, not a
          // disagreement, so it is excluded from the variance numbers.
          ...(stopped === "contractViolation" || stopped === "budget"
            ? { crash: `stoppedBecause=${stopped}` }
            : {}),
        });
      } catch (err) {
        obs.push({
          run: i,
          recordsScanned: 0,
          scopesScanned: [],
          complete: false,
          inputTokens: 0,
          outputTokens: 0,
          durationMs: Date.now() - t0,
          crash: err instanceof Error ? err.message.slice(0, 90) : "threw",
        });
      }
      const last = obs.at(-1)!;
      process.stderr.write(
        `  ${testCase.id} ${i + 1}/${repeat}  value=${last.value ?? "-"}` +
          `  records=${last.recordsScanned}  ${last.crash ?? ""}\n`,
      );
    }
    const expected =
      testCase.expect.kind === "numeric"
        ? { value: testCase.expect.value, tolerance: testCase.expect.tolerance }
        : undefined;
    sections.push(report(testCase.id, expected, obs));
    raw.push({ case: testCase.id, expected, runs: obs });
  }

  process.stdout.write(sections.join("\n") + "\n");
  process.stdout.write(
    `\n  total wall clock ${((Date.now() - started) / 1000).toFixed(1)}s\n`,
  );
  if (rawOut) {
    await writeFile(rawOut, JSON.stringify(raw, null, 2));
    process.stdout.write(`  raw observations -> ${rawOut}\n`);
  }
  await rm(dir, { recursive: true, force: true });
}

main().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});
