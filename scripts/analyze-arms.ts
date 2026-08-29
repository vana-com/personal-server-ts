/**
 * Side-by-side analysis of two benchmark dumps written by `query-benchmark.ts`.
 *
 *   npx tsx scripts/analyze-arms.ts --agent <dump.json> --stuffed <dump.json>
 *
 * Reads the dumps only. Every number here is grouped out of `rows`, never
 * re-graded: the grader already recorded `outcome`, `gradedBy` and
 * `strictPass` on each row, and re-deriving them here would produce a
 * reconstruction that reads exactly like a measurement while being nothing of
 * the kind.
 */

import { readFile } from "node:fs/promises";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  DEFAULT_SEED,
  buildCases,
  generateInto,
} from "@opendatalabs/personal-server-ts-core/query/evals";

import { FsFixtureSink } from "./query-eval-fs-sink.js";

interface Row {
  id: string;
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
  complete: boolean;
  value?: number;
  expected?: number;
  resolution?: string;
  gradedBy?: string;
  strictPass?: boolean;
  reasons: string[];
  answerHead: string;
}

interface Dump {
  profile: string;
  seed: number;
  model: string | null;
  repeat: number;
  arm?: string;
  answerer?: string;
  corpusBudgetChars?: number;
  totals: Record<string, number>;
  rows: Row[];
}

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i === -1 ? undefined : process.argv[i + 1];
}

interface Agg {
  passes: number;
  graded: number;
  skips: number;
  inTok: number;
  outTok: number;
  ms: number;
  records: number;
  anyComplete: boolean;
  strictPasses: number;
  reasons: string[];
  values: (number | undefined)[];
  resolutions: string[];
  answers: string[];
}

function aggregate(rows: Row[]): Map<string, Agg> {
  const out = new Map<string, Agg>();
  for (const r of rows) {
    let a = out.get(r.id);
    if (!a) {
      a = {
        passes: 0,
        graded: 0,
        skips: 0,
        inTok: 0,
        outTok: 0,
        ms: 0,
        records: 0,
        anyComplete: false,
        strictPasses: 0,
        reasons: [],
        values: [],
        resolutions: [],
        answers: [],
      };
      out.set(r.id, a);
    }
    if (r.outcome === "skipped") a.skips += 1;
    else a.graded += 1;
    if (r.outcome === "pass") a.passes += 1;
    if (r.strictPass === true) a.strictPasses += 1;
    a.inTok += r.inTok;
    a.outTok += r.outTok;
    a.ms += r.ms;
    a.records = Math.max(a.records, r.records);
    a.anyComplete ||= r.complete;
    if (r.outcome === "fail" && r.reasons[0]) a.reasons.push(r.reasons[0]);
    a.values.push(r.value);
    if (r.resolution) a.resolutions.push(r.resolution);
    a.answers.push(r.answerHead);
  }
  return out;
}

async function load(path: string | undefined): Promise<Dump | undefined> {
  if (!path) return undefined;
  return JSON.parse(await readFile(path, "utf8")) as Dump;
}

const score = (a: Agg | undefined): string =>
  a === undefined
    ? "  -  "
    : a.graded === 0
      ? `-/${a.skips}sk`
      : `${a.passes}/${a.graded}`;

async function main(): Promise<void> {
  const agent = await load(arg("agent"));
  const stuffed = await load(arg("stuffed"));
  if (!stuffed) throw new Error("--stuffed <dump.json> is required");

  /* Granted-corpus size per question, so the truncation fraction is real. */
  const dir = await mkdtemp(join(tmpdir(), "arms-"));
  const sink = new FsFixtureSink(dir);
  await sink.init();
  const { manifest, source } = await generateInto(sink, {
    profile: "dogfood",
    seed: DEFAULT_SEED,
  });
  const cases = await buildCases(source);
  const recordsByScope = new Map(
    manifest.scopes.map((s) => [s.scope, s.records]),
  );
  const bytesByScope = new Map<string, number>();
  for (const s of manifest.scopes) {
    let bytes = 0;
    for (const f of s.files) bytes += await sink.size(f);
    bytesByScope.set(s.scope, bytes);
  }
  const grantOf = new Map(
    cases.map((c) => [
      c.id,
      {
        scopes: c.scopes,
        records: c.scopes.reduce((n, s) => n + (recordsByScope.get(s) ?? 0), 0),
        bytes: c.scopes.reduce((n, s) => n + (bytesByScope.get(s) ?? 0), 0),
        klass: c.class,
        kind: c.expect.kind,
      },
    ]),
  );

  const aStuffed = aggregate(stuffed.rows);
  const aAgent = agent ? aggregate(agent.rows) : undefined;
  const ids = [
    ...new Set([...aStuffed.keys(), ...(aAgent?.keys() ?? [])]),
  ].sort((x, y) => Number(x.slice(1)) - Number(y.slice(1)));

  console.log(
    `\nstuffed: ${stuffed.rows.length} rows  model=${stuffed.model} profile=${stuffed.profile} seed=${stuffed.seed} budget=${stuffed.corpusBudgetChars ?? "?"} chars`,
  );
  if (agent) {
    console.log(
      `agent:   ${agent.rows.length} rows  model=${agent.model} profile=${agent.profile} seed=${agent.seed}`,
    );
  }

  console.log(
    `\n${"id".padEnd(4)} ${"class".padEnd(13)} ${"kind".padEnd(8)} ${"agent".padEnd(6)} ${"stuff".padEnd(6)} ` +
      `${"corpus seen".padStart(12)} ${"in/run".padStart(9)} ${"agent in".padStart(9)}  verdict`,
  );
  for (const id of ids) {
    const s = aStuffed.get(id);
    const g = grantOf.get(id);
    const seen =
      g && g.records > 0 && s
        ? `${((s.records / g.records) * 100).toFixed(0)}% (${s.records}/${g.records})`
        : "n/a";
    const sp = s?.passes ?? 0;
    const ap = aAgent?.get(id)?.passes ?? 0;
    const verdict = !aAgent
      ? ""
      : sp > ap
        ? "BASELINE WINS"
        : ap > sp
          ? "agent wins"
          : sp === 0
            ? "both fail"
            : "both pass";
    console.log(
      `${id.padEnd(4)} ${(g?.klass ?? "").padEnd(13)} ${(g?.kind ?? "").padEnd(8)} ` +
        `${score(aAgent?.get(id)).padEnd(6)} ${score(s).padEnd(6)} ${seen.padStart(12)} ` +
        `${String(Math.round((s?.inTok ?? 0) / Math.max(1, s?.graded ?? 1))).padStart(9)} ` +
        `${String(Math.round((aAgent?.get(id)?.inTok ?? 0) / Math.max(1, aAgent?.get(id)?.graded ?? 1))).padStart(9)}  ${verdict}`,
    );
  }

  const sum = (m: Map<string, Agg>, k: keyof Agg) =>
    [...m.values()].reduce((n, a) => n + (a[k] as number), 0);

  const report = (label: string, m: Map<string, Agg>) => {
    const passes = sum(m, "passes");
    const inTok = sum(m, "inTok");
    const outTok = sum(m, "outTok");
    const qs = [...m.values()].filter((a) => a.passes > 0).length;
    const solid = [...m.values()].filter(
      (a) => a.graded > 0 && a.passes === a.graded,
    ).length;
    const flaky = [...m.values()].filter(
      (a) => a.passes > 0 && a.passes < a.graded,
    ).length;
    console.log(
      `\n${label}\n` +
        `  rows passing:      ${passes} / ${sum(m, "graded")} graded (${sum(m, "skips")} skipped)\n` +
        `  questions >=1 pass: ${qs} of ${m.size}   always-pass: ${solid}   flaky: ${flaky}\n` +
        `  strict scoreboard: ${sum(m, "strictPasses")}\n` +
        `  tokens:            ${inTok.toLocaleString("en-US")} in / ${outTok.toLocaleString("en-US")} out\n` +
        `  input tokens per passing row: ${passes === 0 ? "n/a (no passes)" : Math.round(inTok / passes).toLocaleString("en-US")}\n` +
        `  wall clock:        ${(sum(m, "ms") / 1000).toFixed(0)}s`,
    );
  };

  if (aAgent) report("AGENT ARM", aAgent);
  report("STUFFED BASELINE", aStuffed);

  /*
   * Honesty: did a run over a truncated slice SAY so?
   *
   * Measured off the grader's own verdict, not off a fresh regex here. `runEval`
   * already tests the WHOLE answer text for an incompleteness marker on every
   * `mustReportCoverage` case and records
   * "coverage.complete is false but the answer text does not say so" when it is
   * absent. Re-testing `answerHead` would be a different, weaker measurement —
   * it is only the first 400 characters — and it would read identically in a
   * report. So the reason string is the measurement.
   */
  const SILENT = "coverage.complete is false but the answer text does not say";
  const honesty = (label: string, dump: Dump) => {
    let truncated = 0;
    let silent = 0;
    for (const r of dump.rows) {
      if (r.complete) continue;
      truncated += 1;
      if (r.reasons.some((x) => x.includes(SILENT))) silent += 1;
    }
    console.log(
      `  ${label}: ${truncated} of ${dump.rows.length} rows had incomplete coverage; ` +
        `${truncated - silent} said so in the answer text, ` +
        `${silent} did NOT (${truncated === 0 ? "n/a" : ((silent / truncated) * 100).toFixed(0) + "%"} silently confident).`,
    );
  };
  console.log(`\nHONESTY — did an incomplete run admit it? (grader's verdict)`);
  if (agent) honesty("agent  ", agent);
  honesty("stuffed", stuffed);

  await rm(dir, { recursive: true, force: true });
}

main().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});
