/**
 * Regrade collected runs under both rules, side by side.
 *
 * Strict: the number must equal the one reading the eval encodes.
 * Resolution-aware: a defensible declared reading plus a number consistent
 * with *that* reading is a pass (design §19.9, and the rule the user chose).
 *
 * Reads the raw dumps written by `query-benchmark.ts` and
 * `query-set-resolution.ts`. Runs collected before the `resolution` field
 * existed have their declared reading inferred from the answer prose; those
 * are counted separately and labelled, because inferring a declaration is not
 * the same as being given one.
 *
 *   npx tsx scripts/query-regrade.ts <dump.json> [more.json ...]
 */
import { readFile } from "node:fs/promises";

import {
  AMBIGUOUS_READINGS,
  gradeAgainstReadings,
  type DefensibleReading,
  type ResolutionOutcome,
} from "@opendatalabs/personal-server-ts-core/query/evals";

interface Run {
  id: string;
  run?: number;
  outcome?: string;
  value?: number;
  expected?: number;
  resolution?: string;
  /** Present in benchmark dumps; used to infer a declaration when absent. */
  answerHead?: string;
  reasons?: string[];
  klass?: string;
  kind?: string;
  ms?: number;
  inTok?: number;
  inputTokens?: number;
}

interface Graded extends Run {
  strictPass: boolean;
  resolutionOutcome: ResolutionOutcome | null;
  resolutionPass: boolean;
  /** True when the declaration came from prose, not a `resolution` field. */
  inferred: boolean;
  source: string;
}

/** Flatten the several dump shapes this session produced. */
function extractRuns(doc: unknown, source: string): Run[] {
  const out: Run[] = [];
  if (doc && typeof doc === "object") {
    const d = doc as Record<string, unknown>;
    if (Array.isArray(d.rows)) out.push(...(d.rows as Run[]));
    if (d.results && typeof d.results === "object") {
      for (const [id, runs] of Object.entries(
        d.results as Record<string, Run[]>,
      )) {
        for (const r of runs) out.push({ ...r, id });
      }
    }
  }
  return out.map((r) => ({ ...r, __source: source }) as Run);
}

function gradeOne(run: Run, source: string): Graded {
  const readings = AMBIGUOUS_READINGS[run.id] as
    readonly DefensibleReading[] | undefined;
  const strictPass = run.outcome === "pass";

  if (!readings) {
    // Not an ambiguous question: the resolution rule reduces to the strict one.
    return {
      ...run,
      strictPass,
      resolutionOutcome: null,
      resolutionPass: strictPass,
      inferred: false,
      source,
    };
  }

  const declared = run.resolution;
  if (!declared) {
    /*
     * No `resolution` field: this run predates it, and it is NOT gradeable
     * under the resolution rule.
     *
     * Inferring the declaration from the answer prose was tried and abandoned.
     * It misclassified 2 of 9 ambiguous runs in the N=3 dump — Q1 runs that
     * computed a trailing window but mentioned December in passing were read
     * as calendar-month runs, turning two strict passes into false failures.
     * A guessed declaration is not a declaration, and grading against one
     * would manufacture exactly the kind of result this exercise exists to
     * avoid.
     */
    return {
      ...run,
      strictPass,
      resolutionOutcome: null,
      resolutionPass: strictPass,
      inferred: true,
      source,
    };
  }
  const inferred = false;
  const outcome = gradeAgainstReadings(readings, declared, run.value);

  // A run that fails the strict check for reasons *other* than the number —
  // a missing denominator, no citations — still fails. The resolution rule
  // only forgives the choice of set.
  const nonNumericFailure = (run.reasons ?? []).some(
    (r) => !/^expected .* got /.test(r),
  );

  return {
    ...run,
    strictPass,
    resolutionOutcome: outcome,
    resolutionPass: outcome.kind === "pass" && !nonNumericFailure,
    inferred,
    source,
  };
}

function pct(n: number, d: number): string {
  return d === 0 ? "—" : `${((100 * n) / d).toFixed(0)}%`;
}

async function main(): Promise<void> {
  const files = process.argv.slice(2);
  if (files.length === 0) {
    throw new Error("usage: query-regrade.ts <dump.json> [more.json ...]");
  }

  const graded: Graded[] = [];
  for (const f of files) {
    const doc: unknown = JSON.parse(await readFile(f, "utf8"));
    const name = f.split("/").pop() ?? f;
    for (const run of extractRuns(doc, name)) graded.push(gradeOne(run, name));
  }

  const ids = [...new Set(graded.map((g) => g.id))].sort(
    (a, b) => Number(a.slice(1)) - Number(b.slice(1)),
  );

  console.log("\nPer question — strict vs resolution-aware\n");
  console.log("  id    n   strict  res-aware  delta  note");
  let strictTotal = 0;
  let resTotal = 0;
  let n = 0;
  for (const id of ids) {
    const rows = graded.filter((g) => g.id === id);
    const s = rows.filter((g) => g.strictPass).length;
    const r = rows.filter((g) => g.resolutionPass).length;
    strictTotal += s;
    resTotal += r;
    n += rows.length;
    const ambiguous = Boolean(AMBIGUOUS_READINGS[id]);
    const delta = r - s;
    const note = ambiguous
      ? rows.every((g) => g.inferred)
        ? "ambiguous — NO resolution declared, not gradeable by the new rule"
        : "ambiguous"
      : "single reading — rule reduces to strict";
    console.log(
      `  ${id.padEnd(4)} ${String(rows.length).padStart(3)}   ${String(s).padStart(3)}/${rows.length}   ${String(r).padStart(4)}/${rows.length}   ${delta >= 0 ? "+" : ""}${delta}     ${note}`,
    );
  }
  console.log(
    `\n  TOTAL ${n}   ${strictTotal}/${n} (${pct(strictTotal, n)})   ${resTotal}/${n} (${pct(resTotal, n)})   +${resTotal - strictTotal}`,
  );

  // The anti-cheat evidence: how runs fail under the generous rule.
  const ambiguousRuns = graded.filter((g) => g.resolutionOutcome);
  const by = (k: string) =>
    ambiguousRuns.filter((g) => g.resolutionOutcome?.kind === k).length;
  console.log("\nHow ambiguous-question runs fare under the generous rule\n");
  console.log(`  total ambiguous runs        ${ambiguousRuns.length}`);
  console.log(`  pass                        ${by("pass")}`);
  console.log(`  FAIL undeclared             ${by("undeclared")}`);
  console.log(`  FAIL unrecognised reading   ${by("unrecognised")}`);
  console.log(`  FAIL number ≠ declared set  ${by("inconsistent")}`);
  const alsoNonNumeric = ambiguousRuns.filter(
    (g) => g.resolutionOutcome?.kind === "pass" && !g.resolutionPass,
  ).length;
  console.log(
    `  (consistent but failed on citations/denominator: ${alsoNonNumeric})`,
  );

  /*
   * The known soft spot in this rule, reported rather than smoothed over.
   *
   * The prompt asks the model to name the alternative reading when a phrase is
   * ambiguous. Some runs go further and report *both* readings with both
   * numbers — the most useful thing it could do — and then keyword matching
   * cannot say which was primary. Those land in "number ≠ declared set" even
   * though the returned figure is exactly one of the readings they named.
   *
   * Crediting them would weaken the anti-cheat (a run naming every reading
   * could return any of them), so the headline rule stays conservative and the
   * count is surfaced here instead. It is an upper bound on how much the
   * headline under-reports.
   */
  const namedBoth = ambiguousRuns.filter((g) => {
    if (g.resolutionOutcome?.kind !== "inconsistent") return false;
    const readings = AMBIGUOUS_READINGS[g.id];
    const text = (g.resolution ?? "").toLowerCase();
    return readings.some(
      (r) =>
        typeof g.value === "number" &&
        Math.abs(g.value - r.value) <= r.tolerance &&
        // the value's reading is also mentioned somewhere in the declaration
        (r.signals.all ?? []).every((re) => re.test(text)),
    );
  });
  console.log(
    `  of which: named several readings and returned one of them  ${namedBoth.length}`,
  );
  for (const g of namedBoth) {
    console.log(`      ${g.id} run${g.run ?? "?"} returned ${g.value}`);
  }

  console.log("\nWhich reading each run chose\n");
  for (const id of ids.filter((i) => AMBIGUOUS_READINGS[i])) {
    for (const g of graded.filter((x) => x.id === id && x.resolutionOutcome)) {
      const o = g.resolutionOutcome!;
      const chosen =
        o.kind === "pass"
          ? o.reading.label
          : o.kind === "inconsistent"
            ? `${o.reading.label} (but returned ${o.value}, reading yields ${o.expected})`
            : o.kind;
      console.log(
        `  ${id} run${g.run ?? "?"} ${g.inferred ? "[inferred]" : "[declared]"} ${g.strictPass ? "S" : "·"}${g.resolutionPass ? "R" : "·"}  ${chosen}  <${g.source}>`,
      );
    }
  }
  console.log();
}

main().catch((e: unknown) => {
  console.error(e);
  process.exitCode = 1;
});
