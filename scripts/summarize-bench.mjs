// Summarize a query-benchmark JSON dump.
//
// Handles both shapes: the pre-`--repeat` dumps (one row per question) and the
// aggregated N-run dumps (rows carry a `run` index). Prints pass-count-out-of-N
// per question, because a single verdict is exactly what the N=3 standard
// exists to stop reporting.
//
//   node scripts/summarize-bench.mjs <path.json> [--rows]
import { readFileSync } from "node:fs";

const path = process.argv[2];
if (!path) {
  console.error("usage: summarize-bench.mjs <path.json> [--rows]");
  process.exit(1);
}
const d = JSON.parse(readFileSync(path, "utf8"));
const rows = d.rows ?? [];
const repeat = d.repeat ?? 1;

const median = (xs) => {
  if (!xs.length) return 0;
  const v = [...xs].sort((a, b) => a - b);
  const m = v.length >> 1;
  return v.length % 2 ? v[m] : Math.round((v[m - 1] + v[m]) / 2);
};

console.log(
  `profile=${d.profile} model=${d.model ?? "-"} repeat=${repeat} judged=${d.judged}`,
);
console.log(`totals: ${JSON.stringify(d.totals)}`);
console.log(`wall: ${((d.wallClockMs ?? 0) / 1000).toFixed(1)}s\n`);

const ids = [...new Set(rows.map((r) => r.id))];
const agg = ids.map((id) => {
  const rs = rows.filter((r) => r.id === id);
  const skips = rs.filter((r) => r.outcome === "skip").length;
  const graded = rs.length - skips;
  const passes = rs.filter((r) => r.outcome === "pass").length;
  return {
    id,
    klass: rs[0].klass,
    kind: rs[0].kind,
    passes,
    graded,
    skips,
    flaky: passes > 0 && passes < graded,
    ms: median(rs.map((r) => r.ms)),
    inTok: median(rs.map((r) => r.inTok)),
    outTok: median(rs.map((r) => r.outTok)),
    calls: median(rs.map((r) => r.toolCalls)),
    records: median(rs.map((r) => r.records)),
    anyComplete: rs.some((r) => r.complete),
    values: [...new Set(rs.map((r) => r.value).filter((v) => v != null))],
    modes: [
      ...new Set(
        rs
          .filter((r) => r.outcome === "fail")
          .map((r) => r.stoppedBecause ?? r.reasons?.[0] ?? "wrong-answer")
          .map((m) => String(m).slice(0, 46)),
      ),
    ],
  };
});

const hdr =
  "id".padEnd(5) +
  "class".padEnd(14) +
  "kind".padEnd(9) +
  "pass".padEnd(7) +
  "ms".padStart(7) +
  "in".padStart(8) +
  "out".padStart(6) +
  "calls".padStart(6) +
  "records".padStart(9) +
  "cmpl".padStart(5) +
  "  failure mode";
console.log(hdr);
for (const a of agg) {
  const score = a.graded === 0 ? `-/${a.skips}sk` : `${a.passes}/${a.graded}`;
  console.log(
    a.id.padEnd(5) +
      a.klass.padEnd(14) +
      a.kind.padEnd(9) +
      score.padEnd(7) +
      String(a.ms).padStart(7) +
      String(a.inTok).padStart(8) +
      String(a.outTok).padStart(6) +
      String(a.calls).padStart(6) +
      String(a.records).padStart(9) +
      (a.anyComplete ? "yes" : "no").padStart(5) +
      "  " +
      a.modes.join("; ") +
      (a.flaky ? "   << FLAKY" : ""),
  );
}

const flaky = agg.filter((a) => a.flaky);
const solid = agg.filter((a) => a.graded > 0 && a.passes === a.graded);
const zero = agg.filter((a) => a.graded > 0 && a.passes === 0);
console.log(
  `\nalways-pass ${solid.length}: ${solid.map((a) => a.id).join(", ") || "none"}`,
);
console.log(
  `FLAKY       ${flaky.length}: ${flaky.map((a) => `${a.id} ${a.passes}/${a.graded}`).join(", ") || "none"}`,
);
console.log(
  `never-pass  ${zero.length}: ${zero.map((a) => a.id).join(", ") || "none"}`,
);
console.log(
  `coverage.complete ever true: ${agg.some((a) => a.anyComplete) ? "YES" : "NO"}`,
);

if (process.argv.includes("--rows")) {
  console.log("\nper-run detail:");
  for (const r of rows) {
    console.log(
      `  ${r.id} run${r.run ?? 0} ${r.outcome} value=${r.value ?? "-"} ` +
        `stopped=${r.stoppedBecause ?? "-"} unreadable=${r.unreadable ?? "-"} ` +
        `${(r.reasons ?? []).join(" | ")}`,
    );
  }
}
