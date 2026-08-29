// Answer the specific confirm-or-refute questions from a benchmark dump.
// Reports raw counts, not verdicts — every number here is checkable against
// the JSON it came from.
import { readFileSync } from "node:fs";

const d = JSON.parse(readFileSync(process.argv[2], "utf8"));
const rows = d.rows ?? [];
const n = rows.length;

const count = (p) => rows.filter(p).length;
const pct = (k) => `${k}/${n} (${((k / n) * 100).toFixed(1)}%)`;

console.log(`runs: ${n}  (repeat=${d.repeat ?? 1})\n`);

console.log("--- failure modes across all runs ---");
const modes = {};
for (const r of rows) {
  const k = r.stoppedBecause ?? "(none)";
  modes[k] = (modes[k] ?? 0) + 1;
}
for (const [k, v] of Object.entries(modes).sort((a, b) => b[1] - a[1])) {
  console.log(`  ${k.padEnd(18)} ${pct(v)}`);
}

console.log("\n--- known open issues ---");
console.log(
  `  null-content crashes : ${pct(count((r) => (r.reasons ?? []).some((x) => /no assistant content/.test(x))))}`,
);
console.log(
  `  budget kills         : ${pct(count((r) => r.stoppedBecause === "budget"))}`,
);
console.log(
  `  policyDenied         : ${pct(count((r) => r.stoppedBecause === "policyDenied"))}`,
);
console.log(
  `  coverage.complete    : ${pct(count((r) => r.complete))} ever true`,
);
console.log(
  `  unreadable populated : ${pct(count((r) => (r.unreadable ?? 0) > 0))} (only when documents.files is read)`,
);

console.log("\n--- cost distribution (per run) ---");
const inToks = rows
  .map((r) => r.inTok)
  .filter((x) => x > 0)
  .sort((a, b) => a - b);
const byQ = {};
for (const r of rows) (byQ[r.id] ??= []).push(r.inTok);
const medians = Object.entries(byQ).map(([id, xs]) => {
  const v = [...xs].sort((a, b) => a - b);
  return [id, v[v.length >> 1]];
});
medians.sort((a, b) => b[1] - a[1]);
console.log(`  cheapest run : ${inToks[0]}`);
console.log(`  dearest run  : ${inToks[inToks.length - 1]}`);
console.log(
  `  ratio        : ${(inToks[inToks.length - 1] / inToks[0]).toFixed(1)}x`,
);
console.log("  top 5 by median input tokens:");
for (const [id, m] of medians.slice(0, 5))
  console.log(`    ${id.padEnd(4)} ${m}`);
console.log("  bottom 5:");
for (const [id, m] of medians.slice(-5))
  console.log(`    ${id.padEnd(4)} ${m}`);

// §18.3 predicted semantic questions dominate because of per-item classify.
const CLASSES = {};
for (const r of rows) (CLASSES[r.klass] ??= []).push(r.inTok);
console.log("\n  median input tokens by class:");
for (const [k, xs] of Object.entries(CLASSES)) {
  const v = [...xs].sort((a, b) => a - b);
  console.log(`    ${k.padEnd(14)} ${v[v.length >> 1]}`);
}

console.log("\n--- scanning ---");
const bytes = rows.map((r) => r.bytes).sort((a, b) => a - b);
console.log(
  `  max bytes scanned in one run: ${(bytes[bytes.length - 1] / 1e6).toFixed(1)}MB`,
);
console.log(
  `  median records: ${rows.map((r) => r.records).sort((a, b) => a - b)[n >> 1]}`,
);

console.log("\n--- distinct values per numeric question ---");
for (const id of [...new Set(rows.map((r) => r.id))]) {
  const rs = rows.filter((r) => r.id === id && r.value != null);
  if (!rs.length) continue;
  const vals = rs.map((r) => r.value);
  const exp = rs[0].expected;
  console.log(
    `  ${id.padEnd(4)} expected ${exp ?? "-"}  got [${vals.join(", ")}]  distinct=${new Set(vals).size}`,
  );
}
