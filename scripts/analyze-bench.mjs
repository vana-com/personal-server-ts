import { readFileSync } from "node:fs";

const d = JSON.parse(readFileSync(process.argv[2], "utf8"));
const rows = d.rows;
const totIn = rows.reduce((a, r) => a + r.inTok, 0);
const totOut = rows.reduce((a, r) => a + r.outTok, 0);
console.log(
  `TOTAL in=${totIn} out=${totOut} wall=${(d.wallClockMs / 1000).toFixed(1)}s`,
);

console.log("\n--- cost distribution (input tokens, desc) ---");
for (const r of [...rows].sort((a, b) => b.inTok - a.inTok)) {
  const pct = totIn ? (100 * r.inTok) / totIn : 0;
  console.log(
    `${r.id.padEnd(4)} ${r.klass.padEnd(13)} ${String(r.inTok).padStart(7)} (${pct.toFixed(1).padStart(4)}%) calls=${String(r.toolCalls).padStart(2)} ${String(r.ms).padStart(6)}ms  ${r.stoppedBecause ?? "-"}`,
  );
}

console.log("\n--- by class ---");
const byc = new Map();
for (const r of rows) {
  const c = byc.get(r.klass) ?? { n: 0, pass: 0, inTok: 0, ms: 0 };
  c.n++;
  if (r.outcome === "pass") c.pass++;
  c.inTok += r.inTok;
  c.ms += r.ms;
  byc.set(r.klass, c);
}
for (const [k, v] of [...byc.entries()].sort()) {
  console.log(
    `${k.padEnd(14)} n=${v.n} pass=${v.pass} avg_in=${String(Math.round(v.inTok / v.n)).padStart(6)} avg_ms=${String(Math.round(v.ms / v.n)).padStart(6)}`,
  );
}

const ids = (f) => rows.filter(f).map((r) => r.id);
console.log("\nbudget kills:", ids((r) => r.stoppedBecause === "budget"));
console.log(
  "null content:",
  ids((r) => r.reasons.some((x) => x.includes("no assistant content"))),
);
console.log("stopped=error:", ids((r) => r.stoppedBecause === "error"));
console.log("coverage complete:", ids((r) => r.complete));
console.log("passes:", ids((r) => r.outcome === "pass"));
