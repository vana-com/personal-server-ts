// Print the full record for one question-run, so a graded verdict can be
// checked against what the model actually said rather than against a summary.
import { readFileSync } from "node:fs";

const d = JSON.parse(readFileSync(process.argv[2], "utf8"));
const id = process.argv[3];
const run = Number(process.argv[4] ?? 0);
const r = (d.rows ?? []).find((x) => x.id === id && (x.run ?? 0) === run);
if (!r) {
  console.error(`no row for ${id} run${run}`);
  process.exit(1);
}
console.log(`${r.id} run${r.run ?? 0}  outcome=${r.outcome}`);
console.log(`value=${r.value ?? "(unset)"}  expected=${r.expected ?? "-"}`);
console.log(`stopped=${r.stoppedBecause ?? "-"}  complete=${r.complete}`);
console.log(
  `records=${r.records} bytes=${r.bytes} unreadable=${r.unreadable ?? "-"}`,
);
console.log(`calls=${r.toolCalls} in=${r.inTok} out=${r.outTok} ms=${r.ms}`);
console.log(`\nreasons:\n  ${(r.reasons ?? []).join("\n  ")}`);
console.log(`\nanswer head:\n  ${r.answerHead}`);
if (process.argv.includes("--script") && r.script) {
  console.log(`\nscript:\n${r.script}`);
}
