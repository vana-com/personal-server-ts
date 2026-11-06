/**
 * Print a replay report for a corpus file:
 *   npx tsx conformance/report.ts [corpus.ndjson[.gz]]
 */
import { readCorpus, replayCorpus } from "./replay.js";

const { meta, stats, divergences } = await replayCorpus(
  readCorpus(process.argv[2]),
);
console.log(JSON.stringify({ model: meta.model, stats }, null, 2));
const groups = new Map<string, typeof divergences>();
for (const d of divergences) {
  const key = `${d.check}: model ${d.model} / package ${d.package}`;
  groups.set(key, [...(groups.get(key) ?? []), d]);
}
for (const [key, list] of groups) {
  console.log(`\n${list.length}x ${key}`);
  for (const d of list.slice(0, 3))
    console.log(`  ${d.trace} step ${d.step} ${d.action} ${d.detail ?? ""}`);
}
console.log(`\n${divergences.length} divergences`);
