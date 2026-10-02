import { readFileSync, writeFileSync } from "node:fs";
import { projectPdppRecordsToLegacyPayload } from "../src/index.js";
import { diffBodies } from "../src/__fixtures__/parity/diff.js";
const dir = new URL("../src/__fixtures__/parity/", import.meta.url).pathname;
const rules: [RegExp, (d: any, all: any[]) => boolean, string][] = [
  [/\.create_time$/, (d) => typeof d.legacy === "number", "time format: legacy emits the detail body's epoch seconds, the PDPP stream stores ISO 8601; same instant"],
  [/\.update_time$/, (d) => typeof d.legacy === "string", "time format: legacy copies the provider string verbatim (microseconds, +00:00), the PDPP stream stores toISOString(); same instant"],
  [/\.message_count$/, (d) => typeof d.legacy === "number" && typeof d.projected === "number" && d.projected < d.legacy, "branch walk: legacy keeps walking past current_node into its last child; the projection stops at current_node"],
  [/\.messages\[id=[^\]]+\]$/, (d, all) => d.projected === "<absent>" && all.some((o) => o.path === d.path.replace(/\.messages\[id=[^\]]+\]$/, ".message_count")), "branch walk: legacy keeps walking past current_node into its last child; the projection stops at current_node"],
  [/\.content$/, (d) => typeof d.projected === "string" && d.projected.startsWith("[asset:"), "content: the PDPP connector renders image parts as [asset:<pointer>] lines; legacy joins only string parts"],
  [/\.fetchError$/, (d) => d.legacy === null && d.projected === "<absent>", "legacy-only constant: claude-export always writes fetchError: null; the binding omits it"],
  [/\.detail\.archived_at$/, (d) => d.projected === null, "projection-only key: the PDPP projects stream always carries archived_at (null when not archived)"],
  [/\.detail\.docs\[.*\]\.updated_at$/, (d) => d.projected === null, "projection-only key: the adapter always writes docs[].updated_at; raw export docs have none"],
  [/\.detail\.docs\[\d+\]$/, (d) => d.projected === "<absent>" && typeof d.legacy === "object" && d.legacy !== null && !("uuid" in d.legacy), "a raw doc without a uuid is not a project_documents record; it survives only in detail.raw_docs"],
  [/\.detail\.raw_docs$/, (d) => d.legacy === "<absent>" && Array.isArray(d.projected), "projection-only key: the adapter adds raw_docs from the PDPP projects stream"],
  [/\.detail\.(description|prompt_template)$/, (d) => d.legacy === "" && d.projected === null, "the PDPP connector maps an empty description/prompt_template to null; legacy keeps the raw \"\""],
];
for (const scope of ["chatgpt.conversations","chatgpt.memories","claude.conversations","claude.projects"]) {
  const file = dir + scope + ".json";
  const g = JSON.parse(readFileSync(process.argv[2] ? `${process.argv[2]}/${scope}.json` : file, "utf8"));
  delete g.reviewedDifferences;
  const records = Object.entries(g.streams).flatMap(([stream, rows]: any) => rows.map((data: any) => ({ stream, data })));
  const r = projectPdppRecordsToLegacyPayload(scope, records, { fetchedStreams: g.fetchedStreams, now: "2026-10-01T00:00:00.000Z" });
  if (!r.ok) throw new Error(scope);
  const all = diffBodies(g.legacyBody, r.payload);
  const reviewed = all.map((d) => {
    const rule = rules.find(([re, ok]) => re.test(d.path) && ok(d, all));
    if (!rule) throw new Error(`unclassified ${scope} ${d.path}`);
    return { ...d, reason: rule[2] };
  });
  const { legacyBody, ...rest } = g;
  writeFileSync(file, JSON.stringify({ ...rest, legacyBody, reviewedDifferences: reviewed }, null, 2) + "\n");
  console.log(scope, reviewed.length);
}
