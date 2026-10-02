#!/usr/bin/env node
// Regenerates goldens/<scope>.json (and the adapter diff evidence) from
// inputs/ + the two frozen scripts per source. Deterministic: the clock is
// frozen at 2026-10-01T00:00:00.000Z in every child process.
//
// usage (from this directory):  node generate.mjs
// paths (env, defaults shown):
//   REF_DIR            required: a unity-surfaces checkout (goldens were made from origin/dev b227e8ce)
//   LEGACY_CHATGPT_JS  $REF_DIR/apps/mobile/public/connectors/chatgpt-4.0.0-vana.1.js
//   LEGACY_CLAUDE_JS   $REF_DIR/apps/desktop/connectors/anthropic/claude-export-playwright.js
//   PDPP_CHATGPT_JS    $REF_DIR/apps/mobile/public/connectors/chatgpt-0.2.20.js
//   PDPP_CLAUDE_JS     $REF_DIR/apps/mobile/public/connectors/claude-0.2.23.js
//   ADAPTER_DIR        ../src/legacy-projection (the adapter source)
//   INPUTS_DIR         ./inputs
// outputs: goldens/<scope>.json, captures/*.json (raw script I/O),
//          diffs/<scope>.json, diffs/DIFFS.md
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { classify } from "./lib/classify.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const REF = process.env.REF_DIR;
if (!REF) throw new Error("Set REF_DIR to a unity-surfaces checkout");
const paths = {
  LEGACY_CHATGPT_JS: process.env.LEGACY_CHATGPT_JS ?? join(REF, "apps/mobile/public/connectors/chatgpt-4.0.0-vana.1.js"),
  LEGACY_CLAUDE_JS: process.env.LEGACY_CLAUDE_JS ?? join(REF, "apps/desktop/connectors/anthropic/claude-export-playwright.js"),
  PDPP_CHATGPT_JS: process.env.PDPP_CHATGPT_JS ?? join(REF, "apps/mobile/public/connectors/chatgpt-0.2.20.js"),
  PDPP_CLAUDE_JS: process.env.PDPP_CLAUDE_JS ?? join(REF, "apps/mobile/public/connectors/claude-0.2.23.js"),
  INPUTS_DIR: resolve(process.env.INPUTS_DIR ?? join(here, "inputs")),
};
const ADAPTER_DIR = resolve(process.env.ADAPTER_DIR ?? join(here, "../src/legacy-projection"));
const MENU_NAME = "Syn";
const WINDOW_SINCE = "2026-09-01T00:00:00Z"; // frozen now (2026-10-01) minus 30 days
const sha = (p) => createHash("sha256").update(readFileSync(p)).digest("hex");
const tsx = join(here, "node_modules/.bin/tsx");
const OUT = join(here, "out");
for (const d of ["goldens", "captures", "diffs"]) mkdirSync(join(OUT, d), { recursive: true });

// 1. Run each script in its own process (isolated globals, frozen clock).
const run = (runner, which, variant = "", extraEnv = {}) => {
  const out = join(OUT, "captures", `${runner}-${which}${variant}.json`);
  const stdout = execFileSync("node", [join(here, "lib", `run-${runner}.mjs`), which, out], {
    env: { ...process.env, TIME_RANGE_SINCE: "", ...paths, ...extraEnv }, encoding: "utf8", timeout: 300_000,
  });
  process.stdout.write(stdout.split("\n").filter((l) => /^(legacy|bundle) /.test(l)).join("\n") + "\n");
  return JSON.parse(readFileSync(out, "utf8"));
};
const captures = {
  legacy: { chatgpt: run("legacy", "chatgpt"), claude: run("legacy", "claude") },
  bundle: { chatgpt: run("bundle", "chatgpt"), claude: run("bundle", "claude") },
  // Variant: what the phone actually requests today (connector-policy.json
  // scopeTimeWindows: chatgpt.* and claude.* 30 days). Not used for goldens.
  bundleWindow30: {
    chatgpt: run("bundle", "chatgpt", "-window30", { TIME_RANGE_SINCE: WINDOW_SINCE }),
    claude: run("bundle", "claude", "-window30", { TIME_RANGE_SINCE: WINDOW_SINCE }),
  },
  // Variant: account menu shows a display name that differs from users.json.
  menuMismatch: {
    legacy: run("legacy", "claude", "-menu-mismatch", { CLAUDE_MENU_NAME: MENU_NAME }),
    bundle: run("bundle", "claude", "-menu-mismatch", { CLAUDE_MENU_NAME: MENU_NAME }),
  },
};
for (const [kind, bySource] of Object.entries(captures))
  for (const [src, cap] of Object.entries(bySource)) {
    if (cap.unknownUpstreamRequests.length) throw new Error(`${kind} ${src}: unmodelled upstream requests ${cap.unknownUpstreamRequests}`);
    if (kind === "legacy" && !cap.result) throw new Error(`legacy ${src} delivered no result`);
    if (kind === "menuMismatch") continue;
    if (kind !== "legacy" && (cap.threw || !cap.streamDone || cap.data.error)) throw new Error(`bundle ${src} did not complete: ${cap.threw ?? cap.data.error}`);
  }

// 2. Stored form: per stream, the `records` array of the streamed scope,
// deduped by key (`record.key ?? data.id`; pageshim records carry no key/op,
// so data.id). Latest wins; position of first occurrence is kept.
const storedStreams = (cap, source) => {
  const out = {};
  const dedupe = {};
  for (const [scope, { value, complete }] of Object.entries(cap.streamedScopes)) {
    if (!complete) throw new Error(`${scope} stream not completed`);
    const stream = scope.slice(source.length + 1);
    const byKey = new Map();
    let unkeyed = 0;
    for (const rec of value.records) {
      const isEnvelope = rec && typeof rec === "object" && "data" in rec && "stream" in rec;
      const data = isEnvelope ? rec.data : rec;
      if (isEnvelope && rec.op === "delete") { byKey.delete(rec.key ?? data?.id); continue; }
      const key = (isEnvelope ? rec.key : undefined) ?? data?.id;
      if (key === undefined || key === null) { byKey.set(Symbol("unkeyed"), data); unkeyed++; continue; }
      byKey.set(key, data);
    }
    out[stream] = [...byKey.values()];
    dedupe[stream] = { emitted: value.records.length, stored: out[stream].length, unkeyed };
  }
  return { streams: out, dedupe };
};
const stored = {
  chatgpt: storedStreams(captures.bundle.chatgpt, "chatgpt"),
  claude: storedStreams(captures.bundle.claude, "claude"),
};
const storedWindow = {
  chatgpt: storedStreams(captures.bundleWindow30.chatgpt, "chatgpt"),
  claude: storedStreams(captures.bundleWindow30.claude, "claude"),
};

// 3. Goldens.
const SCOPES = ["chatgpt.conversations", "chatgpt.memories", "claude.conversations", "claude.projects"];
const bindings = JSON.parse(execFileSync(tsx, [join(here, "lib/project.ts"), ADAPTER_DIR, "--bindings", SCOPES.join(",")], { encoding: "utf8" }).trim().split("\n").at(-1));
const versions = { chatgpt: "4.0.0-vana.1", claude: "claude-export-playwright 2.0.1" };
const legacyPath = { chatgpt: paths.LEGACY_CHATGPT_JS, claude: paths.LEGACY_CLAUDE_JS };
const bundlePath = { chatgpt: paths.PDPP_CHATGPT_JS, claude: paths.PDPP_CLAUDE_JS };
const inputsDesc = {
  chatgpt: "inputs/chatgpt/{conversations,list-items,search-items,memories,session}.json (synthetic, authored by inputs/chatgpt/build-inputs.mjs); served by lib/chatgpt-upstream.mjs to both scripts",
  claude: "inputs/claude/{export-entries,organizations,site}.json (synthetic; real export key names from data-connectors connectors/anthropic/__fixtures__/split-export + fixtures/scrubbed/pilot-real-shape, packed as one old-format ZIP); served by lib/claude-upstream.mjs to both scripts",
};
const goldens = {};
for (const scope of SCOPES) {
  const source = scope.split(".")[0];
  const b = bindings[scope];
  const streams = Object.fromEntries(b.pdppStreams.map((s) => [s, stored[source].streams[s] ?? []]));
  goldens[scope] = {
    scope,
    provenance: {
      legacyConnector: `${basename(legacyPath[source])} ${versions[source]} sha256:${sha(legacyPath[source])}`,
      pdppBundle: `${basename(bundlePath[source])} sha256:${sha(bundlePath[source])}`,
      inputs: inputsDesc[source],
      generatedBy: "generate.mjs",
      clock: "frozen at 2026-10-01T00:00:00.000Z in both script runs (legacy now()-derived fields carry this value)",
      legacyRequestedScopes: captures.legacy[source].requestedScopes,
      pdppRequestedScopes: captures.bundle[source].requestedScopes,
      pdppStreamDedupe: Object.fromEntries(b.pdppStreams.map((s) => [s, stored[source].dedupe[s] ?? { emitted: 0, stored: 0, unkeyed: 0, note: "bundle emitted no scope for this stream" }])),
    },
    fetchedStreams: b.pdppStreams,
    streams,
    legacyBody: captures.legacy[source].result[scope],
  };
  writeFileSync(join(OUT, "goldens", `${scope}.json`), `${JSON.stringify(goldens[scope], null, 2)}\n`);
}

// 4. Project through the real adapter.
const projIn = join(OUT, "diffs", "_projection-input.json");
const projOut = join(OUT, "diffs", "_projection-output.json");
writeFileSync(projIn, JSON.stringify(Object.fromEntries(SCOPES.map((s) => [s, { fetchedStreams: goldens[s].fetchedStreams, streams: goldens[s].streams }]))));
execFileSync(tsx, [join(here, "lib/project.ts"), ADAPTER_DIR, projIn, projOut], { encoding: "utf8" });
const projected = JSON.parse(readFileSync(projOut, "utf8"));
// Same rows, adapter clock moved +1 day: paths that change are now()-derived.
// They match legacy above only because both runs share one frozen instant.
const projOutLater = join(OUT, "diffs", "_projection-output-clock+1d.json");
execFileSync(tsx, [join(here, "lib/project.ts"), ADAPTER_DIR, projIn, projOutLater], { encoding: "utf8", env: { ...process.env, PROJECTION_NOW: "2026-10-02T00:00:00.000Z" } });
const projectedLater = JSON.parse(readFileSync(projOutLater, "utf8"));
// Window variant rows (what the phone stores under the 30-day policy).
const windowIn = join(OUT, "diffs", "_projection-input-window30.json");
const windowOut = join(OUT, "diffs", "_projection-output-window30.json");
writeFileSync(windowIn, JSON.stringify(Object.fromEntries(SCOPES.map((s) => {
  const src = s.split(".")[0];
  return [s, { fetchedStreams: goldens[s].fetchedStreams, streams: Object.fromEntries(goldens[s].fetchedStreams.map((st) => [st, storedWindow[src].streams[st] ?? []])) }];
}))));
execFileSync(tsx, [join(here, "lib/project.ts"), ADAPTER_DIR, windowIn, windowOut], { encoding: "utf8" });
const projectedWindow = JSON.parse(readFileSync(windowOut, "utf8"));

// 5. Diff legacy body vs projected payload.
const ABSENT = "<absent>";
const identity = (v) => (v && typeof v === "object" && !Array.isArray(v) ? (typeof v.id === "string" ? `id=${v.id}` : typeof v.uuid === "string" ? `uuid=${v.uuid}` : null) : null);
function diff(a, b, path, out) {
  if (Array.isArray(a) && Array.isArray(b)) {
    const ka = a.map(identity), kb = b.map(identity);
    if (a.length + b.length > 0 && [...ka, ...kb].every(Boolean)) {
      const sharedA = ka.filter((k) => kb.includes(k)), sharedB = kb.filter((k) => ka.includes(k));
      if (sharedA.join() !== sharedB.join()) out.push({ path: `${path}[order]`, legacy: sharedA, projected: sharedB });
      for (const k of ka) diff(a[ka.indexOf(k)], kb.includes(k) ? b[kb.indexOf(k)] : ABSENT, `${path}[${k}]`, out);
      for (const k of kb) if (!ka.includes(k)) diff(ABSENT, b[kb.indexOf(k)], `${path}[${k}]`, out);
      return;
    }
    for (let i = 0; i < Math.max(a.length, b.length); i++) diff(i < a.length ? a[i] : ABSENT, i < b.length ? b[i] : ABSENT, `${path}[${i}]`, out);
    return;
  }
  const isObj = (v) => v && typeof v === "object" && !Array.isArray(v);
  if (isObj(a) && isObj(b)) {
    for (const k of new Set([...Object.keys(a), ...Object.keys(b)]))
      diff(k in a ? a[k] : ABSENT, k in b ? b[k] : ABSENT, path ? `${path}.${k}` : k, out);
    return;
  }
  if (JSON.stringify(a) !== JSON.stringify(b)) out.push({ path, legacy: a, projected: b });
}
function getPath(obj, path) {
  let cur = obj;
  for (const part of path.match(/[^.[\]]+|\[[^\]]+\]/g) ?? []) {
    if (cur == null) return "<absent>";
    if (part.startsWith("[")) {
      const k = part.slice(1, -1);
      if (/^\d+$/.test(k)) cur = cur[Number(k)];
      else { const [f, v] = k.split("="); cur = Array.isArray(cur) ? cur.find((e) => e?.[f] === v) : undefined; }
    } else cur = cur[part];
  }
  return cur === undefined ? "<absent>" : cur;
}
const md = ["# Legacy body vs adapter projection — generated by generate.mjs", ""];
const summary = {};
for (const scope of SCOPES) {
  const res = projected[scope].result;
  const rows = [];
  if (!res.ok) rows.push({ path: "<projection>", legacy: "ok", projected: res.error, category: "PROJECTION_REJECTED", cause: "adapter refused the golden streams" });
  else {
    diff(goldens[scope].legacyBody, res.payload, "", rows);
    const clockRows = [];
    diff(res.payload, projectedLater[scope].result.payload, "", clockRows);
    for (const c of clockRows) if (!rows.some((r) => r.path === c.path))
      rows.push({ path: c.path, legacy: getPath(goldens[scope].legacyBody, c.path), projected: c.legacy, projectedAtClockPlus1d: c.projected, category: "clock-dependent", cause: "value is now() at projection time (legacy: now() at run time); equal here only because both clocks are frozen at 2026-10-01T00:00:00Z" });
  }
  for (const r of rows) if (!r.category) Object.assign(r, classify(scope, r, { legacy: goldens[scope].legacyBody, projected: res.payload, streams: goldens[scope].streams }));
  writeFileSync(join(OUT, "diffs", `${scope}.json`), `${JSON.stringify({ scope, projectionOk: res.ok, projected: res.ok ? res.payload : res.error, differences: rows }, null, 2)}\n`);
  summary[scope] = rows.reduce((m, r) => ({ ...m, [r.category]: (m[r.category] ?? 0) + 1 }), {});
  md.push(`## ${scope}`, "", `projection ok: ${res.ok}; differences: ${rows.length}`, "", "| path | legacy | projected | category | believed cause |", "|---|---|---|---|---|");
  const cell = (v) => (v === undefined ? "undefined" : JSON.stringify(v)).replace(/\|/g, "\\|").slice(0, 160);
  for (const r of rows) md.push(`| \`${r.path}\` | ${cell(r.legacy)} | ${cell(r.projected)} | ${r.category} | ${r.cause} |`);
  md.push("");
}
// Window variant: legacy body (no window) vs projection of the 30-day rows.
md.push("## Variant: 30-day time window (connector-policy.json scopeTimeWindows)", "", `PDPP bundles re-run with requestedScopeEntries time_range.since=${WINDOW_SINCE}; legacy body unchanged (legacy scripts take no window). Not a golden; shows what the phone policy changes.`, "");
const windowReport = {};
for (const scope of SCOPES) {
  const res = projectedWindow[scope].result;
  const rows = [];
  if (!res.ok) rows.push({ path: "<projection>", legacy: "ok", projected: res.error });
  else diff(goldens[scope].legacyBody, res.payload, "", rows);
  const full = projected[scope].result.ok ? projected[scope].result.payload : null;
  const extra = [];
  if (full && res.ok) diff(full, res.payload, "", extra);
  windowReport[scope] = { projectionOk: res.ok, windowVsLegacy: rows, windowVsFullProjection: extra,
    dedupe: storedWindow[scope.split(".")[0]].dedupe, bundleErrors: captures.bundleWindow30[scope.split(".")[0]].streamDone?.errors ?? null };
  md.push(`### ${scope}`, "", `projection ok: ${res.ok}; window-vs-full-projection differences: ${extra.length}`, "", "| path | full (no window) | 30-day window |", "|---|---|---|");
  const cell = (v) => (v === undefined ? "undefined" : JSON.stringify(v)).replace(/\|/g, "\\|").slice(0, 160);
  for (const r of (res.ok ? extra : rows)) md.push(`| \`${r.path}\` | ${cell(r.legacy)} | ${cell(r.projected)} |`);
  md.push("");
}
// Menu-name mismatch variant: profile fields only.
{
  const st = storedStreams(captures.menuMismatch.bundle, "claude");
  const vin = join(OUT, "diffs", "_projection-input-menu-mismatch.json");
  const vout = join(OUT, "diffs", "_projection-output-menu-mismatch.json");
  const sc = ["claude.conversations", "claude.projects"];
  writeFileSync(vin, JSON.stringify(Object.fromEntries(sc.map((s) => [s, { fetchedStreams: goldens[s].fetchedStreams, streams: Object.fromEntries(goldens[s].fetchedStreams.map((x) => [x, st.streams[x] ?? []])) }]))));
  execFileSync(tsx, [join(here, "lib/project.ts"), ADAPTER_DIR, vin, vout], { encoding: "utf8" });
  const vp = JSON.parse(readFileSync(vout, "utf8"));
  md.push(`## Variant: Claude account menu name "${MENU_NAME}" != users.json full_name`, "", "Both scripts re-run with only the DOM menu name changed. Not a golden.", "", "| scope | path | legacy | projected | account_profile row |", "|---|---|---|---|---|");
  const variant = {};
  for (const s of sc) {
    const rows = [];
    const res = vp[s].result;
    if (!res.ok) rows.push({ path: "<projection>", legacy: "ok", projected: res.error });
    else diff(captures.menuMismatch.legacy.result[s], res.payload, "", rows);
    const profRows = rows.filter((r) => r.path.startsWith("profile"));
    variant[s] = { accountProfile: st.streams.account_profile, profileDifferences: profRows, legacyProfile: captures.menuMismatch.legacy.result[s].profile };
    for (const r of profRows) md.push(`| ${s} | \`${r.path}\` | ${JSON.stringify(r.legacy)} | ${JSON.stringify(r.projected)} | ${JSON.stringify(st.streams.account_profile)} |`);
  }
  md.push("");
  writeFileSync(join(OUT, "diffs", "claude-menu-mismatch.json"), `${JSON.stringify(variant, null, 2)}\n`);
}
writeFileSync(join(OUT, "diffs", "time-window-30d.json"), `${JSON.stringify(windowReport, null, 2)}\n`);
writeFileSync(join(OUT, "diffs", "DIFFS.md"), md.join("\n"));
console.log(JSON.stringify(summary, null, 1));
const unclassified = Object.values(summary).reduce((n, s) => n + (s.UNCLASSIFIED ?? 0), 0);
if (unclassified) { console.error(`${unclassified} unclassified difference(s); see diffs/DIFFS.md`); process.exitCode = 1; }
