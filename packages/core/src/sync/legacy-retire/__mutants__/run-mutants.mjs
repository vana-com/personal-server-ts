#!/usr/bin/env node
/**
 * Apply each mutant of `mutants.mjs` as a real code edit to a scratch copy of
 * the repository, run the focused tests, record RED (a test failed, and the
 * named one) or SURVIVED, and restore. The working tree is never edited.
 *
 *   node packages/core/src/sync/legacy-retire/__mutants__/run-mutants.mjs
 *   ... --only STALE_PASS_DELETES,UNCOVERED_RETIRES   (names, comma separated)
 *   ... --list
 *   ... --keep            (keep the scratch copy)
 *
 * Needs the repository installed (`npm ci`) on Node 22; the baseline builds
 * core's dist in the scratch copy first, and stops with a clear message if
 * that build fails. A test file that did not load is never a kill. Exit 0 only when the baseline is green and every mutant is RED.
 * Prints a markdown table.
 */

import { spawnSync } from "node:child_process";
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { MUTANTS } from "./mutants.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "../../../../../..");
const args = process.argv.slice(2);
const flag = (name) => args.includes(name);
const option = (name) => {
  const at = args.indexOf(name);
  return at >= 0 ? args[at + 1] : undefined;
};

const only = option("--only")?.split(",");
const selected = MUTANTS.filter((m) => !only || only.includes(m.name));
if (flag("--list")) {
  for (const m of MUTANTS) console.log(`${m.name}\t${m.why}`);
  process.exit(0);
}
if (only && selected.length !== only.length) {
  const known = new Set(MUTANTS.map((m) => m.name));
  console.error(
    `unknown mutant: ${only.filter((n) => !known.has(n)).join(", ")}`,
  );
  process.exit(2);
}

// Scratch copy under ~/.tmp (never /tmp: it is RAM-backed).
const base = join(homedir(), ".tmp");
mkdirSync(base, { recursive: true });
const scratch = mkdtempSync(join(base, "retire-mutants-"));
const skip = new Set(["node_modules", ".git"]);
cpSync(repo, scratch, {
  recursive: true,
  filter: (src) => !skip.has(src.split("/").at(-1)) || src === repo,
});

// node_modules: every entry links to the installed one, except the workspace
// packages, which link to the scratch copy so a rebuilt core is the one read.
const modules = join(scratch, "node_modules");
mkdirSync(modules);
for (const entry of readdirSync(join(repo, "node_modules"))) {
  if (entry === "@opendatalabs") continue;
  symlinkSync(join(repo, "node_modules", entry), join(modules, entry));
}
mkdirSync(join(modules, "@opendatalabs"));
for (const entry of readdirSync(join(repo, "node_modules/@opendatalabs"))) {
  const source = join(repo, "node_modules/@opendatalabs", entry);
  const isWorkspace = entry.startsWith("personal-server-ts");
  symlinkSync(
    isWorkspace ? join(scratch, "packages", workspaceDir(entry)) : source,
    join(modules, "@opendatalabs", entry),
  );
}
for (const pkg of readdirSync(join(repo, "packages"))) {
  const nested = join(repo, "packages", pkg, "node_modules");
  if (existsSync(nested))
    symlinkSync(nested, join(scratch, "packages", pkg, "node_modules"));
}

function workspaceDir(entry) {
  if (entry === "personal-server-ts") return "cli";
  return entry.replace(/^personal-server-ts-/, "");
}

const env = { ...process.env };

function run(cmd, cmdArgs) {
  return spawnSync(cmd, cmdArgs, {
    cwd: scratch,
    env,
    encoding: "utf8",
    maxBuffer: 256 * 1024 * 1024,
  });
}

function buildCore() {
  const out = run("nice", [
    "-n",
    "19",
    "npx",
    "tsc",
    "--build",
    "packages/core",
  ]);
  if (out.status !== 0)
    throw new Error(`core build failed:\n${out.stdout}${out.stderr}`);
}

/** Run vitest on `tests`; return the failed test names and counts. */
function vitest(tests) {
  const outputFile = join(scratch, "vitest-result.json");
  rmSync(outputFile, { force: true });
  const out = run("nice", [
    "-n",
    "19",
    "npx",
    "vitest",
    "run",
    "--maxWorkers=4",
    "--reporter=json",
    `--outputFile=${outputFile}`,
    ...tests,
  ]);
  if (!existsSync(outputFile)) {
    return {
      ok: false,
      crashed: true,
      failed: [],
      total: 0,
      log: out.stdout + out.stderr,
    };
  }
  const result = JSON.parse(readFileSync(outputFile, "utf8"));
  const failed = [];
  for (const file of result.testResults) {
    for (const t of file.assertionResults) {
      if (t.status === "failed") failed.push(t.fullName);
    }
    // A file that failed to load has no assertion results.
    if (file.status === "failed" && file.assertionResults.length === 0) {
      failed.push(`${file.name} (did not run)`);
    }
  }
  return {
    ok: failed.length === 0,
    crashed: false,
    failed,
    total: result.numTotalTests,
    log: "",
  };
}

function applyEdits(edits) {
  const saved = new Map();
  for (const { file, find, replace } of edits) {
    const path = join(scratch, file);
    const text = saved.has(path)
      ? readFileSync(path, "utf8")
      : (saved.set(path, readFileSync(path, "utf8")), saved.get(path));
    const parts = text.split(find);
    if (parts.length !== 2) {
      throw new Error(
        `${file}: expected exactly one occurrence of the edit, found ${parts.length - 1}:\n${find}`,
      );
    }
    writeFileSync(path, parts.join(replace));
  }
  return () => {
    for (const [path, text] of saved) writeFileSync(path, text);
  };
}

const rows = [];
let bad = 0;
try {
  // Every edit still applies exactly once (fails fast on a stale edit).
  for (const m of selected) applyEdits(m.edits)();
  // The tests of server and lite read core through its built output, so the
  // baseline starts from a fresh build of the unmutated tree.
  try {
    buildCore();
  } catch (error) {
    console.error(
      `BASELINE BUILD FAILED; no mutant was run (a missing build is not a kill)\n${error.message}`,
    );
    process.exitCode = 1;
    throw new Error("baseline");
  }
  if (!existsSync(join(scratch, "packages/core/dist/sync/index.js"))) {
    console.error(
      "BASELINE BUILD PRODUCED NO packages/core/dist; no mutant was run",
    );
    process.exitCode = 1;
    throw new Error("baseline");
  }
  // Baseline: every test any mutant relies on is green without a mutation.
  const baselineTests = [...new Set(selected.flatMap((m) => m.tests))];
  const baseline = vitest(baselineTests);
  if (!baseline.ok) {
    console.error("BASELINE IS NOT GREEN; no mutant was run");
    console.error(baseline.failed.join("\n") || baseline.log);
    process.exitCode = 1;
    throw new Error("baseline");
  }
  for (const m of selected) {
    const restore = applyEdits(m.edits);
    let outcome;
    try {
      if (m.build) buildCore();
      outcome = vitest(m.tests);
    } finally {
      restore();
      if (m.build) buildCore();
    }
    const missing = m.mustFail.filter(
      (text) => !outcome.failed.some((name) => name.includes(text)),
    );
    let verdict;
    if (outcome.crashed) verdict = "ERROR (tests did not run)";
    else if (outcome.failed.some((name) => name.endsWith("(did not run)")))
      verdict = "ERROR (a test file did not load; not a kill)";
    else if (outcome.ok) verdict = "SURVIVED";
    else if (missing.length > 0)
      verdict = `RED, but not in: ${missing.join("; ")}`;
    else verdict = "RED";
    if (verdict !== "RED") bad += 1;
    rows.push({ m, verdict, failed: outcome.failed });
  }
} catch (error) {
  if (error.message !== "baseline") throw error;
} finally {
  if (!flag("--keep")) rmSync(scratch, { recursive: true, force: true });
  else console.error(`scratch kept at ${scratch}`);
}

if (rows.length > 0) {
  console.log("| Mutant | Edit | Result | Failing tests | Killed by |");
  console.log("| --- | --- | --- | --- | --- |");
  for (const { m, verdict, failed } of rows) {
    // The first failing test whose title names the mutant (what the verdict checked).
    const killer =
      failed.find((name) => m.mustFail.every((text) => name.includes(text))) ??
      failed[0] ??
      "";
    const shown = killer.length > 90 ? `${killer.slice(0, 87)}...` : killer;
    console.log(
      `| ${m.name} | ${m.why} | ${verdict} | ${failed.length} | ${shown.replaceAll("|", "/")} |`,
    );
  }
  console.log(`\n${rows.length - bad} of ${rows.length} mutants RED`);
}
if (bad > 0) process.exitCode = 1;
