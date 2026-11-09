#!/usr/bin/env node
/**
 * Mutant runner for the stream-sync connection delete.
 *
 * First an unmutated baseline: the focused tests of every mutant run once, and
 * any failure aborts the run (a mutant cannot be told apart from a broken
 * tree). Then each mutant edits its source files, runs its focused tests, and
 * must turn at least one test red whose name contains `aim`. The sources are
 * restored after every mutant, even on a crash. Run from the repository root:
 *
 *   node scripts/stream-sync-delete-mutants.mjs [NAME ...]
 *
 * A mutant in `packages/core` marks `build: true`, so the server and Lite
 * tests (which read core's compiled output) see it.
 */
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";

const DELETE_TESTS = [
  "packages/core/src/stream-sync/writer-delete-connection.test.ts",
];
const WRITER = "packages/core/src/stream-sync/writer.ts";

/** @type {Array<{name: string, edits: Array<{file: string, find: string, replace: string}>, tests: string[], aim: string, build?: boolean}>} */
const MUTANTS = [
  {
    // The rowless streams are not fenced: declared names are ignored.
    name: "DECLARED_OMITTED",
    edits: [
      {
        file: WRITER,
        find: "for (const stream of this.options.declaredStreams(connector)) {",
        replace: "for (const stream of []) {",
      },
    ],
    tests: DELETE_TESTS,
    aim: "rowless streams come from the verified manifest",
  },
  {
    // The writer accepts a missing declaredStreams again.
    name: "DECLARED_UNCHECKED",
    edits: [
      {
        file: WRITER,
        find: 'typeof options.declaredStreams !== "function"',
        replace: "false",
      },
    ],
    tests: DELETE_TESTS,
    aim: "built without declaredStreams is refused",
  },
  {
    // A connector with rows and no declared names is deleted anyway.
    name: "EMPTY_DECLARED_ACCEPTED",
    edits: [
      {
        file: WRITER,
        find: "if (this.options.declaredStreams(connector).length === 0) {",
        replace: "if (false) {",
      },
    ],
    tests: DELETE_TESTS,
    aim: "refuses a connector with rows and no declared names",
  },
];

const only = new Set(process.argv.slice(2));
const run = (cmd, args) =>
  spawnSync("nice", ["-n", "19", cmd, ...args], { encoding: "utf8" });
const failing = (result) =>
  `${result.stdout}${result.stderr}`
    .split("\n")
    .filter((line) => /^\s*(FAIL|×)/.test(line));

const selected = MUTANTS.filter(
  (mutant) => only.size === 0 || only.has(mutant.name),
);
const baselineTests = [...new Set(selected.flatMap((mutant) => mutant.tests))];
const baseline = run("npx", [
  "vitest",
  "run",
  "--maxWorkers=4",
  ...baselineTests,
]);
const baselineRed = failing(baseline);
if (baseline.status !== 0 || baselineRed.length > 0) {
  console.log(
    `BASELINE RED (${baselineRed.length} failing line(s)); mutants not run`,
  );
  console.log(baselineRed.join("\n"));
  process.exit(2);
}
console.log(`BASELINE green (${baselineTests.length} file(s))`);

let failed = false;
for (const mutant of selected) {
  const originals = new Map();
  try {
    for (const edit of mutant.edits) {
      const source =
        originals.get(edit.file) ?? readFileSync(edit.file, "utf8");
      originals.set(edit.file, source);
      const current = readFileSync(edit.file, "utf8");
      if (!current.includes(edit.find)) {
        throw new Error(`pattern not found in ${edit.file}`);
      }
      writeFileSync(edit.file, current.replace(edit.find, edit.replace));
    }
    if (mutant.build) run("npx", ["tsc", "--build"]);
    const result = run("npx", [
      "vitest",
      "run",
      "--maxWorkers=4",
      ...mutant.tests,
    ]);
    const red = failing(result);
    const aimed = red.some((line) => line.includes(mutant.aim));
    console.log(
      `${mutant.name}: ${aimed ? "RED on aim" : "NOT RED ON AIM"} (${red.length} failing line(s))`,
    );
    if (!aimed) failed = true;
  } catch (error) {
    console.log(`${mutant.name}: ERROR ${error.message}`);
    failed = true;
  } finally {
    for (const [file, source] of originals) writeFileSync(file, source);
    if (mutant.build) run("npx", ["tsc", "--build"]);
  }
}
process.exit(failed ? 1 : 0);
