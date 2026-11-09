#!/usr/bin/env node
/**
 * Mutant runner for the stream-sync connection delete.
 *
 * Each mutant edits one source file, runs the focused tests, and must turn at
 * least one test red whose name contains `aim`. The source is restored after
 * every mutant, even on a crash. Run from the repository root:
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

/** @type {Array<{name: string, file: string, find: string, replace: string, tests: string[], aim: string, build?: boolean}>} */
const MUTANTS = [
  {
    // The rowless streams are not fenced: declared names are ignored.
    name: "DECLARED_OMITTED",
    file: "packages/core/src/stream-sync/writer.ts",
    find: "this.options.declaredStreams(connector)",
    replace: "[]",
    tests: DELETE_TESTS,
    aim: "rowless streams come from the verified manifest",
  },
  {
    // The writer accepts a missing declaredStreams again.
    name: "DECLARED_UNCHECKED",
    file: "packages/core/src/stream-sync/writer.ts",
    find: 'typeof options.declaredStreams !== "function"',
    replace: "false",
    tests: DELETE_TESTS,
    aim: "built without declaredStreams is refused",
  },
];

const only = new Set(process.argv.slice(2));
const run = (cmd, args) =>
  spawnSync("nice", ["-n", "19", cmd, ...args], { encoding: "utf8" });

let failed = false;
for (const mutant of MUTANTS) {
  if (only.size > 0 && !only.has(mutant.name)) continue;
  const original = readFileSync(mutant.file, "utf8");
  if (!original.includes(mutant.find)) {
    console.log(`${mutant.name}: SKIPPED, pattern not found in ${mutant.file}`);
    failed = true;
    continue;
  }
  try {
    writeFileSync(mutant.file, original.replace(mutant.find, mutant.replace));
    if (mutant.build) run("npx", ["tsc", "--build"]);
    const result = run("npx", [
      "vitest",
      "run",
      "--maxWorkers=4",
      ...mutant.tests,
    ]);
    const output = `${result.stdout}${result.stderr}`;
    const red = output.split("\n").filter((line) => /^\s*(FAIL|×)/.test(line));
    const aimed = red.some((line) => line.includes(mutant.aim));
    console.log(
      `${mutant.name}: ${aimed ? "RED on aim" : "NOT RED ON AIM"} (${red.length} failing line(s))`,
    );
    if (!aimed) failed = true;
  } finally {
    writeFileSync(mutant.file, original);
    if (mutant.build) run("npx", ["tsc", "--build"]);
  }
}
process.exit(failed ? 1 : 0);
