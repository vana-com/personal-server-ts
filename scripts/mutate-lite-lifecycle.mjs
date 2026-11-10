// Run on Node 22 from the repo root. Restore source even if the mutant fails.
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";

const file = "packages/lite/src/browser-runtime.ts";
const test = "packages/lite/src/start-lifecycle.test.ts";
const original = readFileSync(file, "utf8");
const anchor = "      autoStartSync: false,\n";
const hash = (value) => createHash("sha256").update(value).digest("hex");
function run() {
  const result = spawnSync(
    "nice",
    [
      "-n",
      "10",
      "npx",
      "vitest",
      "run",
      "--maxWorkers=4",
      "--reporter=json",
      test,
      "-t",
      "cold assembly",
    ],
    { encoding: "utf8", maxBuffer: 8 * 1024 * 1024 },
  );
  return {
    code: result.status,
    report: JSON.parse(result.stdout.slice(result.stdout.indexOf("{"))),
  };
}
const baseline = run();
if (baseline.code !== 0 || baseline.report.numPassedTests !== 1)
  throw new Error("Baseline must pass one cold-assembly test");
if (original.split(anchor).length !== 2)
  throw new Error("Mutation anchor must match once");
let mutant;
try {
  writeFileSync(file, original.replace(anchor, ""));
  mutant = run();
} finally {
  writeFileSync(file, original);
  if (hash(readFileSync(file, "utf8")) !== hash(original))
    throw new Error("Restore failed");
}
const failures = mutant.report.testResults
  .flatMap((result) => result.assertionResults)
  .filter((result) => result.status === "failed");
if (
  mutant.code === 0 ||
  failures.length !== 1 ||
  !failures[0].fullName.includes("cold assembly") ||
  !failures[0].failureMessages.join("\n").includes("expected true to be false")
)
  throw new Error("Auto-start mutant was not killed by the intended assertion");
console.log(
  "Baseline: 1 passed; auto-start mutant: 1 killed (running manager before explicit start); source restored and hash verified",
);
