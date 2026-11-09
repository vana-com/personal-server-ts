#!/usr/bin/env node
// Mutation check for the PS Lite start/cleanup path.
// 1. Runs the unmutated tests and requires them green.
// 2. Applies each mutant, runs ONLY its aimed test (-t), and requires that
//    test to run and fail with the expected message. Anchors must match
//    exactly once. Originals are restored in `finally` and verified by hash.
// Run from the repo root: node scripts/mutate-lite-start.mjs
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const dir = "packages/lite/src";
const CLIENT = `${dir}/client.ts`;
const RELAY = `${dir}/relay.ts`;
const tests = [
  `${dir}/client-start-throw.test.ts`,
  `${dir}/client-start-sync-last.test.ts`,
  `${dir}/relay.test.ts`,
];

const mutants = [
  {
    name: "throw_after_sync_built_stops_sync",
    file: CLIENT,
    find: "        autoStartSync: false,\n",
    replace: "",
    test: "throw_after_sync_built_stops_sync",
    expect: /expected true to be false/,
  },
  {
    name: "sync_never_started_after_success",
    file: CLIENT,
    find: "      runtimeBundle?.syncManager?.start?.();",
    replace: "",
    test: "starts the sync manager only after the relay has started",
    expect: /to be called once, but got 0 times/,
  },
  {
    name: "abandon_stop_failure_swallowed",
    file: CLIENT,
    find: "throw unstopped ? withUnstoppedRuntime(error, unstopped) : error;",
    replace: "throw error;",
    test: "abandon_stop_failure_swallowed",
    expect: /expected undefined to be defined/,
  },
  {
    name: "abandon_stop_hang_unbounded",
    file: CLIENT,
    find: '        timer = setTimeout(\n          () => reject(new Error("Stopping the failed start timed out")),\n          START_CLEANUP_STOP_TIMEOUT_MS,\n        );',
    replace: "        void reject;",
    test: "abandon_stop_hang_unbounded",
    expect: /expected 'pending' to be/,
  },
  {
    name: "abandon_stop_failure_attached_even_on_success",
    file: CLIENT,
    find: "    return undefined;\n  } catch {\n    return handle;",
    replace: "    return handle;\n  } catch {\n    return handle;",
    test: "carries no unstopped runtime when the cleanup stop succeeded",
    expect: /to be undefined/,
  },
  {
    name: "live_relay_not_closed_on_start_failure",
    file: CLIENT,
    find: '        relayClient?.close("personal-server-start-failed");',
    replace: "        void relayClient;",
    test: "closes a live relay client when the sync start throws",
    expect: /to be called once, but got 0 times/,
  },
  {
    name: "relay_connect_throw_closes_socket",
    file: RELAY,
    find: '        currentSocket.close(1000, "status-handler-threw");',
    replace: "        void currentSocket;",
    test: "relay_connect_throw_closes_socket",
    expect: /expected 1 to be 3/,
  },
];

const sha = (text) => createHash("sha256").update(text).digest("hex");
const countOf = (text, needle) => text.split(needle).length - 1;

function vitest(extra) {
  const run = spawnSync(
    "nice",
    ["-n", "19", "./node_modules/.bin/vitest", "run", "--maxWorkers=4", "--reporter=json", ...extra, ...tests],
    { cwd: root, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 },
  );
  let report = null;
  try {
    report = JSON.parse(run.stdout.slice(run.stdout.indexOf("{")));
  } catch {
    // A run with no report cannot count as a kill.
  }
  return { status: run.status, report };
}

const baseline = vitest([]);
if (baseline.status !== 0 || !baseline.report) {
  console.error("BASELINE NOT GREEN: refusing to run mutants");
  process.exit(2);
}
console.log(`baseline green (${baseline.report.numPassedTests} tests)`);

const originals = new Map();
const rows = [];
try {
  for (const mutant of mutants) {
    const path = resolve(root, mutant.file);
    if (!originals.has(path)) originals.set(path, readFileSync(path, "utf8"));
    const original = originals.get(path);
    const occurrences = countOf(original, mutant.find);
    if (occurrences !== 1) {
      rows.push({ ...mutant, result: `ANCHOR MATCHES ${occurrences}x`, evidence: "" });
      continue;
    }
    writeFileSync(path, original.replace(mutant.find, () => mutant.replace));
    const { report } = vitest(["-t", mutant.test]);
    writeFileSync(path, original);
    const aimed = (report?.testResults ?? [])
      .flatMap((file) => file.assertionResults)
      .filter((result) => result.fullName.includes(mutant.test));
    const failed = aimed.filter((result) => result.status === "failed");
    const text = failed
      .flatMap((result) => result.failureMessages)
      .join("\n")
      // biome-ignore lint/suspicious/noControlCharactersInRegex: strips ANSI
      .replace(/\u001b\[[0-9;]*m/g, "");
    let result = "SURVIVED";
    let evidence = "";
    if (aimed.length === 0) {
      result = "AIMED TEST DID NOT RUN";
    } else if (failed.length > 0) {
      evidence = text.split("\n")[0].slice(0, 140);
      result = mutant.expect.test(text) ? "killed" : "FAILED WITH THE WRONG MESSAGE";
    }
    rows.push({ ...mutant, result, evidence });
  }
} finally {
  for (const [path, original] of originals) writeFileSync(path, original);
}
let restored = true;
for (const [path, original] of originals) {
  if (sha(readFileSync(path, "utf8")) !== sha(original)) restored = false;
}
for (const row of rows) {
  console.log(`${row.result.padEnd(30)} ${row.name}  <- ${row.test}\n    ${row.evidence}`);
}
console.log(restored ? "originals restored (hash verified)" : "RESTORE HASH MISMATCH");
if (!restored || rows.some((row) => row.result !== "killed")) process.exit(1);
