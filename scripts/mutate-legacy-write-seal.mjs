#!/usr/bin/env node
/**
 * Mutation runner for the legacy-write seal (stream-sync write fence).
 *
 * Proves that each guard is load-bearing: it breaks one guard at a time, runs
 * the focused tests, and records which tests fail. A mutant that no test kills
 * (a "survivor") is a hole in the proof.
 *
 *   node scripts/mutate-legacy-write-seal.mjs            # baseline, then all
 *   node scripts/mutate-legacy-write-seal.mjs --list     # print the table
 *   node scripts/mutate-legacy-write-seal.mjs --only ID[,ID]
 *   node scripts/mutate-legacy-write-seal.mjs --markdown # table for a PR body
 *
 * Steps:
 *   1. Build core, then run the focused tests once with no mutation. They must
 *      all pass (green baseline) or the run stops.
 *   2. For each mutant: apply one source edit, rebuild core `dist` when the
 *      edit is in core (lite and server import core from `dist`), run the
 *      focused tests, record the failing tests, restore the file, rebuild.
 *   3. Exit non-zero if any mutant survives.
 *
 * Every file is restored from memory in a `finally` block. The run is
 * synchronous, so a signal does not interrupt it: to stop early, kill the node
 * PID and then check `git diff` for a left-over mutation (re-run
 * `--list` to see the patterns). The run takes the files' contents before editing; it never uses
 * `git checkout`, so uncommitted work is safe. Runs in the foreground, under
 * `nice`, with at most 4 test workers.
 */

import { spawnSync } from "node:child_process";
import {
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/** The focused tests that carry the proof. */
const TEST_FILES = [
  // core
  "packages/core/src/api/legacy-write-gate.test.ts",
  "packages/core/src/api/legacy-write-commit-fence.test.ts",
  "packages/core/src/api/account-storage-mode.test.ts",
  "packages/core/src/storage/legacy-write-seal.test.ts",
  "packages/core/src/sync/pdpp-import.test.ts",
  // server
  "packages/server/src/bootstrap-legacy-write-switch.test.ts",
  "packages/server/src/app-refuse-legacy-writes.test.ts",
  "packages/server/src/routes/data-refuse-legacy-writes.test.ts",
  "packages/server/src/routes/chunked-scope-import-node-http.test.ts",
  "packages/server/src/routes/derivatives.test.ts",
  "packages/server/src/storage/legacy-write-seal.test.ts",
  // lite
  "packages/lite/src/legacy-write-seal.test.ts",
  "packages/lite/src/oura-import.test.ts",
  "packages/lite/src/runtime-account-storage-mode.test.ts",
];

const SEAL = "packages/core/src/storage/legacy-write-seal.ts";
const GATE = "packages/core/src/api/legacy-write-gate.ts";
const API = "packages/core/src/api/index.ts";
const MANAGER = "packages/server/src/storage/index-manager.ts";
const HIERARCHY = "packages/server/src/storage/hierarchy.ts";
const IMPORT_OPS = "packages/server/src/storage/import-operations.ts";
const NODE_STORAGE = "packages/server/src/storage/node-data-storage.ts";
const CHUNKED = "packages/server/src/routes/chunked-scope-import.ts";
const LITE_STORAGE = "packages/lite/src/storage.ts";
const LITE_RUNTIME = "packages/lite/src/runtime.ts";

/**
 * `from` must occur in `file`; `nth` (1-based, default 1) picks which
 * occurrence to replace. `review` names the review finding the mutant answers.
 */
const MUTANTS = [
  // --- the seal itself -----------------------------------------------------
  {
    id: "SEAL_BYPASSED",
    review: "SEAL_BYPASSED",
    note: "assertOpen/commit never refuse",
    file: SEAL,
    from: 'if (v === "allow") return;',
    to: 'if (v === "allow" || v !== "allow") return;',
  },
  {
    id: "SEAL_UNBOUND_ALLOWS",
    review: "UNWIRED_ALLOWS",
    note: "a seal nobody bound answers allow",
    file: SEAL,
    from: 'binding === undefined\n      ? "unknown"',
    to: 'binding === undefined\n      ? "allow"',
  },
  {
    id: "GATE_UNWIRED_ALLOWS",
    review: "UNWIRED_ALLOWS",
    note: "legacyWriteVerdict(undefined) is allow",
    file: GATE,
    from: 'if (mode === undefined) return "unknown";',
    to: 'if (mode === undefined) return "allow";',
  },
  {
    id: "SEAL_DRAIN_NOOP",
    review: "P2.9",
    note: "drain() does not wait for in-flight commits",
    file: SEAL,
    from: "while (inFlight.size > 0) await Promise.all([...inFlight]);",
    to: "",
  },
  // --- Node durable commits ------------------------------------------------
  {
    id: "NODE_INDEX_INSERT_UNSEALED",
    review: "DOWNLOAD_UNFENCED",
    note: "index insert (insertIfCurrent, so insert) skips the seal",
    file: MANAGER,
    from: "legacyWriteSeal.commit(() =>\n      insertIfCurrentTransaction(entry, precondition),\n    );",
    to: "insertIfCurrentTransaction(entry, precondition);",
  },
  {
    id: "NODE_INDEX_RECOVERED_UNSEALED",
    review: "RECOVER_AFTER_SWITCH",
    note: "insertRecovered skips the seal",
    file: MANAGER,
    from: "return legacyWriteSeal.commit(() => insertRow(entry));",
    to: "return insertRow(entry);",
  },
  {
    id: "NODE_PUBLISH_FILE_UNSEALED",
    review: "RECOVER_AFTER_SWITCH",
    note: "publishDataFile skips the seal",
    file: HIERARCHY,
    from: "return seal.commit(() =>\n    publishDataFileSealed(options, envelope, bytes, operation),\n  );",
    to: "return publishDataFileSealed(options, envelope, bytes, operation);",
  },
  {
    id: "NODE_PUBLISH_STAGED_UNSEALED",
    review: "CHUNK_REFUSAL_KEEPS_CHUNKS",
    note: "publishStagedDataFile skips the seal",
    file: HIERARCHY,
    from: "return seal.commit(() => publishStagedDataFileSealed(stagePath, finalPath));",
    to: "return publishStagedDataFileSealed(stagePath, finalPath);",
  },
  {
    id: "NODE_IMPORT_PREPARE_UNSEALED",
    review: "RECOVER_AFTER_SWITCH",
    note: "the prepared-row INSERT does not ask the seal",
    file: IMPORT_OPS,
    from: "        // A switched or unknown account journals no new legacy write.\n        seal.assertOpen();\n",
    to: "",
  },
  {
    id: "NODE_IMPORT_409_NOT_426",
    review: "RECOVER_AFTER_SWITCH",
    note: "a recover() drop answers 409 instead of 426",
    file: IMPORT_OPS,
    from: "        seal.assertOpen();\n        throw new ProtocolError(\n          409,",
    to: "        throw new ProtocolError(\n          409,",
  },
  {
    id: "NODE_RECOVER_KEEPS_PREPARED_ON_SWITCH",
    review: "RECOVER_AFTER_SWITCH",
    note: "recover() leaves a prepared op in place on a switched refusal",
    file: IMPORT_OPS,
    from: 'error.verdict === "switched"\n      ) {\n        db.prepare(',
    to: 'false\n      ) {\n        db.prepare(',
  },
  {
    id: "NODE_BOOT_STAGED_PUBLISH_KEPT",
    review: "P3.10",
    note: "boot staged recovery keeps the stage and row on switched",
    file: NODE_STORAGE,
    from: 'if (refused.verdict === "switched") {',
    to: "if (false) {",
  },
  // --- chunked import ------------------------------------------------------
  {
    id: "CHUNK_SESSION_KEPT_ON_ROUTE_REFUSAL",
    review: "CHUNK_REFUSAL_KEEPS_CHUNKS",
    note: "route refusal on switched leaves the session's chunks",
    file: CHUNKED,
    from: "    refusal.status === 426 &&\n    sessionId &&",
    to: "    false &&\n    sessionId &&",
  },
  {
    id: "CHUNK_SESSION_KEPT_ON_FINALIZE_REFUSAL",
    review: "CHUNK_REFUSAL_KEEPS_CHUNKS",
    note: "finalize refusal on switched leaves the session's chunks",
    file: CHUNKED,
    from: '    error.verdict === "switched"\n  ) {\n    await rm(importPath(deps, metadata.id)',
    to: '    false\n  ) {\n    await rm(importPath(deps, metadata.id)',
  },
  {
    id: "CHUNK_REFUSED_ARTIFACTS_KEPT",
    review: "CHUNK_REFUSAL_KEEPS_CHUNKS",
    note: "a refused finalize leaves its staged and final files",
    file: CHUNKED,
    from: "  await removeImportArtifacts(deps, metadata);\n  if (\n    error instanceof LegacyWriteRefusedError",
    to: "  if (\n    error instanceof LegacyWriteRefusedError",
  },
  // --- background writers --------------------------------------------------
  {
    id: "DERIV_COMPUTE_UNFENCED",
    review: "DERIV_UNFENCED",
    note: "derivative compute does not ask the seal",
    file: "packages/core/src/derivatives/compute.ts",
    from: "deps.storage.legacyWriteSeal?.assertOpen();",
    to: "",
  },
  {
    id: "DOWNLOAD_ENTRY_UNFENCED",
    review: "DOWNLOAD_UNFENCED",
    note: "download worker: first seal check removed",
    file: "packages/core/src/sync/workers/download.ts",
    from: "deps.storage.legacyWriteSeal?.assertOpen();",
    to: "",
    nth: 1,
  },
  {
    id: "DOWNLOAD_COMMIT_UNFENCED",
    review: "DOWNLOAD_UNFENCED",
    note: "download worker: second seal check removed",
    file: "packages/core/src/sync/workers/download.ts",
    from: "deps.storage.legacyWriteSeal?.assertOpen();",
    to: "",
    nth: 2,
  },
  // --- Oura ----------------------------------------------------------------
  {
    id: "OURA_BATCH_FENCE_REMOVED",
    review: "OURA_SWITCH_MID_BATCH",
    note: "Oura early fence removed (seal still refuses per stream)",
    file: "packages/core/src/oura/index.ts",
    from: "  fenceLegacyCommit(options.accountStorageMode, options.serverOwner);\n",
    to: "",
  },
  // --- Lite ----------------------------------------------------------------
  {
    id: "LITE_INDEX_INSTALL_UNSEALED",
    review: "LITE_INDEX_AFTER_FENCE",
    note: "Lite index install no longer goes through the seal",
    file: LITE_STORAGE,
    from: "await (options.legacyCommit\n        ? legacyWriteSeal.commit(() => publish(next))\n        : publish(next));",
    to: "await publish(next);",
  },
  {
    id: "LITE_INSTALL_NOT_LEGACY_COMMIT",
    review: "LITE_INDEX_AFTER_FENCE",
    note: "installEntry drops the legacyCommit option",
    file: LITE_STORAGE,
    from: "      { legacyCommit: true },",
    to: "      {},",
  },
  {
    id: "LITE_BLOB_WRITE_UNFENCED",
    review: "LITE_INDEX_AFTER_FENCE",
    note: "Lite writeEnvelope no longer refuses early",
    file: LITE_STORAGE,
    from: "      legacyWriteSeal.assertOpen();\n      const path = envelopePath(",
    to: "      const path = envelopePath(",
  },
  {
    id: "LITE_SEAL_NOT_BOUND",
    review: "UNWIRED_ALLOWS",
    note: "Lite runtime never binds the storage seal",
    file: LITE_RUNTIME,
    from: "if (options.accountStorageMode) {\n    (\n      options.storage",
    to: "if (false as boolean) {\n    (\n      options.storage",
  },
  {
    id: "LITE_CONFIG_NO_DRAIN",
    review: "P2.9",
    note: "Lite config PUT does not drain in-flight legacy writes",
    file: LITE_RUNTIME,
    from: "await dataStorage.legacyWriteSeal?.drain();",
    to: "",
  },
  {
    id: "LITE_CONFIG_NO_PRESAMPLE",
    review: "P3.10",
    note: "Lite config PUT does not sample the mode before saving",
    file: LITE_RUNTIME,
    from: "options.accountStorageMode?.read(options.serverOwner);\n              await saveConfig(config);",
    to: "await saveConfig(config);",
  },
  // --- round 1: the mode and the route fences ------------------------------
  {
    id: "API_FENCE_1_REMOVED",
    review: "round 1",
    note: "route commit fence #1 (write) removed",
    file: API,
    from: "fence: commitFenceFor(deps),",
    to: "fence: () => {},",
    nth: 1,
  },
  {
    id: "API_FENCE_2_REMOVED",
    review: "round 1",
    note: "route commit fence #2 removed",
    file: API,
    from: "fence: commitFenceFor(deps),",
    to: "fence: () => {},",
    nth: 2,
  },
  {
    id: "API_FENCE_3_REMOVED",
    review: "round 1",
    note: "route commit fence #3 removed",
    file: API,
    from: "fence: commitFenceFor(deps),",
    to: "fence: () => {},",
    nth: 3,
  },
  {
    id: "API_FENCE_4_REMOVED",
    review: "round 1",
    note: "route commit fence #4 removed",
    file: API,
    from: "fence: commitFenceFor(deps),",
    to: "fence: () => {},",
    nth: 4,
  },
  {
    id: "SWITCH_REQUIRES_SECOND_FLAG",
    review: "round 1",
    note: "the switch needs refuseLegacyWrites as well as write",
    file: "packages/server/src/bootstrap.ts",
    from: "source: () => config.streamSync.write === true,",
    to: "source: () =>\n      config.streamSync.write === true &&\n      config.streamSync.refuseLegacyWrites === true,",
  },
  {
    id: "LAZY_LATCH",
    review: "round 1",
    note: "the mode is not sampled when built",
    file: "packages/core/src/api/account-storage-mode.ts",
    from: "  // Eager sample: latch a startup `true` before any request arrives.\n  mode.read();\n",
    to: "",
  },
];

// --- runner ------------------------------------------------------------------

const args = process.argv.slice(2);
const only = args.includes("--only")
  ? new Set(args[args.indexOf("--only") + 1].split(","))
  : undefined;

if (args.includes("--list")) {
  for (const m of MUTANTS) console.log(`${m.id}\t${m.review}\t${m.note}`);
  process.exit(0);
}

function run(cmd, cmdArgs, cwd = root) {
  return spawnSync(cmd, cmdArgs, {
    cwd,
    encoding: "utf8",
    maxBuffer: 256 * 1024 * 1024,
  });
}

function buildCore() {
  const r = run("npx", ["tsc", "--build"], join(root, "packages/core"));
  if (r.status !== 0) {
    return `core build failed:\n${(r.stdout + r.stderr).slice(0, 2000)}`;
  }
  return undefined;
}

/** Runs the focused tests. Returns `{ failed: string[], error?: string }`. */
function runTests() {
  const dir = mkdtempSync(join(tmpdir(), "seal-mutants-"));
  const out = join(dir, "result.json");
  try {
    const r = run("nice", [
      "-n",
      "19",
      "npx",
      "vitest",
      "run",
      "--maxWorkers=4",
      "--reporter=json",
      `--outputFile=${out}`,
      ...TEST_FILES,
    ]);
    let report;
    try {
      report = JSON.parse(readFileSync(out, "utf8"));
    } catch {
      return {
        failed: [],
        error: `no vitest report (exit ${r.status}): ${(r.stdout + r.stderr).slice(-1500)}`,
      };
    }
    const failed = [];
    for (const file of report.testResults ?? []) {
      const name = file.name.replace(`${root}/`, "");
      const cases = file.assertionResults ?? [];
      const failedCases = cases.filter((c) => c.status === "failed");
      for (const c of failedCases) failed.push(`${name} > ${c.fullName}`);
      // A suite that failed to load has no failed case; count the file.
      if (file.status === "failed" && failedCases.length === 0) {
        failed.push(`${name} > (suite failed: ${(file.message ?? "").split("\n")[0]})`);
      }
    }
    return { failed };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const originals = new Map();
function restoreAll() {
  for (const [file, text] of originals) writeFileSync(join(root, file), text);
  originals.clear();
}
for (const sig of ["SIGINT", "SIGTERM"]) {
  process.on(sig, () => {
    restoreAll();
    process.exit(130);
  });
}

function applyMutation(m) {
  const path = join(root, m.file);
  const text = readFileSync(path, "utf8");
  const nth = m.nth ?? 1;
  let index = -1;
  for (let i = 0; i < nth; i++) {
    index = text.indexOf(m.from, index + 1);
    if (index < 0) {
      throw new Error(
        `${m.id}: occurrence ${nth} of the pattern is not in ${m.file}; update the runner`,
      );
    }
  }
  originals.set(m.file, text);
  writeFileSync(
    path,
    text.slice(0, index) + m.to + text.slice(index + m.from.length),
  );
}

const coreChanged = (m) => m.file.startsWith("packages/core/src/");

console.log("Building core, then running the green baseline...");
let err = buildCore();
if (err) {
  console.error(err);
  process.exit(2);
}
const baseline = runTests();
if (baseline.error || baseline.failed.length > 0) {
  console.error("BASELINE IS NOT GREEN; no mutant result would mean anything.");
  console.error(baseline.error ?? baseline.failed.join("\n"));
  process.exit(2);
}
console.log(`baseline green (${TEST_FILES.length} files)\n`);

const results = [];
for (const m of MUTANTS) {
  if (only && !only.has(m.id)) continue;
  process.stdout.write(`${m.id} ... `);
  let outcome;
  try {
    applyMutation(m);
    const buildError = coreChanged(m) ? buildCore() : undefined;
    outcome = buildError
      ? { failed: [], error: buildError }
      : runTests();
  } catch (error) {
    outcome = { failed: [], error: String(error) };
  } finally {
    restoreAll();
    if (coreChanged(m)) buildCore();
  }
  const status = outcome.error
    ? "ERROR"
    : outcome.failed.length > 0
      ? "KILLED"
      : "SURVIVED";
  console.log(`${status}${outcome.failed.length ? ` (${outcome.failed.length})` : ""}`);
  results.push({ m, status, ...outcome });
}

// Leave `dist` matching the restored source.
err = buildCore();
if (err) console.error(err);

console.log("\n=== attribution ===");
for (const { m, status, failed, error } of results) {
  console.log(`\n${m.id} [${m.review}] ${status}: ${m.note}`);
  if (error) console.log(`  ${error.split("\n")[0]}`);
  for (const f of failed.slice(0, 4)) console.log(`  - ${f}`);
  if (failed.length > 4) console.log(`  - ... ${failed.length - 4} more`);
}

if (args.includes("--markdown")) {
  console.log("\n| Mutant | Answers | Status | First killing test |\n|---|---|---|---|");
  for (const { m, status, failed } of results) {
    const first = failed[0]?.replace(/\|/g, "\\|") ?? "";
    console.log(`| ${m.id} | ${m.review} | ${status} | ${first} |`);
  }
}

const bad = results.filter((r) => r.status !== "KILLED");
console.log(
  `\n${results.length - bad.length}/${results.length} mutants killed` +
    (bad.length ? `; not killed: ${bad.map((r) => r.m.id).join(", ")}` : ""),
);
process.exit(bad.length ? 1 : 0);
