#!/usr/bin/env node
/**
 * Mutation proof for the group D read entry points (sync gate, scope delete,
 * Oura, takeover). For each named mutant: back up the file bytes, apply one
 * textual edit, run the focused tests, record RED (some test failed) or
 * SURVIVED, then restore the exact bytes and verify the hash. A mutant whose
 * anchor text is missing is an error, never a silent pass.
 *
 *   node scripts/stream-sync-read-other-mutants.mjs [NAME ...]
 *
 * Exit 0 only when every mutant ran RED and every file is restored.
 * Run under Node 22 after `npm run build`. Tests run in the foreground.
 */
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const FOCUSED = [
  "packages/core/src/api/stream-sync-read-other.test.ts",
  "packages/core/src/sync/engine/sync-manager.account-mode.test.ts",
  "packages/server/src/routes/stream-sync-read-other.test.ts",
  "packages/server/src/bootstrap-account-mode.test.ts",
  "packages/lite/src/runtime-stream-sync-read-other.test.ts",
  "packages/lite/src/sync-account-mode.test.ts",
  "packages/lite/src/browser-runtime-account-mode.test.ts",
];

const API = "packages/core/src/api/index.ts";
const MGR = "packages/core/src/sync/engine/sync-manager.ts";
const DATA = "packages/server/src/routes/data.ts";
const OURA = "packages/server/src/routes/oura.ts";
const OURA_CORE = "packages/core/src/api/oura-collection-requirements.ts";
const LITE = "packages/lite/src/runtime.ts";

/** name, file, find (exact text), replace */
const MUTANTS = [
  [
    "SYNC_FILE_LEGACY",
    API,
    'if (fileStorage.kind === "streams") {',
    "if (false as boolean) {",
  ],
  [
    "STREAMS_ALWAYS_REFUSE",
    API,
    'if (fileStorage.kind === "refuse") return fileStorage.response;\n        if (fileStorage.kind === "streams") {',
    "if (true as boolean) {",
  ],
  [
    "CASCADE_READS_LEGACY",
    API,
    'if (deleteStorage.kind === "streams")',
    "if (false as boolean)",
  ],
  [
    "DELETE_UNKNOWN_AS_LEGACY",
    API,
    'if (deleteStorage.kind === "refuse") return deleteStorage.response;',
    "",
  ],
  [
    "DELETE_CODE_DIVERGES",
    "packages/core/src/api/switched-read-refusal.ts",
    "error: USE_CONNECTOR_DELETE_CODE,",
    'error: "STREAM_SYNC_LEGACY_READ_UNAVAILABLE",',
  ],
  [
    "TAKEOVER_LEGACY_ON_SWITCH",
    DATA,
    'refuseTakeoverOnStreams(parsed.scope, "read");\n      return {',
    "return {",
  ],
  [
    "TAKEOVER_RESET_LEGACY_ON_SWITCH",
    DATA,
    'refuseTakeoverOnStreams(parsed.scope, "reset");\n      deps.legacyScopeView?.resetTakeover',
    "deps.legacyScopeView?.resetTakeover",
  ],
  [
    "OURA_LEGACY_ON_SWITCH",
    OURA_CORE,
    'if (selection.kind === "streams") {',
    "if (false as boolean) {",
  ],
  [
    "OURA_POST_FAILS_OPEN_ON_UNKNOWN",
    OURA,
    'if (selection.kind === "refuse") return selection.response;',
    "",
  ],
  [
    "NODE_OURA_MODE_DROPPED",
    OURA,
    "      accountStorageMode: deps.accountStorageMode,\n      serverOwner: deps.serverOwner,\n      retainedCanonicalRecords",
    "      retainedCanonicalRecords",
  ],
  [
    "NODE_SYNC_MODE_DROPPED",
    "packages/server/src/routes/sync.ts",
    "        accountStorageMode: deps.accountStorageMode,\n",
    "",
  ],
  [
    "NODE_SYNC_APP_MODE_DROPPED",
    "packages/server/src/app.ts",
    '      accountStorageMode,\n      mountPath: "/v1/sync",',
    '      mountPath: "/v1/sync",',
  ],
  [
    "LITE_MODE_DROPPED",
    LITE,
    "              accountStorageMode: options.accountStorageMode,\n              serverOwner: options.serverOwner,\n            },\n            { basePath: syncPrefix }",
    "            },\n            { basePath: syncPrefix }",
  ],
  [
    "LITE_SYNC_OWNER_DROPPED",
    LITE,
    "              serverOwner: options.serverOwner,\n            },\n            { basePath: syncPrefix }",
    "            },\n            { basePath: syncPrefix }",
  ],
  [
    "LITE_OURA_MODE_DROPPED",
    LITE,
    "            storage: toDataStoragePort(options.storage),\n            accountStorageMode: options.accountStorageMode,\n            serverOwner: options.serverOwner,\n          });",
    "            storage: toDataStoragePort(options.storage),\n          });",
  ],
  [
    "LITE_OURA_OWNER_DROPPED",
    LITE,
    "            storage: toDataStoragePort(options.storage),\n            accountStorageMode: options.accountStorageMode,\n            serverOwner: options.serverOwner,\n          });",
    "            storage: toDataStoragePort(options.storage),\n            accountStorageMode: options.accountStorageMode,\n          });",
  ],
  [
    "LITE_OURA_POST_UNKNOWN",
    LITE,
    'if (ouraSelection.kind === "refuse") return ouraSelection.response;',
    "",
  ],
  [
    "SYNC_TRIGGER_CYCLE_ON_SWITCH",
    MGR,
    "const modeGate = accountModeGate() ?? earlyGate;",
    "const modeGate = null as ReturnType<typeof accountModeGate>;",
  ],
  [
    "STATUS_READS_LEGACY_ON_SWITCH",
    MGR,
    "const pendingFiles = modeGate\n        ? 0\n        : uploadDeps.storage.findUnsynced().length;",
    "const pendingFiles = uploadDeps.storage.findUnsynced().length;",
  ],
  [
    "HYDRATE_ON_SWITCH",
    MGR,
    'const earlyGate = accountModeGate();\n        if (earlyGate) {\n          blocked = { reason: earlyGate.reason, message: earlyGate.message };\n          downloadDeps.logger.warn(blocked, "Scope hydration blocked");',
    'const earlyGate = null as ReturnType<typeof accountModeGate>;\n        if (earlyGate) {\n          blocked = { reason: earlyGate.reason, message: earlyGate.message };\n          downloadDeps.logger.warn(blocked, "Scope hydration blocked");',
  ],
  [
    "STREAM_PUBLISH_DROPPED_ON_SWITCH",
    MGR,
    "if (modeGate.reason === SYNC_BLOCKED_STREAM_SYNC)\n            await runStreamSyncPublish();",
    "",
  ],
  [
    "UNKNOWN_RUNS_LEGACY_SYNC",
    MGR,
    "    return {\n      ok: false,\n      reason: SYNC_BLOCKED_ACCOUNT_MODE_UNKNOWN,",
    "    return null;\n    return {\n      ok: false,\n      reason: SYNC_BLOCKED_ACCOUNT_MODE_UNKNOWN,",
  ],
  [
    "CYCLE_GATE_CAPTURED_ONCE",
    MGR,
    "const modeGate = accountModeGate() ?? earlyGate;",
    "const modeGate = earlyGate;",
  ],
  [
    "DOWNLOAD_GATE_DROPPED",
    MGR,
    "const downloadGate = accountModeGate();",
    "const downloadGate = null as ReturnType<typeof accountModeGate>;",
  ],
  [
    "HYDRATE_GATE_CAPTURED_ONCE",
    MGR,
    "// The mode can change while canSync awaits.\n        const modeGate = accountModeGate();",
    "// The mode can change while canSync awaits.\n        const modeGate = null as ReturnType<typeof accountModeGate>;",
  ],
  [
    "PUBLISH_BEFORE_CAN_SYNC",
    MGR,
    "if (earlyGate && earlyGate.reason !== SYNC_BLOCKED_STREAM_SYNC) {",
    "if (earlyGate) {\n          if (earlyGate.reason === SYNC_BLOCKED_STREAM_SYNC)\n            await runStreamSyncPublish();",
  ],
  [
    "CONTROL_SCOPE_BEFORE_MODE",
    DATA,
    'parseScope(c.req.param("scope"))?.kind === "control" &&\n    selectAccountStorageMode({\n      accountStorageMode: deps.accountStorageMode,\n      serverOwner: deps.serverOwner,\n    }).kind === "legacy"',
    'parseScope(c.req.param("scope"))?.kind === "control"',
  ],
  [
    "IMPORT_ABORT_LEGACY_ON_SWITCH",
    DATA,
    'if (selection.kind === "refuse")\n        throw new LegacyWriteRefused(selection.response);\n      const refusal = refuseLegacyWrite(writeSwitch);\n      if (refusal) throw new LegacyWriteRefused(refusal);\n      return abortScopeImport(',
    "return abortScopeImport(",
  ],
  [
    "TAKEOVER_RESET_SHARES_READ_CODE",
    "packages/core/src/api/switched-read-refusal.ts",
    "errorCode: STREAM_SYNC_TAKEOVER_RESET_UNAVAILABLE_CODE,",
    'errorCode: "STREAM_SYNC_LEGACY_READ_UNAVAILABLE",',
  ],
  [
    "LITE_BROWSER_MODE_DROPPED",
    "packages/lite/src/browser-runtime.ts",
    "      config,\n      accountStorageMode,\n      serverOwner,\n      stateStore,",
    "      config,\n      stateStore,",
  ],
  [
    "NODE_SYNC_MANAGER_MODE_DROPPED",
    "packages/server/src/bootstrap.ts",
    "      accountStorageMode,\n      serverOwner,\n      async canSync() {",
    "      async canSync() {",
  ],
  [
    "LITE_SYNC_MANAGER_MODE_DROPPED",
    "packages/lite/src/sync.ts",
    "        accountStorageMode: options.accountStorageMode,\n",
    "",
  ],
];

const sha = (s) => createHash("sha256").update(s).digest("hex");
const wanted = process.argv.slice(2);
const unknown = wanted.filter((n) => !MUTANTS.some((m) => m[0] === n));
if (unknown.length) throw new Error(`unknown mutant: ${unknown.join(", ")}`);

function runTests() {
  const r = spawnSync(
    "nice",
    ["-n", "19", "npx", "vitest", "run", "--maxWorkers=4", ...FOCUSED],
    { cwd: ROOT, encoding: "utf8" },
  );
  const out = `${r.stdout}\n${r.stderr}`;
  const failed = /Tests\s+(\d+) failed/.exec(out);
  const passed = /Tests\s+(?:\d+ failed \| )?(\d+) passed/.exec(out);
  return {
    failed: failed ? Number(failed[1]) : 0,
    passed: passed ? Number(passed[1]) : 0,
    status: r.status,
  };
}

const rows = [];
let bad = false;
const baseline = runTests();
console.log(`baseline: ${baseline.passed} passed, ${baseline.failed} failed`);
if (baseline.failed || baseline.status !== 0) {
  console.error("baseline is not green; refusing to run mutants");
  process.exit(2);
}
for (const [name, file, find, replace] of MUTANTS) {
  if (wanted.length && !wanted.includes(name)) continue;
  const path = join(ROOT, file);
  const original = readFileSync(path);
  const before = sha(original);
  try {
    const text = original.toString("utf8");
    const at = text.indexOf(find);
    if (at < 0 || text.indexOf(find, at + 1) >= 0)
      throw new Error(`anchor missing or not unique in ${file}`);
    writeFileSync(
      path,
      text.replace(find, () => replace),
    );
    const result = runTests();
    const red = result.failed > 0;
    rows.push({ name, file, red, failed: result.failed });
    if (!red) bad = true;
  } catch (error) {
    rows.push({ name, file, red: false, failed: -1, error: String(error) });
    bad = true;
  } finally {
    writeFileSync(path, original);
    if (sha(readFileSync(path)) !== before) {
      console.error(`RESTORE FAILED: ${file}`);
      bad = true;
    }
  }
}
console.log("\n| mutant | file | result | failing tests |\n|---|---|---|---|");
for (const r of rows)
  console.log(
    `| ${r.name} | ${r.file} | ${r.error ? `ERROR ${r.error}` : r.red ? "RED" : "SURVIVED"} | ${r.failed} |`,
  );
process.exit(bad ? 1 : 0);
