#!/usr/bin/env node
// Mutant runner for the switched-account scope listing.
//
// 1. Runs the unmutated baseline and aborts unless it is green with tests run.
// 2. Applies each mutant, runs the focused tests with the JSON reporter, and
//    calls the mutant killed only when ITS AIMED TEST failed on an assertion
//    while the suite loaded and ran every test the baseline ran. Import,
//    compile, timeout, crash and zero-test failures are INVALID, never kills.
// 3. Harness mutants break the build on purpose (an import error); the runner
//    must call those INVALID. If it calls one killed, the runner is broken.
// 4. The mutated file is restored byte for byte on exit, SIGINT and SIGTERM.
//
// Run from the repo root: nice -n 19 node scripts/mutants-read-listing.mjs
import { execFileSync, spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const API = "packages/core/src/api/index.ts";
const OVL = "packages/core/src/stream-sync/writer-overlay.ts";
const SVC = "packages/core/src/stream-sync-read/service.ts";
const MIR = "packages/core/src/stream-sync-read/mirror.ts";
const VST = "packages/core/src/stream-sync-read/view-store.ts";
const WRT = "packages/core/src/stream-sync/writer.ts";
const T_API = "packages/core/src/api/stream-sync-read-listing.test.ts";
const T_RS = "packages/core/src/stream-sync-read/readable-scopes.test.ts";
const TESTS = [T_API, T_RS];
const TIMEOUT_MS = 240_000;

const SW = "switched listing and history > ";
const BR = "readableScopes against the body read > ";
const WB = "readableScopes work is bounded by the grant > ";
const BUILD = "readableScopes against what a body read can build > ";
const KEY = "readableScopes cache key covers every stream of the connector > ";
const WRITES = "readableScopes cache misses after every write under the connector > ";
const SURV = "readableScopes survives one connector's local failure > ";

// [name, file, from, to, aimed test full name]
const MUTANTS = [
  ["ALWAYS_REFUSE", API, "return listStreamSyncScopes(deps, url, listAuth);", 'return errorResponse(503, "X", "x");', `${SW}lists the stream scope for the owner`],
  ["LIST_LEGACY", API, "  const scopes = readable.filter(", "  const scopes = [...readable, ...deps.storage.listScopes({ limit: 100 }).scopes].filter(", `${SW}does not list a scope that only legacy storage holds`],
  ["LIST_HIDES_READABLE", API, "  const scopes = readable.filter(", "  const scopes = readable.slice(1).filter(", `${SW}lists exactly the scopes the same caller can read`],
  ["VERSIONS_LEGACY", API, '        return streamHistoryUnsupported("versions");', "        void 0;", `${SW}refuses versions, lineage and additions with a typed error`],
  ["LINEAGE_LEGACY", API, '        return streamHistoryUnsupported("lineage");', "        void 0;", `${SW}refuses versions, lineage and additions with a typed error`],
  ["ADDITIONS_LEGACY", API, '        return streamHistoryUnsupported("additions");', "        void 0;", `${SW}refuses versions, lineage and additions with a typed error`],
  ["READER_PRESENCE_AS_MODE", API, 'if (storageSelection?.kind === "streams") {\n        return listStreamSyncScopes', 'if (storageSelection?.kind === "streams" && deps.streamSyncRead) {\n        return listStreamSyncScopes', `${SW}refuses a switched listing with no stream reader, never legacy`],
  ["UNKNOWN_READS_LEGACY", API, '      if (storageSelection?.kind === "refuse") return storageSelection.response;\n      if (storageSelection?.kind === "streams") {\n        return listStreamSyncScopes', '      if (storageSelection?.kind === "streams") {\n        return listStreamSyncScopes', `${SW}returns the selector's refusal when the mode is unknown`],
  ["UNSWITCHED_CHANGED", API, 'if (storageSelection?.kind === "streams") {\n        return listStreamSyncScopes', "if (storageSelection) {\n        return listStreamSyncScopes", "unswitched listing and history > answers byte for byte as with no mode wired"],
  ["OVERLAY_CONNECTORS_EMPTY", OVL, "connectors: () => writer.overlayConnectors(),", "connectors: async () => [],", "readableScopes with the real writer overlay > lists an owner's first run, collected and not yet published, of an unseen connector"],
  ["MIRROR_ONLY_CONNECTOR_DISCOVERY", SVC, "for (const connector of this.overlayConnectorsLastGood) {", "for (const connector of [] as string[]) {", `${BR}lists an owner's first run of a connector the mirror has never seen`],
  ["OMIT_OVERLAY_STREAM_NAMES", SVC, "addLogical(connector, stream.name);", "void stream;", `${BR}lists an overlay-only stream beside an imported one of the same connector`],
  ["ABORT_CANDIDATE_DISCOVERY", SVC, "this.skipped(connector, error);", "throw error;", "readableScopes survives one connector's local failure > lists A when B's overlay fails, covered or not, and A's body still reads"],
  ["LIST_UNSERVABLE_PROJECTION", SVC, "!(await this.projectable(input, all2, snapshots))", "false", "readableScopes against what a body read can build > omits an alias over the size budget and keeps the control alias"],
  ["RESOLVE_BEFORE_GRANT_AND_PAGE", SVC, "      if (input.isCovered && !input.isCovered(scope)) continue;\n      let newest: number | null;\n      try {\n        const found = await this.readable(scope, input.isOwnerView);\n        if (!found) continue;", "      let newest: number | null;\n      try {\n        const found = await this.readable(scope, input.isOwnerView);\n        if (!found) continue;\n        if (input.isCovered && !input.isCovered(scope)) continue;", `${WB}checks only the covered scope among 1000 candidates`],
  ["ABORT_LIST_ON_ONE_FAILURE", SVC, "      } catch (error) {\n        this.skipped(scope, error);\n        continue;\n      }", "      } catch (error) {\n        throw error;\n      }", `${WB}skips a covered broken scope, logs it, and still lists the others`],
  ["BODY_BUILT_FOR_LISTING", SVC, "        const found = await this.readable(scope, input.isOwnerView);", "        const decision = await this.resolve({ scope, connection: null, cursor: null, legacyFile: false, isOwnerView: input.isOwnerView });\n        if (\"body\" in decision) await decision.body.cancel();\n        const found = await this.readable(scope, input.isOwnerView);", `${BR}builds no view or body while deciding`],
  ["KEY_OMITS_NONTARGET_IMPORT", SVC, "        this.revisions.of(t.connector),", "        t.streams.map((s) => this.views.revision(t.connector, s)),", `${KEY}an import into a non-target stream flips the selected namespace and the alias leaves the listing`],
  ["KEY_OMITS_IMPORT", VST, "    this.revisions.bump(key.connector);", "    void this.revisions;", `${WRITES}misses after an import (ViewStore.commit)`],
  ["KEY_OMITS_MIRROR_ROW", MIR, "      if (replaced) revised.add(parsed.connector);", '      if (replaced && parsed.kind === "control") revised.add(parsed.connector);', `${WRITES}misses after a stream row (RegistryMirror.observePage)`],
  ["KEY_OMITS_CONTROL", MIR, "      if (replaced) revised.add(parsed.connector);", '      if (replaced && parsed.kind === "stream") revised.add(parsed.connector);', `${WRITES}misses after a control row (RegistryMirror.observePage)`],
  ["KEY_OMITS_FLOOR", MIR, "      if (floorRaised) revised.add(parsed.connector);", "      if (false) revised.add(parsed.connector);", `${WRITES}misses after a deletion floor (RegistryMirror.observePage)`],
  ["KEY_OMITS_RECORD_DELETE", MIR, "      if (parsed) this.revisions.bump(parsed.connector);", "      if (parsed) void this.revisions;", `${WRITES}misses after a deletion floor (RegistryMirror.recordDelete, importer-driven)`],
  ["NOTIFY_SKIPPED_WRITE_ENTRY", WRT, "    this.planInputsChanged(host.entry.connector);\n    return write;", "    void host;\n    return write;", `${WRITES}notifies the connector on every run-entry write`],
  ["NOTIFY_SKIPPED_WITH_STATE", WRT, "      for (const connector of changedPlanConnectors(before, state))\n        this.planInputsChanged(connector);", "      for (const connector of changedPlanConnectors(before, state))\n        void connector;", `${WRITES}misses after a receipt-only change to writer state, with nothing else changed (withState)`],
  ["NOTIFY_SKIPPED_SELECTION", WRT, "    this.selected.add(key);\n    this.planInputsChanged(connector);\n  }\n\n  /** A publish pass releases a run's stream. */\n  private unselect(connector: string, key: string): void {\n    this.selected.delete(key);\n    this.planInputsChanged(connector);", "    this.selected.add(key);\n    void connector;\n  }\n\n  /** A publish pass releases a run's stream. */\n  private unselect(connector: string, key: string): void {\n    this.selected.delete(key);\n    void connector;", `${WRITES}misses between a publish reservation and its release (writer selection)`],
  ["LISTENER_ERROR_PROPAGATES", WRT, "      } catch (error) {\n        // Reporting is best effort too: a throwing logger or `message` getter\n        // must not stop the other listeners.\n", "      } catch (error) {\n        if (error) throw error;\n        // Reporting is best effort too: a throwing logger or `message` getter\n        // must not stop the other listeners.\n", `${WRITES}a throwing listener does not fail the run or silence the other listeners`],
  ["LISTENER_LOGGER_ESCAPE", WRT, "        try {\n          settled(\n            this.options.logger?.warn(\n              {\n                connector,\n                error: error instanceof Error ? error.message : \"unknown\",\n              },\n              \"stream-sync writer: a plan-input listener failed\",\n            ),\n          );\n        } catch {\n          // Nothing left to report to.\n        }", "        this.options.logger?.warn(\n            {\n              connector,\n              error: error instanceof Error ? error.message : \"unknown\",\n            },\n            \"stream-sync writer: a plan-input listener failed\",\n          );", `${WRITES}a throwing listener and a throwing logger do not fail the run or silence later listeners`],
  ["LISTENER_ASYNC_REJECTION_ESCAPES", WRT, "function settled(result: unknown): void {\n  Promise.resolve(result).catch(() => {});\n}", "function settled(result: unknown): void {\n  void result;\n}", `${WRITES}an async listener that rejects neither reaches unhandledRejection nor silences later listeners`],
  ["MESSAGE_FORMAT_OUTSIDE_GUARD", WRT, "        try {\n          settled(\n            this.options.logger?.warn(\n              {\n                connector,\n                error: error instanceof Error ? error.message : \"unknown\",", "        const message = error instanceof Error ? error.message : \"unknown\";\n        try {\n          settled(\n            this.options.logger?.warn(\n              {\n                connector,\n                error: message,", `${WRITES}a listener error whose message getter throws does not fail the run or silence later listeners`],
  ["UNSUBSCRIBE_NOT_CALLED", SVC, "    this.unsubscribePlanInputs?.();", "    void this.unsubscribePlanInputs;", `${WRITES}a closed read service stops receiving plan-input changes`],
  ["OPEN_FAILURE_KEEPS_SUBSCRIPTION", SVC, "        unsubscribe?.();\n      } catch {", "        void unsubscribe;\n      } catch {", `${WRITES}a failed open leaves no plan-input callback behind`],
  ["KEY_OMITS_OVERLAY", SVC, "        snapshots.get(t.connector)?.runs ?? [],", "        [],", `${WRITES}misses after an overlay run (overlay snapshot)`],
  ["PROJECTOR_REFUSAL_NOT_CACHED", SVC, "    this.projectability.set(key, ok);", "    if (ok) this.projectability.set(key, ok);", `${BUILD}a projector refusal is built once across listings with no version change`],
  ["OVERLAY_CONNECTORS_DROP_ALL", SVC, 'this.skipped("overlay connectors", error);', 'this.skipped("overlay connectors", error);\n        this.overlayConnectorsLastGood = [];', `${SURV}keeps the last good overlay connector set when connectors() fails`],
];

// Harness mutants: the failure is an import error. The runner must call them
// INVALID. ACCEPT_IMPORT_ERROR_AS_KILL is "caught" when the verdict is INVALID.
const HARNESS = [
  ["ACCEPT_IMPORT_ERROR_AS_KILL", SVC, "export class StreamSyncReadService {", 'import "./this-module-does-not-exist.js";\nexport class StreamSyncReadService {', `${BR}lists an owner's first run of a connector the mirror has never seen`],
];

const scratch = mkdtempSync(join(homedir(), ".tmp", "mutants-read-listing-"));
let active = null; // { file, original }
let child = null; // saved child; killed by handle, never by pattern

function restore() {
  if (active) {
    writeFileSync(active.file, active.original);
    active = null;
  }
}
function cleanup() {
  restore();
  rmSync(scratch, { recursive: true, force: true });
}
for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => {
    child?.kill("SIGKILL");
    cleanup();
    process.exit(130);
  });
}
process.on("exit", cleanup);

let runNumber = 0;
async function runTests() {
  const out = join(scratch, `report-${runNumber++}.json`);
  const status = await new Promise((resolve) => {
    child = spawn(
      "npx",
      ["vitest", "run", "--maxWorkers=4", "--reporter=json", `--outputFile=${out}`, ...TESTS],
      { stdio: "ignore" },
    );
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      resolve("timeout");
    }, TIMEOUT_MS);
    child.on("exit", (code) => {
      clearTimeout(timer);
      resolve(code);
    });
    child.on("error", () => resolve("spawn-error"));
  });
  child = null;
  let report = null;
  try {
    report = JSON.parse(readFileSync(out, "utf8"));
  } catch {
    // no report: judged below
  }
  return { status, report };
}

function outcomes(report) {
  const results = new Map();
  let loadErrors = 0;
  for (const file of report?.testResults ?? []) {
    if (!file.assertionResults?.length && file.status === "failed") loadErrors += 1;
    for (const test of file.assertionResults ?? []) {
      results.set([...(test.ancestorTitles ?? []), test.title].join(" > "), test.status);
    }
  }
  return { results, loadErrors, total: results.size };
}

// KILLED only when the aimed test failed on an assertion and the suite
// otherwise loaded and ran exactly the baseline's tests.
function judge(run, baselineTotal, aimed) {
  if (run.status === "timeout" || run.status === "spawn-error") return `INVALID (${run.status})`;
  if (!run.report) return "INVALID (no report: crash or compile failure)";
  const { results, loadErrors, total } = outcomes(run.report);
  if (loadErrors > 0) return "INVALID (a test file failed to load: import or compile error)";
  if (total === 0) return "INVALID (zero tests ran)";
  if (total !== baselineTotal) return `INVALID (ran ${total} tests, baseline ran ${baselineTotal})`;
  const aimedStatus = results.get(aimed);
  if (aimedStatus === undefined) return "INVALID (aimed test not found)";
  if (aimedStatus === "failed") return "KILLED";
  return "SURVIVED";
}

async function applyAndRun(file, from, to) {
  const original = readFileSync(file);
  const text = original.toString("utf8");
  if (text.split(from).length !== 2) return null;
  active = { file, original };
  writeFileSync(file, text.replace(from, () => to));
  try {
    return await runTests();
  } finally {
    restore();
  }
}

const baseline = await runTests();
const base = outcomes(baseline.report);
const baselineFailed = [...base.results.values()].filter((s) => s !== "passed").length;
if (baseline.status !== 0 || base.total === 0 || base.loadErrors > 0 || baselineFailed > 0) {
  console.log(`BASELINE                             RED (exit ${baseline.status}, ${base.total} tests, ${baselineFailed} not passed, ${base.loadErrors} load errors): aborting`);
  process.exit(2);
}
const rows = [[`BASELINE`, `GREEN (${base.total} tests)`]];
let bad = 0;

for (const [name, file, from, to, aimed] of MUTANTS) {
  const run = await applyAndRun(file, from, to);
  if (!run) {
    rows.push([name, "INVALID (pattern not unique)"]);
    bad += 1;
    continue;
  }
  const verdict = judge(run, base.total, aimed);
  rows.push([name, verdict]);
  if (verdict !== "KILLED") bad += 1;
}
for (const [name, file, from, to, aimed] of HARNESS) {
  const run = await applyAndRun(file, from, to);
  if (!run) {
    rows.push([name, "HARNESS-BROKEN (pattern not unique)"]);
    bad += 1;
    continue;
  }
  const verdict = judge(run, base.total, aimed);
  const caught = verdict.startsWith("INVALID (a test file failed to load");
  rows.push([name, caught ? "CAUGHT (import error rejected as a kill)" : `HARNESS-BROKEN (${verdict})`]);
  if (!caught) bad += 1;
}
execFileSync("git", ["diff", "--exit-code", "--", API, SVC, OVL, MIR, VST, WRT], { stdio: "inherit" });
for (const [n, r] of rows) console.log(`${n.padEnd(36)} ${r}`);
process.exit(bad === 0 ? 0 : 1);
