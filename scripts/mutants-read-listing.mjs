#!/usr/bin/env node
// Mutant runner for the switched-account scope listing (stream-sync-read-listing).
// Applies each mutant, expects the focused tests to FAIL, restores the file
// byte for byte, and prints a table. Exit 1 if any mutant survives.
// Run from the repo root: nice -n 19 node scripts/mutants-read-listing.mjs
import { execFileSync, spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";

const API = "packages/core/src/api/index.ts";
const OVL = "packages/core/src/stream-sync/writer-overlay.ts";
const SVC = "packages/core/src/stream-sync-read/service.ts";
const TESTS = [
  "packages/core/src/api/stream-sync-read-listing.test.ts",
  "packages/core/src/stream-sync-read/readable-scopes.test.ts",
];

const MUTANTS = [
  ["ALWAYS_REFUSE", API, "return listStreamSyncScopes(deps, url, listAuth);", 'return errorResponse(503, "X", "x");'],
  ["LIST_LEGACY", API, "  const scopes = readable.filter(", "  const scopes = [...readable, ...deps.storage.listScopes({ limit: 100 }).scopes].filter("],
  ["LIST_HIDES_READABLE", API, "  const scopes = readable.filter(", "  const scopes = readable.slice(1).filter("],
  ["VERSIONS_LEGACY", API, '        return streamHistoryUnsupported("versions");', "        void 0;"],
  ["LINEAGE_LEGACY", API, '        return streamHistoryUnsupported("lineage");', "        void 0;"],
  ["ADDITIONS_LEGACY", API, '        return streamHistoryUnsupported("additions");', "        void 0;"],
  ["READER_PRESENCE_AS_MODE", API, 'if (storageSelection?.kind === "streams") {\n        return listStreamSyncScopes', 'if (storageSelection?.kind === "streams" && deps.streamSyncRead) {\n        return listStreamSyncScopes'],
  ["UNKNOWN_READS_LEGACY", API, '      if (storageSelection?.kind === "refuse") return storageSelection.response;\n      if (storageSelection?.kind === "streams") {\n        return listStreamSyncScopes', '      if (storageSelection?.kind === "streams") {\n        return listStreamSyncScopes'],
  ["UNSWITCHED_CHANGED", API, 'if (storageSelection?.kind === "streams") {\n        return listStreamSyncScopes', "if (storageSelection) {\n        return listStreamSyncScopes"],
  ["OVERLAY_CONNECTORS_EMPTY", OVL, "connectors: () => writer.overlayConnectors(),", "connectors: async () => [],"],
  ["MIRROR_ONLY_CONNECTOR_DISCOVERY", SVC, "if (input.isOwnerView && this.options.overlay) {", "if (false) {"],
  ["OMIT_OVERLAY_STREAM_NAMES", SVC, "        for (const run of snapshot.runs) {\n          for (const stream of run.streams) addLogical(connector, stream.name);\n        }", ""],
  ["RESOLVE_BEFORE_GRANT_AND_PAGE", SVC, "      if (input.isCovered && !input.isCovered(scope)) continue;\n      let newest: number | null;\n      try {\n        const found = await this.readable(scope, input.isOwnerView);\n        if (!found) continue;", "      let newest: number | null;\n      try {\n        const found = await this.readable(scope, input.isOwnerView);\n        if (!found) continue;\n        if (input.isCovered && !input.isCovered(scope)) continue;"],
  ["ABORT_LIST_ON_ONE_FAILURE", SVC, "      } catch (error) {\n        this.options.logger.warn(", "      } catch (error) {\n        throw error;\n        this.options.logger.warn("],
  ["BODY_BUILT_FOR_LISTING", SVC, "        const found = await this.readable(scope, input.isOwnerView);", "        const decision = await this.resolve({ scope, connection: null, cursor: null, legacyFile: false, isOwnerView: input.isOwnerView });\n        if (\"body\" in decision) await decision.body.cancel();\n        const found = await this.readable(scope, input.isOwnerView);"],
];

let survived = 0;
const rows = [];
for (const [name, file, from, to] of MUTANTS) {
  const original = readFileSync(file);
  const text = original.toString("utf8");
  if (text.split(from).length !== 2) {
    rows.push([name, "NOT-APPLIED (pattern not unique)"]);
    survived += 1;
    continue;
  }
  writeFileSync(file, text.replace(from, () => to));
  try {
    const run = spawnSync("npx", ["vitest", "run", "--maxWorkers=4", ...TESTS], { encoding: "utf8" });
    const failed = run.status !== 0;
    if (!failed) survived += 1;
    rows.push([name, failed ? "RED (killed)" : "GREEN (SURVIVED)"]);
  } finally {
    writeFileSync(file, original);
  }
}
execFileSync("git", ["diff", "--exit-code", "--", API, SVC, OVL], { stdio: "inherit" });
for (const [n, r] of rows) console.log(`${n.padEnd(36)} ${r}`);
process.exit(survived === 0 ? 0 : 1);
