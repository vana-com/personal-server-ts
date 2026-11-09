#!/usr/bin/env node
// Mutation runner for the MCP account-storage-mode routing.
//
// Each mutant edits one production file, runs the focused tests that must
// notice, and expects them to FAIL (RED). The file is restored byte for byte
// afterward, and the runner exits non-zero if any mutant survives (GREEN) or
// a file does not restore.
//
//   node scripts/mutants/mcp-account-mode.mjs [NAME ...]
import { readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const MCP = "packages/core/src/mcp";
const MODE_TEST = `${MCP}/read-client-account-mode.test.ts`;
const REMEMBER_TEST = "packages/server/src/routes/mcp-remember.test.ts";

/** `from` must occur exactly once in `file`. */
const MUTANTS = [
  {
    name: "READER_PRESENCE_AS_MODE_MCP",
    file: `${MCP}/read-client.ts`,
    from: "const selection = selectAccountStorageMode(options.dataApiDeps);\n    switch (selection.kind) {",
    to: 'const selection = (options.dataApiDeps.streamSyncRead ? { kind: "streams" } : { kind: "legacy" }) as ReturnType<typeof selectAccountStorageMode>;\n    switch (selection.kind) {',
    tests: [MODE_TEST],
  },
  {
    name: "INDEX_SHORTCUT",
    file: `${MCP}/tools.ts`,
    from: '(readClient.storageSelection?.() ?? { kind: "legacy" }).kind ===\n          "legacy" &&\n',
    to: "",
    tests: [MODE_TEST],
  },
  {
    name: "MEMORY_READBACK",
    file: `${MCP}/write-client.ts`,
    from: 'if (selection.kind === "streams") {',
    to: "if (false as boolean) {",
    tests: [MODE_TEST, REMEMBER_TEST],
  },
  {
    name: "MEMORY_READBACK_UNKNOWN",
    file: `${MCP}/write-client.ts`,
    from: 'if (selection.kind === "refuse") {',
    to: "if (false as boolean) {",
    tests: [MODE_TEST, REMEMBER_TEST],
  },
  {
    name: "MCP_SETTLE_LEGACY",
    file: `${MCP}/session.ts`,
    from: "const selection = selectAccountStorageMode(deps);",
    to: 'const selection = { kind: "legacy" } as ReturnType<typeof selectAccountStorageMode>;',
    tests: [MODE_TEST],
  },
  {
    name: "UNKNOWN_WITH_HEAD_SETTLES",
    file: `${MCP}/session.ts`,
    from: 'if (selection.kind === "refuse") {\n          throw new ProtocolError(',
    to: 'if (selection.kind === "refuse" && !input.servedEntry) {\n          throw new ProtocolError(',
    tests: [MODE_TEST],
  },
  {
    name: "MCP_SETTLE_IGNORES_HEAD",
    file: `${MCP}/session.ts`,
    from: "input.servedEntry\n            ? undefined",
    to: "false\n            ? undefined",
    tests: [MODE_TEST],
  },
  {
    name: "SEAL_DROPPED",
    file: `${MCP}/read-client.ts`,
    from: "deps: sealLegacyReads(options.dataApiDeps)",
    to: "deps: options.dataApiDeps",
    tests: [MODE_TEST],
  },
  {
    name: "ALWAYS_REFUSE_STREAMS",
    file: `${MCP}/read-client.ts`,
    from: "if (!options.dataApiDeps.streamSyncRead) {",
    to: "if (true as boolean) {",
    tests: [MODE_TEST],
  },
  {
    name: "UNKNOWN_AS_LEGACY",
    file: `${MCP}/read-client.ts`,
    from: '      case "refuse":\n        throw new McpDataReadError(',
    to: '      case "refuse":\n        return { kind: "legacy", deps: options.dataApiDeps };\n      case "unreachable" as never:\n        throw new McpDataReadError(',
    tests: [MODE_TEST],
  },
  {
    name: "STORAGE_SELECTION_DROPPED",
    file: `${MCP}/read-client.ts`,
    from: "    storageSelection: () => selectAccountStorageMode(options.dataApiDeps),\n",
    to: "",
    tests: [MODE_TEST],
  },
  {
    name: "STREAM_LIST_AS_EMPTY_SUCCESS",
    file: `${MCP}/read-client.ts`,
    from: 'route.kind === "streams" &&\n        typeof (',
    to: "false &&\n        typeof (",
    tests: [MODE_TEST],
  },
  {
    name: "WRITE_CLIENT_MODE_NOT_WIRED",
    file: "packages/server/src/routes/mcp.ts",
    from: "    accountStorage: { accountStorageMode: deps.accountStorageMode },\n",
    to: "",
    tests: [REMEMBER_TEST],
  },
];

const wanted = process.argv.slice(2);
const selected = wanted.length
  ? MUTANTS.filter((m) => wanted.includes(m.name))
  : MUTANTS;
if (wanted.length && selected.length !== wanted.length) {
  console.error(`unknown mutant in: ${wanted.join(", ")}`);
  process.exit(2);
}

const rows = [];
let bad = false;
for (const m of selected) {
  const path = resolve(root, m.file);
  const original = readFileSync(path, "utf8");
  const occurrences = original.split(m.from).length - 1;
  if (occurrences !== 1) {
    rows.push([m.name, `PATTERN (${occurrences} matches)`]);
    bad = true;
    continue;
  }
  let verdict;
  try {
    writeFileSync(
      path,
      original.replace(m.from, () => m.to),
    );
    const run = spawnSync(
      "nice",
      ["-n", "19", "npx", "vitest", "run", "--maxWorkers=4", ...m.tests],
      { cwd: root, encoding: "utf8" },
    );
    verdict = run.status === 0 ? "GREEN (survived)" : "RED";
    if (run.status === 0) bad = true;
  } finally {
    writeFileSync(path, original);
  }
  if (readFileSync(path, "utf8") !== original) {
    verdict += " + NOT RESTORED";
    bad = true;
  }
  rows.push([m.name, verdict]);
  console.log(`${m.name}: ${verdict}`);
}
console.log("\n" + rows.map(([n, v]) => `${n.padEnd(34)} ${v}`).join("\n"));
process.exit(bad ? 1 : 0);
