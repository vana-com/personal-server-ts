#!/usr/bin/env node
/**
 * Mutant runner for the account storage mode.
 *
 * Each mutant is one small edit to production code that re-introduces a named
 * defect. The runner applies it in place, runs the focused tests that must
 * catch it, and records RED (caught) or GREEN (missed, a test gap). It puts
 * every file back byte for byte, also on Ctrl-C, and checks that it did.
 *
 *   node scripts/mutants/account-storage-mode.mjs [name-substring ...]
 *
 * Exit code 1 when any mutant stays GREEN or a file did not restore.
 * Run it with Node 22 from the repository root.
 */
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";

const CORE = "packages/core/src/api/account-storage-mode.test.ts";
const GATES = [
  "packages/core/src/api/legacy-write-gate.test.ts",
  "packages/core/src/api/legacy-write-refusal-core.test.ts",
];
const SERVER = [
  "packages/server/src/app-refuse-legacy-writes.test.ts",
  "packages/server/src/routes/mcp-account-storage-mode.test.ts",
  "packages/server/src/routes/data-refuse-legacy-writes.test.ts",
  "packages/server/src/routes/data-write.test.ts",
];
const LITE = [
  "packages/lite/src/runtime-account-storage-mode.test.ts",
  "packages/lite/src/runtime-write.test.ts",
];

const MODE = "packages/core/src/api/account-storage-mode.ts";
const API = "packages/core/src/api/index.ts";
const APP = "packages/server/src/app.ts";
const MCP = "packages/server/src/routes/mcp.ts";
const DATA = "packages/server/src/routes/data.ts";
const OURA = "packages/server/src/routes/oura.ts";
const LITE_RT = "packages/lite/src/runtime.ts";

/** A bound view that asks without the owner: the mode can only answer unknown. */
const OWNERLESS = '{ owner: "", read: () => "unknown" as const }';

/** [name, file, old text (exactly once), new text, tests that must go RED] */
const MUTANTS = [
  [
    "GATE_AND_SELECTOR_DISAGREE: plain switch wins over the mode",
    API,
    "  return deps.accountStorageMode\n    ? legacyWriteSwitchOf(deps.accountStorageMode)\n    : deps.legacyWritesRefused;",
    "  return (\n    deps.legacyWritesRefused ??\n    (deps.accountStorageMode\n      ? legacyWriteSwitchOf(deps.accountStorageMode)\n      : undefined)\n  );",
    [CORE],
  ],
  [
    "GATE_AND_SELECTOR_DISAGREE: gate refuses on unknown",
    MODE,
    '  return () => mode.read() === "switched";',
    '  return () => mode.read() !== "unswitched";',
    [CORE],
  ],
  [
    "READER_PRESENCE_AS_MODE: selector keys on the stream reader",
    MODE,
    '  if (deps.accountStorageMode === undefined) return { kind: "legacy" };',
    '  if ((deps as { streamSyncRead?: unknown }).streamSyncRead) return { kind: "streams" };\n  if (deps.accountStorageMode === undefined) return { kind: "legacy" };',
    [CORE],
  ],
  [
    "UNKNOWN_READS_LEGACY: unknown selects legacy",
    MODE,
    '    case "unknown":\n      return {\n        kind: "refuse",',
    '    case "unknown":\n      return { kind: "legacy" };\n    case "never" as never:\n      return {\n        kind: "refuse",',
    [CORE],
  ],
  [
    "LATCH_CROSSES_ACCOUNTS: latch at module scope",
    MODE,
    "  let latched = false;\n  return {",
    "  return {",
    [CORE],
    [
      "export function createAccountStorageMode(",
      "let latched = false;\nexport function createAccountStorageMode(",
    ],
  ],
  [
    "DROP_REQUEST_OWNER: the port stops checking the owner",
    MODE,
    '      if (\n        !requestOwner ||\n        !input.owner ||\n        !sameOwner(input.owner, requestOwner)\n      ) {\n        return "unknown";\n      }',
    "",
    [CORE, ...SERVER, ...LITE],
  ],
  [
    "DROP_REQUEST_OWNER: the binding asks without the owner",
    MODE,
    '  const bound = owner ?? "";',
    '  const bound = "";',
    [CORE, ...SERVER, ...LITE],
  ],
  [
    "UNSWITCHED_CHANGED: unswitched selects streams",
    MODE,
    '    case "unswitched":\n      return { kind: "legacy" };',
    '    case "unswitched":\n      return { kind: "streams" };',
    [CORE],
  ],
  [
    "#591: latch dropped",
    MODE,
    "          latched = true;\n",
    "",
    [...GATES, CORE, ...SERVER, ...LITE],
  ],
  [
    "#591: write gate switch removed",
    API,
    "  return deps.accountStorageMode\n    ? legacyWriteSwitchOf(deps.accountStorageMode)\n    : deps.legacyWritesRefused;",
    "  return undefined;",
    [CORE, ...GATES, ...SERVER, ...LITE],
  ],
  [
    "MCP_REQUEST_OWNER_DROPPED: Node MCP engines ask without the owner",
    MCP,
    "    accountStorageMode: deps.accountStorageMode,\n    auth,",
    `    accountStorageMode: deps.accountStorageMode && ${OWNERLESS},\n    auth,`,
    SERVER,
  ],
  [
    "MCP_REQUEST_OWNER_DROPPED: Lite MCP engine asks without the owner",
    LITE_RT,
    "        accountStorageMode: input.accountStorageMode,\n",
    `        accountStorageMode: input.accountStorageMode && ${OWNERLESS},\n`,
    LITE,
  ],
  [
    "LITE_APPEND_OWNER_DROPPED: Lite scope-upload append asks without the owner",
    LITE_RT,
    "                scopeUploads,\n                accountStorageMode,\n",
    `                scopeUploads,\n                accountStorageMode: accountStorageMode && ${OWNERLESS},\n`,
    LITE,
  ],
  [
    "DROP_REQUEST_OWNER: Lite data handler asks without the owner",
    LITE_RT,
    "              storage: dataStorage,\n              accountStorageMode,\n              auth,\n              logger",
    `              storage: dataStorage,\n              accountStorageMode: accountStorageMode && ${OWNERLESS},\n              auth,\n              logger`,
    LITE,
  ],
  [
    "DROP_REQUEST_OWNER: Lite Oura gate asks without the owner",
    LITE_RT,
    "            accountStorageMode\n              ? legacyWriteSwitchOf(accountStorageMode)\n              : undefined,",
    `            accountStorageMode\n              ? legacyWriteSwitchOf(${OWNERLESS})\n              : undefined,`,
    LITE,
  ],
  [
    "DROP_REQUEST_OWNER: Lite binds the runtime without its owner",
    LITE_RT,
    "      ? accountStorageModeFor(options.accountStorageMode, ownerAddress())",
    "      ? accountStorageModeFor(options.accountStorageMode, undefined)",
    LITE,
  ],
  [
    "DROP_REQUEST_OWNER: createApp binds the server without its owner",
    APP,
    "    deps.serverOwner,\n  );\n",
    "    undefined,\n  );\n",
    SERVER,
  ],
  [
    "DROP_REQUEST_OWNER: Node data routes ask without the owner",
    DATA,
    "        accountStorageMode: deps.accountStorageMode,\n        auth,",
    `        accountStorageMode: deps.accountStorageMode && ${OWNERLESS},\n        auth,`,
    SERVER,
  ],
  [
    "DROP_REQUEST_OWNER: Node write gate asks without the owner",
    DATA,
    "    ? legacyWriteSwitchOf(deps.accountStorageMode)",
    `    ? legacyWriteSwitchOf(${OWNERLESS})`,
    SERVER,
  ],
  [
    "DROP_REQUEST_OWNER: Node Oura gate asks without the owner",
    OURA,
    "        ? legacyWriteSwitchOf(deps.accountStorageMode)",
    `        ? legacyWriteSwitchOf(${OWNERLESS})`,
    SERVER,
  ],
  [
    "WIRING: createApp does not hand the mode to the data routes",
    APP,
    "      // The account's storage mode (see the top of createApp).\n      accountStorageMode,\n",
    "",
    SERVER,
  ],
  [
    "WIRING: createApp does not hand the mode to the MCP route deps",
    APP,
    "    streamSyncRead: deps.streamSyncRead,\n    accountStorageMode,\n    runtimeAvailability",
    "    streamSyncRead: deps.streamSyncRead,\n    runtimeAvailability",
    SERVER,
  ],
  [
    "WIRING: buildDataApiDeps drops the mode (Node MCP engines)",
    MCP,
    "    accountStorageMode: deps.accountStorageMode,\n    auth,",
    "    auth,",
    SERVER,
  ],
  [
    "WIRING: Lite MCP dataApiDeps drops the mode",
    LITE_RT,
    "        accountStorageMode: input.accountStorageMode,\n",
    "",
    LITE,
  ],
];

const filters = process.argv.slice(2);
const selected = MUTANTS.filter(
  ([name]) => filters.length === 0 || filters.some((f) => name.includes(f)),
);

const originals = new Map();
function original(file) {
  if (!originals.has(file)) originals.set(file, readFileSync(file, "utf8"));
  return originals.get(file);
}
function restoreAll() {
  for (const [file, text] of originals) writeFileSync(file, text);
}
for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => {
    restoreAll();
    process.exit(130);
  });
}

const rows = [];
try {
  for (const [name, file, from, to, tests, extra] of selected) {
    const text = original(file);
    if (text.split(from).length !== 2) {
      throw new Error(`${name}: expected one match in ${file}`);
    }
    let mutated = text.replace(from, () => to);
    if (extra) {
      if (mutated.split(extra[0]).length !== 2) {
        throw new Error(`${name}: expected one match for the second edit`);
      }
      mutated = mutated.replace(extra[0], () => extra[1]);
    }
    writeFileSync(file, mutated);
    const run = spawnSync(
      "nice",
      ["-n", "19", "npx", "vitest", "run", "--maxWorkers=4", ...tests],
      { encoding: "utf8" },
    );
    writeFileSync(file, text);
    const out = `${run.stdout}\n${run.stderr}`;
    const failed = new Set(
      out
        .split("\n")
        .filter((line) => line.trim().startsWith("FAIL"))
        .map((line) => line.trim()),
    ).size;
    const red = run.status !== 0;
    rows.push({ name, red, failed });
    console.log(
      `${red ? "RED  " : "GREEN"} ${String(failed).padStart(3)}  ${name}`,
    );
  }
} finally {
  restoreAll();
}

let restored = true;
for (const [file, text] of originals) {
  if (readFileSync(file, "utf8") !== text) {
    restored = false;
    console.error(`NOT RESTORED: ${file}`);
  }
}
const missed = rows.filter((r) => !r.red);
console.log(
  `\n${rows.length - missed.length}/${rows.length} mutants caught; files restored: ${restored}`,
);
process.exit(missed.length > 0 || !restored ? 1 : 0);
