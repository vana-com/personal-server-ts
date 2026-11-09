#!/usr/bin/env node
/**
 * Mutant runner for the shared account-mode module.
 *
 * Each mutant re-introduces one named defect with a small edit to production
 * code. The runner applies it in place, runs the focused tests, and reads the
 * vitest JSON report. A mutant is KILLED only when a test named as its aim ran
 * and failed. These outcomes are never kills:
 *   INVALID   the aimed test did not run, or a test file failed to load or build
 *   SURVIVED  the aimed test ran and passed
 *
 *   node scripts/mutants/account-mode-module.mjs [name-substring ...]
 *
 * The unmutated baseline runs first. If any aimed test is missing or red, the
 * runner stops before it mutates anything. Every mutated file is put back byte
 * for byte, also on SIGINT and SIGTERM, and the runner checks that it did.
 * Exit code 1 for any mutant that is not killed, a red baseline, or a file that
 * did not restore. Run it with Node 22 from the repository root, in the
 * foreground, to the end.
 */
import { spawn } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const DIR = "packages/core/src/sync/account-mode";
const AUTHORITY = `${DIR}/authority.ts`;
// The policy: the only place that decides what the mode is.
const CORE = `${DIR}/mode-machine.ts`;
const FLAG = `${DIR}/flag-evidence.ts`;

const RECORD_STORE = `${DIR}/record-store.ts`;
const NODE_STORE = "packages/server/src/account-mode/file-record-store.ts";
const LITE_STORE = "packages/lite/src/account-mode-store.ts";
const APP = "packages/server/src/app.ts";
const LITE_RUNTIME = "packages/lite/src/runtime.ts";

const AUTHORITY_TESTS = `${DIR}/authority.test.ts`;
const FLAG_TESTS = `${DIR}/flag-evidence.test.ts`;
// Runs the shared vectors (vectors.json) and the policy's unit tests.
const CORE_TESTS = `${DIR}/mode-machine.test.ts`;
const NODE_STORE_TESTS =
  "packages/server/src/account-mode/file-record-store.test.ts";
const LITE_STORE_TESTS = "packages/lite/src/account-mode-store.test.ts";
const SERVER_APP_TESTS = "packages/server/src/routes/account-mode.test.ts";
const LITE_RUNTIME_TESTS = "packages/lite/src/runtime-account-mode.test.ts";
// The core files run for every mutant of core code. A mutant of a host file
// names its own test files: those import the host source directly, and reach
// the module through its built output, which a mutant of core cannot change.
const CORE_FILES = [AUTHORITY_TESTS, FLAG_TESTS, CORE_TESTS];
const TEST_FILES = [
  ...CORE_FILES,
  NODE_STORE_TESTS,
  LITE_STORE_TESTS,
  SERVER_APP_TESTS,
  LITE_RUNTIME_TESTS,
];

const nodeStore = (name) => ({ file: NODE_STORE_TESTS, name });
const liteStore = (name) => ({ file: LITE_STORE_TESTS, name });
const serverApp = (name) => ({ file: SERVER_APP_TESTS, name });
const liteRuntime = (name) => ({ file: LITE_RUNTIME_TESTS, name });

const vector = (id) => ({
  file: CORE_TESTS,
  name: `the shared vectors, run through the module ${id}`,
});
const authority = (name) => ({ file: AUTHORITY_TESTS, name });
const core = (name) => ({ file: CORE_TESTS, name });

/**
 * name, edits [[file, old text (exactly once), new text]], aimed tests.
 * The aimed test is the one that must fail; others may fail too.
 */
const MUTANTS = [
  {
    name: "UNKNOWN_AS_OFF",
    edits: [[CORE, "        succeeded(event.rawStatus) &&\n", ""]],
    aimed: [
      authority("changes nothing for an answer that was not a success"),
      vector("unknown-evidence-refuses"),
      core(
        "UNKNOWN_AS_OFF: an answer that is not a usable Off never mints or ends one",
      ),
    ],
  },
  {
    name: "OFF_AFTER_ON_LOWERS",
    edits: [
      [
        CORE,
        "      } else if (!next.switched) {\n        // An older",
        "      } else {\n        // An older",
      ],
      [
        CORE,
        "            cleanOffAt: clock.nowWall,\n            offFetchStartMono: event.fetchStartMono as number,",
        "            switched: false,\n            cleanOffAt: clock.nowWall,\n            offFetchStartMono: event.fetchStartMono as number,",
      ],
    ],
    aimed: [
      vector("on-is-never-lowered"),
      core(
        "OFF_AFTER_ON_LOWERS: a later Off and an outage do not lower a saved On",
      ),
    ],
  },
  {
    name: "OWNERLESS_READ_ANSWERS",
    edits: [
      [
        CORE,
        "  if (!validModeOwner(owner)) return refuseUnchanged();\n  if (record !== null && record.owner !== owner) return refuseUnchanged();\n",
        "",
      ],
      [
        AUTHORITY,
        "      records.get(normalizeOwner(event.owner)) ?? null,\n      event,\n      now(),\n    ).decision;",
        "      records.get(normalizeOwner(event.owner)) ??\n        records.values().next().value ??\n        null,\n      event,\n      now(),\n    ).decision;",
      ],
    ],
    aimed: [
      authority("is unknown, even though other owners have answers"),
      vector("owner-mismatch-is-unknown"),
      core(
        "OWNERLESS_READ_ANSWERS: a missing or foreign owner changes nothing",
      ),
    ],
  },
  {
    name: "ADMISSION_ONLY_CHECK",
    edits: [
      [
        AUTHORITY,
        "  function refusal(decision: ModeDecision): RefuseDecision | null {\n",
        "  function refusal(decision: ModeDecision): RefuseDecision | null {\n    // Mutant: the mode was checked at admission; a commit trusts that.\n    if (decision) return null;\n",
      ],
    ],
    aimed: [
      authority(
        "refuses a write that was admitted before the account switched",
      ),
      vector("commit-rechecks-after-admission"),
    ],
  },
  {
    name: "LATCH_NOT_DURABLE",
    edits: [
      [
        AUTHORITY,
        "      await settleWithin(\n        options.store.save(owner, next, stored.get(owner) ?? null),\n        saveTimeoutMs,\n      );",
        "      await Promise.resolve();",
      ],
    ],
    aimed: [
      authority("survives a restart that forgets everything but the store"),
      vector("on-survives-crash-and-wipe"),
    ],
  },
  {
    name: "SAVE_AFTER_USE",
    edits: [
      [
        AUTHORITY,
        "    try {\n      await settleWithin(",
        '    apply({ type: "saveComplete", owner });\n    try {\n      await settleWithin(',
      ],
    ],
    aimed: [
      authority("blocks legacy work and stream answers until the save settles"),
      vector("on-save-boundaries"),
    ],
  },
  {
    name: "OFF_NEVER_EXPIRES",
    edits: [
      [
        CORE,
        "    nowMono - fetchStartMono < OFF_TTL_MS\n  );",
        "    true\n  );",
      ],
    ],
    aimed: [
      vector("off-expires-at-deadline"),
      core("OFF_NEVER_EXPIRES: the deadline itself is expired"),
    ],
  },
  {
    name: "EXPIRY_LOWERS_LATCH",
    edits: [
      [
        CORE,
        "  return record.offFetchStartMono === null\n    ? record\n    : { ...record, offFetchStartMono: null };",
        "  return { ...record, switched: false, offFetchStartMono: null };",
      ],
    ],
    aimed: [
      vector("on-survives-crash-and-wipe"),
      core(
        "EXPIRY_LOWERS_LATCH: expiry and an untrusted reboot keep a saved On",
      ),
    ],
  },
  {
    name: "FLAG_MINTS_OFF",
    edits: [
      [
        FLAG,
        '    state: "unknown",',
        '    state: _flag?.write ? "unknown" : "off",',
      ],
    ],
    aimed: [
      { file: FLAG_TESTS, name: "never says Off, whatever the flags hold" },
    ],
  },
  {
    name: "SEAL_OUTSIDE_LOCK",
    edits: [
      [
        AUTHORITY,
        "      const release = await lock.shared();",
        "      const release = () => {};",
      ],
    ],
    aimed: [
      authority(
        "makes an On latch wait for a legacy write in flight, and refuses the write queued behind it",
      ),
    ],
  },
  {
    name: "NEVER_SEEN_OWNER_ADMITS",
    edits: [
      [
        CORE,
        '  if (record === null && event.type !== "evidence") return refuseUnchanged();',
        '  if (record === null && event.type !== "evidence")\n    record = createModeRecord(owner, clock.bootId);',
      ],
      [
        CORE,
        "    if (unsaved(record) || !freshOff(record, clock)) return UNKNOWN;",
        "    if (unsaved(record) || (record.cleanOffAt !== null && !freshOff(record, clock)))\n      return UNKNOWN;",
      ],
    ],
    aimed: [
      authority("answers 503 for an owner it has never heard of"),
      core(
        "NEVER_SEEN_OWNER_ADMITS: first access is unknown and creates nothing",
      ),
    ],
  },
  {
    name: "OFF_USED_BEFORE_SAVE",
    edits: [
      [
        AUTHORITY,
        '      const decision = apply({ type: "saveFailed", owner }).decision;',
        '      const decision = apply({ type: "saveComplete", owner }).decision;',
      ],
    ],
    aimed: [
      vector("off-save-fails"),
      authority(
        "treats an Off whose save throws as unknown, until a later Off is saved",
      ),
    ],
  },
  {
    name: "DROP_PENDING_ON_ON_SAVE_FAILURE",
    edits: [
      [
        AUTHORITY,
        '      const decision = apply({ type: "saveFailed", owner }).decision;',
        '      apply({ type: "saveFailed", owner });\n      const prior = stored.get(owner);\n      if (prior) records.set(owner, fromDurable(owner, prior));\n      const decision = decide({ type: "read", owner });',
      ],
    ],
    aimed: [
      authority(
        "is held in memory, so a store that still serves the old Off never brings legacy back",
      ),
    ],
  },
  {
    name: "OUTAGE_ENDS_FRESH_OFF",
    edits: [
      [
        CORE,
        "return record === null ? refuseUnchanged() : settle(record);",
        "return record === null ? refuseUnchanged() : settle(expireOff(record));",
      ],
    ],
    aimed: [
      vector("outage-keeps-fresh-off"),
      authority(
        "leave a still-fresh Off in place, because an unreachable Account blocks no one who has not switched",
      ),
    ],
  },
  {
    name: "OLDER_RESPONSE_EXTENDS_OFF",
    edits: [
      [
        CORE,
        "          (event.fetchStartMono as number) >= next.offFetchStartMono;",
        "          true;",
      ],
    ],
    aimed: [
      core("does not extend freshness when an older response arrives late"),
    ],
  },
  {
    name: "OWNER_CASE_SENSITIVE",
    edits: [[CORE, "owner.toLowerCase()", "owner"]],
    aimed: [
      authority("is folded to lower case, so one address is one owner"),
      core("owners are compared lowercased"),
    ],
  },
  {
    name: "SECOND_RUNTIME_ADMITTED (core: the claim is not required)",
    edits: [
      [
        AUTHORITY,
        "    const mine = await options.store.claim();",
        "    const mine = await options.store\n      .claim()\n      .catch((): ModeStoreLease => ({ release: async () => {} }));",
      ],
    ],
    aimed: [
      authority(
        "refuses a second runtime on the same store, and it never admits a legacy write",
      ),
      vector("second-runtime-is-refused"),
    ],
  },
  {
    name: "SECOND_RUNTIME_ADMITTED (Node: the lock file is not checked)",
    files: [NODE_STORE_TESTS],
    edits: [
      [
        NODE_STORE,
        "        if (await createLock(token)) {",
        "        await createLock(token);\n        {",
      ],
    ],
    aimed: [
      nodeStore(
        "lets one runtime own the folder, and refuses a second without touching its files",
      ),
      nodeStore(
        "two authorities on the folder: the second is refused and its Off never reaches the disk",
      ),
    ],
  },
  {
    name: "SECOND_RUNTIME_ADMITTED (Lite: the Web Lock is not checked)",
    files: [LITE_STORE_TESTS],
    edits: [
      [
        LITE_STORE,
        "            if (!lock) {\n              reject(new ModeStoreOwnedError());\n              return;\n            }\n",
        "",
      ],
    ],
    aimed: [
      liteStore(
        "lets one tab own the database and refuses a second until the first lets go",
      ),
      liteStore(
        "two authorities on the database: the second is refused and writes nothing",
      ),
    ],
  },
  {
    name: "LIVE_LOCK_TAKEN_OVER",
    files: [NODE_STORE_TESTS],
    edits: [
      [
        NODE_STORE,
        "    if (!body || body.host !== hostname() || !processIsGone(body.pid)) {",
        "    if (!body) {",
      ],
    ],
    aimed: [
      nodeStore(
        "takes over a lock whose process is gone, and keeps one held by a live process",
      ),
    ],
  },
  {
    name: "SWEEP_BY_NON_OWNER (a load deletes another runtime's temp file)",
    files: [NODE_STORE_TESTS],
    edits: [
      [
        NODE_STORE,
        "      const records = new Map<string, DurableModeRecord>();\n      for (const name of await readdir(dir)) {\n        const match",
        "      const records = new Map<string, DurableModeRecord>();\n      await sweepTemps();\n      for (const name of await readdir(dir)) {\n        const match",
      ],
    ],
    aimed: [
      nodeStore(
        "sweeps the temp file of a crashed save when it becomes the owner, and at no other time",
      ),
      nodeStore(
        "lets one runtime own the folder, and refuses a second without touching its files",
      ),
    ],
  },
  {
    name: "BLIND_OFF_OVERWRITES_ON (core: a stored On can be lowered)",
    edits: [
      [
        RECORD_STORE,
        '    if (!next.switched) {\n      throw new ModeStoreConflictError("an On record cannot be lowered");\n    }\n',
        "",
      ],
    ],
    aimed: [
      authority(
        "rejects an Off write over a stored On, and a write based on a stale read",
      ),
    ],
  },
  {
    name: "BLIND_OFF_OVERWRITES_ON (core: the expected record is not compared)",
    edits: [
      [
        RECORD_STORE,
        "  if (!sameDurableRecord(current, expected)) {",
        "  if (false) {",
      ],
    ],
    aimed: [
      authority(
        "rejects an Off write over a stored On, and a write based on a stale read",
      ),
    ],
  },
  {
    name: "BLIND_OFF_OVERWRITES_ON (Node: the file is written without the check)",
    files: [NODE_STORE_TESTS],
    edits: [
      [
        NODE_STORE,
        "        assertMonotoneWrite(await readCurrent(owner), expected, record);\n",
        "",
      ],
    ],
    aimed: [
      nodeStore(
        "rejects an Off over a stored On and a write based on a stale read, leaving the file as it was",
      ),
    ],
  },
  {
    name: "BLIND_OFF_OVERWRITES_ON (Lite: the row is written without the check)",
    files: [LITE_STORE_TESTS],
    edits: [
      [
        LITE_STORE,
        "              assertMonotoneWrite(\n                found === undefined ? null : toRecord(found as StoredRow),\n                expected,\n                record,\n              );\n",
        "",
      ],
    ],
    aimed: [
      liteStore(
        "rejects an Off over a stored On and a write based on a stale read, in one transaction",
      ),
    ],
  },
  {
    name: "COMMIT_TRUSTS_MEMORY (the commit does not re-read the store)",
    edits: [
      [
        AUTHORITY,
        "        if (!(await refresh(normalizeOwner(owner)))) {",
        "        if (false) {",
      ],
    ],
    aimed: [
      authority(
        "picks up an On that something other than this runtime saved to the store",
      ),
    ],
  },
  {
    name: "ASYNC_CALLBACK_ESCAPES_SYNC_SEAL (a synchronous commit exists again)",
    edits: [
      [
        AUTHORITY,
        "    async commitLegacy(owner, operationId, write) {",
        "    commitLegacySync(owner: string, operationId: string, write: () => unknown) {\n      const refused = refusal(decide(commitEvent(owner, operationId)));\n      if (refused) return { ok: false, decision: refused };\n      return { ok: true, value: write() };\n    },\n\n    async commitLegacy(owner, operationId, write) {",
      ],
    ],
    aimed: [
      authority(
        "has no synchronous commit: every legacy write holds the lock until it settles",
      ),
    ],
  },
  {
    name: "INDEPENDENT_APP_MODE_PORT (server: the app takes a mode beside the module)",
    files: [SERVER_APP_TESTS],
    edits: [
      [
        APP,
        '    deps.accountModeAuthority\n      ? accountStorageModeOf(deps.accountModeAuthority)\n      : { read: () => "unknown" },',
        '    (deps as { accountStorageMode?: never }).accountStorageMode ??\n      (deps.accountModeAuthority\n        ? accountStorageModeOf(deps.accountModeAuthority)\n        : { read: () => "unknown" }),',
      ],
    ],
    aimed: [
      serverApp(
        "ignores a mode passed beside the module: an On in the module refuses a legacy write",
      ),
      serverApp(
        "ignores a mode passed with no module: legacy writes stay refused with 503",
      ),
    ],
  },
  {
    name: "INDEPENDENT_APP_MODE_PORT (Lite: the runtime takes a mode beside the module)",
    files: [LITE_RUNTIME_TESTS],
    edits: [
      [
        LITE_RUNTIME,
        '    options.accountModeAuthority\n      ? accountStorageModeOf(options.accountModeAuthority)\n      : { read: () => "unknown" },',
        '    (options as { accountStorageMode?: never }).accountStorageMode ??\n      (options.accountModeAuthority\n        ? accountStorageModeOf(options.accountModeAuthority)\n        : { read: () => "unknown" }),',
      ],
    ],
    aimed: [
      liteRuntime(
        "ignores a mode passed beside the module: an On in the module refuses a legacy write",
      ),
      liteRuntime(
        "ignores a mode passed with no module: legacy writes stay refused with 503",
      ),
    ],
  },
  {
    name: "IMPORT_FLAG_NOT_PERSISTED",
    edits: [
      [
        CORE,
        "    bootId: record.bootId,\n    importPending: record.importPending,\n  };",
        "    bootId: record.bootId,\n    importPending: false,\n  };",
      ],
    ],
    aimed: [
      authority(
        "saves importPending in the same write as the first On, when the owner has legacy files",
      ),
      authority(
        "survives a crash between the On save and the answer: a restarted host is told again",
      ),
      vector("import-pending-survives-crash"),
    ],
  },
  {
    name: "STREAM_WRITE_BEFORE_IMPORT_DONE",
    edits: [
      [
        CORE,
        '  if (\n    event.type === "commit" &&\n    event.sink === "stream" &&\n    record.importPending\n  ) {\n    return { kind: "refuse", code: "IMPORT_PENDING", status: 503 };\n  }\n',
        "",
      ],
    ],
    aimed: [
      authority(
        "refuses stream commits with 503 IMPORT_PENDING until importDone is saved",
      ),
      core(
        "STREAM_WRITE_BEFORE_IMPORT_DONE: a stream commit is refused until the import is done",
      ),
      vector("import-pending-survives-crash"),
    ],
  },
  {
    name: "ORDINARY_WRITE_PASSES_WHILE_PENDING",
    edits: [
      [
        AUTHORITY,
        '      decide({ type: "commit", owner, operationId, sink: "stream" }),',
        '      decide({ type: "commit", owner, operationId, sink: "importSeed" }),',
      ],
    ],
    aimed: [
      authority(
        "admits only the importer's seed publish while the import is pending",
      ),
      authority(
        "refuses stream commits with 503 IMPORT_PENDING until importDone is saved",
      ),
      vector("import-seed-publish-while-pending"),
    ],
  },
  {
    name: "IMPORT_SEED_REFUSED_WHILE_PENDING",
    edits: [
      [
        AUTHORITY,
        '      decide({ type: "commit", owner, operationId, sink: "importSeed" }),',
        '      decide({ type: "commit", owner, operationId, sink: "stream" }),',
      ],
    ],
    aimed: [
      authority(
        "admits only the importer's seed publish while the import is pending",
      ),
      vector("import-seed-publish-while-pending"),
    ],
  },
  {
    name: "IMPORT_DONE_USED_BEFORE_SAVE",
    edits: [
      [
        CORE,
        '        { ...base, importPending: false, persistence: "pending" },',
        '        { ...base, importPending: false, persistence: "saved" },',
      ],
    ],
    aimed: [
      core(
        "STREAM_WRITE_BEFORE_IMPORT_DONE: a stream commit is refused until the import is done",
      ),
      vector("import-done-opens-streams"),
    ],
  },
  {
    name: "FUTURE_FETCH_MINTS_FRESH_OFF",
    edits: [
      [
        AUTHORITY,
        "        fetchStartMono: future ? Number.NaN : clock.mono() - age,",
        "        fetchStartMono: clock.mono() - age,",
      ],
    ],
    aimed: [
      authority(
        "treats an Off whose fetch started more than 60 s in the future as unknown",
      ),
      vector("future-fetch-start-is-unknown"),
    ],
  },
  {
    name: "HUNG_SAVE_HOLDS_LOCK",
    edits: [
      [
        AUTHORITY,
        "      await settleWithin(\n        options.store.save(owner, next, stored.get(owner) ?? null),\n        saveTimeoutMs,\n      );",
        "      await options.store.save(owner, next, stored.get(owner) ?? null);",
      ],
    ],
    aimed: [
      authority(
        "counts as a failed save after the bound, releases the lock and refuses until a later save",
      ),
    ],
  },
  {
    name: "PROBE_THROW_MEANS_NONE",
    edits: [
      [
        AUTHORITY,
        '      warn("legacy file probe failed; reporting an import is required", error);\n      return true;',
        '      warn("legacy file probe failed; reporting an import is required", error);\n      return false;',
      ],
    ],
    aimed: [authority("counts a probe that throws as legacy files present")],
  },
];

const filters = process.argv.slice(2);
const selected = MUTANTS.filter(
  ({ name }) => filters.length === 0 || filters.some((f) => name.includes(f)),
);

const originals = new Map();
const original = (file) => {
  if (!originals.has(file)) originals.set(file, readFileSync(file, "utf8"));
  return originals.get(file);
};
const restoreAll = () => {
  for (const [file, text] of originals) writeFileSync(file, text);
};

let child = null;
for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => {
    if (child) child.kill("SIGTERM");
    restoreAll();
    console.error(`\n${signal}: files restored`);
    process.exit(130);
  });
}

const outDir = join(homedir(), ".tmp", "account-mode-mutants");
mkdirSync(outDir, { recursive: true });

function runTests(label, files = TEST_FILES) {
  const outputFile = join(outDir, `${label.replace(/\W+/g, "-")}.json`);
  return new Promise((resolve) => {
    child = spawn(
      "nice",
      [
        "-n",
        "19",
        "npx",
        "vitest",
        "run",
        "--maxWorkers=4",
        "--reporter=json",
        `--outputFile=${outputFile}`,
        ...files,
      ],
      { stdio: ["ignore", "ignore", "ignore"] },
    );
    child.on("close", () => {
      child = null;
      try {
        resolve(JSON.parse(readFileSync(outputFile, "utf8")));
      } catch {
        resolve(null);
      }
    });
  });
}

/** Cases that ran, by file and full name; plus files that did not load. */
function digest(report) {
  if (!report) return { loadFailure: "no report", cases: [] };
  const cases = [];
  let loadFailure = null;
  for (const file of report.testResults ?? []) {
    const results = file.assertionResults ?? [];
    if (file.status === "failed" && results.length === 0) {
      loadFailure = `${file.name}: ${String(file.message).split("\n")[0]}`;
    }
    for (const r of results) {
      cases.push({ file: file.name, name: r.fullName, status: r.status });
    }
  }
  return { loadFailure, cases };
}

const find = (cases, aim) =>
  cases.filter((c) => c.file.endsWith(aim.file) && c.name.includes(aim.name));

// Every anchor must match exactly once before anything runs.
for (const m of MUTANTS) {
  const current = new Map();
  for (const [file, from, to] of m.edits) {
    const text = current.get(file) ?? original(file);
    if (text.split(from).length !== 2) {
      console.error(`${m.name}: expected exactly one match in ${file}`);
      process.exit(2);
    }
    current.set(
      file,
      text.replace(from, () => to),
    );
  }
}
if (process.env.CHECK_ONLY) {
  console.log(`${MUTANTS.length} mutants: every anchor matches once`);
  process.exit(0);
}

console.log("baseline (unmutated)");
const base = digest(await runTests("baseline"));
let baselineOk = base.loadFailure === null && base.cases.length > 0;
const baselineProblems = [];
if (base.loadFailure) baselineProblems.push(base.loadFailure);
for (const c of base.cases) {
  if (c.status !== "passed") baselineProblems.push(`${c.status}: ${c.name}`);
}
for (const m of MUTANTS) {
  for (const aim of m.aimed) {
    if (find(base.cases, aim).length === 0) {
      baselineProblems.push(`aimed test not found: ${aim.name}`);
    }
  }
}
if (baselineProblems.length > 0) baselineOk = false;
console.log(
  `${baselineOk ? "GREEN" : "RED  "}  ${base.cases.length} tests in ${TEST_FILES.length} files`,
);
if (!baselineOk) {
  for (const p of baselineProblems) console.error(`  ${p}`);
  console.error("baseline is not green: no mutant was run");
  process.exit(1);
}

const rows = [];
try {
  for (const m of selected) {
    // Edits to one file build on each other; each must match exactly once.
    const current = new Map();
    for (const [file, from, to] of m.edits) {
      const text = current.get(file) ?? original(file);
      if (text.split(from).length !== 2) {
        throw new Error(`${m.name}: expected exactly one match in ${file}`);
      }
      current.set(
        file,
        text.replace(from, () => to),
      );
    }
    for (const [file, text] of current) writeFileSync(file, text);
    const result = digest(await runTests(m.name, m.files ?? CORE_FILES));
    restoreAll();

    let outcome;
    let note = "";
    const aimedHits = m.aimed.flatMap((aim) => find(result.cases, aim));
    if (result.loadFailure) {
      outcome = "INVALID";
      note = `did not load: ${result.loadFailure}`;
    } else if (aimedHits.length === 0) {
      outcome = "INVALID";
      note = "aimed test did not run";
    } else if (aimedHits.some((c) => c.status === "failed")) {
      outcome = "KILLED";
    } else {
      outcome = "SURVIVED";
    }
    const aimedFailed = aimedHits.filter((c) => c.status === "failed");
    const failedTotal = result.cases.filter(
      (c) => c.status === "failed",
    ).length;
    rows.push({ name: m.name, outcome });
    console.log(
      `${outcome.padEnd(8)} ${m.name}  (${failedTotal} failing)${note ? `  ${note}` : ""}`,
    );
    for (const aim of m.aimed) {
      const hit = aimedFailed.some((c) => find([c], aim).length > 0);
      console.log(
        `           aimed: ${aim.name}${hit ? "  [failed, as aimed]" : ""}`,
      );
    }
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
const notKilled = rows.filter((r) => r.outcome !== "KILLED");
console.log(
  `\n${rows.length - notKilled.length}/${rows.length} mutants killed; files restored: ${restored}`,
);
process.exit(notKilled.length > 0 || !restored ? 1 : 0);
