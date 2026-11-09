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

const AUTHORITY_TESTS = `${DIR}/authority.test.ts`;
const FLAG_TESTS = `${DIR}/flag-evidence.test.ts`;
// Runs the shared vectors (vectors.json) and the policy's unit tests.
const CORE_TESTS = `${DIR}/mode-machine.test.ts`;
const TEST_FILES = [AUTHORITY_TESTS, FLAG_TESTS, CORE_TESTS];

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
        "      await options.store.save(owner, toDurable(record));",
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
        "    try {\n      await options.store.save(owner, toDurable(record));",
        '    apply({ type: "saveComplete", owner });\n    try {\n      await options.store.save(owner, toDurable(record));',
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
        '      return apply({ type: "saveFailed", owner }).decision;',
        '      return apply({ type: "saveComplete", owner }).decision;',
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
        '      warn("account mode record could not be saved", error);\n      return apply({ type: "saveFailed", owner }).decision;',
        '      warn("account mode record could not be saved", error);\n      const stored = (await options.store.load()).get(owner);\n      if (stored) records.set(owner, fromDurable(owner, stored));\n      return decide({ type: "read", owner });',
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

function runTests(label) {
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
        ...TEST_FILES,
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
    const result = digest(await runTests(m.name));
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
