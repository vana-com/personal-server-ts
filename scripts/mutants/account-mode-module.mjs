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
// The pure per-owner policy and the seam that joins it to the authority.
const CORE = `${DIR}/mode-machine.ts`;
const ADAPTER = `${DIR}/reduce-adapter.ts`;
const FLAG = `${DIR}/flag-evidence.ts`;

const AUTHORITY_TESTS = `${DIR}/authority.test.ts`;
const VECTORS = `${DIR}/authority-vectors.test.ts`;
const FLAG_TESTS = `${DIR}/flag-evidence.test.ts`;
const CORE_TESTS = `${DIR}/mode-machine.test.ts`;
const CORE_VECTORS = `${DIR}/vectors.test.ts`;
const TEST_FILES = [
  AUTHORITY_TESTS,
  VECTORS,
  FLAG_TESTS,
  CORE_TESTS,
  CORE_VECTORS,
];

const vector = (id) => ({ file: VECTORS, name: `vector ${id}` });
const authority = (name) => ({ file: AUTHORITY_TESTS, name });
const core = (name) => ({ file: CORE_TESTS, name });

/**
 * name, edits [[file, old text (exactly once), new text]], aimed tests.
 * The aimed test is the one that must fail; others may fail too.
 */
const MUTANTS = [
  {
    name: "UNKNOWN_AS_OFF",
    edits: [
      [
        CORE,
        '          successful &&\n          event.state === "off" &&',
        '          event.state === "off" &&',
      ],
      [
        ADAPTER,
        "const good = succeeded(event.rawStatus);",
        "const good = true;",
      ],
    ],
    aimed: [
      authority("changes nothing for an answer that was not a success"),
      vector("unknown-evidence-refuses"),
      core("UNKNOWN_AS_OFF: a failed answer invalidates an existing Off"),
    ],
  },
  {
    name: "OFF_AFTER_ON_LOWERS",
    edits: [
      [
        CORE,
        "      } else if (!next.switched) {\n        if (\n          successful &&",
        "      } else {\n        if (\n          successful &&",
      ],
      [
        CORE,
        "              cleanOffAt: clock.nowWall,\n              offFetchStartMono: event.fetchStartMono,",
        "              switched: false,\n              cleanOffAt: clock.nowWall,\n              offFetchStartMono: event.fetchStartMono,",
      ],
    ],
    aimed: [
      vector("on-is-never-lowered"),
      core("OFF_AFTER_ON_LOWERS: stale Off and outage do not lower saved On"),
    ],
  },
  {
    name: "OWNERLESS_READ_ANSWERS",
    edits: [
      [
        ADAPTER,
        "  const owner = normalize(event.owner);\n  const before",
        '  const owner =\n    normalize(event.owner) || (recordsIn.keys().next().value ?? "");\n  const before',
      ],
    ],
    aimed: [
      authority("is unknown, even though other owners have answers"),
      vector("owner-mismatch-is-unknown"),
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
        "      await options.store.save(owner, { ...record });",
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
        "    try {\n      await options.store.save(owner, { ...record });",
        '    apply({ op: "saveComplete", owner });\n    try {\n      await options.store.save(owner, { ...record });',
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
        "    clock.nowMono - record.offFetchStartMono < OFF_TTL_MS\n  );",
        "    true\n  );",
      ],
    ],
    aimed: [
      vector("off-expires-at-deadline"),
      core(
        "OFF_NEVER_EXPIRES: deadline equality expires fetch-start freshness",
      ),
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
      core("EXPIRY_LOWERS_LATCH: expiry and untrusted reboot retain saved On"),
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
        "  if (!next.switched) {\n    if (!freshOff(next, clock))",
        "  if (!next.switched) {\n    if (record !== null && !freshOff(next, clock))",
      ],
    ],
    aimed: [
      authority("answers 503 for an owner it has never heard of"),
      core(
        "NEVER_SEEN_OWNER_ADMITS: first access is unknown, first explicit Off is immediately usable",
      ),
    ],
  },
  {
    name: "OFF_USED_BEFORE_SAVE",
    edits: [
      [
        AUTHORITY,
        '      return apply({ op: "saveFailed", owner }).decision ?? REFUSE_UNKNOWN;',
        '      return apply({ op: "saveComplete", owner }).decision ?? REFUSE_UNKNOWN;',
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
    name: "OUTAGE_ENDS_FRESH_OFF",
    edits: [[ADAPTER, "if (ownersAgree && !forwardable) {", "if (false) {"]],
    aimed: [
      authority(
        "leave a still-fresh Off in place, because an unreachable Account blocks no one who has not switched",
      ),
    ],
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
