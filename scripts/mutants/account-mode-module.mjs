#!/usr/bin/env node
/**
 * Mutant runner for the shared account-mode module.
 *
 * Each mutant re-introduces one named defect with a small edit to production
 * code. The runner applies it in place, runs the focused tests, and reads the
 * vitest JSON report. A mutant is KILLED only when a test named as its aim ran
 * and failed. These outcomes are never kills:
 *   INVALID   the aimed test did not run; a test file failed to load or build;
 *             the run left no fresh, parseable report; or the report held no
 *             test at all
 *   SURVIVED  the aimed test ran and passed
 *
 * Every vitest run writes its report to a new directory made for that run, so
 * a report from an earlier run can never be read as this one, and the run is
 * INVALID unless that report is newer than the moment the run started. A
 * self-check runs before the first mutant: a mutant that cannot load and a run
 * of a test file that does not exist must both come out INVALID.
 *
 *   node scripts/mutants/account-mode-module.mjs [name-substring | !name-substring ...]
 *
 * The unmutated baseline runs first. If any aimed test is missing or red, the
 * runner stops before it mutates anything. Every mutated file is put back byte
 * for byte, also on SIGINT and SIGTERM, and the runner checks that it did.
 * Exit code 1 for any mutant that is not killed (SURVIVED or INVALID), a red
 * baseline, a failed self-check, or a file that did not restore. Run it with Node 22 from the repository root, in the
 * foreground, to the end.
 */
import { spawn } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
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
const BROWSER_RUNTIME = "packages/lite/src/browser-runtime.ts";

const AUTHORITY_TESTS = `${DIR}/authority.test.ts`;
const LIFECYCLE_TESTS = `${DIR}/authority-lifecycle.test.ts`;
const FLAG_TESTS = `${DIR}/flag-evidence.test.ts`;
// Runs the shared vectors (vectors.json) and the policy's unit tests.
const CORE_TESTS = `${DIR}/mode-machine.test.ts`;
const NODE_STORE_TESTS =
  "packages/server/src/account-mode/file-record-store.test.ts";
const LITE_STORE_TESTS = "packages/lite/src/account-mode-store.test.ts";
const OWNER_LOCK = "packages/server/src/account-mode/owner-lock.ts";
const SERVER_BOOTSTRAP = "packages/server/src/bootstrap.ts";
const SERVER_ROUTE = "packages/server/src/routes/account-mode.ts";
const NODE_OWNERSHIP_TESTS =
  "packages/server/src/account-mode/file-record-store.ownership.test.ts";
const SERVER_BOOT_TESTS =
  "packages/server/src/bootstrap-account-mode-ownership.test.ts";
const SERVER_CONTRACT_TESTS =
  "packages/server/src/routes/account-mode.contract.test.ts";
const SERVER_APP_TESTS = "packages/server/src/routes/account-mode.test.ts";
const LITE_RUNTIME_TESTS = "packages/lite/src/runtime-account-mode.test.ts";
const BROWSER_RUNTIME_TESTS = "packages/lite/src/browser-runtime.test.ts";
// The core files run for every mutant of core code. A mutant of a host file
// names its own test files: those import the host source directly, and reach
// the module through its built output, which a mutant of core cannot change.
const CORE_FILES = [AUTHORITY_TESTS, LIFECYCLE_TESTS, FLAG_TESTS, CORE_TESTS];

const nodeStore = (name) => ({ file: NODE_STORE_TESTS, name });
const liteStore = (name) => ({ file: LITE_STORE_TESTS, name });
const serverApp = (name) => ({ file: SERVER_APP_TESTS, name });
const liteRuntime = (name) => ({ file: LITE_RUNTIME_TESTS, name });
const nodeOwnership = (name) => ({ file: NODE_OWNERSHIP_TESTS, name });
const serverBoot = (name) => ({ file: SERVER_BOOT_TESTS, name });
const serverContract = (name) => ({ file: SERVER_CONTRACT_TESTS, name });

const vector = (id) => ({
  file: CORE_TESTS,
  name: `the shared vectors, run through the module ${id}`,
});
const authority = (name) => ({ file: AUTHORITY_TESTS, name });
const lifecycle = (name) => ({ file: LIFECYCLE_TESTS, name });
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
        "        options.store.save(owner, next, stored.get(owner) ?? null),",
        "        Promise.resolve(),",
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
        "    const next = toDurable(record);\n    try {\n",
        '    const next = toDurable(record);\n    apply({ type: "saveComplete", owner });\n    try {\n',
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
    name: "SECOND_RUNTIME_ADMITTED (Lite: the Web Lock is not checked)",
    files: [LITE_STORE_TESTS],
    edits: [
      [
        LITE_STORE,
        "      if (held === null) throw new ModeStoreOwnedError();\n",
        "      if (held === null) {\n        const taken = {};\n        lease = taken;\n        return {\n          async release() {\n            if (lease === taken) lease = null;\n          },\n        };\n      }\n",
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
    name: "SWEEP_OUTSIDE_CLAIM (a load deletes temp files)",
    files: [NODE_STORE_TESTS],
    edits: [
      [
        NODE_STORE,
        "      const records = new Map<string, DurableModeRecord>();\n      let changed = false;\n",
        "      const records = new Map<string, DurableModeRecord>();\n      await sweepTemps(folder);\n      let changed = false;\n",
      ],
    ],
    aimed: [
      nodeStore(
        "sweeps the temp file of a crashed save when it becomes the owner, and at no other time",
      ),
      nodeStore(
        "lets one store own the folder, and a second touches none of its files",
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
        "        assertMonotoneWrite(await readCurrent(folder, owner), expected, record);\n",
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
        "                assertMonotoneWrite(\n                  found === undefined ? null : toRecord(found as StoredRow),\n                  expected,\n                  record,\n                );\n",
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
        "    bootId: record.bootId,\n    importPending: record.importPending,",
        "    bootId: record.bootId,\n    importPending: false,",
      ],
    ],
    aimed: [
      authority(
        "saves importPending in the same write as the first On, when the owner has legacy files",
      ),
      authority(
        "survives a crash between the On save and the answer: a restarted host is told again",
      ),
      vector("import-pending-survives-restart"),
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
      vector("import-pending-survives-restart"),
    ],
  },
  {
    name: "ORDINARY_WRITE_PASSES_WHILE_PENDING",
    edits: [
      [
        AUTHORITY,
        'const event: ModeEvent = { type: "commit", owner, operationId, sink };',
        'const event: ModeEvent = {\n      type: "commit",\n      owner,\n      operationId,\n      sink: "importSeed",\n    };',
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
        'const event: ModeEvent = { type: "commit", owner, operationId, sink };',
        'const event: ModeEvent = {\n      type: "commit",\n      owner,\n      operationId,\n      sink: "stream",\n    };',
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
  // ---- round 4: store ownership, drain on close, unreadable records ----
  {
    name: "CLOSE_BEFORE_DRAIN",
    edits: [
      [
        AUTHORITY,
        "        const release = await lock.exclusive();\n        try {\n          await Promise.allSettled([...inFlightSaves]);\n",
        "        const release = () => {};\n        try {\n",
      ],
    ],
    aimed: [
      lifecycle(
        "keeps the store while an admitted legacy write is in flight, and lands nothing after the next owner has it",
      ),
      lifecycle(
        "keeps the store while an evidence save is in flight, and lands nothing after the next owner has it",
      ),
    ],
  },
  {
    name: "CLOSE_IGNORES_TIMED_OUT_SAVE",
    edits: [[AUTHORITY, "      inFlightSaves.add(work);\n", ""]],
    aimed: [
      lifecycle("also waits for a save the authority already gave up on"),
    ],
  },
  {
    name: "LOAD_AFTER_CLOSE_SERVES",
    edits: [
      [
        AUTHORITY,
        '      const rows = await options.store.load();\n      if (closed) throw new Error("The account mode authority is closed.");\n',
        "      const rows = await options.store.load();\n",
      ],
    ],
    aimed: [
      lifecycle(
        "never serves from a load that finishes after close, and gives the store back",
      ),
    ],
  },
  {
    name: "READ_NEVER_RETRIES_OWNERSHIP",
    edits: [
      [
        AUTHORITY,
        "    if (closed || loaded || starting !== null) return;\n",
        "    if (closed || loaded || starting !== null || true) return;\n",
      ],
    ],
    aimed: [
      lifecycle(
        "claims again from an ordinary read once the owner has closed, and serves what is stored",
      ),
    ],
  },
  {
    name: "RETRY_NOT_RATE_LIMITED",
    edits: [
      [
        AUTHORITY,
        "    if (lastAttempt !== null && clock.mono() - lastAttempt < ownerRetryMs) {\n      return;\n    }\n",
        "",
      ],
    ],
    aimed: [
      lifecycle("asks again at most once per interval, and one ask at a time"),
    ],
  },
  {
    name: "SEED_CAPABILITY_PUBLIC",
    edits: [
      [
        AUTHORITY,
        "  const authority: ModeAuthority = {\n    ready,\n",
        "  const authority: ModeAuthority = {\n    ...importSeed,\n    ready,\n",
      ],
    ],
    aimed: [lifecycle("is not a method of the authority a caller is handed")],
  },
  {
    name: "STREAM_COMMIT_OUTSIDE_LOCK",
    edits: [
      [
        AUTHORITY,
        '    if (early.kind !== "streams") return refuse(early);\n    const release = await lock.shared();\n',
        '    if (early.kind !== "streams") return refuse(early);\n    const release = () => {};\n',
      ],
    ],
    aimed: [
      lifecycle(
        "makes importDone, and a close, wait for a stream callback in flight",
      ),
    ],
  },
  {
    name: "SAVE_TIMEOUT_WEDGES_QUEUE (the save is not bounded)",
    edits: [
      [
        AUTHORITY,
        '      await settleWithin(work, saveTimeoutMs, "save");',
        "      await work;",
      ],
    ],
    aimed: [
      authority(
        "poisons the authority: later work refuses at once, nothing queues behind the hung save and nothing writes",
      ),
    ],
  },
  {
    name: "SAVE_TIMEOUT_WEDGES_QUEUE (a timed-out save does not poison)",
    edits: [
      [
        AUTHORITY,
        "      stale.add(owner);\n      if (error instanceof StoreStalledError) poisoned = true;\n",
        "      stale.add(owner);\n      if (false) poisoned = true;\n",
      ],
    ],
    aimed: [
      authority(
        "poisons the authority: later work refuses at once, nothing queues behind the hung save and nothing writes",
      ),
    ],
  },
  {
    name: "UNBOUNDED_PRE_SAVE_AWAIT (the legacy-file probe)",
    edits: [
      [
        AUTHORITY,
        '      return await settleWithin(\n        Promise.resolve(options.hasLegacyFiles(owner)),\n        saveTimeoutMs,\n        "legacy file probe",\n      );',
        "      return await options.hasLegacyFiles(owner);",
      ],
    ],
    aimed: [
      authority(
        "does not wait for a legacy-file probe that never settles: the import is owed",
      ),
    ],
  },
  {
    name: "UNBOUNDED_PRE_SAVE_AWAIT (the re-read)",
    edits: [
      [
        AUTHORITY,
        '      const rows = await settleWithin(\n        Promise.resolve(options.store.load()),\n        saveTimeoutMs,\n        "load",\n      );',
        "      const rows = await options.store.load();",
      ],
    ],
    aimed: [
      authority(
        "does not wait for a re-read that never settles, and then refuses everything",
      ),
      authority(
        "does not wait for the re-read that follows a failed save, and then refuses everything",
      ),
    ],
  },
  {
    name: "QUARANTINE_FORGETS_ON (core: a lost record is not held as a tombstone)",
    edits: [
      [
        AUTHORITY,
        "      (row.historyUnknown === true && !held.switched)\n",
        "      false\n",
      ],
    ],
    aimed: [
      lifecycle(
        "also wins over a fresh Off held in memory when the record is lost while running",
      ),
    ],
  },
  {
    name: "TOMBSTONE_MINTS_OFF",
    edits: [
      [
        CORE,
        '      if (event.state === "off" && next.historyUnknown === true) {\n        // The owner\'s record was unreadable, so it may have been On: no Off\n        // is accepted until an On answers.\n        return settle(next);\n      }\n',
        "",
      ],
    ],
    aimed: [
      core(
        "TOMBSTONE_MINTS_OFF: an Off over a tombstone mints nothing and the owner stays unknown",
      ),
      vector("unreadable-record-cannot-erase-on"),
    ],
  },
  {
    name: "TOMBSTONE_ON_OWES_NO_IMPORT",
    edits: [
      [
        CORE,
        "            next.historyUnknown === true || event.legacyFiles === true;",
        "            event.legacyFiles === true;",
      ],
    ],
    aimed: [
      core(
        "an On over a tombstone owes the import, whatever the probe says, and clears it",
      ),
    ],
  },
  {
    name: "TOMBSTONE_WRITTEN_BY_SAVE",
    edits: [
      [
        RECORD_STORE,
        '  if (next.historyUnknown === true) {\n    throw new ModeStoreConflictError(\n      "a tombstone is written only by the store\'s own quarantine",\n    );\n  }\n',
        "",
      ],
    ],
    aimed: [
      lifecycle(
        "never lets save write a tombstone over an On, or an Off over a tombstone",
      ),
    ],
  },
  {
    name: "OFF_WRITTEN_OVER_TOMBSTONE",
    edits: [
      [
        RECORD_STORE,
        '    if (!next.switched || !next.importPending) {\n      throw new ModeStoreConflictError(\n        "an owner with unknown history can only be written as On with an import owed",\n      );\n    }\n',
        "",
      ],
    ],
    aimed: [
      lifecycle(
        "never lets save write a tombstone over an On, or an Off over a tombstone",
      ),
    ],
  },
  {
    name: "QUARANTINE_FORGETS_ON (Node: the unreadable file leaves no tombstone)",
    files: [NODE_STORE_TESTS],
    edits: [
      [
        NODE_STORE,
        "          await tombstoneUnreadable(folder, name);\n",
        "          await unlink(join(folder, name));\n",
      ],
      [NODE_STORE, "          records.set(match[1], tombstoneRecord());\n", ""],
    ],
    aimed: [
      nodeStore(
        "is kept aside, never deleted, and its owner loads as a tombstone, not as never seen",
      ),
    ],
  },
  {
    name: "QUARANTINE_FORGETS_ON (Lite: a malformed row leaves no tombstone)",
    files: [LITE_STORE_TESTS],
    edits: [
      [
        LITE_STORE,
        "                store.put({ owner, ...tombstoneRecord() });",
        "                store.delete(owner);",
      ],
      [
        LITE_STORE,
        "              records.set(owner, tombstoneRecord());\n",
        "",
      ],
    ],
    aimed: [
      liteStore(
        "sets a malformed row aside as a tombstone, so that owner is never read as unseen",
      ),
      liteStore(
        "keeps a saved On through a corrupt row: after the restart an Off is refused and an On owes the import",
      ),
    ],
  },
  {
    name: "LITE_SAVE_WITHOUT_LEASE (a call needs no lease)",
    files: [LITE_STORE_TESTS],
    edits: [
      [
        LITE_STORE,
        "    if (mine === null) return Promise.reject(unowned());\n",
        "",
      ],
    ],
    aimed: [liteStore("neither reads nor writes without a live lease")],
  },
  {
    name: "LITE_SAVE_WITHOUT_LEASE (the lease is not checked after the database opens)",
    files: [LITE_STORE_TESTS],
    edits: [
      [
        LITE_STORE,
        "          // The lease may have been released while the database opened.\n          if (!stillMine()) throw unowned();\n",
        "",
      ],
    ],
    aimed: [
      liteStore(
        "gives up a save whose database opened after the lease was released, and frees the lock only after it",
      ),
    ],
  },
  {
    name: "LITE_RELEASE_BEFORE_DRAIN",
    files: [LITE_STORE_TESTS],
    edits: [
      [LITE_STORE, "          await Promise.allSettled([...running]);\n", ""],
    ],
    aimed: [
      liteStore(
        "gives up a save whose database opened after the lease was released, and frees the lock only after it",
      ),
    ],
  },
  {
    name: "LITE_LOCK_PORT_OPTIONAL",
    files: [LITE_STORE_TESTS],
    edits: [
      [
        LITE_STORE,
        "      const acquire = options.acquireOwnerLock;\n",
        "      const acquire =\n        options.acquireOwnerLock ??\n        (async () => ({ release: async () => {} }));\n",
      ],
    ],
    aimed: [
      liteStore(
        "starts only with an owner lock port: with none, every claim is refused and nothing is read or written",
      ),
    ],
  },
  {
    name: "LITE_LOCK_NAME_IGNORES_DATABASE",
    files: [LITE_STORE_TESTS],
    edits: [
      [
        LITE_STORE,
        "acquire(`${dbName}:owner`)",
        'acquire("account-mode:owner")',
      ],
    ],
    aimed: [
      liteStore(
        "includes the database name in the lock, so two databases do not contend",
      ),
    ],
  },
  {
    name: "LITE_MEMORY_MODE_STORE",
    files: [BROWSER_RUNTIME_TESTS],
    edits: [
      [
        BROWSER_RUNTIME,
        "  createUnavailableModeRecordStore,\n",
        "  createUnavailableModeRecordStore as _unused,\n",
      ],
      [
        BROWSER_RUNTIME,
        "        ? createUnavailableModeRecordStore()\n",
        "        ? createMemoryModeRecordStore()\n",
      ],
      [
        BROWSER_RUNTIME,
        "  createModeAuthority,\n",
        "  createModeAuthority,\n  createMemoryModeRecordStore,\n",
      ],
    ],
    aimed: [
      {
        file: BROWSER_RUNTIME_TESTS,
        name: "has no durable mode store of its own, so it decides nothing: an On is not kept and no Off is ever believed",
      },
    ],
  },
  {
    name: "LITE_REFUSAL_ANSWERED_200",
    files: [LITE_RUNTIME_TESTS],
    edits: [
      [
        LITE_RUNTIME,
        "    status: refused ? decision.status : 200,\n",
        "    status: 200,\n",
      ],
    ],
    aimed: [
      liteRuntime(
        "answers every refusal with its own status and body, and a success with 200",
      ),
    ],
  },
  {
    name: "LITE_MODE_OWNER_FALLS_BACK_TO_IDENTITY",
    files: [LITE_RUNTIME_TESTS],
    edits: [
      [
        LITE_RUNTIME,
        "    return options.serverOwner;\n  }\n\n  function modeMethodNotAllowed",
        "    return options.serverOwner ?? ownerAddress();\n  }\n\n  function modeMethodNotAllowed",
      ],
    ],
    aimed: [
      liteRuntime(
        "refuses evidence when only a server identity is given, and latches nothing",
      ),
    ],
  },
  {
    name: "LITE_IMPORT_DONE_READS_OTHER_OWNER",
    files: [LITE_RUNTIME_TESTS],
    edits: [
      [
        LITE_RUNTIME,
        "          const mismatch = modeOwnerRefusal(body.owner);\n          if (mismatch) return mismatch;\n",
        "          const mismatch = modeOwnerRefusal(body.owner);\n          if (mismatch) {\n            await options.accountModeAuthority.importDone(body.owner);\n            return mismatch;\n          }\n",
      ],
    ],
    aimed: [
      liteRuntime(
        "does not read another owner's mode to answer their import-done report",
      ),
      liteRuntime(
        "answers a caller that is not the owner with 401, another owner's report with 403, a bad body with 400",
      ),
    ],
  },
  {
    name: "LITE_OWNER_MISMATCH_AFTER_BODY_VALIDATION",
    files: [LITE_RUNTIME_TESTS],
    edits: [
      [
        LITE_RUNTIME,
        "          const mismatch = modeOwnerRefusal(\n            (raw as Record<string, unknown>).owner,\n          );\n          if (mismatch) return mismatch;\n          const body = parseEvidenceBody(raw);\n",
        "          const body = parseEvidenceBody(raw);\n          const mismatch = modeOwnerRefusal(\n            (raw as Record<string, unknown>).owner,\n          );\n          if (body && mismatch) return mismatch;\n",
      ],
    ],
    aimed: [
      liteRuntime(
        "answers another owner with 403 before the rest of the body is read, and never asks the module",
      ),
    ],
  },
  {
    name: "LITE_503_WITHOUT_RETRY_AFTER",
    files: [LITE_RUNTIME_TESTS],
    edits: [
      [
        LITE_RUNTIME,
        '      ? { headers: { "Retry-After": MODE_RETRY_AFTER_SECONDS } }\n',
        "      ? {}\n",
      ],
    ],
    aimed: [
      liteRuntime(
        "tells a client to retry a 503 after 5 seconds, and not a 426 or a success",
      ),
    ],
  },
  {
    name: "LITE_BODY_CAP_COUNTS_ONLY_DECLARED_SIZE",
    files: [LITE_RUNTIME_TESTS],
    edits: [
      [
        LITE_RUNTIME,
        "    if (size > MODE_BODY_MAX_BYTES) {\n",
        "    if (false) {\n",
      ],
    ],
    aimed: [
      liteRuntime(
        "answers 413 above 16 KiB, whether the length is declared or the body is chunked",
      ),
    ],
  },

  // ---- Node host: kernel-held owner lock, boot order, routes ------------
  {
    name: "LOCK_RELEASED_EARLY",
    files: [NODE_OWNERSHIP_TESTS, NODE_STORE_TESTS],
    edits: [
      [
        OWNER_LOCK,
        "  const held = db;\n  return {",
        "  const held = db;\n  held.close();\n  return {",
      ],
    ],
    aimed: [
      nodeOwnership("a: of two processes that claim at once"),
      nodeOwnership("c: a stopped but live owner still owns"),
      nodeStore("lets one store own the folder"),
    ],
  },
  {
    name: "SECOND_OWNER_ADMITTED",
    files: [NODE_OWNERSHIP_TESTS, NODE_STORE_TESTS],
    edits: [
      [
        OWNER_LOCK,
        '  if (!db) {\n    throw new ModeStoreOwnedError(\n      "another runtime holds the account mode record folder",\n    );\n  }\n  const held = db;',
        "  if (!db) {\n    return { dir: canonical, release() {} };\n  }\n  const held = db;",
      ],
    ],
    aimed: [
      nodeOwnership("a: of two processes that claim at once"),
      nodeOwnership("a: a contender in this process is refused"),
      nodeStore("lets one store own the folder"),
    ],
  },
  {
    name: "LOCK_ON_SHARED_DB_FILE",
    files: [NODE_OWNERSHIP_TESTS],
    edits: [
      [
        OWNER_LOCK,
        'const LOCK_FILE = ".mode-owner.lock.db";',
        'const LOCK_FILE = "index.db";',
      ],
    ],
    aimed: [nodeOwnership("h: the owner using other files in the folder")],
  },
  {
    name: "OWNED_REFUSAL_SWALLOWED",
    files: [SERVER_BOOT_TESTS],
    edits: [
      [
        SERVER_BOOTSTRAP,
        "      if (err instanceof ModeStoreOwnedError) throw err;\n",
        "      if (err instanceof ModeStoreOwnedError) return false;\n",
      ],
    ],
    aimed: [serverBoot("a runtime another one owns is refused")],
  },
  {
    name: "BOOT_DATA_BEFORE_OWNER",
    files: [SERVER_BOOT_TESTS],
    edits: [
      [
        SERVER_BOOTSTRAP,
        "  const modeLoaded = await accountModeAuthority.ready.then(",
        "  initializeDatabase(indexPath);\n  const modeLoaded = await accountModeAuthority.ready.then(",
      ],
    ],
    aimed: [
      serverBoot("a runtime another one owns is refused"),
      serverBoot("opens no index while the records are still being claimed"),
    ],
  },
  {
    name: "NO_RELEASE_ON_FAILED_START",
    files: [SERVER_BOOT_TESTS],
    edits: [
      [
        SERVER_BOOTSTRAP,
        "holds.accountModeAuthority?.close().catch(",
        "Promise.resolve(holds.accountModeAuthority).catch(",
      ],
    ],
    aimed: [serverBoot("a start that fails after the records are claimed")],
  },
  {
    name: "SAVED_ON_REPAIRS_LEGACY",
    files: [SERVER_BOOT_TESTS],
    edits: [
      [
        SERVER_BOOTSTRAP,
        "  const legacyMaintenanceMayRun =\n    modeLoaded &&\n",
        "  const legacyMaintenanceMayRun =\n    true ||\n",
      ],
    ],
    aimed: [
      serverBoot("a saved On plus a reindex condition at boot"),
      serverBoot("a saved mode that cannot be loaded starts the runtime"),
    ],
  },
  {
    name: "CROSS_OWNER_READ_ANSWERS",
    files: [SERVER_CONTRACT_TESTS, SERVER_APP_TESTS],
    edits: [
      [
        SERVER_ROUTE,
        "    if (\n      !deps.serverOwner ||\n      normalizeOwner(owner) !== normalizeOwner(deps.serverOwner)\n    ) {",
        "    if (false) {",
      ],
    ],
    aimed: [
      serverContract("answer 403 before the module is asked anything"),
      serverContract("binds a bearer caller to the server's owner too"),
    ],
  },
  {
    name: "REFUSAL_STATUS_200",
    files: [SERVER_CONTRACT_TESTS],
    edits: [
      [
        SERVER_ROUTE,
        "return c.json(decisionBody(decision), decision.status);",
        "return c.json(decisionBody(decision), 200);",
      ],
    ],
    aimed: [serverContract("answers 503 ACCOUNT_MODE_STORE_OWNED")],
  },
  {
    name: "NO_RETRY_AFTER",
    files: [SERVER_CONTRACT_TESTS],
    edits: [
      [
        SERVER_ROUTE,
        'if (decision.status === 503) c.header("Retry-After"',
        'if (false) c.header("Retry-After"',
      ],
    ],
    aimed: [serverContract("answers 503 ACCOUNT_MODE_STORE_OWNED")],
  },
  {
    name: "NO_BODY_LIMIT",
    files: [SERVER_CONTRACT_TESTS],
    edits: [
      [
        SERVER_ROUTE,
        "    app.use(path, createBodyLimit(MAX_BODY_BYTES));\n",
        "",
      ],
    ],
    aimed: [
      serverContract(
        "takes a body at the limit and refuses one a byte over it",
      ),
    ],
  },
  {
    name: "NO_METHOD_GATE",
    files: [SERVER_CONTRACT_TESTS],
    edits: [
      [
        SERVER_ROUTE,
        "    app.all(path, (c) => {",
        '    app.all(path + "-x", (c) => {',
      ],
    ],
    aimed: [serverContract("answers any method but POST with 405")],
  },
];

// Arguments pick mutants by a part of the name; "!part" leaves them out.
const args = process.argv.slice(2);
const include = args.filter((a) => !a.startsWith("!"));
const exclude = args.filter((a) => a.startsWith("!")).map((a) => a.slice(1));
const selected = MUTANTS.filter(
  ({ name }) =>
    (include.length === 0 || include.some((f) => name.includes(f))) &&
    !exclude.some((f) => name.includes(f)),
);

const originals = new Map();
const original = (file) => {
  if (!originals.has(file)) originals.set(file, readFileSync(file, "utf8"));
  return originals.get(file);
};
const restoreAll = () => {
  for (const [file, text] of originals) writeFileSync(file, text);
};

// One directory for this invocation; each vitest run gets a new directory in
// it. Nothing outside it is ever read as a report.
const outRoot = join(homedir(), ".tmp", "account-mode-mutants");
mkdirSync(outRoot, { recursive: true });
const runDir = mkdtempSync(join(outRoot, "run-"));
const removeRunDir = () => rmSync(runDir, { recursive: true, force: true });

let child = null;
for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => {
    if (child) child.kill("SIGTERM");
    restoreAll();
    removeRunDir();
    console.error(`\n${signal}: files restored`);
    process.exit(130);
  });
}

/**
 * Runs vitest once. Resolves {report} for a fresh, parseable report, or
 * {problem} when there is none. It never reads a path an earlier run wrote.
 */
function runTests(label, files) {
  const dir = mkdtempSync(
    join(runDir, `${label.replace(/\W+/g, "-").slice(0, 40)}-`),
  );
  const outputFile = join(dir, "report.json");
  const startedAt = Date.now();
  return new Promise((resolve) => {
    let stderr = "";
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
      { stdio: ["ignore", "ignore", "pipe"] },
    );
    child.stderr.on("data", (chunk) => {
      stderr = (stderr + chunk).slice(-400);
    });
    child.on("error", (error) => {
      child = null;
      resolve({ problem: `vitest did not start: ${error.message}` });
    });
    child.on("close", (code) => {
      child = null;
      const tail = stderr.trim().split("\n").at(-1) ?? "";
      let report;
      try {
        report = JSON.parse(readFileSync(outputFile, "utf8"));
      } catch {
        resolve({
          problem: `no report from this run (exit ${code})${tail ? `: ${tail}` : ""}`,
        });
        return;
      }
      if (
        typeof report.startTime !== "number" ||
        report.startTime < startedAt
      ) {
        resolve({ problem: "the report is older than the run that wrote it" });
        return;
      }
      resolve({ report });
    });
  });
}

/**
 * Cases that ran, by file and full name. `invalid` says why the run proves
 * nothing at all (no fresh report, no test, a requested file with no result);
 * `loadFailure` names a test file that failed to load or build.
 */
function digest(run, files) {
  if (run.problem)
    return { invalid: run.problem, loadFailure: null, cases: [] };
  const cases = [];
  let loadFailure = null;
  const seen = [];
  for (const file of run.report.testResults ?? []) {
    seen.push(file.name);
    const results = file.assertionResults ?? [];
    if (file.status === "failed" && results.length === 0) {
      loadFailure = `${file.name}: ${String(file.message).split("\n")[0]}`;
    }
    for (const r of results) {
      cases.push({ file: file.name, name: r.fullName, status: r.status });
    }
  }
  let invalid = null;
  if (cases.length === 0 && loadFailure === null) {
    invalid = "the report holds no test";
  }
  const absent = files.filter((f) => !seen.some((n) => n.endsWith(f)));
  if (invalid === null && absent.length > 0) {
    invalid = `no result for ${absent.join(", ")}`;
  }
  return { invalid, loadFailure, cases };
}

const find = (cases, aim) =>
  cases.filter((c) => c.file.endsWith(aim.file) && c.name.includes(aim.name));

/** KILLED only when an aimed test ran and failed; see the header. */
function classify(result, aimed) {
  if (result.invalid) return { outcome: "INVALID", note: result.invalid };
  if (result.loadFailure) {
    return { outcome: "INVALID", note: `did not load: ${result.loadFailure}` };
  }
  const hits = aimed.flatMap((aim) => find(result.cases, aim));
  if (hits.length === 0) {
    return { outcome: "INVALID", note: "aimed test did not run" };
  }
  if (hits.some((c) => c.status === "failed")) {
    return { outcome: "KILLED", note: "" };
  }
  return { outcome: "SURVIVED", note: "" };
}

// Every anchor must match exactly once before anything runs.
const badAnchors = [];
for (const m of MUTANTS) {
  const current = new Map();
  for (const [file, from, to] of m.edits) {
    const text = current.get(file) ?? original(file);
    if (text.split(from).length !== 2) {
      badAnchors.push(`${m.name}: expected exactly one match in ${file}`);
      break;
    }
    current.set(
      file,
      text.replace(from, () => to),
    );
  }
}
if (badAnchors.length > 0) {
  for (const line of badAnchors) console.error(line);
  removeRunDir();
  process.exit(2);
}
if (process.env.CHECK_ONLY) {
  console.log(`${MUTANTS.length} mutants: every anchor matches once`);
  removeRunDir();
  process.exit(0);
}

/**
 * Proves the runner cannot call a broken run a kill. Both probes must come out
 * INVALID: a run of a test file that does not exist, and a run in which the
 * module under test fails to load.
 */
async function selfCheck() {
  const problems = [];
  const aimed = [authority("a test that does not matter")];
  const missingFile = `${DIR}/this-test-file-does-not-exist.test.ts`;
  const missing = classify(
    digest(await runTests("selfcheck-missing", [missingFile]), [missingFile]),
    aimed,
  );
  if (missing.outcome !== "INVALID") {
    problems.push(`a missing test file came out ${missing.outcome}`);
  }
  writeFileSync(AUTHORITY, `${original(AUTHORITY)}\nexport const = ;\n`);
  try {
    const broken = classify(
      digest(await runTests("selfcheck-broken", [AUTHORITY_TESTS]), [
        AUTHORITY_TESTS,
      ]),
      aimed,
    );
    if (broken.outcome !== "INVALID") {
      problems.push(`a module that cannot load came out ${broken.outcome}`);
    }
  } finally {
    restoreAll();
  }
  return problems;
}

try {
  console.log("self-check (a missing file and an unloadable module)");
  const selfProblems = await selfCheck();
  if (selfProblems.length > 0) {
    for (const p of selfProblems) console.error(`  ${p}`);
    console.error("self-check failed: the runner cannot be trusted");
    process.exitCode = 1;
  } else {
    console.log("OK     both probes are INVALID");
  }
  if (process.exitCode === 1 || process.env.SELF_CHECK_ONLY) {
    removeRunDir();
    process.exit(process.exitCode ?? 0);
  }

  // The baseline runs the test files the selected mutants use, no others.
  const baselineFiles = [
    ...new Set(selected.flatMap((m) => m.files ?? CORE_FILES)),
  ];
  console.log("baseline (unmutated)");
  const base = digest(await runTests("baseline", baselineFiles), baselineFiles);
  const baselineProblems = [];
  if (base.invalid) baselineProblems.push(base.invalid);
  if (base.loadFailure) baselineProblems.push(base.loadFailure);
  for (const c of base.cases) {
    if (c.status !== "passed") baselineProblems.push(`${c.status}: ${c.name}`);
  }
  for (const m of selected) {
    for (const aim of m.aimed) {
      if (find(base.cases, aim).length === 0) {
        baselineProblems.push(`aimed test not found: ${aim.name}`);
      }
    }
  }
  const baselineOk = baselineProblems.length === 0;
  console.log(
    `${baselineOk ? "GREEN" : "RED  "}  ${base.cases.length} tests in ${baselineFiles.length} files`,
  );
  if (!baselineOk) {
    for (const p of baselineProblems) console.error(`  ${p}`);
    console.error("baseline is not green: no mutant was run");
    removeRunDir();
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
      const files = m.files ?? CORE_FILES;
      const result = digest(await runTests(m.name, files), files);
      restoreAll();

      const { outcome, note } = classify(result, m.aimed);
      const aimedFailed = m.aimed
        .flatMap((aim) => find(result.cases, aim))
        .filter((c) => c.status === "failed");
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
  removeRunDir();
  process.exit(notKilled.length > 0 || !restored ? 1 : 0);
} finally {
  restoreAll();
}
