/**
 * The mutants of the legacy retire gates. Each one is a REAL one-place code
 * edit (`find` must occur exactly once in `file`) that a gate test must catch:
 * `run-mutants.mjs` applies it to a scratch copy, runs `tests`, and requires
 * at least one failing test whose name contains every `mustFail` text.
 *
 * Paths are from the repository root. A mutant with `build: true` edits
 * `packages/core`, which the tests in `packages/server` read through its built
 * output, so the runner rebuilds core around it.
 */

const R = "packages/core/src/sync/legacy-retire";
const RETIRE = `${R}/retire.ts`;
const READBACK = `${R}/readback.ts`;
const HOST = `${R}/host.ts`;
const LEDGER = `${R}/ledger.ts`;
const IMPORT = `${R}/import.ts`;
const SERVICE = "packages/core/src/stream-sync-read/service.ts";
const MIRROR = "packages/core/src/stream-sync-read/mirror.ts";
const KEYS = "packages/core/src/storage/legacy-entity-key-sets.ts";
const WRITER = "packages/core/src/stream-sync/writer.ts";

const ROUND2 = `${R}/retire-round2.test.ts`;
const GATES = `${R}/retire.test.ts`;
const FLOW = `${R}/retire-flow.test.ts`;
const CYCLE =
  "packages/core/src/sync/engine/sync-manager.legacy-retire.test.ts";
const BASIS = "packages/core/src/stream-sync-read/retire-basis.test.ts";
const MIRROR_TEST = "packages/core/src/stream-sync-read/mirror.test.ts";
const CYCLE_FILE = "packages/core/src/sync/engine/sync-manager.ts";
const IMPORT_SINK_TEST =
  "packages/server/src/stream-sync/legacy-import-sink.test.ts";

const edit = (file, find, replace) => [{ file, find, replace }];

export const MUTANTS = [
  // ---- round 2 (review of 3996047f) ----
  {
    name: "STALE_PASS_DELETES",
    why: "a stored pass deletes without a fresh readback in the same pass",
    edits: edit(
      RETIRE,
      "if (report.wouldDelete && mayDelete) {",
      "if (false && report.wouldDelete && mayDelete) {",
    ),
    tests: [ROUND2],
    mustFail: [
      "STALE_PASS_DELETES",
      "reads the version back again in the same pass",
    ],
  },
  {
    name: "DRYRUN_READBACK_USABLE",
    why: "a dry run's stored readback counts as a stored pass",
    edits: edit(
      LEDGER,
      "return found && found.dry !== true ? found : null;",
      "return found ?? null;",
    ),
    tests: [ROUND2],
    mustFail: ["DRYRUN_READBACK_USABLE"],
  },
  {
    name: "FENCE_AFTER_DELETE_WRITE",
    why: "the fence ignores when the file was written (also EMPTY_IMPORT_FENCE_DELETES and FENCE_CHANGED_PASSES)",
    edits: edit(READBACK, "writtenAt < s.deleteAtMs", "true"),
    tests: [ROUND2],
    mustFail: [
      "never excuses a file collected after the delete",
      "never excuses a changed entity of a file collected after the delete",
      "EMPTY_IMPORT_FENCE_DELETES",
    ],
  },
  {
    name: "FENCE_IGNORES_STORED_AT",
    why: "only collectedAt orders the file against the delete; a late-stored file is excused",
    edits: edit(
      READBACK,
      "const writtenAt = Math.max(collected, stored);",
      "const writtenAt = collected;",
    ),
    tests: [ROUND2],
    mustFail: ["never excuses a file this device stored after the delete"],
  },
  {
    name: "UNKNOWN_DELETE_TIME_EXCUSES",
    why: "a delete with no known time counts as older than the file",
    edits: edit(
      READBACK,
      "s.deleteVersion > 0 && s.deleteAtMs !== null && writtenAt < s.deleteAtMs",
      "s.deleteVersion > 0 && (s.deleteAtMs === null || writtenAt < s.deleteAtMs)",
    ),
    tests: [ROUND2],
    mustFail: ["UNKNOWN_DELETE_TIME_EXCUSES"],
  },
  {
    name: "FENCE_NULL_VIEW_PASSES",
    why: "a failed or unkeyed published read excuses every entity",
    edits: edit(
      READBACK,
      "const viewGone = basis !== null && fenceOpen && basis.viewDeleted;",
      "const viewGone = fenceOpen;",
    ),
    tests: [ROUND2],
    mustFail: ["FENCE_NULL_VIEW_PASSES"],
  },
  {
    name: "UNCOVERED_RETIRES",
    why: "the host gives a basis for a scope the registry does not cover",
    edits: edit(
      HOST,
      "if (!basis || basis.ambiguous || !(basis.covered || basis.deleted)) {",
      "if (!basis || basis.ambiguous) {",
    ),
    tests: [ROUND2],
    mustFail: ["is no fence and no pass when the basis is uncovered"],
  },
  {
    name: "AMBIGUOUS_RETIRES",
    why: "the host gives a basis for an ambiguous scope",
    edits: edit(
      HOST,
      "if (!basis || basis.ambiguous || !(basis.covered || basis.deleted)) {",
      "if (!basis || !(basis.covered || basis.deleted)) {",
    ),
    tests: [ROUND2],
    mustFail: ["is no fence and no pass when the basis is ambiguous"],
  },
  {
    name: "UNLISTED_TOP_LEVEL_IGNORED",
    why: "a top-level array or object no table path covers is not compared",
    edits: edit(
      KEYS,
      'if (!covered.has(key) && value !== null && typeof value === "object") {',
      "if (false) {",
    ),
    tests: [ROUND2],
    mustFail: ["UNLISTED_TOP_LEVEL_IGNORED"],
  },
  {
    name: "UNKNOWN_ALTERNATE_UNCOVERS",
    why: "retireBasis counts connectors the registry never saw",
    edits: edit(
      SERVICE,
      "readTargets(scope).filter((t) => known.has(t.connector));",
      "readTargets(scope);",
    ),
    tests: [BASIS],
    mustFail: ["UNKNOWN_ALTERNATE_UNCOVERS"],
  },
  {
    name: "WHOLE_DELETE_BASIS",
    why: "retireBasis never says a scope is deleted whole",
    edits: edit(
      SERVICE,
      "deleted: !ambiguous && deletedTargets === targets.length,",
      "deleted: false,",
    ),
    tests: [BASIS, ROUND2],
    mustFail: ["WHOLE_DELETE_BASIS"],
  },
  {
    name: "DELETE_TIME_LOST",
    why: "the mirror does not persist the time of a delete",
    edits: edit(
      MIRROR,
      "deletionTimes: Object.fromEntries(times),",
      "deletionTimes: {},",
    ),
    tests: [MIRROR_TEST, BASIS],
    mustFail: ["DELETE_TIME"],
  },
  {
    name: "HEAD_FLOOR_HAS_NO_TIME",
    why: "a higher delete learned from a head keeps the older delete's time",
    edits: edit(
      MIRROR,
      "times.delete(scope); // a head carries the version, not the time",
      "",
    ),
    tests: [MIRROR_TEST],
    mustFail: ["HEAD_FLOOR_HAS_NO_TIME"],
  },
  {
    name: "DEVICE_ONLY_RETIRED_EARLY",
    why: "a fenced file is retired without a full run since the delete",
    edits: edit(RETIRE, "if (stored.fenced > 0) {", "if (false) {"),
    tests: [FLOW, GATES, ROUND2],
    mustFail: ["DEVICE_ONLY_RETIRED_EARLY"],
  },

  // ---- earlier rounds (named in the tests of #595) ----
  {
    name: "RETIRE_WITHOUT_READBACK",
    why: "a failed readback still deletes",
    edits: edit(
      RETIRE,
      'if (!stored.pass) return report("readback_failed");',
      "",
    ),
    tests: [GATES, FLOW],
    mustFail: ["RETIRE_WITHOUT_READBACK"],
  },
  {
    name: "READBACK_COUNT_ONLY",
    why: "readback compares counts, not content",
    edits: edit(
      READBACK,
      "else if (other !== hash) changed += 1;",
      "else if (false) changed += 1;",
    ),
    tests: [GATES, FLOW],
    mustFail: ["READBACK_COUNT_ONLY"],
  },
  {
    name: "VACUOUS_RETIRE",
    why: "a file that holds nothing passes its readback",
    edits: edit(READBACK, "if (total === 0) {", "if (false) {"),
    tests: [GATES],
    mustFail: ["VACUOUS_RETIRE"],
  },
  {
    name: "RETIRE_FLAG_IGNORED",
    why: "the delete flag is ignored",
    edits: edit(
      RETIRE,
      "const mayDelete = deps.deleteEnabled && deps.dryRun !== true;",
      "const mayDelete = deps.dryRun !== true;",
    ),
    tests: [GATES, CYCLE],
    mustFail: ["RETIRE_FLAG_IGNORED"],
  },
  {
    name: "DRYRUN_DELETES",
    why: "a dry run deletes",
    edits: edit(
      RETIRE,
      "const mayDelete = deps.deleteEnabled && deps.dryRun !== true;",
      "const mayDelete = deps.deleteEnabled;",
    ),
    tests: [GATES],
    mustFail: ["DRYRUN_DELETES"],
  },
  {
    name: "RETIRE_BEFORE_IMPORT",
    why: "a file retires before this device's import finished",
    edits: edit(RETIRE, 'if (!importDone) return report("no_import");', ""),
    tests: [GATES],
    mustFail: ["RETIRE_BEFORE_IMPORT"],
  },
  {
    name: "UNFENCED_DELETE",
    why: "the delete does not name the version it read back",
    edits: edit(
      RETIRE,
      `await deps.storage.deleteVersion(scope, row.collectedAt, {
        id: row.id,
        path: row.path,
      });`,
      "await deps.storage.deleteVersion(scope, row.collectedAt);",
    ),
    tests: [GATES],
    mustFail: ["UNFENCED_DELETE"],
  },
  {
    name: "RETIRE_ON_SPOOL",
    why: "the published body includes this device's unpublished runs (also READBACK_ON_SPOOL)",
    edits: edit(
      SERVICE,
      `legacyFile: true,
        isOwnerView: false,
      });
      if (decision.kind !== "view") return null;`,
      `legacyFile: true,
        isOwnerView: true,
      });
      if (decision.kind !== "view") return null;`,
    ),
    tests: [FLOW],
    mustFail: ["RETIRE_ON_SPOOL"],
  },
  {
    name: "LEGACY_NAME_TOMBSTONE",
    why: "a retire pass reaches the gateway",
    edits: edit(
      CYCLE_FILE,
      `lastRetire = report;
      return report;`,
      `lastRetire = report;
      void (uploadDeps.gateway as unknown as { tombstone: unknown }).tombstone;
      return report;`,
    ),
    tests: [CYCLE],
    mustFail: ["LEGACY_NAME_TOMBSTONE"],
  },
  {
    name: "RUN_BEFORE_IMPORT",
    why: "a run begins before the import finished",
    edits: edit(
      WRITER,
      `this.options.importDone &&
        !(await this.options.importDone(input.connector))`,
      `false &&
        !(await this.options.importDone!(input.connector))`,
    ),
    tests: [FLOW],
    mustFail: ["RUN_BEFORE_IMPORT"],
  },
  {
    name: "IMPORT_IGNORES_FENCE",
    why: "the import seeds a stream that was deleted",
    edits: edit(
      WRITER,
      "if (stream.seedApplies && lastDeleteVersion > 0) {",
      "if (false && stream.seedApplies && lastDeleteVersion > 0) {",
    ),
    tests: [FLOW],
    mustFail: ["IMPORT_IGNORES_FENCE"],
  },
  {
    name: "UNSWITCHED_CHANGED",
    why: "an unswitched account imports and gates runs",
    edits: [
      {
        file: IMPORT,
        find: "if (!this.options.switched()) return true;",
        replace: "",
      },
      {
        file: IMPORT,
        find: `if (!this.options.switched()) {
      return { ran: false, connectorsStaged: 0, failed: 0 };
    }`,
        replace: "",
      },
    ],
    tests: [FLOW, CYCLE],
    mustFail: ["UNSWITCHED_CHANGED"],
  },
  {
    name: "IMPORT_LOSES_ON_RERUN",
    why: "a pass with a failed connector marks the import complete",
    edits: edit(IMPORT, "if (failed === 0) {", "if (true) {"),
    tests: [IMPORT_SINK_TEST],
    mustFail: ["IMPORT_LOSES_ON_RERUN"],
    build: true,
  },
  {
    name: "IMPORT_DUPLICATES",
    why: "a re-run stages a connector again after its pass finished",
    edits: edit(
      IMPORT,
      `if ((await ledger.read()).importComplete) {
      return { ran: false, connectorsStaged: 0, failed: 0 };
    }`,
      "",
    ),
    tests: [IMPORT_SINK_TEST],
    mustFail: ["IMPORT_DUPLICATES"],
    build: true,
  },
];
