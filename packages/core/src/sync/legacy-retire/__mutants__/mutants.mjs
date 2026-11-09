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
const CANON = `${R}/canonical-source.ts`;
const BOOTSTRAP = "packages/server/src/bootstrap.ts";
const STATUS_ROUTE = "packages/server/src/routes/stream-sync-import-status.ts";
const STATUS_ROUTE_TEST =
  "packages/server/src/routes/stream-sync-import-status.test.ts";
const PUBLISH_TEST = `${R}/import-publish.test.ts`;

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

const CANON_TEST = `${R}/canonical-source.test.ts`;
const CANON_STORE_TEST =
  "packages/server/src/stream-sync/canonical-import.test.ts";
const BOOT_TEST = "packages/server/src/canonical-import-boot.test.ts";

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
      "found && found.dry !== true && found.preImport !== true",
      "found && found.preImport !== true",
    ),
    tests: [ROUND2],
    mustFail: ["DRYRUN_READBACK_USABLE"],
  },
  {
    name: "FENCE_AFTER_DELETE_WRITE",
    why: "the fence ignores when the file was written",
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
      "body === null && basis !== null && fenceOpen && basis.viewDeleted;",
      "fenceOpen;",
    ),
    tests: [ROUND2],
    mustFail: ["FENCE_NULL_VIEW_PASSES"],
  },
  {
    name: "PREIMPORT_READBACK_USABLE",
    why: "a readback made before the import finished counts as a stored pass",
    edits: edit(
      LEDGER,
      "found && found.dry !== true && found.preImport !== true",
      "found && found.dry !== true",
    ),
    tests: [ROUND2],
    mustFail: ["PREIMPORT_READBACK_USABLE"],
  },
  {
    name: "FENCE_PASSES_WITHOUT_VIEW",
    why: "a throwing read of the published view counts as no view and passes under the fence",
    edits: edit(
      READBACK,
      `  } catch {
    return store({ pass: false, reason: "no_published_view" });
  }`,
      `  } catch {
    body = null;
  }`,
    ),
    tests: [ROUND2],
    mustFail: ["FENCE_PASSES_WITHOUT_VIEW"],
  },
  {
    name: "FENCE_PASSES_WITHOUT_VIEW_SERVICE",
    why: "publishedBody turns a failed read into no view",
    edits: edit(
      SERVICE,
      `    const decision = await this.resolve({
      scope,
      connection: null,
      cursor: null,
      legacyFile: true,
      isOwnerView: false,
    });
    if (decision.kind !== "view") {`,
      `    const decision = await this.resolve({
      scope,
      connection: null,
      cursor: null,
      legacyFile: true,
      isOwnerView: false,
    }).catch(() => ({ kind: "pass" as const }));
    if (decision.kind !== "view") {`,
    ),
    tests: [BASIS],
    mustFail: ["FENCE_PASSES_WITHOUT_VIEW"],
  },
  // ---- round 3 (review of e6992b5d) ----
  {
    name: "VACUOUS_IMPORT_FENCE_DELETES",
    why: "a fenced file retires although this device staged no rows (an empty import source marks every connector done)",
    edits: edit(
      RETIRE,
      "if (!(await deps.host.importStaged(s.connector, s.stream))) {",
      "if (false) {",
    ),
    tests: [ROUND2],
    mustFail: ["VACUOUS_IMPORT_FENCE_DELETES"],
  },
  {
    name: "EMPTY_IMPORT_FENCE_DELETES",
    why: "round-1 bug whole: the fence ignores when the file was written AND an empty import counts as staged",
    edits: [
      ...edit(READBACK, "writtenAt < s.deleteAtMs", "true"),
      ...edit(
        RETIRE,
        "if (!(await deps.host.importStaged(s.connector, s.stream))) {",
        "if (false) {",
      ),
    ],
    tests: [ROUND2],
    mustFail: ["EMPTY_IMPORT_FENCE_DELETES"],
  },
  {
    name: "FENCE_CHANGED_PASSES",
    why: "a changed entity of a file written after the delete is excused",
    edits: edit(
      READBACK,
      "  if (fenceOpen) {\n    return {",
      "  if (fenceOpen || (missing === 0 && changed > 0)) {\n    return {",
    ),
    tests: [ROUND2],
    mustFail: ["FENCE_CHANGED_PASSES"],
  },
  {
    name: "UNLISTED_SCALAR_IGNORED",
    why: "an uncovered top-level scalar is skipped, not compared",
    edits: edit(
      KEYS,
      "if (READER_STAMPED_SCALARS.has(key)) continue;",
      "continue;",
    ),
    tests: [ROUND2],
    mustFail: ["UNLISTED_SCALAR_IGNORED"],
  },
  {
    name: "DERIVED_TOTAL_COMPARED",
    why: "a `total` derived from a compared collection is compared too: an older snapshot never retires once the collection grew",
    edits: edit(
      KEYS,
      "contentHash(derivedCount(key, value) ? DERIVED_COUNT : value)",
      "contentHash(value)",
    ),
    tests: [ROUND2],
    mustFail: ["still retires an older snapshot whose derived total"],
  },
  {
    name: "UNKNOWN_ALTERNATE_DELETES",
    why: "retireBasis says every target is known although an alternate connector was never seen",
    edits: edit(
      SERVICE,
      "allTargetsKnown: targets.length === allTargets.length,",
      "allTargetsKnown: true,",
    ),
    tests: [BASIS],
    mustFail: ["UNKNOWN_ALTERNATE_DELETES"],
  },
  {
    name: "UNKNOWN_ALTERNATE_FENCES",
    why: "the fence opens for a scope with a connector the registry never saw",
    edits: edit(
      READBACK,
      "basis.streams.length === 0 || !basis.allTargetsKnown",
      "basis.streams.length === 0",
    ),
    tests: [ROUND2],
    mustFail: ["UNKNOWN_ALTERNATE_FENCES"],
  },
  {
    name: "VIEWGONE_WITHOUT_NULL_BODY",
    why: "a served body that cannot be keyed counts as a deleted source",
    edits: edit(
      READBACK,
      "body === null && basis !== null && fenceOpen && basis.viewDeleted",
      "basis !== null && fenceOpen && basis.viewDeleted",
    ),
    tests: [ROUND2],
    mustFail: ["VIEWGONE_WITHOUT_NULL_BODY"],
  },
  {
    name: "FILE_CHANGED_BEFORE_DELETE",
    why: "the file is not hashed again right before the delete",
    edits: edit(
      RETIRE,
      "if (report.wouldDelete && !(await holds(deps, scope, row, fresh))) {",
      "if (false) {",
    ),
    tests: [ROUND2],
    mustFail: ["FILE_CHANGED_BEFORE_DELETE"],
  },
  // ---- round 4 (review of 578fcd2b, and the #601 dry run at 7b7192ed) ----
  {
    name: "ZERO_STREAM_IMPORT_FENCES",
    why: "a connector the source listed with no stream, or a stream with no row, counts as staged: the fence opens for rows never published",
    edits: edit(
      LEDGER,
      "return rows !== undefined && rows > 0;",
      "return (\n      rows !== undefined ||\n      (await this.read()).imported[connector] !== undefined\n    );",
    ),
    tests: [ROUND2],
    mustFail: ["ZERO_STREAM_IMPORT_FENCES", "staged zero rows"],
  },
  {
    name: "RECEIPT_ROWS_NOT_COUNTED",
    why: "the importer records every staged stream with zero rows, so no fence ever opens",
    edits: edit(
      IMPORT,
      "receipt[stream.stream] = await sink.stage(\n            connector,\n            stream,\n            stream.records(),\n          );",
      "await sink.stage(connector, stream, stream.records());\n          receipt[stream.stream] = 0;",
    ),
    tests: [ROUND2],
    mustFail: ["retires a pre-delete file once the import staged rows"],
  },
  {
    name: "RECEIPT_COUNTED_ON_PULL",
    why: "the importer counts the rows the sink pulled, not the rows it kept: an intake that drops every row still opens the fence",
    edits: edit(
      IMPORT,
      "receipt[stream.stream] = await sink.stage(\n            connector,\n            stream,\n            stream.records(),\n          );",
      "let pulled = 0;\n          await sink.stage(\n            connector,\n            stream,\n            (async function* () {\n              for await (const row of stream.records()) {\n                pulled += 1;\n                yield row;\n              }\n            })(),\n          );\n          receipt[stream.stream] = pulled;",
    ),
    tests: [ROUND2],
    mustFail: ["RECEIPT_COUNTED_ON_PULL"],
  },
  {
    name: "DERIVED_TOTAL_ANY_COLLECTION",
    why: "a `total` is derived whenever it equals the length of any covered collection, whatever the scope counts",
    edits: edit(
      KEYS,
      "const counted = DERIVED_COUNT_SCALARS[scope]?.[key];\n    if (counted === undefined || !covered.has(counted)) return false;\n    const items = record[counted];\n    return Array.isArray(items) && items.length === value;",
      "if (!Object.values(DERIVED_COUNT_SCALARS).some((t) => Object.hasOwn(t, key))) return false;\n    return [...covered].some((c) => {\n      const items = record[c];\n      return Array.isArray(items) && items.length === value;\n    });",
    ),
    tests: [ROUND2],
    mustFail: ["DERIVED_TOTAL_ANY_COLLECTION"],
  },
  {
    name: "HASH_NOT_PASSED_TO_ERASE",
    why: "the erase is fenced by id and path only: a same-path rewrite after the recheck is erased",
    edits: edit(
      RETIRE,
      "        ...(readHash === undefined ? {} : { contentHash: readHash }),\n",
      "",
    ),
    tests: [ROUND2, GATES],
    mustFail: ["HASH_NOT_PASSED_TO_ERASE"],
  },
  {
    name: "PUBLISHED_TOTAL_IGNORED",
    why: "a count derived on the local side is skipped without asking whether the published count is derived too",
    edits: edit(
      KEYS,
      "if (READER_STAMPED_SCALARS.has(key)) continue;",
      "if (READER_STAMPED_SCALARS.has(key) || derivedCount(key, value)) continue;",
    ),
    tests: [ROUND2],
    mustFail: ["PUBLISHED_TOTAL_IGNORED"],
  },
  {
    name: "FETCHED_AT_COMPARED",
    why: "the reader's own `fetchedAt` stamp is compared: every scope that carries one fails its readback under the real clock",
    edits: edit(KEYS, '  "fetchedAt",\n]);', "]);"),
    tests: [ROUND2],
    mustFail: ["FETCHED_AT_COMPARED"],
  },
  {
    name: "FETCHED_AT_ITEM_COMPARED",
    why: "a conversation item's reader-stamped `fetched_at` is hashed with the item",
    edits: edit(
      KEYS,
      '"chatgpt.conversations": ["fetched_at"],',
      '"chatgpt.conversations": [],',
    ),
    tests: [ROUND2],
    mustFail: ["FETCHED_AT_ITEM_COMPARED"],
  },
  {
    name: "CONTENT_FENCE_IGNORED_NODE_OPS",
    why: "the Node storage (import operations) erases without checking the content hash inside its transaction",
    edits: edit(
      "packages/server/src/storage/import-operations.ts",
      "if (!fenceContentMatches(fence, stored.data)) return false;",
      "",
    ),
    tests: ["packages/server/src/storage/node-data-storage.test.ts"],
    mustFail: ["with import operations", "rewritten after the fence hash"],
  },
  {
    name: "CONTENT_FENCE_IGNORED_NODE",
    why: "the Node storage without import operations erases without checking the content hash",
    edits: edit(
      "packages/server/src/storage/node-data-storage.ts",
      "if (!fenceContentMatches(fence, stored.data)) return false;",
      "",
    ),
    tests: ["packages/server/src/storage/node-data-storage.test.ts"],
    mustFail: ["without import operations", "rewritten after the fence hash"],
  },
  {
    name: "CONTENT_FENCE_IGNORED_LITE",
    why: "the Lite storage erases without checking the content hash under the path lock",
    edits: edit(
      "packages/lite/src/storage.ts",
      "!present.every((copy) => fenceContentMatches(fence, copy.data))",
      "false",
    ),
    tests: ["packages/lite/src/storage.test.ts"],
    mustFail: ["an erase fenced by content"],
  },
  {
    name: "SINK_RETURNS_PULLED",
    why: "the seed sink reports the rows it was handed, not the rows the intake kept",
    edits: edit(
      "packages/server/src/stream-sync/legacy-import-sink.ts",
      "return seed.records;",
      "return count;",
    ),
    tests: [IMPORT_SINK_TEST],
    mustFail: ["SINK_RETURNS_PULLED"],
  },
  {
    name: "NODE_WRITE_ENVELOPE_UNLOCKED",
    why: "the Node storage writes an envelope without the scope lock every erase takes, so a write can land between an erase's content check and its unlink",
    edits: edit(
      "packages/server/src/storage/node-data-storage.ts",
      "return withScopeLock(envelope.scope, () =>\n        writeDataFile(deps.hierarchyOptions, envelope),\n      );",
      "return writeDataFile(deps.hierarchyOptions, envelope);",
    ),
    tests: ["packages/server/src/storage/node-data-storage.test.ts"],
    mustFail: ["WRITE_ENVELOPE_UNLOCKED"],
  },
  {
    name: "LITE_HASH_ONE_COPY",
    why: "the Lite erase checks the first copy of the file only, but removes every copy",
    edits: edit(
      "packages/lite/src/storage.ts",
      "!present.every((copy) => fenceContentMatches(fence, copy.data))",
      "!fenceContentMatches(fence, present[0]!.data)",
    ),
    tests: ["packages/lite/src/storage.test.ts"],
    mustFail: ["LITE_HASH_ONE_COPY"],
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
      'if (value !== null && typeof value === "object") return null;',
      "if (false) return null;",
    ),
    tests: [ROUND2],
    mustFail: ["UNLISTED_TOP_LEVEL_IGNORED"],
  },
  {
    name: "UNKNOWN_ALTERNATE_UNCOVERS",
    why: "retireBasis counts connectors the registry never saw",
    edits: edit(
      SERVICE,
      "allTargets.filter((t) => known.has(t.connector));",
      "allTargets;",
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
    edits: edit(READBACK, "if (collectionTotal === 0) {", "if (false) {"),
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
        ...(readHash === undefined ? {} : { contentHash: readHash }),
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
    if (decision.kind !== "view") {`,
      `legacyFile: true,
      isOwnerView: true,
    });
    if (decision.kind !== "view") {`,
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
    tests: [FLOW, CANON_TEST],
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
    edits: edit(IMPORT, "if (waiting === 0) {", "if (true) {"),
    tests: [IMPORT_SINK_TEST],
    mustFail: ["IMPORT_LOSES_ON_RERUN"],
    build: true,
  },
  {
    name: "IMPORT_DUPLICATES",
    why: "a re-run stages a connector again after its pass finished",
    edits: [
      {
        file: IMPORT,
        find: `const result = (await ledger.read()).importComplete
      ? { ran: false, connectorsStaged: 0, failed: 0 }
      : await this.stage();`,
        replace: "const result = await this.stage();",
      },
      {
        file: IMPORT,
        find: "if (known.imported[connector] || known.failures[connector]?.gaveUp) {",
        replace: "if (false) {",
      },
    ],
    tests: [IMPORT_SINK_TEST],
    mustFail: ["IMPORT_DUPLICATES"],
    build: true,
  },

  // ---- the canonical import source (stacked on #595) ----
  {
    name: "IMPORT_SOURCE_EMPTY_IN_PRODUCTION",
    why: "the production source lists no connector, so the import completes empty",
    edits: edit(
      CANON,
      "for (const [key, declarations] of sourcesOf(deps)) {",
      "for (const [key, declarations] of new Map<string, DeclarationSnapshot[]>()) {",
    ),
    tests: [CANON_TEST, CANON_STORE_TEST, BOOT_TEST],
    mustFail: ["IMPORT_SOURCE_EMPTY_IN_PRODUCTION"],
    build: true,
  },
  {
    name: "PENDING_COUNTED_AS_EMPTY",
    why: "a source whose stores are not bound reads as having no rows",
    edits: edit(
      CANON,
      "if (!deps) throw new ImportSourceUnavailableError();",
      `if (!deps) {
      return {
        store: {
          listConnections: () => [],
          listStreams: () => [],
          listRecords: () => ({ data: [], hasMore: false }),
        },
        declarations: [],
      };
    }`,
    ),
    tests: [CANON_TEST],
    mustFail: ["PENDING_COUNTED_AS_EMPTY"],
  },
  {
    name: "UNMAPPED_SCOPE_DROPPED_SILENTLY",
    why: "rows the import leaves in the file are not counted or explained",
    edits: edit(
      CANON,
      "return scans.get(connector)?.excluded ?? [];",
      "return [];",
    ),
    tests: [CANON_TEST],
    mustFail: ["UNMAPPED_SCOPE_DROPPED_SILENTLY"],
  },
  {
    name: "UNKEYED_ROW_IMPORTED",
    why: "a row with a missing key field is staged",
    edits: edit(
      CANON,
      "if (!primaryKey.every((field) => isKeyValue(row[field]))) {",
      "if (false) {",
    ),
    tests: [CANON_TEST],
    mustFail: ["UNKEYED_ROW_IMPORTED"],
  },
  {
    name: "BLOB_ROW_EXCLUDED",
    why: "a row that points at a blob is left behind though its reference is plain data",
    edits: edit(
      CANON,
      `    return "unkeyed_row";
  }
  return "import";`,
      `    return "unkeyed_row";
  }
  if (JSON.stringify(row).includes("blob_id")) return "unkeyed_row";
  return "import";`,
    ),
    tests: [CANON_TEST],
    mustFail: ["BLOB_ROW_EXCLUDED"],
  },
  {
    name: "CONNECTOR_DROPPED_WHEN_AMBIGUOUS",
    why: "a connector with two live connections is left out whole",
    edits: edit(
      CANON,
      "if (live.length === 0) return { streams: [], excluded: [] };",
      "if (live.length !== 1) return { streams: [], excluded: [] };",
    ),
    tests: [CANON_TEST],
    mustFail: ["CONNECTOR_DROPPED_WHEN_AMBIGUOUS"],
  },
  {
    name: "OLDEST_CONNECTION_CHOSEN",
    why: "the least recently active connection is imported",
    edits: edit(
      CANON,
      "b.latest.localeCompare(a.latest) ||",
      "a.latest.localeCompare(b.latest) ||",
    ),
    tests: [CANON_TEST],
    mustFail: ["OLDEST_CONNECTION_CHOSEN"],
  },
  {
    name: "OTHER_CONNECTION_NOT_COUNTED",
    why: "the rows of the connections not imported are not counted",
    edits: edit(CANON, "otherRows > 0\n        ?", "false\n        ?"),
    tests: [CANON_TEST],
    mustFail: ["OTHER_CONNECTION_NOT_COUNTED"],
  },
  {
    name: "DELETED_CONNECTION_IMPORTED",
    why: "rows of a connection the owner deleted are imported",
    edits: edit(CANON, "if (connection.deletedAt === null) {", "if (true) {"),
    tests: [CANON_TEST],
    mustFail: ["DELETED_CONNECTION_IMPORTED"],
  },
  {
    name: "IMPORT_DUPLICATES_ON_RERUN",
    why: "a finished pass stages its connectors again on the next call",
    edits: [
      {
        file: IMPORT,
        find: `const result = (await ledger.read()).importComplete
      ? { ran: false, connectorsStaged: 0, failed: 0 }
      : await this.stage();`,
        replace: "const result = await this.stage();",
      },
      {
        file: IMPORT,
        find: "if (known.imported[connector] || known.failures[connector]?.gaveUp) {",
        replace: "if (false) {",
      },
    ],
    tests: [CANON_TEST],
    mustFail: ["IMPORT_DUPLICATES_ON_RERUN"],
  },
  {
    name: "IMPORT_WRONG_OWNER",
    why: "a source of another owner stages into this home",
    edits: edit(
      IMPORT,
      "if (source.owner.toLowerCase() !== ledger.owner) {",
      "if (false) {",
    ),
    tests: [CANON_TEST],
    mustFail: ["IMPORT_WRONG_OWNER"],
  },
  {
    name: "LEDGER_OWNER_IGNORED",
    why: "a ledger recorded for another owner (or none) is trusted",
    edits: edit(
      LEDGER,
      "if (parsed.owner !== this.owner) return empty(this.owner);",
      "",
    ),
    tests: [CANON_TEST],
    mustFail: ["LEDGER_OWNER_IGNORED"],
  },
  {
    name: "BOOT_IMPORT_NEVER_BOUND",
    why: "boot never hands the canonical store to the import source",
    edits: edit(
      BOOTSTRAP,
      "canonicalImportDeps =\n    pdppConnections && pdppAuth",
      "const unboundImportDeps =\n    pdppConnections && pdppAuth",
    ),
    tests: [BOOT_TEST],
    mustFail: ["BOOT_IMPORT_NEVER_BOUND"],
    build: true,
  },

  // ---- round 2 of the import source: readable, bounded, visible ----
  {
    name: "SEED_WAITS_FOR_CONNECTOR_RUN",
    why: "staged rows are published only by the connector's next run",
    edits: edit(IMPORT, "    await this.queueRuns();\n", ""),
    tests: [PUBLISH_TEST, BOOT_TEST],
    mustFail: ["SEED_WAITS_FOR_CONNECTOR_RUN"],
    build: true,
  },
  {
    name: "SEED_BOUND_BEFORE_IMPORT",
    why: "a run admitted before the switch binds generation 1 though the import is not done",
    edits: edit(
      WRITER,
      `this.options.importDone &&
        !(await this.options.importDone(host.entry.connector))`,
      `false &&
        !(await this.options.importDone!(host.entry.connector))`,
    ),
    tests: [PUBLISH_TEST],
    mustFail: ["SEED_BOUND_BEFORE_IMPORT"],
    build: true,
  },
  {
    name: "IMPORT_RUN_SAVES_CHECKPOINT",
    why: "the import's own run saves a checkpoint, so the first real run is incremental",
    edits: edit(
      WRITER,
      "if (host.importOnly) {\n      await this.finish(host, {",
      "if (false) {\n      await this.finish(host, {",
    ),
    tests: [PUBLISH_TEST],
    mustFail: ["IMPORT_RUN_SAVES_CHECKPOINT"],
    build: true,
  },
  {
    name: "PUBLISH_NEVER_RETRIED",
    why: "a publish that is still waiting is recorded as done and never asked again",
    edits: edit(
      IMPORT,
      'if ((await publish(connector)) === "done") {',
      "if ((await publish(connector), true)) {",
    ),
    tests: [PUBLISH_TEST],
    mustFail: ["PUBLISH_NEVER_RETRIED"],
    build: true,
  },
  {
    name: "DUPLICATE_IMPORT_RUNS",
    why: "every ask queues another import run while the first one waits",
    edits: edit(
      WRITER,
      `host.phase !== "done"
      ) {
        return "waiting";`,
      `host.phase !== "done" &&
        false
      ) {
        return "waiting";`,
    ),
    tests: [PUBLISH_TEST],
    mustFail: ["DUPLICATE_IMPORT_RUNS"],
    build: true,
  },
  {
    name: "PERMANENT_FAILURE_STALLS_WRITES",
    why: "a connector whose import keeps failing is never given up",
    edits: edit(
      IMPORT,
      "gaveUp = attempts >= this.maxAttempts;",
      "gaveUp = false;",
    ),
    tests: [PUBLISH_TEST],
    mustFail: ["PERMANENT_FAILURE_STALLS_WRITES"],
    build: true,
  },
  {
    name: "LISTING_FAILURE_STALLS_FOR_EVER",
    why: "a source that never lists is never given up",
    edits: edit(
      IMPORT,
      "if (data.listAttempts >= this.maxAttempts) {",
      "if (false) {",
    ),
    tests: [PUBLISH_TEST],
    mustFail: ["LISTING_FAILURE_STALLS_FOR_EVER"],
    build: true,
  },
  {
    name: "FAILED_IMPORT_RETIRES",
    why: "the legacy file of a connector whose import was given up is retired",
    edits: edit(
      LEDGER,
      "if (data.abandoned || data.failures[connector]?.gaveUp === true) {",
      "if (data.abandoned) {",
    ),
    tests: [PUBLISH_TEST],
    mustFail: ["FAILED_IMPORT_RETIRES"],
    build: true,
  },
  {
    name: "ABANDONED_SOURCE_RETIRES",
    why: "the legacy files are retired though the source was given up unread",
    edits: edit(
      LEDGER,
      "if (data.abandoned || data.failures[connector]?.gaveUp === true) {",
      "if (data.failures[connector]?.gaveUp === true) {",
    ),
    tests: [PUBLISH_TEST],
    mustFail: ["ABANDONED_SOURCE_RETIRES"],
    build: true,
  },
  {
    name: "EXCLUDED_ROWS_RETIRE",
    why: "a connector with rows left behind has its legacy file retired",
    edits: edit(
      LEDGER,
      "if ((data.excluded[connector] ?? []).some((e) => e.rows > 0)) return false;",
      "",
    ),
    tests: [PUBLISH_TEST],
    mustFail: ["EXCLUDED_ROWS_RETIRE"],
    build: true,
  },
  {
    name: "STATUS_HIDES_EXCLUDED",
    why: "the owner read leaves out the rows that stayed behind",
    edits: edit(
      IMPORT,
      ".map(([reason, rows]) => ({ reason, rows })),",
      ".map(([reason, rows]) => ({ reason, rows }))\n            .slice(0, 0),",
    ),
    tests: [PUBLISH_TEST, BOOT_TEST],
    mustFail: ["STATUS_HIDES_EXCLUDED"],
    build: true,
  },
  {
    name: "STATUS_ROUTE_UNAUTHENTICATED",
    why: "anyone can read the import status",
    edits: edit(STATUS_ROUTE, "await auth.authorizeOwner(c.req.raw);", ""),
    tests: [STATUS_ROUTE_TEST, BOOT_TEST],
    mustFail: ["STATUS_ROUTE_UNAUTHENTICATED"],
  },
  {
    name: "PDPP_OFF_STALLS_IMPORT",
    why: "a host without PDPP leaves the import source 'not available' for ever",
    edits: edit(BOOTSTRAP, ": NO_CANONICAL_ROWS;", ": null;"),
    tests: [BOOT_TEST],
    mustFail: ["PDPP_OFF_STALLS_IMPORT"],
    build: true,
  },
  {
    name: "BOOT_PUBLISH_NOT_WIRED",
    why: "boot never asks the writer to publish the staged rows",
    edits: edit(
      BOOTSTRAP,
      "return streamSyncWriter.publishSeed(connector);",
      'return Promise.resolve("done" as const);',
    ),
    tests: [BOOT_TEST],
    mustFail: ["BOOT_PUBLISH_NOT_WIRED"],
    build: true,
  },
];
