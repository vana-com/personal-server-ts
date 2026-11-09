#!/usr/bin/env node
/**
 * Mutant runner for the stream-sync connection delete.
 *
 * First an unmutated baseline: the focused tests of every mutant run once, and
 * any failure aborts the run (a mutant cannot be told apart from a broken
 * tree). Then each mutant edits its source files, runs its focused tests, and
 * must turn at least one test red whose name contains `aim`. The sources are
 * restored after every mutant, even on a crash. Run from the repository root:
 *
 *   node scripts/stream-sync-delete-mutants.mjs [NAME ...]
 *
 * A fresh clone has no compiled output: run `npx tsc --build` first, or the
 * baseline fails with 500s (a safe abort).
 *
 * A mutant in `packages/core` marks `build: true`, so the server and Lite
 * tests (which read core's compiled output) see it.
 */
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";

const DELETE_TESTS = [
  "packages/core/src/stream-sync/writer-delete-connection.test.ts",
];
const REQUEST_TESTS = [
  "packages/core/src/stream-sync/writer-delete-request.test.ts",
];
const NODE_ROUTE = "packages/server/src/routes/owner-connectors.ts";
const NODE_TESTS = ["packages/server/src/routes/owner-connectors.test.ts"];
const LITE_TESTS = ["packages/lite/src/owner-connectors.test.ts"];
const HANDLER = "packages/core/src/api/owner-connector-delete.ts";
const WRITER = "packages/core/src/stream-sync/writer.ts";
const DECLARED_TESTS = [
  "packages/core/src/stream-sync/writer-delete-declared.test.ts",
];
const DURABLE_TESTS = [
  ...DECLARED_TESTS,
  "packages/lite/src/sync-stream-delete-durable.test.ts",
  "packages/server/src/bootstrap-durable-delete.test.ts",
];
const BOOTSTRAP = "packages/server/src/bootstrap.ts";
const BOOTSTRAP_TESTS = [
  "packages/server/src/bootstrap-declared-streams.test.ts",
];

/** @type {Array<{name: string, edits: Array<{file: string, find: string, replace: string}>, tests: string[], aim: string, build?: boolean}>} */
const MUTANTS = [
  {
    // The rowless streams are not fenced: declared names are ignored.
    name: "DECLARED_OMITTED",
    edits: [
      {
        file: WRITER,
        find: "for (const stream of declared) {",
        replace: "for (const stream of []) {",
      },
    ],
    tests: DELETE_TESTS,
    aim: "rowless streams come from the verified manifest",
  },
  {
    // The writer accepts a missing declaredStreams again.
    name: "DECLARED_UNCHECKED",
    edits: [
      {
        file: WRITER,
        find: 'typeof options.declaredStreams !== "function"',
        replace: "false",
      },
    ],
    tests: DELETE_TESTS,
    aim: "built without declaredStreams is refused",
  },
  {
    // A connector with rows and no declared names is deleted anyway.
    name: "EMPTY_DECLARED_ACCEPTED",
    edits: [
      {
        file: WRITER,
        find: "if (declared.length === 0) {",
        replace: "if (false) {",
      },
    ],
    tests: [...DELETE_TESTS, ...REQUEST_TESTS],
    aim: "refuses a connector with rows and no declared names",
  },
  {
    // A second delete after a reconnect reuses a stale open intent.
    name: "REUSE_OPEN_INTENT",
    edits: [
      {
        file: WRITER,
        find: "if (open && (planIsEmpty(plan) || sameDeletePlan(open, plan))) {",
        replace: "if (open) {",
      },
    ],
    tests: REQUEST_TESTS,
    aim: "a second delete after a reconnect",
  },
  {
    // A matching open intent is replaced: two requests land twice.
    name: "ALWAYS_NEW_INTENT",
    edits: [
      {
        file: WRITER,
        find: "if (open && (planIsEmpty(plan) || sameDeletePlan(open, plan))) {",
        replace: "if (false) {",
      },
    ],
    tests: REQUEST_TESTS,
    aim: "two requests for one delete land it once",
  },
  {
    // The registry is planned before the open intent is read, so a delete in
    // flight is refused when the manifest is not verified.
    name: "PLAN_BEFORE_OPEN_INTENT",
    edits: [
      {
        file: WRITER,
        find: "if (open && error instanceof ConnectorNotVerifiedError) return open;",
        replace: "if (false) return open;",
      },
    ],
    tests: REQUEST_TESTS,
    aim: "a repeated request for a delete in flight answers its id",
  },
  {
    // An empty plan (the registry lists nothing) clears the open intent.
    name: "EMPTY_PLAN_CLEARS_OPEN",
    edits: [
      {
        file: WRITER,
        find: "if (open && (planIsEmpty(plan) || sameDeletePlan(open, plan))) {",
        replace: "if (open && sameDeletePlan(open, plan)) {",
      },
      {
        file: WRITER,
        find: "        delete state.seedTargets[connector];\n      });\n      return null;",
        replace:
          "        delete state.seedTargets[connector];\n        delete state.deletes?.[connector];\n      });\n      return null;",
      },
    ],
    tests: REQUEST_TESTS,
    aim: "an empty plan keeps the open intent",
  },
  {
    // Refusals carry a top-level string instead of the API's envelope.
    name: "TOP_LEVEL_ERROR_BODY",
    edits: [
      {
        file: HANDLER,
        find: "JSON.stringify({ error: { code: status, errorCode, message } })",
        replace: "JSON.stringify({ error: errorCode, message })",
      },
    ],
    tests: [...NODE_TESTS, ...LITE_TESTS],
    aim: "one error envelope",
    build: true,
  },
  {
    // The shutdown 503 comes before owner authorization.
    name: "CLOSING_BEFORE_AUTH",
    edits: [
      {
        file: NODE_ROUTE,
        find: "        await auth.authorizeOwner(request);\n        deps.assertAdmitting?.();",
        replace:
          "        deps.assertAdmitting?.();\n        await auth.authorizeOwner(request);",
      },
    ],
    tests: NODE_TESTS,
    aim: "tells a caller who is not the owner nothing about shutdown",
  },
  {
    // A malformed percent-escape falls back to the raw segment.
    name: "RAW_ID_ON_BAD_ESCAPE",
    edits: [
      {
        file: NODE_ROUTE,
        find: "    return null;",
        replace: "    return segment;",
      },
    ],
    tests: NODE_TESTS,
    aim: "refuses a malformed percent-escape",
  },
  {
    // Node answers a wrong method with 405 before owner authorization.
    name: "METHOD_BEFORE_AUTH",
    edits: [
      {
        file: NODE_ROUTE,
        find: "    await auth.authorizeOwner(c.req.raw);\n    return ownerConnectorRefusal(",
        replace: "    return ownerConnectorRefusal(",
      },
    ],
    tests: NODE_TESTS,
    aim: "answers another method with 405 to the owner only",
  },
  {
    // Lite answers a wrong method before owner authorization.
    name: "PRE_AUTH_REFUSAL",
    edits: [
      {
        file: "packages/lite/src/runtime.ts",
        find: "            await auth.authorizeOwner(request);\n            return errorResponse(\n              405,",
        replace: "            return errorResponse(\n              405,",
      },
    ],
    tests: LITE_TESTS,
    aim: "answers a wrong method only to the owner",
  },
  {
    // The durable names are ignored: a delete reads the declarations only from
    // config, so a connector removed from config keeps its rows and answers 503.
    name: "DURABLE_NAMES_IGNORED",
    edits: [
      {
        file: WRITER,
        find: "for (const stream of durable) names.add(stream);",
        replace: "for (const stream of [] as string[]) names.add(stream);",
      },
    ],
    tests: DURABLE_TESTS,
    build: true,
    aim: "rows written under a declaration",
  },
  {
    // The retained manifests name nothing: a connector with rows and no host
    // names is refused as unverified although its manifest is retained.
    name: "RETAINED_DECLARATION_DROPPED",
    edits: [
      {
        file: WRITER,
        find: "for (const stream of manifestStreamLister(retained)(connector)) {",
        replace: "for (const stream of [] as readonly string[]) {",
      },
    ],
    tests: DECLARED_TESTS,
    aim: "a connector with rows and a retained declaration deletes",
  },
  {
    // The host's names replace the retained manifests instead of joining
    // them: a manifest stream the host omits survives the delete.
    name: "DECLARED_STREAMS_NOT_UNIONED",
    edits: [
      {
        file: WRITER,
        find: "for (const stream of manifestStreamLister(retained)(connector)) {",
        replace:
          "for (const stream of this.options.declaredStreams(connector).length > 0 ? [] : manifestStreamLister(retained)(connector)) {",
      },
    ],
    tests: DECLARED_TESTS,
    aim: "the host's declared names and a retained manifest's streams are both fenced",
  },
  {
    // A staged seed of a connector with no registry rows is not marked
    // skipped on delete, so the next identified run seeds it back.
    name: "ROWLESS_DECLARED_STREAM_UNFENCED",
    edits: [
      {
        file: WRITER,
        find: "    await this.skipStagedSeed(connector);\n    if (planIsEmpty({ pins, streams, registered })) {",
        replace: "    if (planIsEmpty({ pins, streams, registered })) {",
      },
    ],
    tests: DECLARED_TESTS,
    aim: "a staged seed of a connector with no registry rows does not return",
  },
  {
    // The purge commits before the staged uploads are retired. A crash between
    // the two leaves the seed target set and the uploads unretired.
    name: "SKIP_AFTER_PURGE",
    edits: [
      {
        file: WRITER,
        find: "    await this.skipStagedSeed(connector);\n    if (planIsEmpty({ pins, streams, registered })) {\n      await this.purgeConnector(connector, []);",
        replace:
          "    if (planIsEmpty({ pins, streams, registered })) {\n      await this.purgeConnector(connector, []);\n      await this.skipStagedSeed(connector);",
      },
    ],
    build: true,
    tests: DECLARED_TESTS,
    aim: "does not publish the staged seed after restart",
  },
  {
    // The retired record is keyed by stream only: a later upload of the same
    // stream is dropped with the old one.
    name: "SKIP_BY_STREAM",
    edits: [
      {
        file: WRITER,
        find: "      ] === upload.upload",
        replace: "      ] !== undefined",
      },
    ],
    build: true,
    tests: DECLARED_TESTS,
    aim: "a new seed staged after a delete publishes on reconnect",
  },
  {
    // The stream-keyed rule, on the stream-delete path: a retired upload
    // blocks a later upload of the same stream.
    name: "DELETE_SKIP_BY_STREAM",
    edits: [
      {
        file: WRITER,
        find: "      ] === upload.upload",
        replace: "      ] !== undefined",
      },
    ],
    build: true,
    tests: DECLARED_TESTS,
    aim: "a new upload staged after another device's stream delete publishes",
  },
  {
    // The host's declaredStreams option is not passed to the writer's hook.
    name: "BOOTSTRAP_OPTION_DROPPED",
    edits: [
      {
        file: BOOTSTRAP,
        find: "declaredStreams: options?.declaredStreams ?? (() => []),",
        replace: "declaredStreams: (() => []),",
      },
    ],
    tests: BOOTSTRAP_TESTS,
    aim: "the host's declaredStreams option names an uninstalled connector's streams to the writer",
  },
];

const only = new Set(process.argv.slice(2));
const run = (cmd, args) =>
  spawnSync("nice", ["-n", "19", cmd, ...args], { encoding: "utf8" });
const failing = (result) =>
  `${result.stdout}${result.stderr}`
    .split("\n")
    .filter((line) => /^\s*(FAIL|×)/.test(line));

const selected = MUTANTS.filter(
  (mutant) => only.size === 0 || only.has(mutant.name),
);
const baselineTests = [...new Set(selected.flatMap((mutant) => mutant.tests))];
const baseline = run("npx", [
  "vitest",
  "run",
  "--maxWorkers=4",
  ...baselineTests,
]);
const baselineRed = failing(baseline);
if (baseline.status !== 0 || baselineRed.length > 0) {
  console.log(
    `BASELINE RED (${baselineRed.length} failing line(s)); mutants not run`,
  );
  console.log(baselineRed.join("\n"));
  process.exit(2);
}
console.log(`BASELINE green (${baselineTests.length} file(s))`);

let failed = false;
for (const mutant of selected) {
  const originals = new Map();
  try {
    for (const edit of mutant.edits) {
      const source =
        originals.get(edit.file) ?? readFileSync(edit.file, "utf8");
      originals.set(edit.file, source);
      const current = readFileSync(edit.file, "utf8");
      if (!current.includes(edit.find)) {
        throw new Error(`pattern not found in ${edit.file}`);
      }
      writeFileSync(edit.file, current.replace(edit.find, edit.replace));
    }
    if (mutant.build) run("npx", ["tsc", "--build"]);
    const result = run("npx", [
      "vitest",
      "run",
      "--maxWorkers=4",
      ...mutant.tests,
    ]);
    const red = failing(result);
    const aimed = red.some((line) => line.includes(mutant.aim));
    console.log(
      `${mutant.name}: ${aimed ? "RED on aim" : "NOT RED ON AIM"} (${red.length} failing line(s))`,
    );
    if (!aimed) failed = true;
  } catch (error) {
    console.log(`${mutant.name}: ERROR ${error.message}`);
    failed = true;
  } finally {
    for (const [file, source] of originals) writeFileSync(file, source);
    if (mutant.build) run("npx", ["tsc", "--build"]);
  }
}
process.exit(failed ? 1 : 0);
