// Default-off differential for the legacy write shutdown gate.
//
//   node scripts/legacy-gate-differential/compare.mjs \
//     --baseline <pre-gate tree> --candidate <gate tree> --work <scratch dir> \
//     [--expect-different] [--no-controls] [--allow-stale-dist] \
//     [--baseline-commit <sha prefix>] [--candidate-commit <sha prefix>]
//
// Both trees must be built (`tsc --build packages/core packages/server`). The
// scenario runs in each tree's own process: baseline, candidate, candidate
// again (determinism) and candidate with a failing gate journal. Every run
// must pass positive sanity checks, so two identical failures prove nothing.
// The candidate must then equal the baseline after removing only the
// authorized changes: the converged schema stamp (16 -> 17), the empty
// additive gate tables and the default-off config key. Gate table rows,
// producers, queues, uploads (decrypted), signatures and registrations are
// compared. See README.md for the exact normalization.
//
// Before any comparison the normalizer controls run (normalize.mjs): mutants
// of a real capture must be detected and declared-volatile edits must not be.
// --expect-different is a negative control for the whole comparison: exit 0
// only when the sanity checks pass and the candidate differs from the baseline
// in a structural field (a schema stamp alone does not count).
import { spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual, parseArgs } from "node:util";
import { differences, normalize, runControls } from "./normalize.mjs";

const { values: args } = parseArgs({
  options: {
    baseline: { type: "string" },
    candidate: { type: "string" },
    work: { type: "string" },
    "expect-different": { type: "boolean", default: false },
    "no-controls": { type: "boolean", default: false },
    "allow-stale-dist": { type: "boolean", default: false },
    "baseline-commit": { type: "string" },
    "candidate-commit": { type: "string" },
  },
});
if (!args.baseline || !args.candidate || !args.work) {
  console.error(
    "usage: compare.mjs --baseline <tree> --candidate <tree> --work <dir> [--expect-different] [--no-controls] [--allow-stale-dist] [--baseline-commit <sha>] [--candidate-commit <sha>]",
  );
  process.exit(2);
}
const scenario = join(dirname(fileURLToPath(import.meta.url)), "scenario.mjs");
const BASELINE_STAMP = 16;
const CANDIDATE_STAMP = 17;

function run(name, tree, extra = []) {
  const work = join(args.work, name);
  rmSync(work, { recursive: true, force: true });
  mkdirSync(work, { recursive: true });
  // The runtime logs every step to stderr; keep it, print its tail on failure.
  const child = spawnSync(
    process.execPath,
    [scenario, "--tree", tree, "--work", work, ...extra],
    {
      encoding: "utf8",
      stdio: ["ignore", "ignore", "pipe"],
      timeout: 600_000,
      maxBuffer: 256 * 1024 * 1024,
    },
  );
  writeFileSync(join(work, "scenario.log"), child.stderr ?? "");
  if (child.status !== 0) {
    const tail = (child.stderr ?? "").split("\n").slice(-40).join("\n");
    console.error(`${name}: scenario failed (exit ${child.status})\n${tail}`);
    process.exit(1);
  }
  const raw = JSON.parse(
    readFileSync(join(work, "raw-transcript.json"), "utf8"),
  );
  const normalized = normalize(raw);
  writeFileSync(
    join(work, "transcript.json"),
    `${JSON.stringify(normalized, null, 2)}\n`,
  );
  return { raw, transcript: normalized };
}

/** Positive evidence that every exercised path really ran and succeeded.
 * Returns the failures; an empty list means the run proves something. */
function sanity(name, transcript) {
  const failures = [];
  const op = (key) => transcript.operations.find((entry) => entry.name === key);
  const value = (key) => op(key)?.value;
  const status = (key, expected) => {
    const actual = value(key)?.status;
    if (actual !== expected)
      failures.push(`${key} status ${actual}, expected ${expected}`);
  };
  const expect = (condition, message) => {
    if (!condition) failures.push(message);
  };
  status("ingest-json", 201);
  status("ingest-binary", 201);
  status("chunk-begin", 201);
  status("chunk-upload", 200);
  status("chunk-finalize", 201);
  status("owner-import", 201);
  status("grant", 201);
  for (const key of ["ingest-json", "chunk-begin", "grant"])
    expect(
      value(key)?.headers?.["content-type"]?.startsWith("application/json"),
      `${key} has no JSON content-type`,
    );
  const calls = (method) =>
    transcript.gateway.filter((call) => call.method === method);
  const signed = (call) =>
    /^0x[0-9a-f]{130}$/i.test(String(call.args[0]?.signature));
  expect(calls("createGrant").some(signed), "no signed grant registration");
  const registrations = calls("registerDataPoint").filter(signed);
  const uploads = transcript.storage.filter(
    (entry) => entry.method === "PUT" && entry.cipherBytes > 0,
  );
  for (const scope of [
    "spotify.profile",
    "files.document",
    "chatgpt.conversations",
    "spotify.history",
    "notes.restart",
  ]) {
    expect(
      registrations.some((call) => call.args[0].scope === scope),
      `no signed data point registration for ${scope}`,
    );
    const mine = uploads.filter((entry) => entry.path.includes(`/${scope}/`));
    expect(mine.length > 0, `no encrypted upload for ${scope}`);
    for (const upload of mine)
      expect(
        !upload.decryptError && upload.envelope?.scope === scope,
        `upload for ${scope} does not decrypt to its own envelope: ${upload.decryptError}`,
      );
    expect(
      transcript.commitments.some(
        (check) =>
          check.scope === scope &&
          check.registrations > 0 &&
          check.dataHashMatches &&
          check.metadataHashMatches,
      ),
      `no matching commitments for ${scope}`,
    );
  }
  expect(
    transcript.commitments.every(
      (check) =>
        check.registrations > 0 &&
        check.dataHashMatches &&
        check.metadataHashMatches,
    ),
    "an upload's commitments do not match its decrypted payload",
  );
  for (const entry of transcript.operations.filter((o) =>
    o.name.startsWith("sync-"),
  ))
    expect(
      entry.value.errors.length === 0 && entry.value.blocked === null,
      `${entry.name}: ${JSON.stringify(entry.value)}`,
    );
  for (const key of ["direct-append-1", "direct-append-2"])
    expect(value(key)?.kind === "stored", `${key} not stored`);
  expect(
    value("recovered-playlists")?.length === 3,
    "prepared import was not recovered at boot",
  );
  expect(
    value("stage-recovery")?.finalExists === true,
    "boot recovery did not publish the leftover stage",
  );

  // Incoming replica through the real download worker, then repair.
  const ingest = value("replica-ingest");
  expect(
    ingest?.entry?.version === 1 &&
      ingest.entry.dataPointId === ingest.expectedDataPointId &&
      ingest.file?.data?.tracks?.length === 2 &&
      ingest.storageGets === 1 &&
      ingest.queued === false,
    `remote replica was not ingested: ${JSON.stringify(ingest)}`,
  );
  const loss = value("replica-same-version-loss");
  expect(loss?.lostBlocks === true, "replica loss was not staged");
  const repair = value("replica-repair");
  expect(
    repair?.restoredFile === true &&
      repair.bytesUnchanged === true &&
      repair.restoredBlocks === true &&
      repair.indexIdentityUnchanged === true &&
      repair.adoptedVersion === 2 &&
      repair.entryCount === 1 &&
      repair.storageGets === 1,
    `replica repair did not restore identical bytes and index identity: ${JSON.stringify(repair)}`,
  );

  // Interrupted chunked import: restart, failed finalize, completion, replay.
  status("restart-begin", 201);
  status("restart-chunk", 200);
  status("restart-chunk-replay", 200);
  status("restart-finalize-failed", 500);
  status("restart-finalize", 201);
  status("restart-finalize-replay", 201);
  status("restart-finalize-replay-after-restart", 201);
  expect(
    isDeepStrictEqual(
      value("restart-chunk")?.body,
      value("restart-chunk-replay")?.body,
    ),
    "chunk replay answered differently",
  );
  const receipt = value("restart-finalize")?.body;
  expect(
    receipt?.importId &&
      receipt.importId === value("restart-begin")?.body?.importId,
    "finalize receipt is not for the begun import",
  );
  for (const key of [
    "restart-finalize-replay",
    "restart-finalize-replay-after-restart",
  ])
    expect(
      isDeepStrictEqual(value(key)?.body, receipt),
      `${key} did not return the same receipt`,
    );
  const failed = value("restart-after-failed-finalize");
  expect(
    failed?.entries.length === 0 && failed.files.length === 0,
    "a failed finalize left a version or file behind",
  );
  const finished = value("restart-versions");
  expect(
    finished?.entries.length === 1 && finished.files.length === 1,
    `restarted import produced ${finished?.entries.length} versions and ${finished?.files.length} files`,
  );
  // Existing created_at values and receipts survive every phase unchanged.
  for (const key of [
    "preservation-replica-repair",
    "preservation-restart-import",
    "preservation-finalized-import",
    "preservation-recovery",
  ]) {
    const kept = value(key);
    expect(
      kept?.rowsChecked > 0 &&
        kept.createdAtRemoved.length === 0 &&
        kept.createdAtRewritten.length === 0 &&
        kept.receiptsChecked > 0 &&
        kept.receiptsRemoved === 0 &&
        kept.receiptsRewritten === 0,
      `${key}: an existing created_at or receipt changed: ${JSON.stringify(kept)}`,
    );
  }
  return failures.map((failure) => `${name}: ${failure}`);
}

/** Remove only the authorized differences, after checking their values. */
function authorized(name, transcript, expected) {
  const problems = [];
  const { userVersion } = transcript.schema;
  if (userVersion !== expected.userVersion)
    problems.push(
      `user_version ${userVersion}, expected ${expected.userVersion}`,
    );
  if (transcript.configFlag !== expected.configFlag)
    problems.push(`config flag ${transcript.configFlag}`);
  const written = Object.entries(transcript.gateRows).filter(([, n]) => n > 0);
  if (written.length)
    problems.push(`gate rows written: ${JSON.stringify(written)}`);
  const rest = structuredClone(transcript);
  delete rest.schema.userVersion;
  delete rest.configFlag;
  // Absent and empty gate tables are equivalent; written rows are not.
  rest.gateRows = Object.fromEntries(written);
  return { rest, problems: problems.map((problem) => `${name}: ${problem}`) };
}

const baseline = run("baseline", args.baseline);
const candidate = run("candidate", args.candidate);
const repeat = run("candidate-repeat", args.candidate);
const injected = run("candidate-journal-failure", args.candidate, [
  "--inject-journal-failure",
]);

// Tree identity: bound to what was supplied, never assumed.
const identity = {
  baseline: baseline.raw.meta.tree,
  candidate: candidate.raw.meta.tree,
};
for (const [label, tree] of Object.entries(identity))
  console.log(
    `${label}: ${tree.tree} commit ${tree.commit} build ${tree.buildDigest?.slice(0, 16)} (${tree.distFiles} files)${tree.dirtyPaths.length ? ` DIRTY ${tree.dirtyPaths.length} source path(s)` : ""}${tree.fresh ? "" : ` STALE dist: ${tree.staleSources.slice(0, 3).join(", ")}`}`,
  );
const identityProblems = [];
for (const [label, tree] of Object.entries(identity)) {
  if (!tree.fresh && !args["allow-stale-dist"])
    identityProblems.push(
      `${label} dist is missing or older than ${tree.staleSources.length} source file(s); rebuild or pass --allow-stale-dist`,
    );
  const wanted = args[`${label}-commit`];
  if (wanted && !tree.commit?.startsWith(wanted))
    identityProblems.push(`${label} commit ${tree.commit}, expected ${wanted}`);
}
if (
  identity.candidate.buildDigest !== repeat.raw.meta.tree.buildDigest ||
  identity.candidate.buildDigest !== injected.raw.meta.tree.buildDigest
)
  identityProblems.push("candidate build changed while the harness ran");
if (identityProblems.length) {
  console.error(`tree identity failed:\n  ${identityProblems.join("\n  ")}`);
  process.exit(1);
}

// The baseline and the candidate's ordinary runs must work. A run with a
// failing journal that breaks is a difference, not an aborted comparison.
const broken = [
  ...sanity("baseline", baseline.transcript),
  ...sanity("candidate", candidate.transcript),
  ...sanity("candidate-repeat", repeat.transcript),
];
if (broken.length) {
  console.error(`sanity failed:\n  ${broken.join("\n  ")}`);
  process.exit(1);
}

if (!args["no-controls"]) {
  // Normalizer controls on both real captures: a lossy normalization must not
  // be able to hide the differences it exists to find.
  const failures = [];
  let total = 0;
  let skipped = 0;
  for (const [label, run_] of Object.entries({ baseline, candidate })) {
    const { failures: bad, results } = runControls(run_.raw);
    total += results.filter((entry) => entry.ok).length;
    skipped += results.filter((entry) => entry.skipped).length;
    failures.push(...bad.map((line) => `${label}: ${line}`));
  }
  if (failures.length) {
    console.error(`normalizer controls failed:\n  ${failures.join("\n  ")}`);
    process.exit(1);
  }
  console.log(
    `normalizer controls: ${total} passed on the two real captures (mutants detected, volatile-only edits equal); ${skipped} optional control(s) skipped (they need a shape only the synthetic fixture has; see normalize.test.mjs)`,
  );
}

if (!args["no-controls"]) {
  // The preservation guards must catch a rewritten timestamp: rerun the
  // candidate with that regression simulated and require sanity to fail.
  for (const [test, needle] of [
    ["rewrite-created-at", "created_at"],
    ["rewrite-receipt", "receipt"],
  ]) {
    const mutated = run(`self-test-${test}`, args.candidate, [
      "--self-test",
      test,
    ]);
    const caught = sanity(`self-test ${test}`, mutated.transcript).some(
      (line) =>
        line.includes("an existing created_at or receipt changed") &&
        line.includes(
          needle === "receipt"
            ? '"receiptsRewritten":1'
            : '"createdAtRewritten":[5]',
        ),
    );
    if (!caught) {
      console.error(`preservation self-test ${test} was NOT detected`);
      process.exit(1);
    }
  }
  console.log(
    "preservation self-tests: rewritten created_at and rewritten receipt both detected",
  );
}

const determinism = differences(candidate.transcript, repeat.transcript);
if (determinism.length) {
  console.error(
    `candidate is not deterministic:\n  ${determinism.join("\n  ")}`,
  );
  process.exit(1);
}
const base = authorized("baseline", baseline.transcript, {
  userVersion: BASELINE_STAMP,
  configFlag: null,
});
const report = [...base.problems, ...sanity("injected", injected.transcript)];
const found = [];
for (const [name, run_] of Object.entries({ candidate, injected })) {
  const checked = authorized(name, run_.transcript, {
    userVersion: CANDIDATE_STAMP,
    configFlag: false,
  });
  report.push(...checked.problems);
  found.push(
    ...differences(base.rest, checked.rest).map((line) => `${name}: ${line}`),
  );
}
const different = report.length > 0 || found.length > 0;
for (const line of [...report, ...found]) console.log(line);
if (args["expect-different"]) {
  // A schema stamp or a gate row alone is the authorized shape of a gate
  // build; the control is meaningful only with a structural difference.
  const meaningful = found.length > 0;
  console.log(
    meaningful
      ? `negative control: candidate differs from baseline in ${found.length} structural field(s) beyond the schema stamp, as expected`
      : different
        ? "negative control FAILED: only authorized-shape differences (stamp, gate rows, sanity)"
        : "negative control FAILED: candidate equals baseline",
  );
  process.exit(meaningful ? 0 : 1);
}
console.log(
  different
    ? "default-off differential FAILED"
    : "default-off differential passed: candidate equals baseline outside authorized changes",
);
process.exit(different ? 1 : 0);
