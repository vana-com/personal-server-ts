// Default-off differential for the legacy write shutdown gate.
//
//   node scripts/legacy-gate-differential/compare.mjs \
//     --baseline <pre-gate tree> --candidate <gate tree> --work <scratch dir> \
//     [--expect-different]
//
// Both trees must be built (`tsc --build packages/core packages/server`). The
// scenario runs in each tree's own process: baseline, candidate, candidate
// again (determinism) and candidate with a failing gate journal. Every run
// must pass positive sanity checks, so two identical failures prove nothing.
// The candidate must then equal the baseline after removing only the
// authorized changes: the converged schema stamp (16 -> 17), the empty
// additive gate tables and the default-off config key. Gate table rows,
// producers, queues, uploads, signatures and registrations are compared.
// --expect-different is a negative control: exit 0 only when the sanity
// checks pass and the candidate differs.
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { isDeepStrictEqual } from "node:util";

const { values: args } = parseArgs({
  options: {
    baseline: { type: "string" },
    candidate: { type: "string" },
    work: { type: "string" },
    "expect-different": { type: "boolean", default: false },
  },
});
if (!args.baseline || !args.candidate || !args.work) {
  console.error(
    "usage: compare.mjs --baseline <tree> --candidate <tree> --work <dir> [--expect-different]",
  );
  process.exit(2);
}
const scenario = join(dirname(fileURLToPath(import.meta.url)), "scenario.mjs");

function run(name, tree, extra = []) {
  const work = join(args.work, name);
  rmSync(work, { recursive: true, force: true });
  mkdirSync(work, { recursive: true });
  try {
    execFileSync(
      process.execPath,
      [scenario, "--tree", tree, "--work", work, ...extra],
      { stdio: ["ignore", "ignore", "inherit"], timeout: 300_000 },
    );
  } catch (error) {
    console.error(`${name}: scenario failed (${error.message})`);
    process.exit(1);
  }
  return JSON.parse(readFileSync(join(work, "transcript.json"), "utf8"));
}

/** Positive evidence that every exercised path really ran and succeeded.
 * Returns the failures; an empty list means the run proves something. */
function sanity(name, transcript) {
  const failures = [];
  const op = (key) => transcript.operations.find((entry) => entry.name === key);
  const status = (key, expected) => {
    const actual = op(key)?.value.status;
    if (actual !== expected)
      failures.push(`${key} status ${actual}, expected ${expected}`);
  };
  status("ingest-json", 201);
  status("ingest-binary", 201);
  status("chunk-begin", 201);
  status("chunk-upload", 200);
  status("chunk-finalize", 201);
  status("owner-import", 201);
  status("grant", 201);
  const calls = (method) =>
    transcript.gateway.filter((call) => call.method === method);
  const signed = (call) =>
    /^0x[0-9a-f]{130}$/i.test(String(call.args[0]?.signature));
  if (!calls("createGrant").some(signed))
    failures.push("no signed grant registration");
  const registrations = calls("registerDataPoint").filter(signed);
  const uploads = transcript.storage.filter(
    (entry) => entry.method === "PUT" && entry.bytes > 0,
  );
  for (const scope of [
    "spotify.profile",
    "files.document",
    "chatgpt.conversations",
    "spotify.history",
  ]) {
    if (!registrations.some((call) => call.args[0].scope === scope))
      failures.push(`no signed data point registration for ${scope}`);
    if (!uploads.some((entry) => entry.path.includes(`/${scope}/`)))
      failures.push(`no encrypted upload for ${scope}`);
  }
  for (const key of ["direct-append-1", "direct-append-2"])
    if (op(key)?.value.kind !== "stored") failures.push(`${key} not stored`);
  if (op("recovered-playlists")?.value.length !== 3)
    failures.push("prepared import was not recovered at boot");
  if (op("stage-recovery")?.value.finalExists !== true)
    failures.push("boot recovery did not publish the leftover stage");
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

function differences(a, b, path = "", out = []) {
  if (out.length >= 40) return out;
  if (isDeepStrictEqual(a, b)) return out;
  if (
    a &&
    b &&
    typeof a === "object" &&
    typeof b === "object" &&
    Array.isArray(a) === Array.isArray(b)
  ) {
    for (const key of new Set([...Object.keys(a), ...Object.keys(b)]))
      differences(a[key], b[key], `${path}/${key}`, out);
    return out;
  }
  out.push(`${path}: ${JSON.stringify(a)} != ${JSON.stringify(b)}`);
  return out;
}

const baseline = run("baseline", args.baseline);
const candidate = run("candidate", args.candidate);
const repeat = run("candidate-repeat", args.candidate);
const injected = run("candidate-journal-failure", args.candidate, [
  "--inject-journal-failure",
]);
// The baseline and the candidate's ordinary runs must work. A run with a
// failing journal that breaks is a difference, not an aborted comparison.
const broken = [
  ...sanity("baseline", baseline),
  ...sanity("candidate", candidate),
  ...sanity("candidate-repeat", repeat),
];
if (broken.length) {
  console.error(`sanity failed:\n  ${broken.join("\n  ")}`);
  process.exit(1);
}

const determinism = differences(candidate, repeat);
if (determinism.length) {
  console.error(
    `candidate is not deterministic:\n  ${determinism.join("\n  ")}`,
  );
  process.exit(1);
}
const base = authorized("baseline", baseline, {
  userVersion: 16,
  configFlag: null,
});
const report = [...base.problems, ...sanity("injected", injected)];
const found = [];
for (const [name, transcript] of Object.entries({ candidate, injected })) {
  const checked = authorized(name, transcript, {
    userVersion: 17,
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
  console.log(
    different
      ? "negative control: candidate differs from baseline, as expected"
      : "negative control FAILED: candidate equals baseline",
  );
  process.exit(different ? 0 : 1);
}
console.log(
  different
    ? "default-off differential FAILED"
    : "default-off differential passed: candidate equals baseline outside authorized changes",
);
process.exit(different ? 1 : 0);
