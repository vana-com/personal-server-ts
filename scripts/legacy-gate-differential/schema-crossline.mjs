// Cross-line index.db stamp checks with real compiled runtimes, one process
// per open so each line uses its own better-sqlite3 and migrations.
//
//   node scripts/legacy-gate-differential/schema-crossline.mjs \
//     --conformance <pre-gate tree> --convergence <#475 tree> \
//     --experimental <first gate tree> --candidate <tree> --work <scratch dir> \
//     [--no-controls] [--allow-stale-dist]
//
// Each tree must be built. Exit 0 only when every expectation holds.
//
// Two kinds of case, labelled in the output:
//
//   migration fixture  Roots written by SQL that imitates the first gate
//                      build (`--experimental`): its policy and retained rows
//                      and stamp 17, written by hand. They test that the
//                      candidate MIGRATES such roots. They say nothing about
//                      what the candidate itself writes.
//   actual enrollment  The candidate's own compiled code enrolls a root: real
//                      storage writes a legacy version, then the real
//                      policy `stop` runs, which persists policy, transition
//                      and retained rows and raises the stamp to 18 itself.
//                      Nothing here inserts policy rows or forces a counter.
//                      Older lines then open the result and must refuse it.
//
// Trusted test inputs, NOT production authority: `stop` needs a shutdown
// qualification port (grant inventory and global issuance fence) and a native
// canonical coverage port. No production implementation of either exists, so
// this file supplies fixed test doubles that return complete, well-formed
// answers (the same shape the policy's own tests use). They prove that the
// candidate persists the enrollment correctly when authority exists. They do
// not prove, and this file never claims, a real grant inventory or reopen.
//
// Controls (--no-controls skips): the actual-enrollment case is rerun with a
// broken candidate simulated inside the child (stamp left at 17, or retained
// rows dropped). Each broken run MUST fail the expectations.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { mkdirSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { treeIdentity } from "./tree-identity.mjs";

const { values: args, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    tree: { type: "string" },
    db: { type: "string" },
    enroll: { type: "string" },
    mutate: { type: "string" },
    "no-controls": { type: "boolean", default: false },
    "allow-stale-dist": { type: "boolean", default: false },
    conformance: { type: "string" },
    convergence: { type: "string" },
    experimental: { type: "string" },
    candidate: { type: "string" },
    work: { type: "string" },
  },
});

const ENROLL_SCOPE = "spotify.profile";
const OWNER = "0xowner";
const GENERATION = "gen-differential";

/** TEST INPUT: a complete, well-formed native canonical coverage answer. */
function trustedCanonicalCoverage() {
  const coverage = (scope, servingGeneration) => ({
    scope,
    identity: {
      declaration: "decl",
      artifact: "artifact",
      projection: "projection",
      binding: "binding",
      servingGeneration,
    },
    inputs: [{ instance: "conn", stream: "profile", generation: 1 }],
    receipts: [],
    additionsTrackedSince: "2026-10-01T00:00:00.000Z",
    inputDigest: "inputs-1",
  });
  return {
    assess: (scope, generation) => ({
      ok: true,
      coverage: coverage(scope, generation),
    }),
    qualify: async (scope, generation) => ({
      ok: true,
      coverage: {
        ...coverage(scope, generation),
        projectionRevision: "projection-1",
        watermark: "committed-1",
      },
    }),
    isCurrent: () => true,
  };
}

/** TEST INPUT: a complete shutdown qualification, echoing the context. */
function trustedQualification() {
  const yes = true;
  return {
    async freezeAndQualify(context) {
      return {
        ...context,
        contractVersion: 1,
        inventory: {
          authoritative: yes,
          complete: yes,
          revision: "registry-1",
          aliasesResolved: yes,
          paginationComplete: yes,
          issuersConnected: yes,
          credentials: [],
          localIntentIds: context.localIntentIds,
        },
        globalFence: {
          id: "durable-global-fence",
          allIssuers: yes,
          renewals: yes,
          durable: yes,
          writerAdmission: yes,
          remotePublicationDrained: yes,
        },
        canonical: {
          identity: context.canonical.identity,
          watermark: context.canonical.watermark,
          inputs: context.canonical.inputs,
          completeBaseline: yes,
          pagination: yes,
          joins: yes,
          blobs: yes,
          incrementalAndDeletion: yes,
          latestLegacyResolved: yes,
          noFailedIngest: yes,
          noForeignOrHeldHeads: yes,
        },
        retention: {
          legacyHistoryReadable: yes,
          canonicalHistoryDurable: yes,
          ownerReadersQualified: yes,
          metricsRecoveryQualified: yes,
          noLegacyWritingRecovery: yes,
          restartReadbackPassed: yes,
          rollbackCompatibilityPassed: yes,
        },
      };
    },
    assertCurrent: () => true,
  };
}

/** The candidate's own enrollment: real storage, real policy `stop`. */
async function enrollReal(db, load) {
  const { createIndexManager } = await load(
    "packages/server/dist/storage/index-manager.js",
  );
  const { createNodeDataStorage } = await load(
    "packages/server/dist/storage/node-data-storage.js",
  );
  const { createLegacyPublicationPolicy } = await load(
    "packages/server/dist/storage/legacy-publication-policy.js",
  );
  const index = createIndexManager(db);
  const hierarchyOptions = { dataDir: join(dirname(args.db), "data") };
  const storage = createNodeDataStorage({
    indexManager: index,
    hierarchyOptions,
  });
  // A real synced legacy version: file on disk, index row, registered point.
  await storage.commitVersion({
    kind: "replica",
    envelope: {
      version: "1.0",
      scope: ENROLL_SCOPE,
      collectedAt: "2026-10-02T00:00:00.000Z",
      data: { profile: { name: "real" } },
    },
    metadata: { schemaId: null, dataPointId: "dp-real", version: 4 },
  });
  const policy = createLegacyPublicationPolicy(db, {
    owner: OWNER,
    serverGeneration: GENERATION,
    enabled: () => true,
    storage: { indexManager: index, hierarchyOptions },
    canonical: trustedCanonicalCoverage(),
    qualification: trustedQualification(),
  });
  const stopped = await policy.stop(ENROLL_SCOPE, {
    ownerOptIn: true,
    expectedEpoch: 0,
  });
  // Controls only: a broken candidate, simulated after the real stop.
  if (args.mutate === "stamp-not-persisted") db.pragma("user_version = 17");
  if (args.mutate === "retention-not-persisted")
    db.prepare("DELETE FROM legacy_publication_retained_versions").run();
  const refusal = async (action) => {
    try {
      await action();
      return "accepted";
    } catch (error) {
      return error.errorCode ?? error.message;
    }
  };
  return {
    enrolled: { state: stopped.state, epoch: stopped.epoch },
    // Real storage, index and retention after the stop.
    probes: {
      indexInsert: await refusal(() =>
        index.insert({
          fileId: null,
          path: "probe.json",
          scope: ENROLL_SCOPE,
          collectedAt: "2026-10-03T00:00:00.000Z",
          sizeBytes: 1,
          dataPointId: "dp-probe",
        }),
      ),
      storageAppend: await refusal(() =>
        storage.commitVersion({
          kind: "append",
          envelope: {
            version: "1.0",
            scope: ENROLL_SCOPE,
            collectedAt: "2026-10-04T00:00:00.000Z",
            data: { late: true },
          },
          metadata: {},
        }),
      ),
      deleteHistory: await refusal(() => index.deleteByScope(ENROLL_SCOPE)),
      siblingScopeWritable: await refusal(() =>
        storage.commitVersion({
          kind: "append",
          envelope: {
            version: "1.0",
            scope: "spotify.playlists",
            collectedAt: "2026-10-05T00:00:00.000Z",
            data: { sibling: true },
          },
          metadata: {},
        }),
      ),
    },
  };
}

/** Child: open (or create) a root with one tree's own index and PDPP openers. */
async function child(mode) {
  const load = (path) => import(pathToFileURL(join(args.tree, path)).href);
  const Database = createRequire(join(args.tree, "package.json"))(
    "better-sqlite3",
  );
  const { initializeDatabase } = await load(
    "packages/server/dist/storage/index-schema.js",
  );
  const { createSqliteRecordStore } = await load(
    "packages/server/dist/storage/pdpp-records-sqlite-store.js",
  );
  let actual = {};
  try {
    const db = initializeDatabase(args.db);
    createSqliteRecordStore(db);
    if (mode === "enroll-real") actual = await enrollReal(db, load);
    if (mode === "create") {
      // Seed readable history through this line's own storage, not an index-only
      // row: real enrollment must seal the actual bytes of every prior version.
      const { createIndexManager } = await load(
        "packages/server/dist/storage/index-manager.js",
      );
      const { createNodeDataStorage } = await load(
        "packages/server/dist/storage/node-data-storage.js",
      );
      const storage = createNodeDataStorage({
        indexManager: createIndexManager(db),
        hierarchyOptions: { dataDir: join(dirname(args.db), "data") },
      });
      await storage.commitVersion({
        kind: "replica",
        envelope: {
          version: "1.0",
          scope: ENROLL_SCOPE,
          collectedAt: "2026-10-01T00:00:00.000Z",
          data: { profile: { name: "history" } },
        },
        metadata: { schemaId: null, dataPointId: "dp-history", version: 3 },
      });
    }
    if (mode === "create" && args.enroll) {
      // Stop retained the scope's history.
      db.prepare(
        "INSERT INTO legacy_publication_retained_versions SELECT id FROM data_files",
      ).run();
      // What the first gate build's enrollment wrote: its rows and stamp 17.
      for (const table of [
        "legacy_publication_policy",
        "legacy_publication_transitions",
      ])
        db.prepare(
          `INSERT INTO ${table} (owner, server_generation, scope, state, epoch${table.endsWith("policy") ? ", owner_opt_in" : ""}) VALUES ('0xowner', 'gen', 'spotify.profile', ?, 4${table.endsWith("policy") ? ", 1" : ""})`,
        ).run(args.enroll);
      db.pragma("user_version = 17");
    }
    db.close();
  } catch (error) {
    process.stdout.write(JSON.stringify({ error: error.message }));
    return;
  }
  const inspect = new Database(args.db, { readonly: true });
  const gate = inspect
    .prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='legacy_publication_policy'",
    )
    .get()
    ? inspect
        .prepare("SELECT scope, state, epoch FROM legacy_publication_policy")
        .all()
    : null;
  const hasRetained = !!inspect
    .prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='legacy_publication_retained_versions'",
    )
    .get();
  const result = {
    ...actual,
    userVersion: inspect.pragma("user_version", { simple: true }),
    pdpp: inspect.prepare("SELECT version FROM pdpp_schema_version").get()
      .version,
    gate,
    history: inspect
      .prepare(
        "SELECT id, path, scope, collected_at, size_bytes, version, data_point_id FROM data_files ORDER BY id",
      )
      .all(),
    retained: hasRetained
      ? inspect
          .prepare(
            "SELECT version_id FROM legacy_publication_retained_versions ORDER BY version_id",
          )
          .all()
      : null,
  };
  if (mode === "enroll-real")
    result.retainedAllHistory =
      JSON.stringify(result.retained) ===
      JSON.stringify(
        inspect
          .prepare(
            "SELECT id AS version_id FROM data_files WHERE scope = ? ORDER BY id",
          )
          .all(ENROLL_SCOPE),
      );
  inspect.close();
  if (mode === "create" || mode === "enroll-real") {
    const raw = new Database(args.db);
    raw.pragma("journal_mode = DELETE");
    raw.close();
  }
  process.stdout.write(JSON.stringify(result));
}

/** Child: fold WAL sidecars back so the next open's changes are visible. */
function settle() {
  const Database = createRequire(join(args.tree, "package.json"))(
    "better-sqlite3",
  );
  const raw = new Database(args.db);
  raw.pragma("journal_mode = DELETE");
  raw.close();
  process.stdout.write("{}");
}

if (positionals[0] === "settle") {
  settle();
  process.exit(0);
}
if (["create", "open", "enroll-real"].includes(positionals[0])) {
  await child(positionals[0]);
  process.exit(0);
}

const self = fileURLToPath(import.meta.url);
const trees = {
  conformance: args.conformance,
  convergence: args.convergence,
  experimental: args.experimental,
  candidate: args.candidate,
};
if (Object.values(trees).some((tree) => !tree) || !args.work) {
  console.error(
    "usage: schema-crossline.mjs --conformance <tree> --convergence <tree> --experimental <tree> --candidate <tree> --work <dir>",
  );
  process.exit(2);
}
// Bind the run to the supplied trees; a stale dist is a failure, not a pass.
let stale = false;
for (const [label, tree] of Object.entries(trees)) {
  const identity = treeIdentity(tree);
  console.log(
    `${label}: ${tree} commit ${identity.commit} build ${identity.buildDigest?.slice(0, 16)}${identity.dirtyPaths.length ? ` DIRTY ${identity.dirtyPaths.length} source path(s)` : ""}${identity.fresh ? "" : ` STALE dist: ${identity.staleSources.slice(0, 3).join(", ")}`}`,
  );
  stale ||= !identity.fresh;
}
if (stale && !args["allow-stale-dist"]) {
  console.error(
    "a tree's dist is missing or older than its source; rebuild or pass --allow-stale-dist",
  );
  process.exit(1);
}
const call = (mode, tree, db, extra = []) =>
  JSON.parse(
    execFileSync(
      process.execPath,
      [self, mode, "--tree", trees[tree], "--db", db, ...extra],
      { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] },
    ),
  );
const snapshot = (db) =>
  readdirSync(dirname(db))
    .filter((name) => name.startsWith("index.db"))
    .sort()
    .map(
      (name) =>
        `${name}:${createHash("sha256")
          .update(readFileSync(join(dirname(db), name)))
          .digest("hex")}`,
    )
    .join(",");

let failed = false;
/**
 * Create with one runtime, then run each step in turn; check the last.
 * A step is a tree name (open it) or { tree, mode: "enroll-real" } (that
 * tree's own code enrolls the root). Expectations may name any result key,
 * plus `unchanged` (the last step left the files byte-identical) and `error`.
 * `label` starts with "migration fixture:" or "actual enrollment:".
 */
function scenario(label, creator, steps, expected, options = {}) {
  const dir = join(
    args.work,
    options.dir ?? label.replace(/[^a-z0-9]+/gi, "-"),
  );
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  const db = join(dir, "index.db");
  const enroll = options.enroll;
  const created = call(
    "create",
    creator,
    db,
    enroll ? ["--enroll", enroll] : [],
  );
  const results = [];
  let unchanged = false;
  for (const step of steps) {
    const { tree, mode = "open" } =
      typeof step === "string" ? { tree: step } : step;
    if (results.length) call("settle", "candidate", db);
    const before = snapshot(db);
    results.push({
      opener: tree,
      mode,
      ...call(
        mode,
        tree,
        db,
        options.mutate && mode === "enroll-real"
          ? ["--mutate", options.mutate]
          : [],
      ),
    });
    unchanged = snapshot(db) === before;
  }
  const opened = results.at(-1);
  // Every successful step keeps the history that existed after the first
  // successful one (the seed, plus the version the candidate itself stored),
  // and an enrolled root keeps its retained identity.
  const reference = results.find((step) => !step.error);
  const kept = results.every(
    (step) =>
      step.error ||
      (JSON.stringify(step.history) === JSON.stringify(reference.history) &&
        (step.retained === null ||
          JSON.stringify(step.retained) ===
            JSON.stringify(reference.retained))),
  );
  const ok =
    created.history?.length === 1 &&
    (!enroll || created.retained?.length === 1) &&
    kept &&
    Object.entries(expected).every(([key, value]) =>
      key === "unchanged"
        ? unchanged === value
        : key === "error"
          ? opened.error?.includes(value)
          : JSON.stringify(opened[key]) === JSON.stringify(value),
    );
  if (!options.control && !ok) failed = true;
  console.log(
    `${options.control ? (ok ? "FAIL (control passed)" : "ok  (control detected)") : ok ? "ok  " : "FAIL"} ${label}: ${JSON.stringify({ created, steps: results, unchanged })}`,
  );
  return ok;
}

// --- Migration fixtures: SQL-written roots, MIGRATED by the candidate.
const FIXTURE = "migration fixture:";
scenario(
  `${FIXTURE} conformance 16 root opened by candidate`,
  "conformance",
  ["candidate"],
  {
    userVersion: 17,
    pdpp: 25,
  },
);
scenario(
  `${FIXTURE} convergence 17 root opened by candidate`,
  "convergence",
  ["candidate"],
  {
    userVersion: 17,
    pdpp: 25,
    gate: [],
  },
);
scenario(
  `${FIXTURE} experimental never-enrolled root opened by candidate`,
  "experimental",
  ["candidate"],
  { userVersion: 17, gate: [] },
);
for (const state of ["stopped", "restoring", "mirroring", "quiescing"])
  scenario(
    `${FIXTURE} experimental 17 ${state} root opened by candidate`,
    "experimental",
    ["candidate", "candidate"],
    {
      userVersion: 18,
      gate: [{ scope: "spotify.profile", state, epoch: 4 }],
    },
    { enroll: state },
  );
// Integrated roots written by SQL, opened by older runtimes, must be refused.
// The conformance line shares PDPP 25, so its legacy counter is its only
// guard; it predates the preflight and refuses after its own WAL switch.
scenario(
  `${FIXTURE} candidate never-enrolled 17 root opened by conformance`,
  "candidate",
  ["conformance"],
  {
    error: "Unsupported index.db schema version 17; runtime supports 16",
  },
);
scenario(
  `${FIXTURE} migrated 18 root opened by conformance`,
  "experimental",
  ["candidate", "conformance"],
  { error: "Unsupported index.db schema version 18; runtime supports 16" },
  { enroll: "mirroring" },
);
// #475 also rejects PDPP 25, so the v18 stamp is not its only guard there.
scenario(
  `${FIXTURE} candidate never-enrolled 17 root opened by convergence`,
  "candidate",
  ["convergence"],
  {
    error: "Unsupported index.db PDPP schema version 25; runtime supports 16",
    unchanged: true,
  },
);
scenario(
  `${FIXTURE} migrated 18 root opened by convergence`,
  "experimental",
  ["candidate", "convergence"],
  {
    error: "Unsupported index.db schema version 18; runtime supports 17",
    unchanged: true,
  },
  { enroll: "mirroring" },
);

// --- Actual enrollment: the candidate's own `stop` writes the root.
const ACTUAL = "actual enrollment:";
const ENROLLED = {
  userVersion: 18,
  enrolled: { state: "stopped", epoch: 2 },
  gate: [{ scope: "spotify.profile", state: "stopped", epoch: 2 }],
  retainedAllHistory: true,
  probes: {
    indexInsert: "legacy_scope_retired",
    storageAppend: "legacy_scope_retired",
    deleteHistory: "legacy_history_retained",
    siblingScopeWritable: "accepted",
  },
};
const enrollStep = { tree: "candidate", mode: "enroll-real" };
const CONFORMANCE_REFUSES = {
  error: "Unsupported index.db schema version 18; runtime supports 16",
};
const CONVERGENCE_REFUSES = {
  error: "Unsupported index.db schema version 18; runtime supports 17",
  unchanged: true,
};
const origins = [
  ["never-enrolled 17 root created by the candidate", "candidate"],
  ["never-enrolled 17 root created by convergence", "convergence"],
  ["16 root created by conformance", "conformance"],
];
for (const [origin, creator] of origins) {
  scenario(
    `${ACTUAL} ${origin}, enrolled, reopened by candidate`,
    creator,
    [enrollStep, "candidate"],
    {
      userVersion: 18,
      gate: ENROLLED.gate,
      retainedAllHistory: undefined,
    },
  );
  scenario(
    `${ACTUAL} ${origin}, enrolled, then opened by conformance`,
    creator,
    [enrollStep, "candidate", "conformance"],
    CONFORMANCE_REFUSES,
  );
  scenario(
    `${ACTUAL} ${origin}, enrolled, then opened by convergence`,
    creator,
    [enrollStep, "candidate", "convergence"],
    CONVERGENCE_REFUSES,
  );
  scenario(
    `${ACTUAL} ${origin}, enrollment itself`,
    creator,
    [enrollStep],
    ENROLLED,
  );
}

// --- Controls: a broken candidate must fail the same expectations.
if (!args["no-controls"]) {
  for (const mutate of ["stamp-not-persisted", "retention-not-persisted"])
    scenario(
      `${ACTUAL} CONTROL ${mutate}: never-enrolled 17 root, enrollment itself`,
      "candidate",
      [enrollStep],
      ENROLLED,
      { control: true, mutate, dir: `control-${mutate}` },
    ) && (failed = true);
  scenario(
    `${ACTUAL} CONTROL stamp-not-persisted: then opened by conformance`,
    "candidate",
    [enrollStep, "conformance"],
    CONFORMANCE_REFUSES,
    {
      control: true,
      mutate: "stamp-not-persisted",
      dir: "control-stamp-conformance",
    },
  ) && (failed = true);
}
process.exit(failed ? 1 : 0);
