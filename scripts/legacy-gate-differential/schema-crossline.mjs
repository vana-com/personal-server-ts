// Cross-line index.db stamp checks with real compiled runtimes, one process
// per open so each line uses its own better-sqlite3 and migrations.
//
//   node scripts/legacy-gate-differential/schema-crossline.mjs \
//     --conformance <pre-gate tree> --convergence <#475 tree> \
//     --experimental <first gate tree> --candidate <tree> --work <scratch dir>
//
// Each tree must be built. Exit 0 only when every expectation holds.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { mkdirSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs } from "node:util";

const { values: args, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    tree: { type: "string" },
    db: { type: "string" },
    enroll: { type: "string" },
    conformance: { type: "string" },
    convergence: { type: "string" },
    experimental: { type: "string" },
    candidate: { type: "string" },
    work: { type: "string" },
  },
});

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
  try {
    const db = initializeDatabase(args.db);
    createSqliteRecordStore(db);
    if (mode === "create")
      // One legacy version in the columns every line shares.
      db.prepare(
        `INSERT INTO data_files (file_id, schema_id, path, scope, collected_at, size_bytes, version, data_point_id)
        VALUES (NULL, NULL, 'spotify/profile/2026-10-01T00-00-00.000Z.json', 'spotify.profile', '2026-10-01T00:00:00.000Z', 42, 3, 'dp-history')`,
      ).run();
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
  inspect.close();
  if (mode === "create") {
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
if (positionals[0] === "create" || positionals[0] === "open") {
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
/** Create with one runtime, then open with each in turn; check the last. */
function scenario(label, creator, openers, expected, enroll) {
  const dir = join(args.work, label);
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  const db = join(dir, "index.db");
  const created = call(
    "create",
    creator,
    db,
    enroll ? ["--enroll", enroll] : [],
  );
  const steps = [];
  let unchanged = false;
  for (const opener of openers) {
    if (steps.length) call("settle", "candidate", db);
    const before = snapshot(db);
    steps.push({ opener, ...call("open", opener, db) });
    unchanged = snapshot(db) === before;
  }
  const opened = steps.at(-1);
  // Every successful open keeps the seeded version, and an enrolled root
  // keeps its retained identity.
  const kept = steps.every(
    (step) =>
      step.error ||
      (JSON.stringify(step.history) === JSON.stringify(created.history) &&
        (!enroll ||
          JSON.stringify(step.retained) === JSON.stringify(created.retained))),
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
  if (!ok) failed = true;
  console.log(
    `${ok ? "ok  " : "FAIL"} ${label}: ${JSON.stringify({ created, steps, unchanged })}`,
  );
}

// Older roots opened by the integrated runtime.
scenario("conformance-16-to-candidate", "conformance", ["candidate"], {
  userVersion: 17,
  pdpp: 25,
});
scenario("convergence-17-to-candidate", "convergence", ["candidate"], {
  userVersion: 17,
  pdpp: 25,
  gate: [],
});
scenario(
  "experimental-unenrolled-to-candidate",
  "experimental",
  ["candidate"],
  { userVersion: 17, gate: [] },
);
for (const state of ["stopped", "restoring", "mirroring", "quiescing"])
  scenario(
    `experimental-17-${state}-to-candidate`,
    "experimental",
    ["candidate", "candidate"],
    {
      userVersion: 18,
      gate: [{ scope: "spotify.profile", state, epoch: 4 }],
    },
    state,
  );
// Integrated roots opened by older runtimes must be refused. The
// conformance line shares PDPP 25, so its legacy counter is its only guard;
// it predates the preflight and refuses after its own WAL switch.
scenario("candidate-17-to-conformance", "candidate", ["conformance"], {
  error: "Unsupported index.db schema version 17; runtime supports 16",
});
scenario(
  "candidate-18-to-conformance",
  "experimental",
  ["candidate", "conformance"],
  { error: "Unsupported index.db schema version 18; runtime supports 16" },
  "mirroring",
);
// #475 also rejects PDPP 25, so the v18 stamp is not its only guard there.
scenario("candidate-17-to-convergence", "candidate", ["convergence"], {
  error: "Unsupported index.db PDPP schema version 25; runtime supports 16",
  unchanged: true,
});
scenario(
  "candidate-18-to-convergence",
  "experimental",
  ["candidate", "convergence"],
  {
    error: "Unsupported index.db schema version 18; runtime supports 17",
    unchanged: true,
  },
  "mirroring",
);
process.exit(failed ? 1 : 0);
