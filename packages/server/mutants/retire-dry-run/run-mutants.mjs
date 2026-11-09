#!/usr/bin/env node
/**
 * Mutant runner for the legacy-retire dry run.
 *
 * Each mutant is a small source edit that breaks one guarantee of the tool.
 * The runner applies it, runs the focused tests that guard that guarantee, and
 * records RED (the tests fail: the guarantee is tested) or SURVIVED (they pass:
 * the test is too weak). The source is always restored from the text read
 * before the edit, also on Ctrl-C. Exit code 1 if any mutant survived or its
 * edit no longer matches the source.
 *
 *   node packages/server/mutants/retire-dry-run/run-mutants.mjs            # all
 *   node packages/server/mutants/retire-dry-run/run-mutants.mjs --only M2a,P2.4
 *   node packages/server/mutants/retire-dry-run/run-mutants.mjs --check    # edits apply?
 *
 * Run from anywhere; it works from the repository root. Foreground only.
 */

import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../../../..");
const dir = "packages/server/src/scripts/retire-dry-run";
const F = {
  copyOnly: `${dir}/copy-only.ts`,
  guard: `${dir}/network-guard.ts`,
  store: `${dir}/legacy-store.ts`,
  heads: `${dir}/published-heads.ts`,
  report: `${dir}/report.ts`,
  run: `${dir}/run.ts`,
  hosts: `${dir}/hosts.ts`,
  home: `${dir}/home-state.ts`,
  recheck: `${dir}/recheck.ts`,
  cli: "packages/server/src/scripts/legacy-retire-dry-run.ts",
};
const T = {
  run: `${dir}/run.test.ts`,
  guard: `${dir}/network-guard.test.ts`,
  hosts: `${dir}/hosts.test.ts`,
  recheck: `${dir}/recheck.test.ts`,
  changed: `${dir}/run-changed.test.ts`,
  cli: "packages/server/src/scripts/legacy-retire-dry-run.test.ts",
};

/** edits: [file, find (must occur once), replace]. tests: [files, -t pattern]. */
const MUTANTS = [
  // --- round 1 ---
  {
    id: "M1a",
    what: "data folder need not be under ~/.tmp",
    edits: [
      [F.copyOnly, "if (!strictlyInside(tmpRoot, dataDir)) {", "if (false) {"],
    ],
    files: [T.run],
    pattern: "refuses a folder outside",
  },
  {
    id: "M1b",
    what: "a -shm file is accepted",
    edits: [[F.copyOnly, 'item.name.endsWith("-shm")', "false"]],
    files: [T.run],
    pattern: "holds a -shm file",
  },
  {
    id: "M1c",
    what: "~/.vana is not refused as such",
    edits: [[F.copyOnly, "if (isInside(vanaHome, dataDir)) {", "if (false) {"]],
    files: [T.run],
    pattern: "refuses ~/.vana",
  },
  {
    id: "M2a",
    what: "a non-GET request is allowed",
    edits: [[F.guard, 'method !== "GET"', "false"]],
    files: [T.guard, T.run],
    pattern: "passes a GET to an allowed host|code under test POSTs",
  },
  {
    id: "M2b",
    what: "any host is allowed",
    edits: [[F.guard, ": !hostAllowed(target)", ": false"]],
    files: [T.guard, T.run],
    pattern: "passes a GET to an allowed host|outside the Dev gateway",
  },
  {
    id: "M2c",
    what: "a swallowed refusal is not re-checked",
    edits: [[F.run, "guard.assertNoViolations();", ""]],
    files: [T.run],
    pattern: "swallows the refusal",
  },
  {
    id: "M3a",
    what: "database opened in place, tripwire off",
    edits: [
      [
        F.store,
        'initializeDatabase(join(input.scratchDir, "index.db"))',
        'initializeDatabase(join(input.rootDir, "index.db"))',
      ],
      [F.run, "(await fingerprintTree(dataDir)) !== before", "false"],
    ],
    files: [T.run],
    pattern: "byte-identical",
  },
  {
    id: "M3b",
    what: "tripwire disabled",
    edits: [[F.run, "(await fingerprintTree(dataDir)) !== before", "false"]],
    files: [T.run],
    pattern: "tripwire",
  },
  {
    id: "M4a",
    what: "an importer is pulled in",
    edits: [
      [
        F.run,
        "const SIGNATURE =",
        'const importer = "LegacyImporter";\nvoid importer;\nconst SIGNATURE =',
      ],
    ],
    files: [T.run],
    pattern: "uses no writer",
  },
  {
    id: "M4b",
    what: "the import-done guard is widened (ledger says done)",
    edits: [
      [
        F.run,
        "data.importComplete = home.importComplete;",
        "data.importComplete = true;",
      ],
    ],
    files: [T.run],
    pattern: "does not run an import",
  },
  {
    id: "M5a",
    what: "full hash in the report",
    edits: [[F.report, "record.aggregate.slice(0, 8)", "record.aggregate"]],
    files: [T.run],
    pattern: "holds counts, short hashes",
  },
  {
    id: "M5b",
    what: "raw version key in the report",
    edits: [
      [F.report, "version: hex8(file.version),", "version: file.version,"],
    ],
    files: [T.run],
    pattern: "holds counts, short hashes",
  },
  {
    id: "M6",
    what: "device registry mirror not loaded",
    edits: [[F.run, "return await readFile(path);", "return null;"]],
    files: [T.run],
    pattern: "device mirror",
  },
  // --- round 2 ---
  {
    id: "P1.2a-1",
    what: "--out symlink/hard link/folder accepted",
    edits: [
      [F.copyOnly, "if (!info.isFile() || info.nlink > 1) {", "if (false) {"],
    ],
    files: [T.run],
    pattern: "symlink to the copy's database|hard link, a folder",
  },
  {
    id: "P1.2a-2",
    what: "report written through the path (follows a link)",
    edits: [
      [
        F.run,
        "await rename(temp, outPath);",
        "await writeFile(outPath, JSON.stringify(report, null, 2));",
      ],
    ],
    files: [T.run],
    pattern: "replaces, and does not follow",
  },
  {
    id: "P1.2a-3",
    what: "--out folder not resolved with realpath",
    edits: [
      [
        F.copyOnly,
        'await realOrThrow(\n    dirname(requested),\n    "The folder of --out",\n  )',
        "dirname(requested)",
      ],
    ],
    files: [T.run],
    pattern: "hard link, a folder",
  },
  {
    id: "P1.2b",
    what: "scratch folder is <out>.work again",
    edits: [
      [
        F.run,
        'await mkdtemp(join(tmpRoot, "retire-dry-run-"))',
        "join(dirname(outPath), `${basename(outPath)}.work`)",
      ],
    ],
    files: [T.run],
    pattern: "exact pair|already sits at",
  },
  {
    id: "P2.3a",
    what: "URL host wins over options.hostname",
    edits: [
      [
        F.guard,
        "const merged = { ...base, ...given };",
        "const merged = { ...given, ...base };",
      ],
    ],
    files: [T.guard],
    pattern: "checks the host Node connects to",
  },
  {
    id: "P2.3b",
    what: "port not checked",
    edits: [
      [
        F.guard,
        'if (port === "" || port === "80" || port === "443") {',
        "if (true) {",
      ],
    ],
    files: [T.guard],
    pattern: "checks the host Node connects to|host:port entry",
  },
  {
    id: "P2.3c",
    what: "socketPath not refused",
    edits: [[F.guard, "if (merged.socketPath !== undefined)", "if (false)"]],
    files: [T.guard],
    pattern: "checks the host Node connects to",
  },
  {
    id: "P2.4",
    what: "fetch follows redirects",
    edits: [[F.guard, 'redirect: "error"', 'redirect: "follow"']],
    files: [T.guard],
    pattern: "asks fetch not to follow|does not follow a redirect from",
  },
  {
    id: "P2.5a",
    what: "any https host is pinned",
    edits: [[F.hosts, "pinned.includes(url.hostname) &&", "true &&"]],
    files: [T.hosts, T.run],
    pattern: "pinned Dev host",
  },
  {
    id: "P2.5b",
    what: "loopback allowed without the test-only switch",
    edits: [
      [F.hosts, "testOnlyAllowLoopback &&\n    LOOPBACK.has", "LOOPBACK.has"],
    ],
    files: [T.hosts, T.run, T.cli],
    pattern: "pinned Dev host|loopback URL without",
  },
  {
    id: "P2.5c",
    what: "production storage host pinned",
    edits: [
      [
        F.hosts,
        '["storage-dev.vana.org"]',
        '["storage-dev.vana.org", "storage.vana.org"]',
      ],
    ],
    files: [T.hosts, T.run],
    pattern: "pinned Dev host",
  },
  {
    id: "P2.5d",
    what: "gateway from the copy's config.json ignored",
    edits: [
      [
        F.run,
        "options.gatewayUrl ?? stringOrUndefined(raw.gateway?.url)",
        "options.gatewayUrl",
      ],
    ],
    files: [T.run],
    pattern: "gateway from the copy's config",
  },
  {
    id: "P2.6a",
    what: "owner recovery not wrapped",
    edits: [
      [
        F.heads,
        "masterKey = legacyMasterKey(input.masterKeySignature);\n  } catch {",
        "masterKey = legacyMasterKey(input.masterKeySignature);\n  } catch (e) {\n    throw e;\n  }\n  try {\n  } catch {",
      ],
    ],
    files: [T.run],
    pattern: "bad owner signature",
  },
  {
    id: "P2.6b",
    what: "owner recovery not wrapped and raw message printed",
    edits: [
      [
        F.heads,
        "masterKey = legacyMasterKey(input.masterKeySignature);\n  } catch {",
        "masterKey = legacyMasterKey(input.masterKeySignature);\n  } catch (e) {\n    throw e;\n  }\n  try {\n  } catch {",
      ],
      [
        F.cli,
        "function messageFor(error: unknown): string {",
        "function messageFor(error: unknown): string {\n  if (error instanceof Error) return `Failed: ${error.message}`;",
      ],
    ],
    files: [T.cli],
    pattern: "wrong but valid-looking",
  },
  {
    id: "P2.7",
    what: "non-empty scratch folder accepted (stale -wal)",
    edits: [
      [
        F.store,
        "if ((await readdir(input.scratchDir)).length > 0) {",
        "if (false) {",
      ],
    ],
    files: [T.run],
    pattern: "scratch folder that is not empty",
  },
  {
    id: "P2.8a",
    what: "scope printed verbatim",
    edits: [
      [
        F.report,
        "connector: connectorLabel(file.scope),",
        "connector: file.scope,",
      ],
    ],
    files: [T.run],
    pattern: "scopes and names|holds counts, short hashes",
  },
  {
    id: "P2.8b",
    what: "symlink refusal names the file",
    edits: [
      [
        F.copyOnly,
        '"Refusing: the data folder holds a symlink. Copy the bytes, not links."',
        "`Refusing: symlink ${item.name}`",
      ],
    ],
    files: [T.run],
    pattern: "names no file",
  },
  {
    id: "P2.8c",
    what: "-shm refusal names the file",
    edits: [
      [
        F.copyOnly,
        '"Refusing: the data folder holds a -shm file. " +',
        '"Refusing: " + item.name + " is a -shm file. " +',
      ],
    ],
    files: [T.run],
    pattern: "names no file",
  },
  {
    id: "P-dec",
    what: "decisions counted only when present",
    edits: [
      [
        F.report,
        "const byDecision = emptyDecisions();",
        "const byDecision = {} as ReturnType<typeof emptyDecisions>;",
      ],
      [
        F.report,
        "byDecision[f.decision] += 1;",
        "byDecision[f.decision] = (byDecision[f.decision] ?? 0) + 1;",
      ],
    ],
    files: [T.run],
    pattern: "counts every decision",
  },
  {
    id: "P-staged",
    what: "the per-stream receipt of the import is dropped",
    edits: [
      [
        F.home,
        "entry.staged = staged as Record<string, number>;",
        "void staged;",
      ],
    ],
    files: [T.run],
    pattern: "receipt names its stream with rows",
  },
  {
    id: "P3.9",
    what: "copy time missing from the report",
    edits: [
      [
        F.run,
        "const copy = await copyAge(dataDir);",
        "const copy = null as unknown as Awaited<ReturnType<typeof copyAge>>;",
      ],
    ],
    files: [T.run],
    pattern: "age of the copy",
  },
  // --- round 4 ---
  {
    id: "R4-recheck-off",
    what: "the last hash check is not taken in the dry run",
    edits: [
      [
        F.run,
        "retire = await recheckReadyFiles({",
        "retire = await (async (x: Parameters<typeof recheckReadyFiles>[0]) => x.retire)({",
      ],
    ],
    files: [T.changed],
    pattern: "holds a ready file that no longer hashes",
  },
  {
    id: "R4-changed-holds",
    what: "a file that hashes differently still counts as ready",
    edits: [
      [
        F.recheck,
        'holds ? file : { ...file, decision: "file_changed", wouldDelete: false },',
        "file,",
      ],
    ],
    files: [T.recheck, T.changed],
    pattern: "reports file_changed|holds a ready file",
  },
  {
    id: "R4-unreadable-holds",
    what: "an unreadable file counts as unchanged",
    edits: [
      [
        F.recheck,
        "holds = false; // unreadable is not a match",
        "holds = true;",
      ],
    ],
    files: [T.recheck],
    pattern: "cannot be read",
  },
  {
    id: "R4-nohash-holds",
    what: "a readback with no recorded hash counts as unchanged",
    edits: [
      [F.recheck, "let holds = false;", "let holds = readHash === undefined;"],
    ],
    files: [T.recheck],
    pattern: "recorded no hash",
  },
  {
    id: "R4-receipt-unchecked",
    what: "a receipt of any shape is passed on",
    edits: [
      [
        F.home,
        "(n) => Number.isFinite(n) && (n as number) >= 0,",
        "() => true,",
      ],
    ],
    files: [T.run],
    pattern: "not a map of numbers",
  },
  {
    id: "R4-clientrequest",
    what: "a ClientRequest built directly is not checked",
    edits: [
      [
        F.guard,
        "check(methodOf(args[0], args[1]), targetOf(args[0], args[1]));\n        return Reflect.construct",
        "return Reflect.construct",
      ],
    ],
    files: [T.guard, T.run],
    pattern: "ClientRequest",
  },
  {
    id: "R4-clientrequest-restore",
    what: "the original ClientRequest is not put back",
    edits: [
      [
        F.guard,
        "(http as unknown as Record<string, unknown>).ClientRequest =\n      RealClientRequest;",
        "void RealClientRequest;",
      ],
    ],
    files: [T.guard],
    pattern: "uninstall restores",
  },
];

const args = process.argv.slice(2);
const check = args.includes("--check");
const onlyArg = args.indexOf("--only");
const only = onlyArg >= 0 ? new Set(args[onlyArg + 1].split(",")) : null;

const originals = new Map();
function restore() {
  for (const [file, text] of originals) writeFileSync(join(root, file), text);
  originals.clear();
}
for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => {
    restore();
    process.exit(130);
  });
}

function apply(mutant) {
  for (const [file, find, replace] of mutant.edits) {
    const path = join(root, file);
    if (!originals.has(file)) originals.set(file, readFileSync(path, "utf8"));
    const text = readFileSync(path, "utf8");
    const count = text.split(find).length - 1;
    if (count !== 1) return `edit matches ${count} times in ${file}`;
    writeFileSync(
      path,
      text.replace(find, () => replace),
    );
  }
  return null;
}

const rows = [];
try {
  for (const mutant of MUTANTS) {
    if (only && !only.has(mutant.id)) continue;
    const problem = apply(mutant);
    if (problem) {
      restore();
      rows.push({ ...mutant, result: `INVALID (${problem})` });
      continue;
    }
    if (check) {
      restore();
      rows.push({ ...mutant, result: "applies" });
      continue;
    }
    const run = spawnSync(
      "nice",
      [
        "-n",
        "19",
        "npx",
        "vitest",
        "run",
        "--maxWorkers=4",
        ...mutant.files,
        "-t",
        mutant.pattern,
      ],
      { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
    );
    restore();
    const out = `${run.stdout}${run.stderr}`;
    const failed = /Tests\s+(\d+) failed/.exec(out)?.[1];
    const passed = /(\d+) passed/.exec(out)?.[1] ?? "0";
    rows.push({
      ...mutant,
      result:
        run.status === 0
          ? `SURVIVED (${passed} passed)`
          : failed
            ? `RED (${failed} failed)`
            : `ERROR (exit ${run.status}, no test result)`,
    });
    console.error(`${mutant.id}: ${rows.at(-1).result}`);
  }
} finally {
  restore();
}

console.log("\n| Mutant | Breaks | Result |\n|---|---|---|");
for (const row of rows)
  console.log(`| ${row.id} | ${row.what} | ${row.result} |`);
const ok = (r) => (check ? r.result === "applies" : r.result.startsWith("RED"));
process.exit(rows.every(ok) ? 0 : 1);
