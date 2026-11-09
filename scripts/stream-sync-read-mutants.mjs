#!/usr/bin/env node
/**
 * Mutant runner for the stream-sync read path. Each mutant is one textual
 * change to a real source file. The runner applies it, runs the focused tests
 * that must catch it, records RED (tests fail) or SURVIVED (tests pass), and
 * restores the file, checking its SHA-256 against the original.
 *
 *   node scripts/stream-sync-read-mutants.mjs [NAME ...]
 *
 * Exit status is 1 when any mutant survives or a file does not restore.
 * Run from the repository root with Node 22 after `npm ci && npm run build`.
 */

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";

const READ = "packages/core/src/stream-sync-read";
const sha = (text) => createHash("sha256").update(text).digest("hex");

const MUTANTS = [
  {
    name: "STREAM_ONLY_PLAN_FROM_COMPLETE_BASE",
    file: `${READ}/service.ts`,
    from: "const planned = options.registry === undefined ? base : options.registry;",
    to: "const planned = base;",
    tests: [`${READ}/stream-only-plan.test.ts`],
  },
  {
    name: "WRITER_OMITS_LAST_COMPLETE",
    file: "packages/core/src/stream-sync/writer.ts",
    from: "...(lastComplete ? { lastComplete } : {}),",
    to: "",
    tests: [`${READ}/writer-last-complete.test.ts`],
  },
  {
    name: "LIST_IGNORES_UNKNOWN_CONNECTORS",
    file: `${READ}/service.ts`,
    from: "      ...overlayConnectors,\n",
    to: "",
    tests: [`${READ}/stream-only-own-writes.test.ts`],
  },
  {
    name: "OWNER_SNAPSHOT_SKIPPED_STREAM_ONLY",
    file: `${READ}/service.ts`,
    from: "input.isOwnerView\n              ? await this.snapshot",
    to: "input.isOwnerView && !input.streamOnly\n              ? await this.snapshot",
    tests: [`${READ}/stream-only-own-writes.test.ts`],
  },
  {
    name: "INCOMPLETE_PARTS_GATE_FALLBACK",
    file: `${READ}/importer.ts`,
    from: "this.missesLastComplete(key, head, row.version) &&",
    to: "!currentProblem && this.missesLastComplete(key, head, row.version) &&",
    tests: [`${READ}/latest-complete.test.ts`],
  },
  {
    name: "TRUST_CLAIMED_FALLBACK_VERSION",
    file: `${READ}/importer.ts`,
    from: "if (!(last.version > 0 && last.version < currentVersion)) return null;",
    to: "",
    // The same rule is also checked where the importer decides to look.
    also: ["if (last.version >= version) return false;", ""],
    tests: [`${READ}/latest-complete.test.ts`],
  },
  {
    name: "FALLBACK_PREDATES_DELETE",
    file: `${READ}/importer.ts`,
    from: "(head.lastDeleteVersion ?? 0) < (current.lastDeleteVersion ?? 0)",
    to: "false",
    tests: [`${READ}/latest-complete.test.ts`],
  },
  {
    name: "REGISTRY_AHEAD_ADMITS_LOCAL_RUNS",
    file: `${READ}/service.ts`,
    from: "if (options.registryAhead) {",
    to: "if (false as boolean) {",
    tests: [`${READ}/stream-only-plan.test.ts`],
  },
  {
    name: "PLAN_HEAD_DROPS_PROFILE",
    file: `${READ}/fold.ts`,
    from: "    profile: head.profile,\n    complete: head.complete,",
    to: '    profile: { key: null, version: "0.0.0" },\n    complete: head.complete,',
    tests: [`${READ}/stream-only-plan.test.ts`],
  },
  {
    name: "STALE_GENERATION_NOT_DISCARDED",
    file: `${READ}/service.ts`,
    from: 'if (verdict === "discard" || (verdict === "wait" && !pending)) continue;',
    to: 'if (verdict === "wait" && !pending) continue;',
    tests: [`${READ}/stream-only-plan.test.ts`],
  },
  {
    name: "OVERLAY_OMITS_CONNECTORS",
    file: `${READ}/writer-rig.ts`,
    from: "      connectors: () => source.connectors(),\n",
    to: "      connectors: async () => [],\n",
    tests: [`${READ}/writer-last-complete.test.ts`],
  },
  {
    name: "NO_RUN_COMPLETE_FROM_REGISTRY_HEAD",
    file: `${READ}/service.ts`,
    from: "const none = foldPlan(rowsHead, [], []);",
    to: "const none = foldPlan(head, [], []);",
    tests: [`${READ}/stream-only-plan.test.ts`],
  },
  {
    name: "SCAN_USES_INCOMPLETE_HEADS",
    file: `${READ}/service.ts`,
    from: "            row,\n            input.streamOnly,\n          );\n          if (live !== null) {",
    to: "            row,\n          );\n          if (live !== null) {",
    tests: [`${READ}/one-store.test.ts`, `${READ}/latest-complete.test.ts`],
  },
];

const wanted = process.argv.slice(2);
const selected = wanted.length
  ? MUTANTS.filter((m) => wanted.includes(m.name))
  : MUTANTS;
let bad = 0;
for (const m of selected) {
  const original = readFileSync(m.file, "utf8");
  const hash = sha(original);
  let outcome;
  try {
    if (
      !original.includes(m.from) ||
      (m.also && !original.includes(m.also[0]))
    ) {
      outcome = "NOT_APPLIED";
    } else {
      let mutated = original.replace(m.from, m.to);
      if (m.also) mutated = mutated.replace(m.also[0], m.also[1]);
      writeFileSync(m.file, mutated);
      const run = spawnSync(
        "nice",
        ["-n", "19", "npx", "vitest", "run", "--maxWorkers=4", ...m.tests],
        { encoding: "utf8" },
      );
      outcome = run.status === 0 ? "SURVIVED" : "RED";
    }
  } finally {
    writeFileSync(m.file, original);
  }
  const restored = sha(readFileSync(m.file, "utf8")) === hash;
  if (outcome !== "RED" || !restored) bad += 1;
  console.log(`${m.name}\t${outcome}\trestored=${restored}`);
}
process.exit(bad ? 1 : 0);
