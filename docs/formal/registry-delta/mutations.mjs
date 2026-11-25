// Run only with no concurrent checks: each mutation is restored before exit.
import { readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";

const manager = "packages/core/src/sync/engine/sync-manager.ts";
const mutations = [
  {
    name: "a partial publication settles with changes pending",
    source: "packages/core/src/localdb/delta-apply.ts",
    from: "if (await hasPendingLogPublication(deps, connectionId))",
    to: "if (false)",
    test: "packages/server/src/localdb/delta-apply.test.ts",
    pattern: "successful first publication round",
  },
  {
    name: "delta settles without publishing apply-created debt",
    source: "packages/core/src/localdb/delta-apply.ts",
    from: "const published = await publishLog(deps, connectionId);",
    to: "const published = [];",
    test: "packages/server/src/localdb/delta-apply.test.ts",
    pattern: "a fork at the held position",
  },
  {
    name: "unreadable reset advertises an applied cursor",
    source: manager,
    from: "refusedPosition = startedUnder;",
    to: "syncedPosition = startedUnder;",
    test: "packages/core/src/sync/engine/sync-manager.delta.test.ts",
    pattern: "listing cannot finish a connection",
  },
  {
    name: "reset settles before persistence",
    source: manager,
    from: "const report = await runLocalCycle(options.localSync);",
    to: "const report = runLocalCycle(options.localSync);",
    test: "packages/core/src/sync/engine/sync-manager.delta.test.ts",
    pattern: "a reset waits for the full listing",
  },
  {
    name: "a delta that reaches the held position is applied again",
    source: manager,
    from: "if (delta && !delta.reset && delta.cursor === syncedPosition) return;",
    to: "",
    test: "packages/core/src/sync/engine/sync-manager.delta.test.ts",
    pattern: "already held",
  },
  {
    name: "one failure leaves a sibling running",
    source: "packages/core/src/localdb/delta-apply.ts",
    from: "const reached = await Promise.allSettled([",
    to: "const reached = await Promise.all([",
    test: "packages/server/src/localdb/delta-apply.test.ts",
    pattern: "waits for every connection",
  },
];

for (const mutation of mutations) {
  const original = readFileSync(mutation.source, "utf8");
  if (!original.includes(mutation.from))
    throw new Error(`Mutation no longer matches: ${mutation.name}`);
  try {
    writeFileSync(
      mutation.source,
      original.replace(mutation.from, mutation.to),
    );
    const result = spawnSync(
      "nice",
      [
        "-n",
        "19",
        "ionice",
        "-c3",
        process.execPath,
        "node_modules/vitest/vitest.mjs",
        "run",
        "--maxWorkers=4",
        mutation.test,
        "-t",
        mutation.pattern,
      ],
      { encoding: "utf8", timeout: 120_000 },
    );
    const output = result.stdout + result.stderr;
    if (result.status !== 1 || !output.includes("AssertionError")) {
      process.stderr.write(output);
      throw new Error(
        `Mutation survived or failed outside its assertion: ${mutation.name}`,
      );
    }
    console.log(`Caught: ${mutation.name}`);
  } finally {
    writeFileSync(mutation.source, original);
  }
}
