/**
 * Generated every-prefix differential (oracle design §2), split into
 * `differential.*.test.ts` shards so test workers run them in parallel.
 *
 * PR CI runs fixed seeds. Set REPLICA_ORACLE_NIGHTLY=1 for the large mode,
 * or REPLICA_ORACLE_SEEDS=<n>[,<length>] / REPLICA_ORACLE_SEED=<seed> to
 * pick the volume or rerun one seed. REPLICA_ORACLE_AVOID=<a,b> overrides the
 * known-defect exclusions; set it empty to hunt with every command shape.
 * A failure prints the seed, the minimized command JSON, the failing prefix
 * and expected/actual, and writes it to REPLICA_ORACLE_REPORT_DIR when set.
 */
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  generateCommands,
  shrinkCommands,
  type Command,
} from "./generator.test-utils.js";
import {
  formatFailure,
  runCommands,
  type Failure,
} from "./runner.test-utils.js";

const nightly = process.env.REPLICA_ORACLE_NIGHTLY === "1";
const [countText, lengthText] = (process.env.REPLICA_ORACLE_SEEDS ?? "").split(
  ",",
);
const count = Number(countText) || (nightly ? 256 : 32);
const length = Number(lengthText) || (nightly ? 64 : 24);
const single = process.env.REPLICA_ORACLE_SEED;
const seeds = single
  ? [Number(single) >>> 0]
  : Array.from({ length: count }, (_, i) => (0x9e3779b9 * (i + 1)) >>> 0);

/**
 * Command shapes the generator leaves out. Empty by default: every shape the
 * oracle found on PR #483 is fixed. Set REPLICA_ORACLE_AVOID=<a,b> to exclude
 * shapes while triaging a new finding.
 */
export const KNOWN_DEFECTS: ReadonlySet<string> = new Set(
  (process.env.REPLICA_ORACLE_AVOID ?? "").split(",").filter(Boolean),
);

async function check(seed: number, commands: Command[]) {
  const failures = await runCommands(commands, { freshReplay: true });
  if (!failures.length) return;
  // Shrink toward the same defect: the first failing port and check must stay.
  const signature = (list: Failure[]) =>
    list[0] && `${list[0].port}/${list[0].check}`;
  const minimized =
    process.env.REPLICA_ORACLE_SHRINK === "0"
      ? commands
      : await shrinkCommands(
          commands,
          async (candidate) =>
            signature(await runCommands(candidate, { freshReplay: true })) ===
            signature(failures),
        );
  const final = await runCommands(minimized, { freshReplay: true });
  const report = formatFailure(
    seed,
    minimized,
    final.length ? final : failures,
  );
  if (process.env.REPLICA_ORACLE_REPORT_DIR)
    writeFileSync(
      join(process.env.REPLICA_ORACLE_REPORT_DIR, `seed-${seed}.json`),
      report,
    );
  expect.fail(report);
}

/** Declare one shard: every `shards`-th seed starting at `shard`. */
export function describeDifferential(shard: number, shards: number) {
  const mine = seeds.filter((_, i) => i % shards === shard);
  describe(`replica differential shard ${shard + 1}/${shards} (${mine.length} seeds × ${length} commands)`, () => {
    for (const seed of mine)
      it(
        `seed ${seed}`,
        async () => {
          await check(
            seed,
            generateCommands(seed, { length, avoid: KNOWN_DEFECTS }),
          );
        },
        nightly ? 900_000 : 120_000,
      );
  });
}
