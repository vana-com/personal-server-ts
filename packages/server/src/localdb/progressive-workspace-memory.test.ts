import { expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import {
  mkdtempSync,
  rmSync,
  mkdirSync,
  copyFileSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";

// Run alone while holding the shared memory-run lock. Each size gets a fresh
// process, file SQLite and disk blobs; no fixture body cache stands in for GET.
it.skipIf(process.env.STREAM_SYNC_PROGRESSIVE_MEMORY !== "1")(
  "10x keys and history retain at most two decoded input units",
  () => {
    const available = Number(
      spawnSync("free", ["-g"], { encoding: "utf8" })
        .stdout.split("\n")[1]!
        .trim()
        .split(/\s+/)
        .at(-1),
    );
    expect(
      available,
      "need 16 GiB available before measurement",
    ).toBeGreaterThanOrEqual(16);
    const scratch = mkdtempSync(
      join(process.cwd(), "scripts/log-memory/.progressive-"),
    );
    const run = (args: string[], env = process.env) => {
      const result = spawnSync(
        "nice",
        ["-n", "19", "ionice", "-c3", process.execPath, ...args],
        { env, encoding: "utf8", timeout: 120000 },
      );
      if (result.error || result.status !== 0)
        throw new Error(
          `${result.error ?? result.status}: ${result.stdout}\n${result.stderr}`,
        );
      return result.stdout;
    };
    try {
      const bundle = join(scratch, "measure.mjs");
      for (const name of ["better-sqlite3-worker.cjs", "statement-cache.cjs"])
        copyFileSync(
          join(process.cwd(), "packages/server/src/localdb", name),
          join(scratch, name),
        );
      run([
        "scripts/log-memory/build.mjs",
        bundle,
        "scripts/log-memory/progressive.mjs",
      ]);
      const receipts = [];
      for (const distinct of [false, true])
        for (const n of [8, 80]) {
          const dir = join(scratch, `${distinct}-${n}`);
          mkdirSync(dir);
          const output = run(["--expose-gc", bundle], {
            ...process.env,
            MEMORY_N: String(n),
            MEMORY_DISTINCT: distinct ? "1" : "0",
            MEMORY_DIR: dir,
          });
          const receipt = JSON.parse(output.trim().split("\n").at(-1)!);
          receipts.push(receipt);
          expect.soft(receipt.peakUnits).toBeLessThanOrEqual(2);
          expect.soft(receipt.peakBytes).toBeLessThanOrEqual(1024);
          expect(receipt.position).toBe(5);
          rmSync(dir, { recursive: true, force: true });
        }
      if (process.env.PROGRESSIVE_WORKSPACE_RECEIPTS)
        writeFileSync(
          process.env.PROGRESSIVE_WORKSPACE_RECEIPTS,
          JSON.stringify(receipts, null, 2),
        );
      console.log(JSON.stringify({ progressiveOwnership: receipts }));
    } finally {
      rmSync(scratch, { recursive: true, force: true });
    }
  },
  600000,
);
