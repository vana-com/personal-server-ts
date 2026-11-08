/**
 * Allocation-churn oracle for the Lite stream-sync writer (lane P3, round 3).
 *
 * Measures bytes allocated per appended record (V8 sampling heap profile, which
 * counts collected objects too) in a child process, so the number does not
 * depend on when GC runs. A mutant that restores the pre-cut writer path fails
 * these assertions.
 */
import { execFile } from "node:child_process";
import { mkdirSync, mkdtempSync } from "node:fs";
import { homedir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";
import type { RunReport } from "./test-support/stream-sync-heap-node.js";
import type { ScenarioSpec } from "./test-support/stream-sync-heap-scenarios.js";
import { LITE_PART_TARGET_BYTES } from "./stream-sync-budget.js";

const exec = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const LITE_DIR = join(here, "..");
const CHILD = join(here, "test-support", "stream-sync-heap-child.ts");

/**
 * Ratchet, not the target. Pre-cut baseline at 2k records: uniform 30,345 B/record,
 * skewed 103,826 B/record. After the cuts: ~27,100 and ~90,900. Budgets sit between the
 * two, so restoring the pre-cut writer path fails them.
 */
const UNIFORM_BYTES_PER_RECORD_BUDGET = 29_000;
const SKEWED_BYTES_PER_RECORD_BUDGET = 98_000;

async function allocPerRecord(spec: ScenarioSpec): Promise<RunReport> {
  const root = join(homedir(), ".tmp", "p3-oracle");
  mkdirSync(root, { recursive: true });
  const dir = mkdtempSync(join(root, "churn-"));
  const input = JSON.stringify({
    spec,
    dir,
    partTargetBytes: LITE_PART_TARGET_BYTES,
    reduceBudgetBytes: LITE_PART_TARGET_BYTES,
    spoolFlushBytes: 1024 * 1024,
  });
  const { stdout } = await exec(
    process.execPath,
    ["--expose-gc", "--import", "tsx", CHILD, input],
    { cwd: LITE_DIR, maxBuffer: 1 << 20, timeout: 10 * 60 * 1000 },
  );
  return JSON.parse(stdout.trim().split("\n").pop() ?? "") as RunReport;
}

describe("stream-sync writer allocation churn", () => {
  it(
    "uniform records allocate within budget",
    async () => {
      const report = await allocPerRecord({ kind: "uniform", records: 2000 });
      expect(report.outcome).toBe("committed");
      expect(report.digestOk && report.countOk).toBe(true);
      expect(report.allocPerRecord).toBeLessThanOrEqual(
        UNIFORM_BYTES_PER_RECORD_BUDGET,
      );
    },
    10 * 60 * 1000,
  );

  it(
    "skewed records allocate within budget",
    async () => {
      const report = await allocPerRecord({ kind: "skewed", records: 2000 });
      expect(report.outcome).toBe("committed");
      expect(report.digestOk && report.countOk).toBe(true);
      expect(report.allocPerRecord).toBeLessThanOrEqual(
        SKEWED_BYTES_PER_RECORD_BUDGET,
      );
    },
    10 * 60 * 1000,
  );
});
