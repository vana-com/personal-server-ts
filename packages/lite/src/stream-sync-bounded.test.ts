/**
 * Bounded-memory oracle for the Lite stream-sync writer (lane P3).
 *
 * Each scenario runs in a child Node process (`--expose-gc`) so the heap
 * peak is not polluted by the vitest worker. The small twin always runs.
 * The big cases run only with STREAM_SYNC_P3_BIG=1 (about 1 GB of synthetic
 * appends in total; several minutes).
 *
 * Budgets are absolute: peak heap above the child's idle baseline, measured
 * with forced GC at part encrypt, blob put/get and flush boundaries, and
 * including the cipher copy and one simulated bridge copy per blob.
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
import {
  expectedCount,
  MiB,
} from "./test-support/stream-sync-heap-scenarios.js";
import { LITE_PART_TARGET_BYTES } from "./stream-sync-budget.js";

const exec = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const LITE_DIR = join(here, "..");
const CHILD = join(here, "test-support", "stream-sync-heap-child.ts");
const BIG = process.env.STREAM_SYNC_P3_BIG === "1";

/** Peak heap above the child's baseline, for non-8 MiB scenarios. */
const SMALL_BUDGET_BYTES = 12 * MiB;
/** One 8 MiB record cannot be split below its size; the floor is ~35 MiB. */
const BIG8_BUDGET_BYTES = 40 * MiB;

async function runChild(spec: ScenarioSpec, tag: string): Promise<RunReport> {
  const root = join(homedir(), ".tmp", "p3-oracle");
  mkdirSync(root, { recursive: true });
  const dir = mkdtempSync(join(root, `${tag}-`));
  const input = JSON.stringify({
    spec,
    dir,
    partTargetBytes: LITE_PART_TARGET_BYTES,
    reduceBudgetBytes: LITE_PART_TARGET_BYTES,
    spoolFlushBytes: 1 * MiB,
  });
  const { stdout } = await exec(
    process.execPath,
    ["--expose-gc", "--import", "tsx", CHILD, input],
    { cwd: LITE_DIR, maxBuffer: 1 << 20, timeout: 20 * 60 * 1000 },
  );
  const line = stdout.trim().split("\n").pop() ?? "";
  return JSON.parse(line) as RunReport;
}

function assertBounded(report: RunReport, budget: number): void {
  expect(report.outcome).toBe("committed");
  expect(report.tooLargeSpooled).toBe(report.spec.kind === "big8" ? 1 : 0);
  expect(report.countOk).toBe(true);
  expect(report.digestOk).toBe(true);
  expect(report.outputCount).toBe(expectedCount(report.spec));
  const above = report.heap.peakBytes - report.baselineBytes;
  expect(
    above,
    `${report.spec.kind} n=${report.spec.records} peak above baseline`,
  ).toBeLessThan(budget);
}

describe("stream-sync bounded writer (small twin, always)", () => {
  it.each<ScenarioSpec>([
    { kind: "uniform", records: 2_000 },
    { kind: "skewed", records: 2_000 },
    { kind: "repeated", records: 20_000 },
    { kind: "tiny", records: 20_000 },
  ])(
    "$kind bounded and correct",
    async (spec) => {
      assertBounded(await runChild(spec, spec.kind), SMALL_BUDGET_BYTES);
    },
    120_000,
  );

  it("big8 twin: one 8 MiB record accepted, 9 MiB excluded", async () => {
    assertBounded(
      await runChild({ kind: "big8", records: 3 }, "big8-twin"),
      BIG8_BUDGET_BYTES,
    );
  }, 120_000);

  it("peak does not grow with record count (uniform 2k vs 20k)", async () => {
    const small = await runChild({ kind: "uniform", records: 2_000 }, "flat-s");
    const large = await runChild(
      { kind: "uniform", records: 20_000 },
      "flat-l",
    );
    const delta = Math.abs(
      small.heap.peakBytes -
        small.baselineBytes -
        (large.heap.peakBytes - large.baselineBytes),
    );
    expect(delta).toBeLessThan(8 * MiB);
  }, 240_000);
});

describe.skipIf(!BIG)(
  "stream-sync bounded writer (big cases, STREAM_SYNC_P3_BIG=1)",
  () => {
    it(
      "uniform 20k",
      async () => {
        assertBounded(
          await runChild({ kind: "uniform", records: 20_000 }, "big-uni"),
          SMALL_BUDGET_BYTES,
        );
      },
      20 * 60_000,
    );

    it(
      "skewed 20k",
      async () => {
        assertBounded(
          await runChild({ kind: "skewed", records: 20_000 }, "big-skew"),
          SMALL_BUDGET_BYTES,
        );
      },
      20 * 60_000,
    );

    it(
      "repeated-key 100k",
      async () => {
        assertBounded(
          await runChild({ kind: "repeated", records: 100_000 }, "big-rep"),
          SMALL_BUDGET_BYTES,
        );
      },
      20 * 60_000,
    );

    it(
      "tiny-record 1M",
      async () => {
        assertBounded(
          await runChild({ kind: "tiny", records: 1_000_000 }, "big-tiny"),
          SMALL_BUDGET_BYTES,
        );
      },
      20 * 60_000,
    );

    it(
      "one 8 MiB record stream",
      async () => {
        assertBounded(
          await runChild({ kind: "big8", records: 3 }, "big-8"),
          BIG8_BUDGET_BYTES,
        );
      },
      20 * 60_000,
    );
  },
);
