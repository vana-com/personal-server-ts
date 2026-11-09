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
 *
 * LIMIT (what this oracle does NOT prove): `peakBytes` is sampled live
 * retention at settled boundaries and timer samples. It does not bound a
 * transient allocation that is created and released between two samples, and
 * it does not bound the process RSS, renderer PSS or any phone maximum. The
 * uniform 2k/20k flatness test is the multi-part retention detector; a
 * per-scenario single peak bound does not separate a retained-all writer from
 * a correct one at these sizes. The phone and emulator maxima are measured
 * outside this file and are disclosed in the PR body.
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
/**
 * One 8 MiB record cannot be split below its size. Measured peak above
 * baseline after the spool fix (10 runs each, big8 n=3, 2 MiB part target):
 *   Node 22 (CI): 34.06-34.08 MB = 32.5 MiB; before the fix 42.25-42.27 MB.
 *   (Intermediate: 35.96-35.98 MB with a per-chunk fragment list.)
 *   Node 24:      33.61-33.65 MB = 32.1 MiB; before the fix 33.81-33.85 MB.
 * Copies of the 8 MiB line live at the peak (the file append of the spool
 * flush): the record body held by the caller (8 MiB), the flat line text
 * (8 MiB), the flattened spool line concatenation (8 MiB), the encoded
 * bytes handed to the append (8 MiB): 32 MiB, plus small state. The
 * shard-derivation pass held a fourth copy (the chunk-joined line bytes)
 * across its yield; removing that copy is what moved Node 22 from 40.3 to
 * 32.5 MiB. The 40 MiB budget keeps ~7.5 MiB of headroom on Node 22 and fails
 * a writer that keeps one more 8 MiB copy until flush (mutant: 50.4 MB on
 * both runtimes).
 */
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

/** Output checks that must pass before any memory number means anything. */
function assertCorrect(report: RunReport): void {
  expect(report.outcome).toBe("committed");
  expect(report.tooLargeSpooled).toBe(0);
  expect(report.countOk).toBe(true);
  expect(report.digestOk).toBe(true);
  expect(report.outputCount).toBe(expectedCount(report.spec));
}

function assertBounded(report: RunReport, budget: number): void {
  assertCorrect(report);
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

  it("big8 twin: 8 MiB and 9 MiB records both accepted", async () => {
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
    // Correct output first: a run that drops or changes records can look flat.
    assertCorrect(small);
    assertCorrect(large);
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
