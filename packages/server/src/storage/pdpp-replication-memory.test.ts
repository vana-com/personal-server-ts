import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { expect, it } from "vitest";
const memoryRoot = tmpdir();
const KIB_PER_MIB = 1024;

/**
 * Peak RSS is monotonic, so each figure bounds everything before it in its
 * process. Three contracts, all measured in child processes:
 *
 * 1. Worker phases (fetch, decrypt, verify, chunk staging) grow with neither
 *    blob size nor the canonical copy. Their peak, measured before promotion,
 *    must stay within WORKER_ALLOWANCE_KIB above the process's startup peak
 *    and spread less than 96 MiB across sizes.
 *
 * 2. Replicated promotion writes main's whole `pdpp_blob_bytes` row, which
 *    costs what main's own blob write costs. It must cost no more than that
 *    plus PROMOTION_MARGIN_KIB. Main's whole row is the rollback format, so
 *    the comparison deliberately mirrors it.
 *
 * WORKER_ALLOWANCE_KIB is the worker's own growth above startup, measured on
 * Node 22.21.1. The typical growth is about 164 MiB at both 32 and 128 MiB.
 * Some runs spike to about 188 to 192 MiB inside the worker phases, so the
 * allowance is the worst observed value plus 16 MiB of headroom. It does not
 * scale with blob size. The growth it covers is fragment churn, one 3 MiB
 * fragment in flight at a time.
 *
 * Newer Node releases retain more freed buffers before returning them to the
 * OS. On Node 24.22.1 the same growth is about 350 to 361 MiB at 32, 64 and
 * 128 MiB alike (still flat, so still independent of blob size). The absolute
 * allowance therefore depends on the Node major; the spread check above is
 * the one that proves growth does not follow blob size.
 */
const WORKER_ALLOWANCE_KIB =
  (Number(process.versions.node.split(".")[0]) <= 22 ? 208 : 416) * KIB_PER_MIB;
const WORKER_SPREAD_KIB = 96 * KIB_PER_MIB;
const PROMOTION_MARGIN_KIB = 16 * KIB_PER_MIB;

type Measurement = { size: number; deltaKiB: number };
type WorkerMeasurement = {
  size: number;
  published: number;
  startKiB: number;
  workerPeakKiB: number;
  afterPromotionKiB: number;
  peakRssKiB: number;
};

function runFixture(mode: string, directory: string, sizeBytes: number) {
  // Promotion probes import the records store, which the worker probe does not need.
  const fixture =
    mode === "promote" || mode === "plain"
      ? "./pdpp-replication-promotion-memory.fixture.ts"
      : "./pdpp-replication-memory.fixture.ts";
  const child = spawnSync(
    process.execPath,
    [
      "--max-old-space-size=1536",
      "--import",
      "tsx",
      new URL(fixture, import.meta.url).pathname,
      mode,
      directory,
      String(sizeBytes),
    ],
    { encoding: "utf8", timeout: 300000, maxBuffer: 16384 },
  );
  expect(child.status, child.stderr.slice(-4000)).toBe(0);
  return child.stdout;
}

it("bounds real transport-worker memory across 32, 64 and 128 MiB blobs", () => {
  const results: {
    sizeMiB: number;
    worker: WorkerMeasurement;
    promote: Measurement;
    plain: Measurement;
  }[] = [];
  for (const sizeMiB of [32, 64, 128]) {
    const sizeBytes = sizeMiB * 1024 * 1024;
    const directory = mkdtempSync(join(memoryRoot, "replica-memory-"));
    const promoteDirectory = mkdtempSync(join(memoryRoot, "replica-promote-"));
    const plainDirectory = mkdtempSync(join(memoryRoot, "replica-plain-"));
    try {
      runFixture("seed", directory, sizeBytes);
      const worker = JSON.parse(runFixture("measure", directory, sizeBytes));
      const promote = JSON.parse(
        runFixture("promote", promoteDirectory, sizeBytes),
      );
      const plain = JSON.parse(runFixture("plain", plainDirectory, sizeBytes));
      results.push({ sizeMiB, worker, promote, plain });
      console.log("replica memory sample", {
        sizeMiB,
        worker,
        promote,
        plain,
      });
    } finally {
      rmSync(directory, { recursive: true, force: true });
      rmSync(promoteDirectory, { recursive: true, force: true });
      rmSync(plainDirectory, { recursive: true, force: true });
    }
  }
  console.log("replica memory", results);
  const workerPeaks = results.map((r) => r.worker.workerPeakKiB);
  expect(Math.max(...workerPeaks) - Math.min(...workerPeaks)).toBeLessThan(
    WORKER_SPREAD_KIB,
  );
  for (const { sizeMiB, worker, promote, plain } of results) {
    expect(worker.published, `${sizeMiB} MiB`).toBeGreaterThan(0);
    expect(
      worker.workerPeakKiB - worker.startKiB,
      `${sizeMiB} MiB worker phases`,
    ).toBeLessThan(WORKER_ALLOWANCE_KIB);
    expect(
      promote.deltaKiB,
      `${sizeMiB} MiB promotion vs main plain write`,
    ).toBeLessThanOrEqual(plain.deltaKiB + PROMOTION_MARGIN_KIB);
    expect(
      worker.peakRssKiB - worker.workerPeakKiB,
      `${sizeMiB} MiB in-worker promotion vs main plain write`,
    ).toBeLessThanOrEqual(plain.deltaKiB + PROMOTION_MARGIN_KIB);
  }
}, 900000);
