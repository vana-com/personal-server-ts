import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { expect, it } from "vitest";
const memoryRoot = tmpdir();
const KIB_PER_MIB = 1024;

/**
 * COARSE SMOKE GUARD. This test does not prove that memory is independent of
 * blob size. Peak RSS is noisy, and the signal from a worker that retains part
 * of each blob is smaller than that noise, so a slope over three RSS peaks
 * cannot separate the two. The size-independence property is asserted in
 * pdpp-binary-chunks.test.ts, which meters each read. This test only catches
 * gross blow-ups.
 *
 * Peak RSS is monotonic, so each figure bounds everything before it in its
 * process. Three guards, all measured in child processes:
 *
 * 1. Worker phases (fetch, decrypt, verify, chunk staging) must stay within
 *    WORKER_ALLOWANCE_KIB above the process's startup peak, measured before
 *    promotion.
 *
 * 2. Replicated promotion copies the verified chunks into canonical chunks,
 *    64 KiB at a time, and assembles no whole value. Its growth must stay
 *    under PROMOTION_ALLOWANCE_KIB at every size, both alone and inside the
 *    worker. Main's own blob write holds the whole blob; it is measured for
 *    comparison only.
 *
 * WORKER_ALLOWANCE_KIB is the worker's own growth above startup. It is not
 * meant to scale with blob size: the growth it covers is fragment churn, one
 * 3 MiB fragment in flight at a time. It is set from CI's spread on Node 22:
 * 105 samples from 35 CI runs on 2026-10-29 (32, 64 and 128 MiB; main and
 * eight branches) had a median of 158 MiB, a p95 of 178 MiB and a maximum of
 * 227 MiB. The spikes do not follow blob size or branch: the three samples
 * over 208 MiB came at 32 and 64 MiB, two of them on a branch that does not
 * touch replication. The allowance is that maximum plus about 29 MiB.
 *
 * A spike is transient, so a size whose first sample exceeds the allowance is
 * measured once more in a fresh process, and the lower sample counts. A
 * worker that retains blob-sized memory fails both samples.
 *
 * Newer Node releases retain more freed buffers before returning them to the
 * OS. On Node 24.22.1 the same growth is about 358 to 394 MiB at 32, 64 and
 * 128 MiB (local runs; CI runs Node 22). The absolute allowance therefore
 * depends on the Node major.
 */
const WORKER_ALLOWANCE_KIB =
  (Number(process.versions.node.split(".")[0]) <= 22 ? 256 : 448) * KIB_PER_MIB;
/**
 * Chunked promotion's growth does not follow blob size: on Node 24.22.1 it
 * measured 32, 62, 60 and 59 MiB at 32, 128, 256 and 512 MiB. The level is
 * freed 64 KiB chunk buffers waiting for garbage collection; each value
 * SQLite hands over is one chunk (pdpp-replication-blob-storage.test.ts).
 * The whole-value promotion this replaced grew 124 MiB at 32 MiB and 452 MiB
 * at 128 MiB, so it fails at every size.
 */
const PROMOTION_ALLOWANCE_KIB = 80 * KIB_PER_MIB;

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

const workerGrowthKiB = (worker: WorkerMeasurement) =>
  worker.workerPeakKiB - worker.startKiB;

/** A worker sample in a fresh seeded directory, for the one re-measure. */
function measureWorker(sizeBytes: number): WorkerMeasurement {
  const directory = mkdtempSync(join(memoryRoot, "replica-memory-"));
  try {
    runFixture("seed", directory, sizeBytes);
    return JSON.parse(
      runFixture("measure", directory, sizeBytes),
    ) as WorkerMeasurement;
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

it("smoke-guards transport-worker RSS at 32, 64 and 128 MiB blobs (coarse, not a size-independence proof)", () => {
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
      let worker = JSON.parse(
        runFixture("measure", directory, sizeBytes),
      ) as WorkerMeasurement;
      if (workerGrowthKiB(worker) >= WORKER_ALLOWANCE_KIB) {
        const again = measureWorker(sizeBytes);
        console.log("replica memory re-measure", { sizeMiB, worker, again });
        if (workerGrowthKiB(again) < workerGrowthKiB(worker)) worker = again;
      }
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
  for (const { sizeMiB, worker, promote } of results) {
    expect(worker.published, `${sizeMiB} MiB`).toBeGreaterThan(0);
    expect(
      workerGrowthKiB(worker),
      `${sizeMiB} MiB worker phases`,
    ).toBeLessThan(WORKER_ALLOWANCE_KIB);
    expect(promote.deltaKiB, `${sizeMiB} MiB promotion`).toBeLessThan(
      PROMOTION_ALLOWANCE_KIB,
    );
    expect(
      worker.peakRssKiB - worker.workerPeakKiB,
      `${sizeMiB} MiB in-worker promotion`,
    ).toBeLessThan(PROMOTION_ALLOWANCE_KIB);
  }
}, 900000);
