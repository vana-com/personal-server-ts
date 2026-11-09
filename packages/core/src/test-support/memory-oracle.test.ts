/**
 * Calibrates the instrument itself, on synthetic workloads with known memory.
 * The instrument must read a bounded workload near zero, and must read a
 * synchronous materialize-then-free of N MiB as roughly N MiB, the case a
 * sampler misses.
 */

import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { run } from "./memory-oracle.js";

const WORKLOADS = fileURLToPath(
  new URL("./memory-oracle.calibration.ts", import.meta.url),
);
const MiB = 1024 * 1024;
const HELD_MiB = 256;

describe("memory-oracle calibration", () => {
  // The bounded case churns the same total through short-lived buffers, paced.
  // Its peak must stay well below a retained accumulation of that size.
  it("reads a bounded churn well below a retained accumulation", async () => {
    const r = await run({
      module: WORKLOADS,
      exportName: "bounded",
      args: { mib: HELD_MiB },
    });
    expect(r.baselineBytes).toBeGreaterThan(0);
    expect(r.peakBytes).toBeLessThan(0.5 * HELD_MiB * MiB);
  }, 60_000);

  it("reads a retained accumulation at its full size", async () => {
    const r = await run({
      module: WORKLOADS,
      exportName: "accumulate",
      args: { mib: HELD_MiB },
    });
    expect(r.peakBytes).toBeGreaterThanOrEqual(0.9 * HELD_MiB * MiB);
  }, 60_000);

  it("reads a synchronous materialize-then-free at its full size", async () => {
    const r = await run({
      module: WORKLOADS,
      exportName: "materializeThenFree",
      args: { mib: HELD_MiB },
    });
    expect(r.peakBytes).toBeGreaterThanOrEqual(0.9 * HELD_MiB * MiB);
  }, 60_000);
});
