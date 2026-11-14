/**
 * Calibrates the instrument itself, on synthetic workloads with known memory.
 * The instrument must read a bounded workload near zero, and must read a
 * synchronous materialize-then-free of N MiB as roughly N MiB, the case a
 * sampler misses.
 */

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { run } from "./memory-oracle.js";

const WORKLOADS = fileURLToPath(
  new URL("./memory-oracle.calibration.ts", import.meta.url),
);
const MiB = 1024 * 1024;
const HELD_MiB = 256;

describe("memory-oracle calibration", () => {
  it("runs compiled JavaScript without a TypeScript loader", async () => {
    const temporary = join(homedir(), ".tmp");
    mkdirSync(temporary, { recursive: true });
    const root = mkdtempSync(join(temporary, "memory-oracle-js-"));
    try {
      const module = join(root, "workload.mjs");
      writeFileSync(
        module,
        "export function args() { return process.execArgv; }",
      );
      const measured = await run<string[]>({ module, exportName: "args" });
      expect(measured.result).not.toContain("tsx");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("caps the young-generation semi-space only when asked", async () => {
    const temporary = join(homedir(), ".tmp");
    mkdirSync(temporary, { recursive: true });
    const root = mkdtempSync(join(temporary, "memory-oracle-semi-"));
    try {
      const module = join(root, "workload.mjs");
      writeFileSync(
        module,
        "export function args() { return process.execArgv; }",
      );
      const capped = await run<string[]>({
        module,
        exportName: "args",
        maxSemiSpaceMiB: 4,
      });
      expect(capped.result).toContain("--max-semi-space-size=4");
      const unset = await run<string[]>({ module, exportName: "args" });
      expect(unset.result.join(" ")).not.toContain("semi-space");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

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
