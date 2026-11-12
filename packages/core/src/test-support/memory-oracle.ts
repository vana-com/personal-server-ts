/**
 * Process-level peak memory of one workload, measured in a fresh child process.
 *
 * Why a child and the kernel's high-water mark: an in-process sampler cannot see
 * a peak that is allocated and freed between two sample points, and a forced GC
 * erases the evidence. VmHWM is the peak resident set size of the process since
 * it started. It counts every byte the process touched, so a synchronous
 * materialize-then-free still shows up.
 *
 * Contract:
 * - `run(workload)` spawns one child. It loads the module, settles the import's
 *   garbage with forced GCs, then resets the child's high-water mark to its
 *   current resident size (`/proc/self/clear_refs`). The workload runs, and the
 *   net peak is `peakBytes = max(0, hwmAfter - rssAtStart)`, all in one process.
 *   Earlier versions subtracted a separate empty child's HWM. That baseline sat
 *   near 230 MiB for the publish harness, and its own HWM moved by about 10 MiB
 *   between runs, which read a 96 MiB retain as 84 MiB. Measuring the growth
 *   inside one process removes that cross-process noise.
 * - The workload's resolved value must be JSON-serializable; it is returned as
 *   `result`. Anything the caller needs later must go to disk, not the heap.
 * - A workload that throws, or a child that dies (for example on a heap
 *   ceiling), rejects `run` with the child's stderr tail.
 * - Linux only: reads `VmHWM` and `VmRSS` from `/proc/self/status` and resets
 *   `VmHWM` through `/proc/self/clear_refs` (needs kernel 4.0+).
 * - Garbage lag: Buffer churn is reclaimed only after a GC, and V8 lets external
 *   memory grow to about 64 MiB before it forces one. `gc: "timer25ms"` (the
 *   default) runs `gc()` every 25 ms for the whole workload.
 *   It gives the floor the writer can reach. `gc: "none"` runs no forced GC and
 *   gives the peak a phone would see, where WebView garbage stays resident. A GC
 *   cannot lower HWM and cannot free live data, so a retained or synchronously
 *   materialized peak shows in full in both modes. Under host load the timer
 *   fires late, so timer-mode readings move by tens of MiB between runs.
 */

import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

export interface Workload {
  /** Absolute path of a module (`.ts` or `.js`). */
  readonly module: string;
  /** Export to call with `args`. Empty string loads the module and calls nothing. */
  readonly exportName: string;
  readonly args?: unknown;
  /** Heap ceiling for the child, in MiB. Default 2048. */
  readonly heapLimitMiB?: number;
  /** Extra environment for the child, for example allocator tunables. */
  readonly env?: Readonly<Record<string, string>>;
}

/**
 * How the child collects garbage while the workload runs.
 * - "timer25ms" (default): `gc()` every 25 ms. Matches a server with an idle
 *   collector; readings are the lowest the writer can reach.
 * - "none": no forced GC. Garbage stays resident until V8 decides to collect.
 *   This is the phone-like peak: the P3 Pixel run showed WebView garbage
 *   staying resident, up to 5.4 GB.
 */
export type GcMode = "timer25ms" | "none";

export interface RunOptions {
  readonly gc?: GcMode;
}

export interface MemoryRun<R = unknown> {
  /** Child HWM after the workload minus its resident size at start, floored at 0. */
  readonly peakBytes: number;
  /** Resident size of the child after the module loaded, before the workload. */
  readonly baselineBytes: number;
  /** Child HWM after the workload, before subtracting the start size. */
  readonly rawPeakBytes: number;
  readonly result: R;
}

const LINE_PREFIX = "MEMORY_ORACLE ";
const CHILD = fileURLToPath(
  new URL("./memory-oracle-child.mjs", import.meta.url),
);

interface ChildReport {
  readonly hwmBytes: number;
  readonly startBytes: number;
  readonly result: unknown;
}

function spawnChild(workload: Workload, gc: GcMode): Promise<ChildReport> {
  const heap = workload.heapLimitMiB ?? 2048;
  const args = [
    // A compiled workload needs no loader realm or TypeScript compiler.
    // Keep the existing loader for source workloads, including on Node 20.
    ...(/\.(?:[cm]?ts|tsx)$/.test(workload.module) ? ["--import", "tsx"] : []),
    "--expose-gc",
    `--max-old-space-size=${heap}`,
    CHILD,
    workload.module,
    workload.exportName,
    JSON.stringify(workload.args ?? null),
    gc,
  ];
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, args, {
      stdio: ["ignore", "pipe", "pipe"],
      // Eager malloc trim. Free allocator memory left by the import stays
      // resident and is reused by the workload's first allocations, so RSS
      // grows by less than the workload retained (87 to 94 MiB for 96 MiB).
      // Trimming at once makes the start point hold no reusable slack.
      env: {
        ...process.env,
        NODE_NO_WARNINGS: "1",
        MALLOC_TRIM_THRESHOLD_: "0",
        MALLOC_TOP_PAD_: "0",
        ...workload.env,
      },
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d: Buffer) => {
      stdout += d.toString("utf8");
    });
    child.stderr.on("data", (d: Buffer) => {
      stderr += d.toString("utf8");
    });
    child.on("error", reject);
    child.on("close", (code, signal) => {
      const line = stdout
        .split("\n")
        .filter((l) => l.startsWith(LINE_PREFIX))
        .at(-1);
      if (code !== 0 || !line) {
        const tail = stderr.slice(-800).trim();
        reject(
          new Error(
            `memory-oracle child for ${workload.exportName || "load-only"} ` +
              `exited ${code ?? signal}: ${tail}`,
          ),
        );
        return;
      }
      resolve(JSON.parse(line.slice(LINE_PREFIX.length)) as ChildReport);
    });
  });
}

/** Run one workload in a fresh child and return its peak above the start size. */
export async function run<R = unknown>(
  workload: Workload,
  opts: RunOptions = {},
): Promise<MemoryRun<R>> {
  const measured = await spawnChild(workload, opts.gc ?? "timer25ms");
  return {
    peakBytes: Math.max(0, measured.hwmBytes - measured.startBytes),
    baselineBytes: measured.startBytes,
    rawPeakBytes: measured.hwmBytes,
    result: measured.result as R,
  };
}
