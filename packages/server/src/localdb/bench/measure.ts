// One measured step: the process high-water mark (kernel `VmHWM`, reset by
// `/proc/self/clear_refs`) over a function, beside the resident size the step
// began with. The kernel mark misses no synchronous allocation, which a
// sampling timer can. Run the process with `--expose-gc`.
import { readFileSync, writeFileSync } from "node:fs";

const MiB = 1024 * 1024;

export interface StepReport {
  readonly step: string;
  /** Resident size after a full collection, when the step began. */
  readonly idleMiB: number;
  /** Process high-water mark during the step (kernel `VmHWM`). */
  readonly peakMiB: number;
  readonly aboveIdleMiB: number;
  /** Resident size when the step ended, before any collection. */
  readonly endMiB: number;
  readonly ms: number;
  readonly notes: Record<string, unknown>;
}

const statusKiB = (field: string): number => {
  const m = new RegExp(`^${field}:\\s+(\\d+) kB$`, "m").exec(
    readFileSync("/proc/self/status", "utf8"),
  );
  if (!m) throw new Error(`${field} missing from /proc/self/status`);
  return Number(m[1]);
};

export async function settle(): Promise<void> {
  const gc = globalThis.gc;
  if (!gc) throw new Error("run with --expose-gc");
  for (let i = 0; i < 3; i += 1) gc();
  await new Promise((r) => setTimeout(r, 300));
  for (let i = 0; i < 2; i += 1) gc();
}

export async function measure<T>(
  step: string,
  fn: () => Promise<T>,
  notes: (result: T) => Record<string, unknown> = () => ({}),
): Promise<{ result: T; report: StepReport }> {
  await settle();
  const idle = statusKiB("VmRSS");
  writeFileSync("/proc/self/clear_refs", "5");
  const started = Date.now();
  // Where the peak lives: sampled maxima of V8's heap and of the Buffers
  // outside it (a lower bound; the kernel mark is the peak itself).
  let heapMax = 0;
  let externalMax = 0;
  const sample = setInterval(() => {
    const m = process.memoryUsage();
    heapMax = Math.max(heapMax, m.heapUsed);
    externalMax = Math.max(externalMax, m.external + m.arrayBuffers);
  }, 20);
  const result = await fn().finally(() => clearInterval(sample));
  const peak = statusKiB("VmHWM");
  return {
    result,
    report: {
      step,
      idleMiB: Math.round(idle / 1024),
      peakMiB: Math.round(peak / 1024),
      aboveIdleMiB: Math.max(0, Math.round((peak - idle) / 1024)),
      endMiB: Math.round(statusKiB("VmRSS") / 1024),
      ms: Date.now() - started,
      notes: {
        sampledHeapMiB: Math.round(heapMax / MiB),
        sampledExternalMiB: Math.round(externalMax / MiB),
        ...notes(result),
      },
    },
  };
}
