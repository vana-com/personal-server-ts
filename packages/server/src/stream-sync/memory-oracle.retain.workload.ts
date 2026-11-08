/**
 * Retain-all calibration workload with the heavy harness baseline. The module
 * imports the same harness as the publish workload, so the empty baseline
 * child loads the same modules and reaches the same high-water mark. Retaining
 * N MiB here must read as about N MiB on top of that baseline, or the delta
 * hides retention in the publish cases.
 */

import "./bounded-publish.harness.js";

export async function retainAll(args: unknown): Promise<number> {
  const { mib } = args as { mib: number };
  const kept: Buffer[] = [];
  for (let i = 0; i < mib * 16; i += 1) {
    kept.push(Buffer.alloc(64 * 1024, i & 0xff));
    if (i % 16 === 15) await new Promise((r) => setImmediate(r));
  }
  return kept.length;
}
