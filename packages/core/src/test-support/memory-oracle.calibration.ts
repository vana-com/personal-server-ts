/**
 * Synthetic workloads for calibrating `memory-oracle.ts`. Each one touches its
 * memory (fill) so the kernel counts it. They run in child processes.
 */

const CHUNK = 1024 * 1024;

/**
 * Streams `mib` MiB in 64 KiB pieces, drops each piece, and waits 1 ms between
 * pieces, as an I/O-bound publish does (about 64 MB/s).
 */
export async function bounded(args: unknown): Promise<number> {
  const { mib } = args as { mib: number };
  let sum = 0;
  for (let i = 0; i < mib * 16; i += 1) {
    const b = Buffer.alloc(64 * 1024, i & 0xff);
    sum += b[0]!;
    await new Promise((r) => setTimeout(r, 1));
  }
  return sum;
}

/** Holds `mib` MiB at the end of the workload (a retained accumulation). */
const retained: Buffer[] = [];
export function accumulate(args: unknown): number {
  const { mib } = args as { mib: number };
  for (let i = 0; i < mib; i += 1) retained.push(Buffer.alloc(CHUNK, i & 0xff));
  return retained.length;
}

/**
 * Holds `mib` MiB synchronously, reduces it, and frees it before returning. No
 * timer or other task runs while it is held, so a sampler sees nothing.
 */
export function materializeThenFree(args: unknown): number {
  const { mib } = args as { mib: number };
  const held: Buffer[] = [];
  for (let i = 0; i < mib; i += 1) held.push(Buffer.alloc(CHUNK, i & 0xff));
  let sum = 0;
  for (const b of held) sum += b[0]!;
  held.length = 0;
  return sum;
}
