/**
 * Deterministic pseudo-randomness for fixture generation.
 *
 * `Math.random()` must never appear anywhere under `evals/`. The corpus is only
 * useful as a grading substrate if a seed reproduces it byte for byte — an
 * expected value computed against a seed has to still hold next week.
 */

/** Mixes an arbitrary 32-bit value into a well-distributed one (splitmix32 finalizer). */
function mix32(x: number): number {
  let z = x | 0;
  z = (z ^ (z >>> 16)) >>> 0;
  z = Math.imul(z, 0x21f0aaad) >>> 0;
  z = (z ^ (z >>> 15)) >>> 0;
  z = Math.imul(z, 0x735a2d97) >>> 0;
  return (z ^ (z >>> 15)) >>> 0;
}

/**
 * Derives an independent stream seed from a root seed and a stream name.
 *
 * Each source draws from its own stream so that changing one generator (fixing
 * the ChatGPT time axis, say) does not shift every other source's values and
 * silently invalidate unrelated expectations.
 */
export function deriveSeed(rootSeed: number, stream: string): number {
  // FNV-1a over the stream name, then mixed with the root seed.
  let h = 0x811c9dc5;
  for (let i = 0; i < stream.length; i++) {
    h = (h ^ stream.charCodeAt(i)) >>> 0;
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return mix32((h ^ mix32(rootSeed)) >>> 0);
}

export interface Rng {
  /** Uniform in [0, 1). */
  next(): number;
  /** Uniform integer in [0, n). */
  int(n: number): number;
  /** Uniform number in [min, max). */
  range(min: number, max: number): number;
  /** True with probability `p`. */
  chance(p: number): boolean;
  /** Uniform element of a non-empty array. */
  pick<T>(items: readonly T[]): T;
  /** Integer in [min, max], inclusive. */
  between(min: number, max: number): number;
}

/** mulberry32 — small, fast, adequate for fixture shaping. Not for crypto. */
export function createRng(seed: number): Rng {
  let a = seed >>> 0;
  const next = (): number => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const int = (n: number): number => Math.floor(next() * n);
  return {
    next,
    int,
    range: (min, max) => min + next() * (max - min),
    chance: (p) => next() < p,
    pick: (items) => items[int(items.length)]!,
    between: (min, max) => min + int(max - min + 1),
  };
}
