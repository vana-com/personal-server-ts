/**
 * Realistic time axes for the fixture corpus.
 *
 * The generator this replaces (`docs/query-layer-fixtures/gen*.js`) spaced every
 * source's records by a fixed delta, which compressed most of them into a
 * fraction of the intended window — conversations into ~10 days, notes into
 * ~278, Spotify into ~475. Q9 ("when did I *first* start thinking about X") and
 * Q10 ("what changed over the last two years") are vacuous on a corpus with no
 * real date spread, so the time axis is a correctness requirement here, not
 * cosmetics.
 *
 * Every source is laid out over the same window with three effects that a fixed
 * delta cannot produce: per-day burstiness, weekday bias, and a diurnal curve.
 */

import type { Rng } from "./prng.js";

export const DAY_MS = 86_400_000;

/** Every source shares this window so cross-source joins (Q4, Q18) have real overlap. */
export const CORPUS_START_MS = Date.parse("2023-01-01T00:00:00.000Z");
export const CORPUS_DAYS = 1100;

export function dayStartMs(dayIndex: number): number {
  return CORPUS_START_MS + dayIndex * DAY_MS;
}

export function dayIso(dayIndex: number): string {
  return new Date(dayStartMs(dayIndex)).toISOString().slice(0, 10);
}

/** 0 = Sunday. The corpus window starts on a Sunday (2023-01-01), so this is exact. */
export function weekday(dayIndex: number): number {
  return (dayIndex + 0) % 7;
}

/**
 * Hour-of-day weights. Real exports are never uniform across the clock, and a
 * flat axis makes Q16 ("am I a morning person?") unanswerable by construction.
 */
export const DIURNAL: Record<string, readonly number[]> = {
  // Work tools: business hours, lunch dip, dead overnight.
  work: [
    0.2, 0.1, 0.05, 0.05, 0.05, 0.2, 0.6, 1.4, 3.0, 4.2, 4.6, 4.4, 3.0, 4.0,
    4.6, 4.4, 3.8, 2.6, 1.6, 1.1, 0.9, 0.7, 0.5, 0.3,
  ],
  // Media: commute bumps and a long evening tail.
  leisure: [
    0.4, 0.2, 0.1, 0.1, 0.1, 0.3, 0.9, 2.2, 2.8, 2.0, 1.8, 1.8, 2.0, 1.9, 1.8,
    2.0, 2.6, 3.4, 3.6, 3.4, 3.0, 2.4, 1.6, 0.8,
  ],
  // Personal writing / chat assistants: evening-heavy, some late night.
  evening: [
    0.6, 0.4, 0.2, 0.1, 0.1, 0.2, 0.5, 1.0, 1.6, 2.0, 2.2, 2.0, 1.8, 1.9, 2.0,
    2.1, 2.4, 3.0, 3.6, 4.0, 4.2, 3.6, 2.4, 1.2,
  ],
  flat: Array.from({ length: 24 }, () => 1),
};

export interface DayWeightOptions {
  /** Multiplier applied to Sat/Sun. <1 for work tools, >1 for leisure. */
  weekendBias?: number;
  /** Probability a given day is "dead" (travel, outage, forgot the device). */
  deadDayChance?: number;
  /** Probability a burst starts on a given day, and how long/strong it runs. */
  burstChance?: number;
  burstStrength?: number;
  /** How fast the slow random walk drifts. */
  drift?: number;
}

/**
 * Per-day activity weights: a slow random walk (seasons, life phases) with
 * bursts (a crunch week, a trip) and dead days (a gap in the export).
 *
 * The dead days matter beyond realism: Q1 must report a denominator like "28 of
 * 31 nights had data", which is only meaningful if some nights genuinely have
 * none.
 */
export function dayWeights(
  rng: Rng,
  days: number,
  options: DayWeightOptions = {},
): number[] {
  const {
    weekendBias = 1,
    deadDayChance = 0,
    burstChance = 0.01,
    burstStrength = 2.5,
    drift = 0.08,
  } = options;

  const weights = new Array<number>(days);
  let level = 1;
  let burstLeft = 0;

  for (let d = 0; d < days; d++) {
    // Slow multiplicative random walk, clamped so nothing runs away.
    level *= 1 + (rng.next() - 0.5) * 2 * drift;
    level = Math.min(2.2, Math.max(0.35, level));

    if (burstLeft > 0) burstLeft--;
    else if (rng.chance(burstChance)) burstLeft = rng.between(3, 12);

    if (rng.chance(deadDayChance)) {
      weights[d] = 0;
      continue;
    }

    const wd = weekday(d);
    const weekend = wd === 0 || wd === 6 ? weekendBias : 1;
    const burst = burstLeft > 0 ? burstStrength : 1;
    // Per-day jitter on top, so consecutive days are not suspiciously smooth.
    weights[d] = level * weekend * burst * (0.6 + rng.next() * 0.8);
  }
  return weights;
}

/**
 * Largest-remainder apportionment: splits `total` across `weights` so the parts
 * sum to exactly `total`, deterministically.
 *
 * Sampling a day per record independently would also work but would not hit an
 * exact record count, and the eval's expected denominators depend on exact
 * counts.
 */
export function apportion(total: number, weights: number[]): number[] {
  const sum = weights.reduce((a, b) => a + b, 0);
  if (sum <= 0 || total <= 0) return weights.map(() => 0);

  const exact = weights.map((w) => (w / sum) * total);
  const counts = exact.map((x) => Math.floor(x));
  let assigned = counts.reduce((a, b) => a + b, 0);

  // Distribute the remainder to the largest fractional parts; index breaks ties.
  const order = exact
    .map((x, i) => ({ frac: x - Math.floor(x), i }))
    .sort((a, b) => b.frac - a.frac || a.i - b.i);

  for (let k = 0; assigned < total; k++, assigned++) {
    counts[order[k % order.length]!.i]!++;
  }
  return counts;
}

/** Builds a cumulative distribution for inverse-transform sampling. */
function cdf(weights: readonly number[]): number[] {
  const out: number[] = [];
  let acc = 0;
  for (const w of weights) {
    acc += w;
    out.push(acc);
  }
  return out.map((x) => x / acc);
}

/**
 * `count` timestamps inside one day, drawn from `hourWeights` and returned in
 * ascending order — real exports are chronological, and Q9's "earliest match"
 * is only a meaningful test if ordering is not accidentally informative.
 */
export function dayTimestamps(
  rng: Rng,
  dayIndex: number,
  count: number,
  hourWeights: readonly number[],
): number[] {
  if (count <= 0) return [];
  const base = dayStartMs(dayIndex);
  const table = cdf(hourWeights);
  const out = new Array<number>(count);
  for (let i = 0; i < count; i++) {
    const u = rng.next();
    let hour = table.findIndex((c) => u <= c);
    if (hour < 0) hour = 23;
    out[i] = base + hour * 3_600_000 + rng.int(3_600_000);
  }
  return out.sort((a, b) => a - b);
}

/**
 * Yields every timestamp for a source across the whole window, in order.
 *
 * This is the routine that replaces `T0 + i * FIXED_DELTA`.
 */
export function* spreadTimestamps(
  rng: Rng,
  total: number,
  hourWeights: readonly number[],
  options: DayWeightOptions = {},
  days = CORPUS_DAYS,
): Generator<number> {
  const counts = apportion(total, dayWeights(rng, days, options));
  for (let d = 0; d < days; d++) {
    for (const ts of dayTimestamps(rng, d, counts[d]!, hourWeights)) {
      yield ts;
    }
  }
}

export function iso(ms: number): string {
  return new Date(ms).toISOString();
}
