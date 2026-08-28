import { describe, expect, it } from "vitest";
import { createRng } from "./prng.js";
import {
  CORPUS_DAYS,
  DIURNAL,
  apportion,
  dayIso,
  dayTimestamps,
  dayWeights,
  spreadTimestamps,
  weekday,
} from "./time.js";

describe("apportion", () => {
  it("sums to exactly the total", () => {
    const weights = Array.from({ length: 100 }, (_, i) => i + 1);
    for (const total of [0, 1, 7, 999, 227_024]) {
      expect(apportion(total, weights).reduce((a, b) => a + b, 0)).toBe(total);
    }
  });

  it("gives zero-weight days zero records", () => {
    const counts = apportion(100, [1, 0, 1, 0]);
    expect(counts[1]).toBe(0);
    expect(counts[3]).toBe(0);
  });

  it("returns all zeros when every weight is zero", () => {
    expect(apportion(50, [0, 0, 0])).toEqual([0, 0, 0]);
  });

  it("is deterministic", () => {
    const weights = Array.from({ length: 40 }, (_, i) => (i % 7) + 0.5);
    expect(apportion(1234, weights)).toEqual(apportion(1234, weights));
  });
});

describe("dayWeights", () => {
  it("emits dead days when asked", () => {
    const weights = dayWeights(createRng(3), 1000, { deadDayChance: 0.1 });
    const dead = weights.filter((w) => w === 0).length;
    expect(dead).toBeGreaterThan(50);
    expect(dead).toBeLessThan(160);
  });

  it("suppresses weekends for work-shaped sources", () => {
    const weights = dayWeights(createRng(4), 700, { weekendBias: 0.1 });
    const weekendMean =
      weights
        .filter((_, d) => weekday(d) === 0 || weekday(d) === 6)
        .reduce((a, b) => a + b, 0) / 200;
    const weekdayMean =
      weights
        .filter((_, d) => weekday(d) !== 0 && weekday(d) !== 6)
        .reduce((a, b) => a + b, 0) / 500;
    expect(weekendMean).toBeLessThan(weekdayMean * 0.4);
  });
});

describe("dayTimestamps", () => {
  it("returns ascending timestamps inside the day", () => {
    const stamps = dayTimestamps(createRng(5), 10, 40, DIURNAL.work!);
    expect(stamps).toEqual([...stamps].sort((a, b) => a - b));
    for (const ts of stamps) {
      expect(new Date(ts).toISOString().slice(0, 10)).toBe(dayIso(10));
    }
  });

  it("follows the diurnal curve", () => {
    const stamps = dayTimestamps(createRng(6), 12, 3000, DIURNAL.work!);
    const hours = stamps.map((ts) => new Date(ts).getUTCHours());
    const night = hours.filter((h) => h >= 1 && h <= 4).length;
    const business = hours.filter((h) => h >= 9 && h <= 16).length;
    expect(business).toBeGreaterThan(night * 10);
  });
});

describe("spreadTimestamps", () => {
  // This is the regression guard for the artifact the old generator had: a
  // fixed delta per record, which compressed 10.4k conversations into ~10 days.
  it("spreads across the whole corpus window, not a fraction of it", () => {
    const stamps = [
      ...spreadTimestamps(createRng(8), 10_400, DIURNAL.evening!),
    ];
    expect(stamps).toHaveLength(10_400);
    const spanDays = (stamps[stamps.length - 1]! - stamps[0]!) / 86_400_000;
    expect(spanDays).toBeGreaterThan(CORPUS_DAYS * 0.95);
  });

  it("emits in chronological order", () => {
    const stamps = [...spreadTimestamps(createRng(9), 2000, DIURNAL.leisure!)];
    expect(stamps).toEqual([...stamps].sort((a, b) => a - b));
  });

  it("is not uniformly spaced", () => {
    const stamps = [...spreadTimestamps(createRng(10), 5000, DIURNAL.work!)];
    const gaps = stamps.slice(1).map((ts, i) => ts - stamps[i]!);
    expect(new Set(gaps).size).toBeGreaterThan(gaps.length * 0.5);
  });
});
