/**
 * The two measured trap cases from design §18.2, as regression tests.
 *
 * These are what T2 source profiles exist to prevent. Both are *structural* —
 * the nap error follows from the nap rate and the duration ranges, the phantom
 * rate follows from the sibling-regeneration rate — so the ratios hold across
 * seeds and profiles even though the absolute figures do not. The ratios are
 * therefore what is asserted; the absolutes are reported by the phase-1 run.
 */

import { beforeAll, describe, expect, it } from "vitest";
import { MemoryFixtureSink, type FixtureSource } from "./fixtures/sink.js";
import { generateCorpus } from "./fixtures/generate.js";
import { branchTrap, localDateDrift, sleepTrap } from "./reference/compute.js";
import { DEFAULT_SEED } from "./fixtures/profiles.js";

let source: FixtureSource;

beforeAll(async () => {
  const sink = new MemoryFixtureSink();
  await generateCorpus(sink, { profile: "small", seed: DEFAULT_SEED });
  source = sink;
}, 60_000);

describe("trap 1 — Oura naps", () => {
  it("averages main sleep near the generator's 4.5–8.5h midpoint", async () => {
    const trap = await sleepTrap(source, null);
    expect(trap.correctHours).toBeGreaterThan(6.3);
    expect(trap.correctHours).toBeLessThan(6.7);
  });

  it("understates sleep by ~10-13% when naps are included", async () => {
    const trap = await sleepTrap(source, null);
    expect(trap.naiveHours).toBeLessThan(trap.correctHours);
    // Design §18.2 measured -11.5% on the previous corpus.
    expect(trap.errorPct).toBeLessThan(-9);
    expect(trap.errorPct).toBeGreaterThan(-14);
  });

  it("reports a denominator smaller than the calendar window", async () => {
    const trap = await sleepTrap(source, 31);
    expect(trap.nights).toBeLessThan(31);
    expect(trap.nights).toBeGreaterThan(23);
  });

  // The verified Oura enum has five values, not two. `rest` and `deleted` must
  // be dropped from every calculation.
  it("excludes rest and deleted periods from the corpus", async () => {
    const trap = await sleepTrap(source, null);
    expect(trap.excludedRows).toBeGreaterThan(0);
  });

  it("catches the filter that excludes naps but keeps rest and deleted", async () => {
    const trap = await sleepTrap(source, null);
    // `type !== "late_nap"` reads as more careful than including everything and
    // is still wrong — it keeps the rejected and deleted periods.
    expect(trap.excludingNapsOnlyHours).not.toBeCloseTo(trap.correctHours, 1);
    expect(Math.abs(trap.excludingNapsOnlyErrorPct)).toBeGreaterThan(1);
  });

  it("catches a null total_sleep_duration coerced to zero", async () => {
    const trap = await sleepTrap(source, null);
    expect(trap.nullDurationRows).toBeGreaterThan(0);
    expect(trap.nullAsZeroHours).toBeLessThan(trap.correctHours);
  });
});

describe("trap 3 — localized bedtime strings", () => {
  it("misdates most rows when the date is re-derived from bedtime_start", async () => {
    const drift = await localDateDrift(source);
    // Oura's `day` is the morning the sleep period ends; `bedtime_start` is the
    // evening before. So re-deriving the date from the timestamp is wrong for
    // essentially every main-sleep row, not just across the timezone change.
    // This is why the profile has to say `day` is authoritative.
    expect(drift.mismatched).toBeGreaterThan(drift.rows * 0.5);
  });
});

describe("trap 2 — ChatGPT sibling branches", () => {
  it("invents ~15% phantom messages when mapping is flattened", async () => {
    const trap = await branchTrap(source);
    expect(trap.naiveMessages).toBeGreaterThan(trap.correctMessages);
    // Follows directly from SIBLING_CHANCE = 0.15.
    expect(trap.phantomPct).toBeGreaterThan(11);
    expect(trap.phantomPct).toBeLessThan(19);
  });

  it("walks current_node rather than trusting insertion order", async () => {
    const trap = await branchTrap(source);
    // Mean turns is 4 + mean(int(16)) = 11.5 per conversation.
    const perConversation = trap.correctMessages / trap.conversations;
    expect(perConversation).toBeGreaterThan(10.5);
    expect(perConversation).toBeLessThan(12.5);
  });
});
