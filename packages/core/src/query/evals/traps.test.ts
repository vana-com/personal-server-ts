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
import {
  generateCorpus,
  SCOPES,
  type CorpusManifest,
} from "./fixtures/generate.js";
import {
  anomalyReference,
  branchTrap,
  localDateDrift,
  sleepTrap,
  tripReference,
} from "./reference/compute.js";
import { Q14_JPY_PER_USD } from "./fixtures/planted.js";
import { buildCases } from "./cases.js";
import { DEFAULT_SEED } from "./fixtures/profiles.js";

let source: FixtureSource;
let manifest: CorpusManifest;

beforeAll(async () => {
  const sink = new MemoryFixtureSink();
  manifest = await generateCorpus(sink, {
    profile: "small",
    seed: DEFAULT_SEED,
  });
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

/*
 * Q11's tolerance, duplicated here rather than imported.
 *
 * `buildCases` needs a whole corpus to produce a case list, and this file is
 * asserting a property of the *fixture*, not of the case. The number is the
 * one thing that must agree, so it is stated once here and once there; if they
 * ever diverge, the assertions below stop being a proof about the eval.
 */
const Q11_TOLERANCE_BPM = 0.5;

describe("trap 4 — Oura heartrate.source contamination", () => {
  /*
   * The arming assertion.
   *
   * Q11 used to grade `oura_sleep.average_heart_rate`, which no
   * `heartrate.source` filter can affect — so 8 of 10 live runs skipped the
   * filter and passed anyway (implementation plan §6). The case now grades the
   * resting series itself, and these are the checks that the filter is the
   * only way to reach it: every route that ignores `source` has to miss by
   * more than the tolerance, or the trap is decorative again.
   */
  it("moves the graded figure far outside tolerance when `source` is ignored", async () => {
    const anomaly = await anomalyReference(source);
    const drift = Math.abs(anomaly.unfilteredLastWeekBpm - anomaly.lastWeekBpm);
    expect(drift).toBeGreaterThan(Q11_TOLERANCE_BPM);
    // Not marginally outside: workout and session samples sit ~45bpm higher
    // and are a third of the enum, so the contaminated mean is ~15bpm high.
    expect(drift).toBeGreaterThan(10);
    expect(anomaly.unfilteredLastWeekBpm).toBeGreaterThan(anomaly.lastWeekBpm);
  });

  it("contaminates the baseline as badly as the window under test", async () => {
    const anomaly = await anomalyReference(source);
    // An unfiltered baseline is inflated by more than the planted 12bpm
    // excursion, so an unfiltered z-score reports the anomalous week as
    // unremarkable — the failure is silent, not loud.
    const drift = Math.abs(anomaly.unfilteredBaselineBpm - anomaly.baselineBpm);
    expect(drift).toBeGreaterThan(10);
  });

  it("cannot be answered from the sleep collection either", async () => {
    const anomaly = await anomalyReference(source);
    // `sleep.average_heart_rate` is mean heart rate *during sleep*, not a
    // resting series. It is the near-miss route, and it must also miss.
    expect(
      Math.abs(anomaly.sleepRowLastWeekBpm - anomaly.lastWeekBpm),
    ).toBeGreaterThan(Q11_TOLERANCE_BPM);
  });

  it("still carries the planted excursion once the filter is applied", async () => {
    const anomaly = await anomalyReference(source);
    // The trap must not have been armed by destroying the signal it guards.
    expect(anomaly.lastWeekBpm).toBeGreaterThan(anomaly.baselineBpm);
    expect(anomaly.zScore).toBeGreaterThan(1);
    expect(anomaly.lastWeekSamples).toBeGreaterThan(0);
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

/*
 * Q14's tolerance, duplicated here for the same reason Q11's is: this file
 * asserts a property of the *fixture and the grant*, and the number is the one
 * thing that has to agree with `cases.ts`.
 */
const Q14_TOLERANCE_USD = 1;

/** In-window spend, the two currencies kept apart. */
async function inWindowByCurrency(
  src: FixtureSource,
  startDay: string,
  endDay: string,
): Promise<{ usd: number; jpy: number }> {
  const rows = JSON.parse(await src.read("bank_transactions.json")) as {
    date: string;
    currency: string;
    amount: number;
  }[];
  let usd = 0;
  let jpy = 0;
  for (const row of rows) {
    if (row.date < startDay || row.date > endDay) continue;
    if (row.currency === "JPY") jpy += Math.abs(row.amount);
    else usd += Math.abs(row.amount);
  }
  return { usd, jpy };
}

describe("trap 5 — Q14's grant must contain the FX rates its answer needs", () => {
  /*
   * The arming assertion, and a regression test for how it came unarmed.
   *
   * Q14's expectation is a single USD figure over a two-currency set. It was
   * measured with `fx.rates` in play (design §19.8's table records `7728.3`
   * for "profile + `fx.rates` scope"), but the case declared only `bank` and
   * `calendar` — the over-granting harness was quietly supplying the scope.
   * The moment each question was narrowed to its own grant the rates vanished,
   * and all three live runs said so outright, answered per-currency, and left
   * `value` unset. A declared grant that cannot reach the declared ground
   * truth is not a hard question, it is a broken one.
   */
  it("declares fx.rates, and the corpus exposes it", async () => {
    const cases = await buildCases(source);
    const q14 = cases.find((c) => c.id === "Q14");
    expect(q14?.scopes).toContain(SCOPES.fx);
    // Declaring a scope the manifest does not serve fails closed at the tool
    // host instead, which reads as the model refusing to look.
    expect(manifest.scopes.map((s) => s.scope)).toContain(SCOPES.fx);
  });

  it("puts the answer out of reach of bank and calendar alone", async () => {
    const trip = await tripReference(source);
    const { usd, jpy } = await inWindowByCurrency(
      source,
      trip.startDay,
      trip.endDay,
    );
    // Without rates the best single number a script can honestly produce is
    // the dollar side plus the flight. It has to miss, or the scope is
    // decorative and the case grades nothing about currency.
    expect(Math.abs(trip.totalUsd - (usd + trip.flightUsd))).toBeGreaterThan(
      Q14_TOLERANCE_USD,
    );
    // Not marginally: converted, the yen half is the larger half of the trip.
    expect(jpy / Q14_JPY_PER_USD).toBeGreaterThan(usd);
  });

  it("puts it out of reach of a guessed flat rate once the series drifts", async () => {
    // `dogfood` is the only profile whose rate moves, and it is the corpus
    // §19.8's numbers and `readings.ts`'s enumerated values come from. A model
    // that happens to know a plausible JPY/USD constant still has to read the
    // file: applying `Q14_JPY_PER_USD` uniformly lands ~106 USD off.
    const sink = new MemoryFixtureSink();
    await generateCorpus(sink, { profile: "dogfood", seed: DEFAULT_SEED });
    const trip = await tripReference(sink);
    const { usd, jpy } = await inWindowByCurrency(
      sink,
      trip.startDay,
      trip.endDay,
    );
    const flatRate = usd + jpy / Q14_JPY_PER_USD + trip.flightUsd;
    expect(Math.abs(trip.totalUsd - flatRate)).toBeGreaterThan(
      Q14_TOLERANCE_USD,
    );
  }, 60_000);
});
