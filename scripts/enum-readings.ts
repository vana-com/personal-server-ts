/**
 * Enumerate the defensible readings of each ambiguous question, computed from
 * the corpus and nothing else.
 *
 * This runs BEFORE any model output is looked at. That ordering is the whole
 * point: a "defensible reading" has to be a property of the data and the
 * English, not a description of whatever the model happened to say. See design
 * §19.9.
 */
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  DEFAULT_SEED,
  generateInto,
  reference,
} from "@opendatalabs/personal-server-ts-core/query/evals";

import { FsFixtureSink } from "./query-eval-fs-sink.js";

const DAY = 86_400_000;
const EXCLUDED_SLEEP = new Set(["rest", "deleted"]);

interface SleepRow {
  day: string;
  type: string;
  total_sleep_duration: number | null;
}
interface BankRow {
  date: string;
  amount: number;
  currency: string;
  merchant: string;
}
interface FxRow {
  date: string;
  jpy_per_usd: number;
}
interface WorkoutRow {
  day: string;
  distance: number;
  source: string;
}
interface HeartRateSleepRow {
  day: string;
  type: string;
  average_heart_rate: number;
}

async function main(): Promise<void> {
  const dir = await mkdtemp(join(tmpdir(), "readings-"));
  const sink = new FsFixtureSink(dir);
  await sink.init();
  await generateInto(sink, { profile: "dogfood", seed: DEFAULT_SEED });
  const read = async <T>(f: string): Promise<T> =>
    JSON.parse(await sink.read(f)) as T;

  const sleep = await read<SleepRow[]>("oura_sleep.json");
  const lastDay = sleep.reduce((a, r) => (r.day > a ? r.day : a), "");
  const meanSleep = (rows: SleepRow[]): { v: number; n: number } => {
    const m = rows.filter(
      (r) =>
        r.type === "long_sleep" &&
        !EXCLUDED_SLEEP.has(r.type) &&
        typeof r.total_sleep_duration === "number",
    );
    return {
      v:
        m.reduce((a, r) => a + (r.total_sleep_duration ?? 0), 0) /
        m.length /
        3600,
      n: m.length,
    };
  };
  const trailing = (n: number): { v: number; n: number } => {
    const cutoff = new Date(
      Date.parse(`${lastDay}T00:00:00.000Z`) - (n - 1) * DAY,
    )
      .toISOString()
      .slice(0, 10);
    return meanSleep(sleep.filter((r) => r.day >= cutoff));
  };

  console.log(`Q1 "last month" — last day in corpus ${lastDay}`);
  for (const n of [28, 30, 31]) {
    const r = trailing(n);
    console.log(`  trailing${n}   ${r.v.toFixed(4)}h  n=${r.n}`);
  }
  for (const m of ["2025-12", "2025-11"]) {
    const r = meanSleep(sleep.filter((x) => x.day.startsWith(m)));
    console.log(`  calendar ${m}  ${r.v.toFixed(4)}h  n=${r.n}`);
  }

  const bank = await read<BankRow[]>("bank_transactions.json");
  const files = await sink.list();
  const fx = files.includes("fx_rates.json")
    ? await read<FxRow[]>("fx_rates.json")
    : [];
  const rateOn = new Map(fx.map((r) => [r.date, r.jpy_per_usd]));
  const usd = (r: BankRow): number =>
    r.currency === "JPY"
      ? Math.abs(r.amount) / (rateOn.get(r.date) ?? 149.5)
      : Math.abs(r.amount);
  const jpyDates = bank
    .filter((r) => r.currency === "JPY")
    .map((r) => r.date)
    .sort();
  const start = jpyDates[0];
  const end = jpyDates[jpyDates.length - 1];
  const inWindow = bank
    .filter((r) => r.date >= start && r.date <= end)
    .reduce((a, r) => a + usd(r), 0);
  const jpyOnly = bank
    .filter((r) => r.currency === "JPY")
    .reduce((a, r) => a + usd(r), 0);
  const flight = bank
    .filter((r) => r.merchant === "DELTA AIR 006")
    .reduce((a, r) => a + Math.abs(r.amount), 0);
  console.log(`\nQ14 "Japan trip" — JPY window ${start} → ${end}`);
  console.log(`  jpyOnly            ${jpyOnly.toFixed(2)}`);
  console.log(`  inWindowAllCcy     ${inWindow.toFixed(2)}`);
  console.log(`  inWindow + flight  ${(inWindow + flight).toFixed(2)}`);
  console.log(`  (flight alone      ${flight.toFixed(2)})`);

  /* --- Q7 "what are my recurring monthly expenses, and which ones have crept up" --- */
  /*
   * Q7 is a `set` case, so no number arbitrates it — but the *set* has two
   * readings, and this is where they are enumerated rather than argued about.
   *
   * The eval's rule (`reference/compute.ts`) is cadence alone: a merchant
   * charged in at least 80% of the months is recurring, whatever the amount.
   * The competing reading is the one "which ones have **crept up**" implies —
   * a recurring *price*, i.e. a subscription, which has a per-charge amount
   * that can transition. A grocery run has no price to creep.
   *
   * Both columns are printed for every merchant that clears the cadence bar,
   * so the split is visible in the data instead of asserted: `amounts` is the
   * count of distinct charge amounts, and `spread` the max/min ratio. A
   * subscription holds a handful of amounts across three years; frequent
   * retail holds one per visit.
   */
  const bankDates = bank.map((r) => r.date).sort();
  const bankMonths = new Set(bank.map((r) => r.date.slice(0, 7))).size;
  const byMerchant = new Map<string, BankRow[]>();
  for (const r of bank) {
    byMerchant.set(r.merchant, [...(byMerchant.get(r.merchant) ?? []), r]);
  }
  console.log(
    `\nQ7 "recurring monthly expenses" — ${bank.length} rows, ` +
      `${bankDates[0]} → ${bankDates[bankDates.length - 1]}, ${bankMonths} months`,
  );
  console.log(
    `  merchant                 n   months  amounts  spread   monthlyGaps  cadenceRule  fixedPrice`,
  );
  for (const [merchant, list] of [...byMerchant].sort()) {
    // The eval's bar, restated from `recurringReference`: ~one charge a month
    // across most of the window. `months * 0.8` with months = ceil(days/30).
    const days =
      (Date.parse(bankDates[bankDates.length - 1]) - Date.parse(bankDates[0])) /
        DAY +
      1;
    const months = Math.ceil(days / 30);
    if (list.length < months * 0.8) continue;

    const sorted = [...list].sort((a, b) => a.date.localeCompare(b.date));
    const amounts = sorted.map((r) => Math.abs(r.amount));
    const distinct = new Set(amounts.map((a) => a.toFixed(2))).size;
    const spread = Math.max(...amounts) / Math.min(...amounts);
    const gaps = sorted
      .slice(1)
      .map((r, i) => (Date.parse(r.date) - Date.parse(sorted[i].date)) / DAY);
    const monthly = gaps.filter((g) => g >= 26 && g <= 35).length / gaps.length;
    // "Fixed price on a monthly cadence": the reading "crept up" presupposes.
    // Deliberately generous on the price side — a subscription that changes
    // price twice still has 3 distinct amounts over 37 charges.
    const fixedPrice = monthly >= 0.8 && distinct <= 5;
    console.log(
      `  ${merchant.padEnd(24)} ${String(list.length).padStart(3)}  ` +
        `${String(months).padStart(6)}  ${String(distinct).padStart(7)}  ` +
        `${spread.toFixed(2).padStart(6)}  ${(monthly * 100).toFixed(0).padStart(10)}%  ` +
        `${"yes".padStart(11)}  ${(fixedPrice ? "yes" : "no").padStart(10)}`,
    );
  }

  const nutFile = files.find((f) => f.startsWith("nutrition"));
  const workouts = await read<WorkoutRow[]>("oura_workout.json");
  const runDays = new Set(
    workouts.filter((w) => w.distance > 10_000).map((w) => w.day),
  );
  if (nutFile) {
    const nut = await read<Record<string, unknown>[]>(nutFile);
    console.log(`\nQ18 nutrition file ${nutFile}`);
    console.log(`  row keys: ${Object.keys(nut[0]).join(", ")}`);
    const byDay = new Map(nut.map((r) => [r.day as string, r]));
    const kcal = (r: Record<string, unknown>): number =>
      Number(r.calories ?? r.kcal ?? r.total_kcal ?? r.energy_kcal ?? 0);
    const logged = [...runDays].filter((d) => byDay.has(d));
    const mean = (ds: string[]): number =>
      ds.reduce((a, d) => a + kcal(byDay.get(d)!), 0) / ds.length;
    console.log(`  run days ${runDays.size}, logged ${logged.length}`);
    console.log(`  mean over logged run days      ${mean(logged).toFixed(2)}`);
    for (const flag of ["complete", "partial"]) {
      const sub = logged.filter((d) => {
        const v = byDay.get(d)![flag];
        return flag === "complete" ? v !== false : v === false;
      });
      if (sub.length && sub.length !== logged.length) {
        console.log(
          `  mean over ${flag} logged days     ${mean(sub).toFixed(2)}  n=${sub.length}`,
        );
      }
    }
  }

  /*
   * The candidate review: the two numeric questions that are NOT declared
   * ambiguous, checked here rather than argued about.
   *
   * Both carry a vague window phrase, so the English alone would let either in.
   * The bar is higher than that: a reading only matters if it *moves the
   * number* by more than the case's own tolerance. Where every defensible
   * window yields the same answer, strict grading can already tell a wrong
   * answer from a different reading, and declaring ambiguity would buy nothing
   * while widening what passes. These figures are the evidence for leaving
   * `AMBIGUOUS_READINGS` at three questions.
   */
  const iso = (day: string, offsetDays: number): string =>
    new Date(Date.parse(`${day}T00:00:00.000Z`) + offsetDays * DAY)
      .toISOString()
      .slice(0, 10);
  const within = (d: string, w: [string, string]): boolean =>
    d >= w[0] && d <= w[1];

  /* --- Q6 "how many distinct people did I talk to last month" --- */
  /*
   * The reference implementation takes a trailing window, so a calendar month
   * cannot be run through it directly. It does not need to be: the corpus has
   * a fixed cast, and the ladder below shows how few days it takes to see all
   * of them. Once every window from four days up returns the same count, no
   * reading of "last month" can move the answer, and the calendar/trailing
   * split has nothing to bite on.
   *
   * `rows` is the case's `denominator`, and it *does* move with the window —
   * noted, not acted on. Fixing that would mean declaring Q6 ambiguous, which
   * §19.10 refuses on separate grounds.
   */
  console.log(`\nQ6 "last month" — identity-resolved, by trailing window`);
  for (const n of [4, 7, 14, 28, 30, 31, 35]) {
    const r = await reference.identityReference(sink, n);
    console.log(
      `  trailing${String(n).padEnd(3)} people=${r.distinctPeople}  raw aliases=${r.distinctAliases}  rows=${r.rowsScanned}`,
    );
  }

  /* --- Q11 "was my resting heart rate unusual last week" --- */
  const hrSleep = await read<HeartRateSleepRow[]>("oura_sleep.json");
  const meanHr = (w: [string, string]): { v: number; n: number } => {
    const m = hrSleep.filter(
      (r) => r.type === "long_sleep" && within(r.day, w),
    );
    return {
      v: m.reduce((a, r) => a + r.average_heart_rate, 0) / m.length,
      n: m.length,
    };
  };
  // Day-of-week matters: a corpus ending mid-week separates "the last 7 days"
  // from "the last Monday-to-Sunday", and one ending on a Sunday collapses them.
  const lastDow = new Date(`${lastDay}T00:00:00.000Z`).getUTCDay();
  const dowName = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"][lastDow];
  const mondayOfLastDay = iso(lastDay, -((lastDow + 6) % 7));
  const q11Windows: [string, [string, string]][] = [
    ["trailing7", [iso(lastDay, -6), lastDay]],
    ["trailing5", [iso(lastDay, -4), lastDay]],
    ["week to date (Mon→)", [mondayOfLastDay, lastDay]],
    [
      "prior full Mon–Sun",
      [iso(mondayOfLastDay, -7), iso(mondayOfLastDay, -1)],
    ],
  ];
  console.log(
    `\nQ11 "last week" — mean long_sleep average_heart_rate (last day ${lastDay}, a ${dowName})`,
  );
  for (const [label, w] of q11Windows) {
    const r = meanHr(w);
    console.log(
      `  ${label.padEnd(20)} ${w[0]}→${w[1]}  ${r.v.toFixed(4)}bpm  n=${r.n}`,
    );
  }

  await rm(dir, { recursive: true, force: true });
}

main().catch((e: unknown) => {
  console.error(e);
  process.exitCode = 1;
});
