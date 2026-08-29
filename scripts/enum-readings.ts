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

  await rm(dir, { recursive: true, force: true });
}

main().catch((e: unknown) => {
  console.error(e);
  process.exitCode = 1;
});
