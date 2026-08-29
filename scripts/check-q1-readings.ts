/**
 * Is the model's number right for the set it declared?
 *
 * The set-resolution runs claimed "last month" = December 2025 and returned
 * 6.68, where the eval means a trailing 31 days and expects 6.5775. If 6.68 is
 * the correct December average then the model is not miscomputing — it is
 * computing correctly over a different, defensible reading, and the eval's
 * reading is the arbitrary one.
 */
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  DEFAULT_SEED,
  generateInto,
} from "@opendatalabs/personal-server-ts-core/query/evals";

import { FsFixtureSink } from "./query-eval-fs-sink.js";

interface SleepRow {
  day: string;
  type: string;
  total_sleep_duration: number | null;
}

const EXCLUDED = new Set(["rest", "deleted"]);

function mean(rows: SleepRow[]): { hours: number; n: number } {
  const main = rows.filter(
    (r) =>
      r.type === "long_sleep" &&
      !EXCLUDED.has(r.type) &&
      typeof r.total_sleep_duration === "number",
  );
  const total = main.reduce((a, r) => a + (r.total_sleep_duration ?? 0), 0);
  return { hours: total / main.length / 3600, n: main.length };
}

async function main(): Promise<void> {
  const dir = await mkdtemp(join(tmpdir(), "q1-readings-"));
  const sink = new FsFixtureSink(dir);
  await sink.init();
  await generateInto(sink, { profile: "dogfood", seed: DEFAULT_SEED });
  const rows = JSON.parse(await sink.read("oura_sleep.json")) as SleepRow[];

  const lastDay = rows.reduce((a, r) => (r.day > a ? r.day : a), "");
  const DAY = 86_400_000;
  const trailing = (n: number) => {
    const cutoff = new Date(
      Date.parse(`${lastDay}T00:00:00.000Z`) - (n - 1) * DAY,
    )
      .toISOString()
      .slice(0, 10);
    return mean(rows.filter((r) => r.day >= cutoff));
  };

  const december = mean(rows.filter((r) => r.day.startsWith("2025-12")));
  const november = mean(rows.filter((r) => r.day.startsWith("2025-11")));

  console.log(`last day in corpus: ${lastDay}\n`);
  console.log('Defensible readings of "the last month":');
  for (const n of [28, 30, 31]) {
    const r = trailing(n);
    console.log(`  trailing ${n} days      ${r.hours.toFixed(4)}h  (n=${r.n})`);
  }
  console.log(
    `  calendar Dec 2025    ${december.hours.toFixed(4)}h  (n=${december.n})`,
  );
  console.log(
    `  calendar Nov 2025    ${november.hours.toFixed(4)}h  (n=${november.n})`,
  );
  console.log(
    `\neval expects 6.5775 (trailing 31). Model returned 6.68 declaring "December 2025".`,
  );
  await rm(dir, { recursive: true, force: true });
}

main().catch((e: unknown) => {
  console.error(e);
  process.exitCode = 1;
});
