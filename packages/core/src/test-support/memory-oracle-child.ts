/**
 * Child entry for `memory-oracle.ts`. Usage:
 *   node --import tsx --max-old-space-size=N memory-oracle-child.ts <module> <export> <argsJson>
 * An empty export name loads the module and calls nothing (the baseline).
 */

import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

function hwmBytes(): number {
  const status = readFileSync("/proc/self/status", "utf8");
  const match = /^VmHWM:\s+(\d+) kB$/m.exec(status);
  if (!match) throw new Error("VmHWM not found in /proc/self/status");
  return Number(match[1]) * 1024;
}

const [modulePath, exportName, argsJson] = process.argv.slice(2);
if (!modulePath || exportName === undefined || argsJson === undefined) {
  throw new Error("usage: memory-oracle-child <module> <export> <argsJson>");
}

const mod = (await import(pathToFileURL(modulePath).href)) as Record<
  string,
  (args: unknown) => unknown
>;
// Periodic GC keeps Buffer churn from piling up across the whole workload,
// including the reduce phase that runs after intake. Unref'd so it never keeps
// the child alive. See memory-oracle.ts for why this is a timer.
const GC_INTERVAL_MS = 25;
const gc = (globalThis as { gc?: () => void }).gc;
if (!gc) throw new Error("memory-oracle child requires --expose-gc");
setInterval(gc, GC_INTERVAL_MS).unref();

let result: unknown = null;
if (exportName !== "") {
  const fn = mod[exportName];
  if (typeof fn !== "function") {
    throw new Error(`${modulePath} has no function export ${exportName}`);
  }
  result = await fn(JSON.parse(argsJson) as unknown);
}
// Read before anything else allocates, so the mark is the workload's peak.
const hwm = hwmBytes();
process.stdout.write(
  `MEMORY_ORACLE ${JSON.stringify({ hwmBytes: hwm, result: result ?? null })}\n`,
);
