/**
 * Child entry for `memory-oracle.ts`. Usage:
 *   node --import tsx --max-old-space-size=N memory-oracle-child.mjs <module> <export> <argsJson> <gcMode>
 * An empty export name loads the module and calls nothing.
 */

import { readFileSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

function statusKiB(field) {
  const status = readFileSync("/proc/self/status", "utf8");
  const match = new RegExp(`^${field}:\\s+(\\d+) kB$`, "m").exec(status);
  if (!match) throw new Error(`${field} not found in /proc/self/status`);
  return Number(match[1]) * 1024;
}

const [modulePath, exportName, argsJson] = process.argv.slice(2);
if (!modulePath || exportName === undefined || argsJson === undefined) {
  throw new Error("usage: memory-oracle-child <module> <export> <argsJson>");
}

const mod = await import(pathToFileURL(modulePath).href);
const gcMode = process.argv[5] ?? "timer25ms";
if (gcMode !== "timer25ms" && gcMode !== "none") {
  throw new Error(`unknown gc mode ${gcMode}`);
}
const gc = globalThis.gc;
if (!gc) throw new Error("memory-oracle child requires --expose-gc");
// Periodic GC keeps Buffer churn from piling up across the whole workload,
// including the reduce phase that runs after intake. Unref'd so it never keeps
// the child alive. Skipped in "none" mode. See memory-oracle.ts.
if (gcMode === "timer25ms") setInterval(gc, 25).unref();

// Start the peak at this process's own resident size after the module loaded.
// Import leaves garbage that V8 releases lazily; a few forced GCs plus a short
// settle let that release finish before the start point is taken, so the release
// cannot lower RSS after the reset and under-read the workload. Then
// /proc/self/clear_refs "5" resets VmHWM to the current RSS, so VmHWM after the
// workload is the peak above this start point, in the same process.
for (let k = 0; k < 3; k += 1) gc();
await new Promise((r) => setTimeout(r, 300));
for (let k = 0; k < 2; k += 1) gc();
writeFileSync("/proc/self/clear_refs", "5");
const startBytes = statusKiB("VmRSS");

let result = null;
if (exportName !== "") {
  const fn = mod[exportName];
  if (typeof fn !== "function") {
    throw new Error(`${modulePath} has no function export ${exportName}`);
  }
  result = await fn(JSON.parse(argsJson));
}
// Read before anything else allocates, so the mark is the workload's peak.
const hwmBytes = statusKiB("VmHWM");
process.stdout.write(
  `MEMORY_ORACLE ${JSON.stringify({ hwmBytes, startBytes, result: result ?? null })}\n`,
);
