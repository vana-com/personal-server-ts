// Recheck after acquiring the cooperative host lock. Exit 75 releases it
// without importing the workload; a deferred admission is never a red receipt.
import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";
const free = execFileSync("free", ["-g"], { encoding: "utf8" });
const pressure = await readFile("/proc/pressure/memory", "utf8");
const availableGiB = Number(
  free
    .split("\n")
    .find((s) => s.startsWith("Mem:"))
    ?.trim()
    .split(/\s+/)
    .at(-1),
);
const fullAvg60 = Number(pressure.match(/full .*?avg60=([\d.]+)/)?.[1]);
console.log(
  JSON.stringify({
    event: "locked-admission",
    at: new Date().toISOString(),
    availableGiB,
    fullAvg60,
    free,
    pressure,
  }),
);
if (availableGiB < 12 || !(fullAvg60 < 1)) process.exit(75);
await import(pathToFileURL(process.argv[2]).href);
